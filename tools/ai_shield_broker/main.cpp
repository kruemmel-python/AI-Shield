#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <span>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "ai_shield/audit.hpp"
#include "ai_shield/abi2.hpp"
#include "ai_shield/pdf_preflight.hpp"
#include "ai_shield/ransomware.hpp"
#include "ai_shield/sha256.hpp"
#include "ai_shield/zip_preflight.hpp"
#include "platform/windows/common/ai_shield_driver_protocol.h"
#include "platform/windows/common/abi_translation.hpp"
#include "platform/windows/security/secure_runtime_state.hpp"

namespace {

constexpr wchar_t kServiceName[] = L"AIShieldBroker";
constexpr std::size_t kRecordsPerSegment = 4096U;
constexpr std::uint64_t kMaximumClassifiedFileSize = 256ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t kContentDocuments = 1U << 0U;
constexpr std::uint32_t kContentArchives = 1U << 1U;
constexpr std::uint32_t kContentImages = 1U << 2U;
constexpr std::uint32_t kContentAudio = 1U << 3U;
constexpr std::uint32_t kContentVideo = 1U << 4U;
constexpr std::uint32_t kContentWeb = 1U << 5U;
constexpr std::uint32_t kContentAll = (1U << 6U) - 1U;

struct ContentPolicy final {
    std::uint32_t magic = 0x50435341U;
    std::uint32_t version = 1U;
    std::uint32_t enabled_categories = kContentAll;
    std::uint32_t fail_closed = 1U;
};

struct Sensor final {
    const wchar_t* name;
    const wchar_t* path;
    ULONG id;
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::uint64_t last_sequence = 0;
};

std::array<Sensor, 3> g_sensors{{
    {L"wfp", L"\\\\.\\AIShieldWfp", AI_SHIELD_SENSOR_WFP},
    {L"minifilter", L"\\\\.\\AIShieldMiniFilter", AI_SHIELD_SENSOR_MINIFILTER},
    {L"process_guard", L"\\\\.\\AIShieldProcessGuard", AI_SHIELD_SENSOR_PROCESS}}};
std::atomic_bool g_stop{false};
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};

bool elevated_administrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&authority, 2U, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0U, 0U, 0U, 0U, 0U, 0U, &administrators)) return false;
    BOOL member = FALSE;
    const bool ok = CheckTokenMembership(nullptr, administrators, &member) != FALSE && member != FALSE;
    FreeSid(administrators);
    return ok;
}

void close_sensors() noexcept {
    for (auto& sensor : g_sensors) {
        if (sensor.handle != INVALID_HANDLE_VALUE) CloseHandle(sensor.handle);
        sensor.handle = INVALID_HANDLE_VALUE;
    }
}

bool open_sensors() {
    close_sensors();
    for (auto& sensor : g_sensors) {
        sensor.handle = CreateFileW(sensor.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (sensor.handle == INVALID_HANDLE_VALUE) {
            std::wcerr << L"broker: open " << sensor.name << L" failed error=" << GetLastError() << L'\n';
            close_sensors();
            return false;
        }
    }
    return true;
}

bool write_atomic(const std::filesystem::path& destination, std::span<const std::byte> bytes) {
    const auto temporary = destination.wstring() + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool size_valid = bytes.size() <= MAXDWORD;
    const bool write_ok = size_valid && WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                          written == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!write_ok) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return MoveFileExW(temporary.c_str(), destination.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

bool append_durable(const std::filesystem::path& destination, const std::string& record) {
    std::error_code error;
    std::filesystem::create_directories(destination.parent_path(), error);
    if (error) return false;
    HANDLE file = CreateFileW(destination.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool valid_size = record.size() <= MAXDWORD;
    const bool written_ok = valid_size && WriteFile(file, record.data(), static_cast<DWORD>(record.size()), &written, nullptr) &&
                            written == record.size() && FlushFileBuffers(file);
    CloseHandle(file);
    return written_ok;
}

class AuditWriter final {
public:
    explicit AuditWriter(std::filesystem::path directory) : directory_(std::move(directory)) {}

    bool initialize() {
        std::error_code error;
        std::filesystem::create_directories(directory_, error);
        if (error) return false;
        for (const auto& entry : std::filesystem::directory_iterator(directory_, error)) {
            const auto name = entry.path().filename().wstring();
            if (name.starts_with(L"kernel-audit-") && entry.path().extension() == L".bin") ++file_index_;
        }
        return !error;
    }

    bool append(const ai_shield::abi2::SensorEvent& event) {
        ai_shield::audit::AuditRecord record{};
        record.sequence = static_cast<std::uint64_t>(count_ + 1U);
        record.monotonic_ns = event.header.monotonic_ns;
        record.reason_mask = (event.event_flags & AI_SHIELD_EVENT_FLAG_BLOCKED) != 0U ? event.decision : 0U;
        record.evidence_hash = event.evidence_hash;
        record.correlation = {.flow_id = event.header.flow_id, .object_id = event.header.object_id,
            .file_id = event.file_id, .volume_id = event.volume_id, .provenance_id = event.provenance_id,
            .process_id = event.process_id, .parent_process_id = event.parent_process_id,
            .policy_version = event.header.policy_version, .model_version = event.header.model_version};
        if (!chain_.append(record).ok()) return false;
        ++count_;
        return count_ < kRecordsPerSegment || flush();
    }

    bool flush() {
        if (count_ == 0U) return true;
        const auto bytes = ai_shield::audit::serialize(chain_);
        const auto filename = L"kernel-audit-" + std::to_wstring(file_index_) + L".bin";
        if (!write_atomic(directory_ / filename, bytes)) return false;
        ++file_index_;
        count_ = 0U;
        chain_ = {};
        return true;
    }

private:
    std::filesystem::path directory_;
    ai_shield::audit::AuditChain chain_;
    std::size_t count_ = 0U;
    std::uint64_t file_index_ = 0U;
};

std::string digest_hex(const ai_shield::crypto::Sha256Digest& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64U);
    for (const auto value : digest) {
        const auto byte = std::to_integer<unsigned int>(value);
        result.push_back(digits[(byte >> 4U) & 0xfU]);
        result.push_back(digits[byte & 0xfU]);
    }
    return result;
}

std::string json_escape(std::wstring_view value) {
    std::string result;
    for (const wchar_t character : value) {
        if (character == L'\\' || character == L'"') result.push_back('\\');
        if (character >= 0x20 && character <= 0x7e) result.push_back(static_cast<char>(character));
        else if (character > 0x7e) result.push_back('?');
    }
    return result;
}

bool executable_extension(std::filesystem::path path) {
    auto extension = path.extension().wstring();
    for (auto& character : extension) character = static_cast<wchar_t>(towlower(character));
    constexpr std::array<std::wstring_view, 15> extensions{
        L".exe", L".dll", L".scr", L".com", L".msi", L".bat", L".cmd", L".ps1",
        L".vbs", L".vbe", L".js", L".jse", L".wsf", L".hta", L".lnk"};
    for (const auto candidate : extensions) if (extension == candidate) return true;
    return false;
}

std::wstring lower_extension(const std::filesystem::path& path) {
    auto extension = path.extension().wstring();
    for (auto& character : extension) character = static_cast<wchar_t>(towlower(character));
    return extension;
}

std::uint32_t content_category(const std::filesystem::path& path) {
    const auto extension = lower_extension(path);
    constexpr auto documents = std::to_array<std::wstring_view>({
        L".pdf", L".doc", L".docx", L".docm", L".xls", L".xlsx", L".xlsm", L".ppt", L".pptx", L".pptm",
        L".rtf", L".odt", L".ods", L".odp", L".one"});
    constexpr auto archives = std::to_array<std::wstring_view>({L".zip", L".7z", L".rar", L".iso", L".cab"});
    constexpr auto images = std::to_array<std::wstring_view>({
        L".jpg", L".jpeg", L".jfif", L".png", L".gif", L".bmp", L".tif", L".tiff", L".webp", L".ico", L".svg"});
    constexpr auto audio = std::to_array<std::wstring_view>({L".mp3", L".wav", L".flac", L".aac", L".ogg", L".m4a"});
    constexpr auto video = std::to_array<std::wstring_view>({L".mp4", L".m4v", L".mov", L".avi", L".mkv", L".webm", L".wmv"});
    constexpr auto web = std::to_array<std::wstring_view>({L".html", L".htm"});
    const auto contains = [&extension](const auto& values) {
        return std::find(values.begin(), values.end(), extension) != values.end();
    };
    if (contains(documents)) return kContentDocuments;
    if (contains(archives)) return kContentArchives;
    if (contains(images)) return kContentImages;
    if (contains(audio)) return kContentAudio;
    if (contains(video)) return kContentVideo;
    if (contains(web)) return kContentWeb;
    return 0U;
}

bool parser_risk_extension(const std::filesystem::path& path, std::uint32_t enabled = kContentAll) {
    return (content_category(path) & enabled) != 0U;
}

std::filesystem::path content_policy_path() {
    return L"C:\\ProgramData\\AIShield\\private-desktop\\content-protection.bin";
}

ContentPolicy load_content_policy() {
    ContentPolicy fallback{};
    std::ifstream input(content_policy_path(), std::ios::binary);
    if (!input) return fallback;
    const std::string encrypted_text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> encrypted(encrypted_text.size());
    std::memcpy(encrypted.data(), encrypted_text.data(), encrypted_text.size());
    if (encrypted.empty() || encrypted.size() > 4096U) return fallback;
    DATA_BLOB source{static_cast<DWORD>(encrypted.size()), reinterpret_cast<BYTE*>(encrypted.data())};
    DATA_BLOB clear{};
    if (!CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &clear)) return fallback;
    ContentPolicy policy{};
    const bool valid = clear.cbData == sizeof(policy);
    if (valid) std::memcpy(&policy, clear.pbData, sizeof(policy));
    LocalFree(clear.pbData);
    if (!valid || policy.magic != fallback.magic || policy.version != 1U ||
        (policy.enabled_categories & ~kContentAll) != 0U || policy.fail_closed > 1U) return fallback;
    return policy;
}

bool save_content_policy(const ContentPolicy& policy) {
    DATA_BLOB source{sizeof(policy), reinterpret_cast<BYTE*>(const_cast<ContentPolicy*>(&policy))};
    DATA_BLOB encrypted{};
    if (!CryptProtectData(&source, L"AI Shield content protection", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) return false;
    std::error_code error;
    std::filesystem::create_directories(content_policy_path().parent_path(), error);
    const bool saved = !error && write_atomic(content_policy_path(), std::span(
        reinterpret_cast<const std::byte*>(encrypted.pbData), encrypted.cbData));
    LocalFree(encrypted.pbData);
    return saved;
}

bool has_external_zone(const std::filesystem::path& path) {
    const std::wstring stream = path.wstring() + L":Zone.Identifier";
    HANDLE file = CreateFileW(stream.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    std::array<char, 4096> buffer{};
    DWORD bytes = 0;
    const bool read = ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size() - 1U), &bytes, nullptr) != FALSE;
    CloseHandle(file);
    if (!read) return false;
    const std::string_view text(buffer.data(), bytes);
    return text.find("ZoneId=3") != std::string_view::npos || text.find("ZoneId=4") != std::string_view::npos;
}

bool read_locked_file(HANDLE file, std::uint64_t expected_size, std::vector<std::byte>& content,
                      ai_shield::crypto::Sha256Digest& digest) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) != expected_size)
        return false;
    if (expected_size > kMaximumClassifiedFileSize) {
        BY_HANDLE_FILE_INFORMATION information{};
        if (!GetFileInformationByHandle(file, &information)) return false;
        const std::array<std::uint64_t, 4> identity{
            information.dwVolumeSerialNumber,
            (static_cast<std::uint64_t>(information.nFileIndexHigh) << 32U) | information.nFileIndexLow,
            expected_size,
            (static_cast<std::uint64_t>(information.ftLastWriteTime.dwHighDateTime) << 32U) |
                information.ftLastWriteTime.dwLowDateTime};
        digest = ai_shield::crypto::sha256(std::as_bytes(std::span(identity)));
        return true;
    }
    content.resize(static_cast<std::size_t>(size.QuadPart));
    std::array<std::byte, 1U << 20U> chunk{};
    std::uint64_t offset = 0;
    bool ok = true;
    HANDLE read_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (read_event == nullptr) return false;
    while (offset < expected_size) {
        const DWORD request = static_cast<DWORD>((std::min)(expected_size - offset, static_cast<std::uint64_t>(chunk.size())));
        DWORD bytes = 0;
        OVERLAPPED operation{};
        operation.Offset = static_cast<DWORD>(offset & 0xffffffffULL);
        operation.OffsetHigh = static_cast<DWORD>(offset >> 32U);
        operation.hEvent = read_event;
        ResetEvent(read_event);
        const BOOL immediate = ReadFile(file, chunk.data(), request, &bytes, &operation);
        if (!immediate && GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(read_event, 5'000U) != WAIT_OBJECT_0) {
                CancelIoEx(file, &operation);
                WaitForSingleObject(read_event, 1'000U);
                ok = false;
                break;
            }
            if (!GetOverlappedResult(file, &operation, &bytes, FALSE)) { ok = false; break; }
        } else if (!immediate) {
            ok = false;
            break;
        }
        if (bytes == 0U) {
            ok = false;
            break;
        }
        std::copy_n(chunk.begin(), bytes, content.begin() + static_cast<std::size_t>(offset));
        offset += bytes;
    }
    CloseHandle(read_event);
    if (!ok || offset != expected_size) return false;
    digest = ai_shield::crypto::sha256(content);
    return ok;
}

enum class DefenderVerdict { clean, threat, unavailable, suspicious };

std::filesystem::path defender_command() {
    const auto platform = std::filesystem::path(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform");
    std::error_code error;
    std::filesystem::path newest;
    if (std::filesystem::exists(platform, error)) {
        for (const auto& entry : std::filesystem::directory_iterator(
                 platform, std::filesystem::directory_options::skip_permission_denied, error)) {
            const auto candidate = entry.path() / L"MpCmdRun.exe";
            if (entry.is_directory(error) && std::filesystem::exists(candidate, error) &&
                (newest.empty() || entry.path().filename() > newest.parent_path().filename())) {
                newest = candidate;
            }
        }
    }
    if (!newest.empty()) return newest;
    wchar_t program_files[MAX_PATH]{};
    const DWORD count = GetEnvironmentVariableW(L"ProgramFiles", program_files, MAX_PATH);
    if (count != 0U && count < MAX_PATH) {
        const auto fallback = std::filesystem::path(program_files) / L"Windows Defender" / L"MpCmdRun.exe";
        if (std::filesystem::exists(fallback, error)) return fallback;
    }
    return {};
}

DefenderVerdict scan_with_defender(const std::filesystem::path& path, std::uint64_t size) {
    if (size > 0U && size <= kMaximumClassifiedFileSize) {
        std::array<wchar_t, 32768> module_path{};
        const DWORD module_length = GetModuleFileNameW(nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
        if (module_length == 0U || module_length >= module_path.size()) return DefenderVerdict::unavailable;
        const auto scanner = std::filesystem::path(module_path.data()).parent_path() / L"ai_shield_integrations.exe";
        if (!std::filesystem::exists(scanner)) return DefenderVerdict::unavailable;
        std::wstring arguments = L"\"" + scanner.wstring() + L"\" amsi-scan-file \"" + path.wstring() + L"\"";
        std::vector<wchar_t> mutable_arguments(arguments.begin(), arguments.end());
        mutable_arguments.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(scanner.c_str(), mutable_arguments.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &startup, &process)) return DefenderVerdict::unavailable;
        const DWORD wait = WaitForSingleObject(process.hProcess, 10'000U);
        DWORD exit_code = ERROR_GEN_FAILURE;
        if (wait == WAIT_TIMEOUT) TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        const bool completed = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (!completed) return DefenderVerdict::unavailable;
        if (exit_code == 0U) return DefenderVerdict::clean;
        if (exit_code == 10U) return DefenderVerdict::threat;
        if (exit_code == 11U) return DefenderVerdict::suspicious;
        return DefenderVerdict::unavailable;
    }
    const auto command = defender_command();
    if (command.empty()) return DefenderVerdict::unavailable;
    std::wstring arguments = L"\"" + command.wstring() + L"\" -Scan -ScanType 3 -File \"" +
                             path.wstring() + L"\" -DisableRemediation";
    std::vector<wchar_t> mutable_arguments(arguments.begin(), arguments.end());
    mutable_arguments.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(command.c_str(), mutable_arguments.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) {
        return DefenderVerdict::unavailable;
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 30'000U);
    DWORD exit_code = ERROR_GEN_FAILURE;
    if (wait == WAIT_TIMEOUT) TerminateProcess(process.hProcess, ERROR_TIMEOUT);
    const bool completed = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!completed) return DefenderVerdict::unavailable;
    if (exit_code == 0U) return DefenderVerdict::clean;
    if (exit_code == 2U) return DefenderVerdict::threat;
    return DefenderVerdict::unavailable;
}

bool suspicious_structure(const std::filesystem::path& path, std::span<const std::byte> content) {
    if (content.empty()) return false;
    const auto extension = lower_extension(path);
    const bool pdf_magic = content.size() >= 5U && std::to_integer<unsigned char>(content[0]) == '%' &&
                           std::to_integer<unsigned char>(content[1]) == 'P' &&
                           std::to_integer<unsigned char>(content[2]) == 'D' &&
                           std::to_integer<unsigned char>(content[3]) == 'F' &&
                           std::to_integer<unsigned char>(content[4]) == '-';
    if (extension == L".pdf" || pdf_magic) {
        const auto result = ai_shield::protocols::pdf::preflight(content);
        if (!result.ok()) return true;
        const auto& summary = result.value();
        return summary.malformed || summary.javascript || summary.launch_action || summary.embedded_file ||
               summary.open_action;
    }
    if (extension == L".zip") {
        const auto result = ai_shield::protocols::zip::preflight(content);
        if (!result.ok()) return true;
        const auto& summary = result.value();
        return summary.path_escape || summary.bomb_risk || summary.encrypted_entry;
    }
    return false;
}

bool safe_stream_set(HANDLE file) {
    std::array<std::byte, 64U * 1024U> buffer{};
    if (!GetFileInformationByHandleEx(file, FileStreamInfo, buffer.data(), static_cast<DWORD>(buffer.size())))
        return GetLastError() == ERROR_HANDLE_EOF;
    auto* stream = reinterpret_cast<FILE_STREAM_INFO*>(buffer.data());
    for (;;) {
        const std::wstring_view name(stream->StreamName, stream->StreamNameLength / sizeof(wchar_t));
        if (name != L"::$DATA" && name != L":Zone.Identifier:$DATA") return false;
        if (stream->NextEntryOffset == 0U) return true;
        auto* next = reinterpret_cast<std::byte*>(stream) + stream->NextEntryOffset;
        if (next < buffer.data() || next >= buffer.data() + buffer.size()) return false;
        stream = reinterpret_cast<FILE_STREAM_INFO*>(next);
    }
}

bool trusted_signature(const std::filesystem::path& path) {
    std::wstring path_text = path.wstring();
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path_text.c_str();
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file_info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trust);
    return status == ERROR_SUCCESS;
}

class QuarantineManager final {
public:
    explicit QuarantineManager(std::filesystem::path directory)
        : directory_(std::move(directory)), objects_(directory_ / L"objects"), journal_(directory_ / L"journal.jsonl"),
          provenance_(directory_ / L"provenance.jsonl"), health_(directory_ / L"scanner-health.jsonl") {}

    ~QuarantineManager() {
        if (objects_handle_ != INVALID_HANDLE_VALUE) CloseHandle(objects_handle_);
    }

    bool initialize() {
        policy_ = load_content_policy();
        std::error_code error;
        std::filesystem::create_directories(objects_, error);
        if (error) return false;
        objects_handle_ = CreateFileW(objects_.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (objects_handle_ == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(objects_handle_, &objects_info_))
            return false;
        const std::filesystem::path users(L"C:\\Users");
        for (const auto& entry : std::filesystem::directory_iterator(users, std::filesystem::directory_options::skip_permission_denied, error)) {
            if (!entry.is_directory(error)) continue;
            roots_.push_back(entry.path() / L"Downloads");
            roots_.push_back(entry.path() / L"AppData" / L"Local" / L"Temp");
        }
        std::size_t baseline = 0U;
        for (const auto& root : roots_) {
            if (!std::filesystem::exists(root, error)) continue;
            const bool downloads_root = _wcsicmp(root.filename().c_str(), L"Downloads") == 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     root, std::filesystem::directory_options::skip_permission_denied, error)) {
                if (!entry.is_regular_file(error)) continue;
                const bool executable = executable_extension(entry.path());
                if ((!downloads_root && !executable) ||
                    (downloads_root && !executable && !parser_risk_extension(entry.path(), policy_.enabled_categories))) continue;
                processed_.insert(entry.path().wstring());
                ++baseline;
                if (baseline >= 20'000U) break;
            }
        }
        append_record(health_, "{\"event\":\"initialized\",\"roots\":" + std::to_string(roots_.size()) +
                               ",\"baseline\":" + std::to_string(baseline) + "}\r\n");
        return true;
    }

    void scan() {
        policy_ = load_content_policy();
        struct Candidate final {
            std::filesystem::path path;
            std::uint64_t size = 0U;
            std::filesystem::file_time_type modified{};
        };
        std::error_code error;
        std::size_t visited = 0;
        std::vector<Candidate> candidates;
        for (const auto& root : roots_) {
            if (!std::filesystem::exists(root, error)) continue;
            const bool downloads_root = lower_extension(root).empty() && _wcsicmp(root.filename().c_str(), L"Downloads") == 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     root, std::filesystem::directory_options::skip_permission_denied, error)) {
                if (++visited > 20'000U) return;
                if (error || !entry.is_regular_file(error)) continue;
                const bool executable = executable_extension(entry.path());
                if ((!downloads_root && !executable) ||
                    (downloads_root && !executable && !parser_risk_extension(entry.path(), policy_.enabled_categories))) continue;
                const auto modified = entry.last_write_time(error);
                if (error) continue;
                const auto size = entry.file_size(error);
                if (error || !has_external_zone(entry.path())) continue;
                const auto key = entry.path().wstring();
                if (processed_.contains(key)) continue;
                const auto found = stable_sizes_.find(key);
                if (found == stable_sizes_.end() || found->second != size) {
                    stable_sizes_[key] = size;
                    continue;
                }
                candidates.push_back({entry.path(), size, modified});
                stable_sizes_.erase(key);
            }
        }
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& left, const Candidate& right) {
            if (left.size != right.size) return left.size < right.size;
            return left.modified > right.modified;
        });
        if (!candidates.empty()) {
            append_record(health_, "{\"event\":\"candidates\",\"count\":" +
                                   std::to_string(candidates.size()) + "}\r\n");
        }
        constexpr std::size_t maximum_per_pass = 256U;
        for (std::size_t i = 0; i < (std::min)(candidates.size(), maximum_per_pass); ++i) {
            classify(candidates[i].path, candidates[i].size);
        }
    }

    static bool restore(std::wstring_view identifier, const std::filesystem::path& destination,
                        std::wstring_view reason) {
        if (identifier.size() != 64U) return false;
        for (const wchar_t character : identifier) {
            if (!iswxdigit(character)) return false;
        }
        if (reason.size() < 3U || reason.size() > 256U || reason.find_first_of(L"\r\n") != std::wstring_view::npos)
            return false;
        const auto source = std::filesystem::path(L"C:\\ProgramData\\AIShield\\quarantine\\objects") /
                            (std::wstring(identifier) + L".quarantine");
        std::error_code error;
        std::filesystem::create_directories(destination.parent_path(), error);
        if (error || std::filesystem::exists(destination, error)) return false;
        if (MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH) == FALSE)
            return false;
        const auto journal_path = std::filesystem::path(L"C:\\ProgramData\\AIShield\\quarantine\\restore.jsonl");
        HANDLE journal = CreateFileW(journal_path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (journal == INVALID_HANDLE_VALUE) return false;
        const std::string record = "{\"id\":\"" + json_escape(identifier) +
                                   "\",\"destination\":\"" + json_escape(destination.wstring()) +
                                   "\",\"reason\":\"" + json_escape(reason) + "\"}\r\n";
        DWORD written = 0;
        const bool logged = WriteFile(journal, record.data(), static_cast<DWORD>(record.size()), &written, nullptr) &&
                            written == record.size() && FlushFileBuffers(journal);
        CloseHandle(journal);
        return logged;
    }

private:
    bool append_record(const std::filesystem::path& destination, const std::string& record) {
        HANDLE journal = CreateFileW(destination.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (journal == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        const bool ok = WriteFile(journal, record.data(), static_cast<DWORD>(record.size()), &written, nullptr) &&
                        written == record.size() && FlushFileBuffers(journal);
        CloseHandle(journal);
        return ok;
    }

    void classify(const std::filesystem::path& source, std::uint64_t size) {
        HANDLE source_handle = CreateFileW(source.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                                           FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                                               FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                                           nullptr);
        if (source_handle == INVALID_HANDLE_VALUE) {
            append_record(health_, "{\"event\":\"open_failed\",\"error\":" +
                                   std::to_string(GetLastError()) + "}\r\n");
            return;
        }
        BY_HANDLE_FILE_INFORMATION source_info{};
        FILE_ATTRIBUTE_TAG_INFO tag_info{};
        const bool basic_info = GetFileInformationByHandle(source_handle, &source_info) != FALSE;
        const bool tag_safe = GetFileInformationByHandleEx(source_handle, FileAttributeTagInfo,
                                                           &tag_info, sizeof(tag_info)) != FALSE &&
                              (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U;
        const bool streams_safe = safe_stream_set(source_handle);
        const bool identity_safe = basic_info && tag_safe && source_info.nNumberOfLinks == 1U &&
                                   source_info.dwVolumeSerialNumber == objects_info_.dwVolumeSerialNumber && streams_safe;
        if (!identity_safe) {
            CloseHandle(source_handle);
            append_record(health_, "{\"event\":\"identity_rejected\"}\r\n");
            processed_.insert(source.wstring());
            return;
        }
        const std::array<std::uint64_t, 4> identity{
            source_info.dwVolumeSerialNumber,
            (static_cast<std::uint64_t>(source_info.nFileIndexHigh) << 32U) | source_info.nFileIndexLow,
            size,
            (static_cast<std::uint64_t>(source_info.ftLastWriteTime.dwHighDateTime) << 32U) |
                source_info.ftLastWriteTime.dwLowDateTime};
        const auto digest = ai_shield::crypto::sha256(std::as_bytes(std::span(identity)));
        const std::string identifier = digest_hex(digest);
        const bool executable = executable_extension(source);
        const bool parser_risk = parser_risk_extension(source, policy_.enabled_categories);
        const bool trusted = executable && trusted_signature(source);
        const auto defender = scan_with_defender(source, size);
        append_record(health_, "{\"event\":\"defender_complete\",\"verdict\":" +
                               std::to_string(static_cast<unsigned int>(defender)) + "}\r\n");
        const bool structure_suspicious = defender == DefenderVerdict::suspicious;
        const bool quarantine = (executable && !trusted) || structure_suspicious || defender == DefenderVerdict::threat ||
                                (parser_risk && policy_.fail_closed != 0U && defender == DefenderVerdict::unavailable);
        const std::string classification = defender == DefenderVerdict::threat ? "malware_detected" :
            structure_suspicious ? "suspicious_file_structure" :
            (parser_risk && policy_.fail_closed != 0U && defender == DefenderVerdict::unavailable) ? "parser_risk_scan_unavailable" :
            (executable && !trusted) ? "external_untrusted_executable" :
            trusted ? "external_trusted_scanned" : "external_content_scanned_safe";
        const std::string record = "{\"id\":\"" + identifier + "\",\"source\":\"" +
                                    json_escape(source.wstring()) + "\",\"size\":" + std::to_string(size) +
                                    ",\"classification\":\"" + classification + "\",\"defender\":\"" +
                                    (defender == DefenderVerdict::clean ? "clean" :
                                     defender == DefenderVerdict::threat ? "threat" :
                                     defender == DefenderVerdict::suspicious ? "structural_suspicious" : "unavailable") + "\"}\r\n";
        if (!append_record(provenance_, record)) { CloseHandle(source_handle); return; }
        if (!quarantine) {
            CloseHandle(source_handle);
            processed_.insert(source.wstring());
            return;
        }
        HANDLE enforcement_handle = CreateFileW(source.c_str(), DELETE | FILE_READ_ATTRIBUTES,
                                                FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION enforcement_info{};
        const bool same_object = enforcement_handle != INVALID_HANDLE_VALUE &&
                                 GetFileInformationByHandle(enforcement_handle, &enforcement_info) != FALSE &&
                                 enforcement_info.dwVolumeSerialNumber == source_info.dwVolumeSerialNumber &&
                                 enforcement_info.nFileIndexHigh == source_info.nFileIndexHigh &&
                                 enforcement_info.nFileIndexLow == source_info.nFileIndexLow &&
                                 enforcement_info.nNumberOfLinks == 1U;
        if (!same_object) {
            if (enforcement_handle != INVALID_HANDLE_VALUE) CloseHandle(enforcement_handle);
            CloseHandle(source_handle);
            append_record(health_, "{\"event\":\"enforcement_identity_changed\"}\r\n");
            return;
        }
        const std::string intent = record.substr(0, record.size() - 3U) + ",\"state\":\"intent\"}\r\n";
        if (!append_record(journal_, intent)) { CloseHandle(enforcement_handle); CloseHandle(source_handle); return; }
        const std::wstring target_name(identifier.begin(), identifier.end());
        const std::wstring filename = target_name + L".quarantine";
        const std::wstring destination = (objects_ / filename).wstring();
        const DWORD destination_bytes = static_cast<DWORD>(destination.size() * sizeof(wchar_t));
        std::vector<std::byte> rename_storage(offsetof(FILE_RENAME_INFO, FileName) + destination_bytes);
        auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(rename_storage.data());
        rename->ReplaceIfExists = FALSE;
        rename->RootDirectory = nullptr;
        rename->FileNameLength = destination_bytes;
        std::memcpy(rename->FileName, destination.data(), destination_bytes);
        const bool moved = SetFileInformationByHandle(enforcement_handle, FileRenameInfo, rename,
                                                       static_cast<DWORD>(rename_storage.size())) != FALSE;
        const DWORD move_error = moved ? ERROR_SUCCESS : GetLastError();
        if (!moved) append_record(health_, "{\"event\":\"rename_failed\",\"error\":" +
                                                   std::to_string(move_error) + "}\r\n");
        FlushFileBuffers(enforcement_handle);
        CloseHandle(enforcement_handle);
        CloseHandle(source_handle);
        if (!moved) return;
        const std::string committed = record.substr(0, record.size() - 3U) + ",\"state\":\"committed\"}\r\n";
        append_record(journal_, committed);
    }

    std::filesystem::path directory_;
    std::filesystem::path objects_;
    std::filesystem::path journal_;
    std::filesystem::path provenance_;
    std::filesystem::path health_;
    std::vector<std::filesystem::path> roots_;
    std::map<std::wstring, std::uint64_t> stable_sizes_;
    std::set<std::wstring> processed_;
    HANDLE objects_handle_ = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION objects_info_{};
    ContentPolicy policy_{};
};

bool valid_event(const Sensor& sensor, const AI_SHIELD_DRIVER_EVENT& event, DWORD bytes) {
    return bytes == sizeof(event) && event.Version == AI_SHIELD_PROTOCOL_VERSION &&
           event.Size == sizeof(event) && event.Sensor == sensor.id && event.Kind >= AI_SHIELD_EVENT_CONNECT &&
           event.Kind <= AI_SHIELD_EVENT_HANDLE_FILTER && event.Sequence != 0ULL;
}

int run_broker(const std::filesystem::path& log_directory, bool once) {
    if (!open_sensors()) return 3;
    ai_shield::platform::windows::security::SecureRuntimeStore runtime_store(L"C:\\ProgramData\\AIShield");
    const auto runtime = runtime_store.load_or_create();
    if (!runtime.ok()) {
        close_sensors();
        return 4;
    }
    const auto& channel_key = runtime.value().channel_key;
    AuditWriter writer(log_directory);
    QuarantineManager quarantine(L"C:\\ProgramData\\AIShield\\quarantine");
    if (!writer.initialize() || !quarantine.initialize()) {
        close_sensors();
        return 4;
    }
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    ai_shield::ransomware::Detector ransomware_detector;
    std::set<std::uint64_t> signaled_processes;
    const std::filesystem::path ransomware_signals =
        L"C:\\ProgramData\\AIShield\\recovery-vault\\kernel-signals.jsonl";
    auto next_flush = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::jthread quarantine_worker;
    if (!once) {
        quarantine_worker = std::jthread([&quarantine](std::stop_token stop) {
            while (!stop.stop_requested()) {
                quarantine.scan();
                for (unsigned int i = 0U; i < 20U && !stop.stop_requested(); ++i) Sleep(100U);
            }
        });
    }
    do {
        bool had_event = false;
        for (auto& sensor : g_sensors) {
            for (;;) {
                AI_SHIELD_DRIVER_EVENT event{};
                DWORD bytes = 0;
                if (!DeviceIoControl(sensor.handle, AI_SHIELD_IOCTL_GET_EVENT, nullptr, 0, &event,
                                     sizeof(event), &bytes, nullptr)) {
                    const DWORD error = GetLastError();
                    if (error == ERROR_NO_MORE_ITEMS || error == ERROR_NO_MORE_FILES || error == ERROR_NOT_FOUND) break;
                    std::wcerr << L"broker: read " << sensor.name << L" failed error=" << error << L'\n';
                    close_sensors();
                    return 5;
                }
                had_event = true;
                if (!valid_event(sensor, event, bytes) ||
                    (sensor.last_sequence != 0ULL && event.Sequence != sensor.last_sequence + 1ULL)) {
                    ++rejected;
                    if (event.Sequence > sensor.last_sequence) sensor.last_sequence = event.Sequence;
                    continue;
                }
                sensor.last_sequence = event.Sequence;
                const ai_shield::platform::windows::DriverEventObservation observation{
                    event.Version, event.Size, event.Sensor, event.Kind, event.Sequence, event.Timestamp100ns,
                    event.ProcessId, event.SubjectId, event.AddressFamily, event.LocalPort, event.RemotePort,
                    event.Decision, event.Flags, event.Reserved};
                const auto translated = ai_shield::platform::windows::to_sensor_event_v2(
                    observation, runtime.value().policy_version, runtime.value().model_version, channel_key);
                if (!translated.ok()) {
                    ++rejected;
                    continue;
                }
                const ai_shield::abi2::ValidationContext context{
                    .expected_sequence = event.Sequence,
                    .now_monotonic_ns = translated.value().header.monotonic_ns,
                    .maximum_clock_skew_ns = 0U,
                    .channel_key = channel_key};
                if (!ai_shield::abi2::validate(translated.value(), context).ok()) {
                    ++rejected;
                    continue;
                }
                if (!writer.append(translated.value())) {
                    close_sensors();
                    return 6;
                }
                if (event.Sensor == AI_SHIELD_SENSOR_MINIFILTER &&
                    (event.Kind == AI_SHIELD_EVENT_FILE_WRITE || event.Kind == AI_SHIELD_EVENT_FILE_RENAME) &&
                    !signaled_processes.contains(event.ProcessId)) {
                    const ai_shield::ransomware::Observation mutation{
                        .process_id = event.ProcessId,
                        .parent_process_id = translated.value().parent_process_id,
                        .object_id = translated.value().file_id,
                        .monotonic_ns = translated.value().header.monotonic_ns,
                        .kind = event.Kind == AI_SHIELD_EVENT_FILE_RENAME
                            ? ai_shield::ransomware::MutationKind::rename
                            : ai_shield::ransomware::MutationKind::write};
                    const auto verdict = ransomware_detector.observe(mutation);
                    if (verdict.create_incident) {
                        const std::string signal =
                            "{\"schema\":\"AIShieldRansomwareKernelSignal/1\",\"process_id\":" +
                            std::to_string(event.ProcessId) + ",\"parent_process_id\":" +
                            std::to_string(translated.value().parent_process_id) + ",\"score\":" +
                            std::to_string(verdict.score) + ",\"reason_mask\":" +
                            std::to_string(verdict.reason_mask) + ",\"containment_recommended\":" +
                            (verdict.contain_process_tree ? "true" : "false") + "}\r\n";
                        if (append_durable(ransomware_signals, signal)) signaled_processes.insert(event.ProcessId);
                    }
                }
                ++accepted;
            }
        }
        if (std::chrono::steady_clock::now() >= next_flush) {
            if (!writer.flush()) {
                close_sensors();
                return 6;
            }
            next_flush = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        }
        if (once) break;
        if (!had_event) Sleep(100U);
    } while (!g_stop.load());
    quarantine_worker.request_stop();
    const bool flushed = writer.flush();
    close_sensors();
    std::wcout << L"broker: accepted=" << accepted << L" rejected=" << rejected << L'\n';
    return flushed ? 0 : 6;
}

void report_service_state(DWORD state, DWORD exit_code = NO_ERROR) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0U;
    SetServiceStatus(g_status_handle, &g_status);
}

void WINAPI service_control(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        g_stop.store(true);
        report_service_state(SERVICE_STOP_PENDING);
    }
}

void WINAPI service_main(DWORD, wchar_t**) {
    g_status_handle = RegisterServiceCtrlHandlerW(kServiceName, service_control);
    if (g_status_handle == nullptr) return;
    report_service_state(SERVICE_START_PENDING);
    report_service_state(SERVICE_RUNNING);
    const int result = run_broker(L"C:\\ProgramData\\AIShield\\audit", false);
    report_service_state(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int self_test() {
    AI_SHIELD_DRIVER_EVENT event{};
    event.Version = AI_SHIELD_PROTOCOL_VERSION;
    event.Size = sizeof(event);
    event.Sensor = AI_SHIELD_SENSOR_WFP;
    event.Kind = AI_SHIELD_EVENT_CONNECT;
    event.Sequence = 1;
    if (!valid_event(g_sensors[0], event, sizeof(event)) || valid_event(g_sensors[1], event, sizeof(event))) return 2;
    ai_shield::crypto::Sha256Digest key{};
    key[0] = std::byte{0x5a};
    const ai_shield::platform::windows::DriverEventObservation observation{
        event.Version, event.Size, event.Sensor, event.Kind, event.Sequence, event.Timestamp100ns,
        event.ProcessId, event.SubjectId, event.AddressFamily, event.LocalPort, event.RemotePort,
        event.Decision, event.Flags, event.Reserved};
    const auto translated = ai_shield::platform::windows::to_sensor_event_v2(observation, 1U, 0U, key);
    if (!translated.ok() || !ai_shield::abi2::validate(translated.value(), ai_shield::abi2::ValidationContext{
            .expected_sequence = 1U, .now_monotonic_ns = 0U, .maximum_clock_skew_ns = 0U,
            .channel_key = key}).ok()) return 3;
    const std::string benign_pdf = "%PDF-1.7\n1 0 obj\n<<>>\nendobj\nxref\n%%EOF";
    const std::string active_pdf = "%PDF-1.7\n1 0 obj\n<</OpenAction<</S/JavaScript/JS(alert(1))>>>>\nendobj\nxref\n%%EOF";
    const auto bytes = [](const std::string& value) {
        return std::span<const std::byte>(reinterpret_cast<const std::byte*>(value.data()), value.size());
    };
    if (suspicious_structure(L"benign.pdf", bytes(benign_pdf)) ||
        !suspicious_structure(L"active.pdf", bytes(active_pdf)) ||
        !parser_risk_extension(L"photo.webp") || !parser_risk_extension(L"movie.mp4") ||
        parser_risk_extension(L"notes.txt") || parser_risk_extension(L"photo.webp", kContentDocuments) ||
        content_category(L"report.pdf") != kContentDocuments || content_category(L"track.mp3") != kContentAudio) return 4;
    std::wcout << L"ai_shield_broker self-test passed\n";
    return 0;
}

int runtime_command(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"content-policy-status") {
        const auto policy = load_content_policy();
        std::wcout << L"{\"schema\":\"AIShieldContentPolicy/1\",\"enabled_categories\":"
                   << policy.enabled_categories << L",\"fail_closed\":"
                   << (policy.fail_closed != 0U ? L"true" : L"false") << L"}\n";
        return 0;
    }
    if (argc == 4 && std::wstring_view(argv[1]) == L"content-policy-set") {
        if (!elevated_administrator()) return 5;
        wchar_t* mask_end = nullptr;
        wchar_t* fail_end = nullptr;
        const auto mask = wcstoul(argv[2], &mask_end, 10);
        const auto fail_closed = wcstoul(argv[3], &fail_end, 10);
        if (mask_end == argv[2] || *mask_end != L'\0' || fail_end == argv[3] || *fail_end != L'\0' ||
            (mask & ~kContentAll) != 0U || fail_closed > 1U) return 2;
        ContentPolicy policy{};
        policy.enabled_categories = mask;
        policy.fail_closed = fail_closed;
        return save_content_policy(policy) ? 0 : 2;
    }
    ai_shield::platform::windows::security::SecureRuntimeStore store(L"C:\\ProgramData\\AIShield");
    if (argc == 2 && std::wstring_view(argv[1]) == L"runtime-status") {
        const auto state = store.load_or_create();
        if (!state.ok()) return 2;
        std::wcout << L"runtime generation=" << state.value().generation
                   << L" policy=" << state.value().policy_version
                   << L" model=" << state.value().model_version << L'\n';
        return 0;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"runtime-rotate-key") {
        if (!elevated_administrator()) return 5;
        const auto state = store.rotate_key();
        if (!state.ok()) return 2;
        std::wcout << L"runtime key generation=" << state.value().generation << L'\n';
        return 0;
    }
    if (argc == 4 && std::wstring_view(argv[1]) == L"runtime-sync") {
        if (!elevated_administrator()) return 5;
        wchar_t* policy_end = nullptr;
        wchar_t* model_end = nullptr;
        const auto policy = _wcstoui64(argv[2], &policy_end, 10);
        const auto model = _wcstoui64(argv[3], &model_end, 10);
        if (policy_end == argv[2] || *policy_end != L'\0' || model_end == argv[3] || *model_end != L'\0') return 2;
        return store.update_versions(policy, model).ok() ? 0 : 2;
    }
    return -1;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const int runtime_result = runtime_command(argc, argv);
    if (runtime_result >= 0) return runtime_result;
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") return self_test();
    if (argc >= 2 && std::wstring_view(argv[1]) == L"--console") {
        std::filesystem::path directory = L".\\audit";
        bool once = false;
        for (int i = 2; i < argc; ++i) {
            const std::wstring_view arg(argv[i]);
            if (arg == L"--once") once = true;
            else if (arg == L"--log-dir" && i + 1 < argc) directory = argv[++i];
            else return 2;
        }
        return run_broker(directory, once);
    }
    if (argc == 5 && std::wstring_view(argv[1]) == L"quarantine-restore") {
        if (!elevated_administrator()) return 5;
        return QuarantineManager::restore(argv[2], argv[3], argv[4]) ? 0 : 2;
    }
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(kServiceName), service_main}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 2;
}
