#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <fltuser.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
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
#include "platform/windows/sandbox/appcontainer_launcher.hpp"

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
constexpr std::uint32_t kContentPrograms = 1U << 6U;
constexpr std::uint32_t kContentWindowsScripts = 1U << 7U;
constexpr std::uint32_t kContentDeveloperScripts = 1U << 8U;
constexpr std::uint32_t kContentLaunchers = 1U << 9U;
constexpr std::uint32_t kContentUnknown = 1U << 10U;
constexpr std::uint32_t kContentLegacyAll = (1U << 6U) - 1U;
constexpr std::uint32_t kContentExecutionAll = kContentPrograms | kContentWindowsScripts |
                                               kContentDeveloperScripts | kContentLaunchers;
constexpr std::uint32_t kContentAll = kContentLegacyAll | kContentExecutionAll | kContentUnknown;

struct ContentPolicy final {
    std::uint32_t magic = 0x50435341U;
    std::uint32_t version = 4U;
    std::uint32_t enabled_categories = kContentAll;
    std::uint32_t fail_closed = 1U;
    std::uint32_t release_required = 1U;
};

struct LegacyContentPolicy final {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t enabled_categories;
    std::uint32_t fail_closed;
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
        sensor.handle = CreateFileW(sensor.path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
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

std::wstring lower_extension(const std::filesystem::path& path) {
    auto extension = path.extension().wstring();
    for (auto& character : extension) character = static_cast<wchar_t>(towlower(character));
    return extension;
}

std::uint32_t content_category(const std::filesystem::path& path) {
    const auto extension = lower_extension(path);
    constexpr auto documents = std::to_array<std::wstring_view>({
        L".pdf", L".doc", L".docx", L".docm", L".xls", L".xlsx", L".xlsm", L".ppt", L".pptx", L".pptm",
        L".rtf", L".odt", L".ods", L".odp", L".one", L".fdf", L".xps", L".oxps", L".djvu",
        L".csv", L".tsv", L".eml", L".msg", L".ics", L".vcf", L".epub", L".mobi", L".azw", L".azw3", L".fb2"});
    constexpr auto archives = std::to_array<std::wstring_view>({
        L".zip", L".7z", L".rar", L".iso", L".cab", L".tar", L".gz", L".bz2", L".xz", L".zst",
        L".img", L".vhd", L".vhdx", L".vmdk", L".wim", L".esd", L".dmg", L".apk", L".nupkg", L".crx", L".xpi", L".vsix"});
    constexpr auto images = std::to_array<std::wstring_view>({
        L".jpg", L".jpeg", L".jfif", L".png", L".gif", L".bmp", L".tif", L".tiff", L".webp", L".ico", L".svg",
        L".heif", L".heic", L".avif", L".jxl", L".psd", L".raw"});
    constexpr auto audio = std::to_array<std::wstring_view>({
        L".mp3", L".wav", L".flac", L".aac", L".ogg", L".m4a", L".wma", L".aiff", L".opus",
        L".m3u", L".m3u8", L".pls", L".asx", L".cue"});
    constexpr auto video = std::to_array<std::wstring_view>({L".mp4", L".m4v", L".mov", L".avi", L".mkv", L".webm", L".wmv"});
    constexpr auto web = std::to_array<std::wstring_view>({
        L".html", L".htm", L".mhtml", L".mht", L".xhtml", L".xml", L".xsl", L".xslt", L".json", L".yaml", L".yml", L".toml"});
    constexpr auto programs = std::to_array<std::wstring_view>({
        L".exe", L".com", L".scr", L".pif", L".dll", L".ocx", L".cpl", L".sys", L".drv",
        L".msi", L".msp", L".mst", L".msix", L".msixbundle", L".appx", L".appxbundle", L".appinstaller", L".efi"});
    constexpr auto windows_scripts = std::to_array<std::wstring_view>({
        L".bat", L".cmd", L".ps1", L".psm1", L".psd1", L".vbs", L".vbe", L".js", L".jse",
        L".wsf", L".wsh", L".hta", L".sct"});
    constexpr auto developer_scripts = std::to_array<std::wstring_view>({
        L".sh", L".bash", L".zsh", L".fish", L".py", L".pyw", L".pyz", L".mjs", L".cjs",
        L".pl", L".pm", L".rb", L".rake", L".php", L".phar", L".lua", L".tcl", L".jar",
        L".groovy", L".kts", L".wasm"});
    constexpr auto launchers = std::to_array<std::wstring_view>({
        L".lnk", L".url", L".scf", L".application", L".appref-ms", L".gadget", L".diagcab",
        L".diagpkg", L".reg", L".inf", L".chm", L".xll", L".iqy", L".oqy", L".rqy", L".slk",
        L".settingcontent-ms", L".library-ms", L".search-ms", L".torrent", L".rdp", L".pbk", L".mobileconfig",
        L".pkl", L".pickle", L".joblib", L".dill", L".pt", L".pth", L".ckpt", L".onnx", L".safetensors", L".gguf"});
    const auto contains = [&extension](const auto& values) {
        return std::find(values.begin(), values.end(), extension) != values.end();
    };
    if (contains(documents)) return kContentDocuments;
    if (contains(archives)) return kContentArchives;
    if (contains(images)) return kContentImages;
    if (contains(audio)) return kContentAudio;
    if (contains(video)) return kContentVideo;
    if (contains(web)) return kContentWeb;
    if (contains(programs)) return kContentPrograms;
    if (contains(windows_scripts)) return kContentWindowsScripts;
    if (contains(developer_scripts)) return kContentDeveloperScripts;
    if (contains(launchers)) return kContentLaunchers;
    return kContentUnknown;
}

bool executable_extension(const std::filesystem::path& path, std::uint32_t enabled = kContentAll) {
    return (content_category(path) & enabled & kContentExecutionAll) != 0U;
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
    bool valid = false;
    if (clear.cbData == sizeof(policy)) {
        std::memcpy(&policy, clear.pbData, sizeof(policy));
        if (policy.version == 3U) {
            policy.version = 4U;
            policy.enabled_categories |= kContentUnknown;
            valid = true;
        } else {
            valid = policy.version == 4U;
        }
    } else if (clear.cbData == sizeof(LegacyContentPolicy)) {
        LegacyContentPolicy legacy{};
        std::memcpy(&legacy, clear.pbData, sizeof(legacy));
        if (legacy.version == 1U || legacy.version == 2U) {
            policy.magic = legacy.magic;
            policy.version = 4U;
            policy.enabled_categories = legacy.enabled_categories;
            policy.fail_closed = legacy.fail_closed;
            policy.release_required = 1U;
            if (legacy.version == 1U) policy.enabled_categories |= kContentExecutionAll;
            policy.enabled_categories |= kContentUnknown;
            valid = true;
        }
    }
    LocalFree(clear.pbData);
    if (!valid || policy.magic != fallback.magic ||
        (policy.enabled_categories & ~kContentAll) != 0U || policy.fail_closed > 1U ||
        policy.release_required > 1U) return fallback;
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

bool hash_locked_file(HANDLE file, std::uint64_t expected_size, ai_shield::crypto::Sha256Digest& digest) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) != expected_size)
        return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0U;
    DWORD received_property = 0U;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) ||
        !BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received_property, 0U))) {
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
        return false;
    }
    std::vector<UCHAR> object(object_size);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0U, 0U))) {
        BCryptCloseAlgorithmProvider(algorithm, 0U);
        return false;
    }
    std::vector<std::byte> chunk(1U << 20U);
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
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(chunk.data()), bytes, 0U))) {
            ok = false;
            break;
        }
        offset += bytes;
    }
    CloseHandle(read_event);
    if (ok && offset == expected_size)
        ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(digest.data()),
                                             static_cast<ULONG>(digest.size()), 0U));
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    return ok && offset == expected_size;
}

enum class DefenderVerdict { clean, threat, unavailable, suspicious };

bool register_isolated_scanner(std::uint32_t process_id);

DefenderVerdict scan_with_defender(const std::filesystem::path& path, std::uint64_t size, HANDLE source_handle,
                                   DWORD& diagnostic) {
    diagnostic = ERROR_SUCCESS;
    if (size == 0U || size > kMaximumClassifiedFileSize) {
        diagnostic = ERROR_FILE_TOO_LARGE;
        return DefenderVerdict::unavailable;
    }
    {
        std::array<wchar_t, 32768> module_path{};
        const DWORD module_length = GetModuleFileNameW(nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
        if (module_length == 0U || module_length >= module_path.size()) { diagnostic = GetLastError(); return DefenderVerdict::unavailable; }
        const auto scanner = std::filesystem::path(module_path.data()).parent_path() / L"ai_shield_file_scanner.exe";
        if (!std::filesystem::exists(scanner)) { diagnostic = ERROR_FILE_NOT_FOUND; return DefenderVerdict::unavailable; }
        HANDLE inherited_handle = INVALID_HANDLE_VALUE;
        if (source_handle == INVALID_HANDLE_VALUE ||
            !DuplicateHandle(GetCurrentProcess(), source_handle, GetCurrentProcess(), &inherited_handle, 0U, TRUE,
                             DUPLICATE_SAME_ACCESS)) { diagnostic = GetLastError(); return DefenderVerdict::unavailable; }
        std::wstring arguments = L"\"" + scanner.wstring() + L"\" scan-handle " +
                                 std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited_handle)) + L" " +
                                 std::to_wstring(size) + L" \"" + path.filename().wstring() + L"\"";
        std::vector<wchar_t> mutable_arguments(arguments.begin(), arguments.end());
        mutable_arguments.push_back(L'\0');
        const auto launched = ai_shield::platform::windows::sandbox::launch_shadow_parser({
            .analysis_id = GetTickCount64() + 1U,
            .parser_id = 1U,
            .budget = {.wall_time_ns = 10'000'000'000ULL, .memory_bytes = 512ULL * 1024ULL * 1024ULL,
                       .max_processes = 1U, .network_allowed = false},
            .allow_network = false,
            .allow_child_processes = false,
            .executable_path = scanner.wstring(),
            .command_line = mutable_arguments.data(),
            .work_directory = scanner.parent_path().wstring(),
            .inherited_handle = inherited_handle});
        CloseHandle(inherited_handle);
        if (!launched.ok()) { diagnostic = 0xE001U + static_cast<DWORD>(launched.status()); return DefenderVerdict::unavailable; }
        auto isolated = launched.value();
        if (!register_isolated_scanner(isolated.process_id)) {
            ai_shield::platform::windows::sandbox::close_launched_process(isolated);
            diagnostic = 0xE080U;
            return DefenderVerdict::unavailable;
        }
        if (!ai_shield::platform::windows::sandbox::resume_launched_process(isolated).ok()) {
            ai_shield::platform::windows::sandbox::close_launched_process(isolated);
            diagnostic = 0xE100U;
            return DefenderVerdict::unavailable;
        }
        const DWORD wait = WaitForSingleObject(isolated.process, 10'000U);
        DWORD exit_code = ERROR_GEN_FAILURE;
        if (wait == WAIT_TIMEOUT) TerminateProcess(isolated.process, ERROR_TIMEOUT);
        const bool completed = wait == WAIT_OBJECT_0 && GetExitCodeProcess(isolated.process, &exit_code) != FALSE;
        ai_shield::platform::windows::sandbox::close_launched_process(isolated);
        bool restricted_fallback = false;
        if (completed && exit_code == 0xC0000142U) {
            HANDLE fallback_handle = INVALID_HANDLE_VALUE;
            if (!DuplicateHandle(GetCurrentProcess(), source_handle, GetCurrentProcess(), &fallback_handle, 0U, TRUE,
                                 DUPLICATE_SAME_ACCESS)) {
                diagnostic = GetLastError();
                return DefenderVerdict::unavailable;
            }
            std::wstring fallback_arguments = L"\"" + scanner.wstring() + L"\" scan-handle " +
                                              std::to_wstring(reinterpret_cast<std::uintptr_t>(fallback_handle)) +
                                              L" " + std::to_wstring(size) + L" \"" +
                                              path.filename().wstring() + L"\"";
            std::vector<wchar_t> mutable_fallback_arguments(fallback_arguments.begin(), fallback_arguments.end());
            mutable_fallback_arguments.push_back(L'\0');
            auto fallback = ai_shield::platform::windows::sandbox::launch_restricted_parser({
                .analysis_id = GetTickCount64() + 1U, .parser_id = 1U,
                .budget = {.wall_time_ns = 10'000'000'000ULL, .memory_bytes = 512ULL * 1024ULL * 1024ULL,
                           .max_processes = 1U, .network_allowed = false},
                .allow_network = false, .allow_child_processes = false, .executable_path = scanner.wstring(),
                .command_line = mutable_fallback_arguments.data(), .work_directory = scanner.parent_path().wstring(),
                .inherited_handle = fallback_handle});
            CloseHandle(fallback_handle);
            if (fallback.ok()) {
                auto restricted_process = fallback.value();
                if (register_isolated_scanner(restricted_process.process_id) &&
                    ai_shield::platform::windows::sandbox::resume_launched_process(restricted_process).ok()) {
                    const DWORD fallback_wait = WaitForSingleObject(restricted_process.process, 10'000U);
                    exit_code = ERROR_GEN_FAILURE;
                    restricted_fallback = fallback_wait == WAIT_OBJECT_0 &&
                        GetExitCodeProcess(restricted_process.process, &exit_code) != FALSE;
                }
                ai_shield::platform::windows::sandbox::close_launched_process(restricted_process);
            }
        }
        diagnostic = restricted_fallback ? 0x00010000U + exit_code :
            (completed ? exit_code : (wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError()));
        if (!completed || (exit_code == 0xC0000142U && !restricted_fallback)) return DefenderVerdict::unavailable;
        if (exit_code == 0U) return DefenderVerdict::clean;
        if (exit_code == 10U) return DefenderVerdict::threat;
        if (exit_code == 11U) return DefenderVerdict::suspicious;
        return DefenderVerdict::unavailable;
    }
}

bool copy_locked_to_quarantine(HANDLE source, std::uint64_t expected_size,
                               const ai_shield::crypto::Sha256Digest& expected_digest,
                               const std::filesystem::path& destination) {
    HANDLE target = CreateFileW(destination.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0U, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (target == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0U;
    DWORD returned = 0U;
    bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) &&
              BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                               reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                                               &returned, 0U));
    std::vector<UCHAR> object(object_size);
    ok = ok && BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0U, 0U));
    std::vector<std::byte> chunk(1U << 20U);
    HANDLE read_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::uint64_t offset = 0U;
    ok = ok && read_event != nullptr;
    while (ok && offset < expected_size) {
        const DWORD request = static_cast<DWORD>((std::min)(expected_size - offset,
                                                             static_cast<std::uint64_t>(chunk.size())));
        DWORD received = 0U;
        OVERLAPPED operation{};
        operation.Offset = static_cast<DWORD>(offset & 0xffffffffULL);
        operation.OffsetHigh = static_cast<DWORD>(offset >> 32U);
        operation.hEvent = read_event;
        ResetEvent(read_event);
        const BOOL immediate = ReadFile(source, chunk.data(), request, &received, &operation);
        if (!immediate && GetLastError() == ERROR_IO_PENDING) {
            ok = WaitForSingleObject(read_event, 5'000U) == WAIT_OBJECT_0 &&
                 GetOverlappedResult(source, &operation, &received, FALSE) != FALSE;
        } else ok = immediate != FALSE;
        DWORD written = 0U;
        ok = ok && received != 0U && WriteFile(target, chunk.data(), received, &written, nullptr) != FALSE &&
             written == received && BCRYPT_SUCCESS(BCryptHashData(
                 hash, reinterpret_cast<PUCHAR>(chunk.data()), received, 0U));
        offset += received;
    }
    ai_shield::crypto::Sha256Digest copied_digest{};
    ok = ok && offset == expected_size && FlushFileBuffers(target) != FALSE &&
         BCRYPT_SUCCESS(BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(copied_digest.data()),
                                        static_cast<ULONG>(copied_digest.size()), 0U)) &&
         copied_digest == expected_digest;
    if (read_event != nullptr) CloseHandle(read_event);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
    if (!ok) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        SetFileInformationByHandle(target, FileDispositionInfo, &disposition, sizeof(disposition));
    }
    CloseHandle(target);
    return ok;
}

bool register_broker_gate() {
    AI_SHIELD_BROKER_REGISTRATION registration{
        AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_BROKER_REGISTRATION), GetCurrentProcessId()};
    DWORD returned = 0U;
    const bool wfp = DeviceIoControl(g_sensors[0].handle, AI_SHIELD_IOCTL_REGISTER_BROKER,
                                     &registration, sizeof(registration), nullptr, 0U, &returned, nullptr) != FALSE;
    const bool minifilter = DeviceIoControl(g_sensors[1].handle, AI_SHIELD_IOCTL_REGISTER_BROKER,
                                            &registration, sizeof(registration), nullptr, 0U, &returned, nullptr) != FALSE;
    return wfp && minifilter;
}

bool register_isolated_scanner(std::uint32_t process_id) {
    AI_SHIELD_BROKER_REGISTRATION registration{
        AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_BROKER_REGISTRATION), process_id};
    DWORD returned = 0U;
    return DeviceIoControl(g_sensors[0].handle, AI_SHIELD_IOCTL_REGISTER_ISOLATED_PROCESS,
                           &registration, sizeof(registration), nullptr, 0U, &returned, nullptr) != FALSE;
}

bool submit_file_verdict(std::uint64_t file_id, std::uint32_t volume_id, std::uint32_t verdict) {
    AI_SHIELD_FILE_VERDICT message{
        AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_FILE_VERDICT), file_id, volume_id, verdict};
    DWORD returned = 0U;
    return DeviceIoControl(g_sensors[1].handle, AI_SHIELD_IOCTL_SET_FILE_VERDICT,
                           &message, sizeof(message), nullptr, 0U, &returned, nullptr) != FALSE;
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
        return summary.malformed || summary.path_escape || summary.bomb_risk || summary.encrypted_entry ||
               summary.unsupported_compression || summary.executable_entry || summary.active_content_entry ||
               summary.nested_container || summary.duplicate_name;
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

std::string certificate_thumbprint(const std::filesystem::path& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0U;
    DWORD content_type = 0U;
    DWORD format_type = 0U;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0U, &encoding, &content_type, &format_type,
                          &store, &message, nullptr)) return {};
    DWORD signer_size = 0U;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0U, nullptr, &signer_size)) {
        CryptMsgClose(message); CertCloseStore(store, 0U); return {};
    }
    std::vector<std::byte> signer_storage(signer_size);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0U, signer_storage.data(), &signer_size)) {
        CryptMsgClose(message); CertCloseStore(store, 0U); return {};
    }
    const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(signer_storage.data());
    CERT_INFO query{};
    query.Issuer = signer->Issuer;
    query.SerialNumber = signer->SerialNumber;
    PCCERT_CONTEXT certificate = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0U, CERT_FIND_SUBJECT_CERT, &query, nullptr);
    std::string thumbprint;
    if (certificate != nullptr) {
        std::array<BYTE, 64> digest{};
        DWORD digest_size = static_cast<DWORD>(digest.size());
        if (CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID,
                                              digest.data(), &digest_size)) {
            constexpr char digits[] = "0123456789ABCDEF";
            thumbprint.reserve(digest_size * 2U);
            for (DWORD index = 0; index < digest_size; ++index) {
                thumbprint.push_back(digits[digest[index] >> 4U]);
                thumbprint.push_back(digits[digest[index] & 0x0fU]);
            }
        }
        CertFreeCertificateContext(certificate);
    }
    CryptMsgClose(message);
    CertCloseStore(store, 0U);
    return thumbprint;
}

std::set<std::string> load_trusted_publishers() {
    std::set<std::string> result;
    std::ifstream input(L"C:\\ProgramData\\AIShield\\policy\\trusted-publishers.txt");
    std::string line;
    while (std::getline(input, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), [](unsigned char value) {
            return value == ' ' || value == '\t' || value == '\r' || value == ':';
        }), line.end());
        std::ranges::transform(line, line.begin(), [](unsigned char value) {
            return static_cast<char>(std::toupper(value));
        });
        if (line.size() == 64U && std::ranges::all_of(line, [](unsigned char value) {
                return std::isxdigit(value) != 0;
            })) result.insert(line);
    }
    return result;
}

struct SignatureTrust final {
    bool valid = false;
    bool pinned = false;
    std::string publisher_thumbprint;
};

SignatureTrust inspect_signature(const std::filesystem::path& path, const std::set<std::string>& publishers) {
    std::wstring path_text = path.wstring();
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path_text.c_str();
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_SAFER_FLAG;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file_info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trust);
    SignatureTrust result{};
    result.valid = status == ERROR_SUCCESS;
    if (result.valid) {
        result.publisher_thumbprint = certificate_thumbprint(path);
        result.pinned = !result.publisher_thumbprint.empty() && publishers.contains(result.publisher_thumbprint);
    }
    return result;
}

std::optional<std::wstring> registry_string(HKEY root, const std::wstring& subkey, const wchar_t* value_name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0U, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return std::nullopt;
    DWORD type = 0U;
    DWORD bytes = 0U;
    if (RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t)) {
        RegCloseKey(key); return std::nullopt;
    }
    std::vector<wchar_t> storage(bytes / sizeof(wchar_t) + 1U, L'\0');
    if (RegQueryValueExW(key, value_name, nullptr, &type,
                         reinterpret_cast<BYTE*>(storage.data()), &bytes) != ERROR_SUCCESS) {
        RegCloseKey(key); return std::nullopt;
    }
    RegCloseKey(key);
    std::wstring value(storage.data());
    if (type == REG_EXPAND_SZ && value.find(L"%USERPROFILE%") == std::wstring::npos) {
        DWORD required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0U);
        if (required != 0U) {
            std::vector<wchar_t> expanded(required);
            if (ExpandEnvironmentStringsW(value.c_str(), expanded.data(), required) != 0U) value = expanded.data();
        }
    }
    return value;
}

std::vector<std::pair<std::filesystem::path, std::wstring>> profile_roots() {
    std::vector<std::pair<std::filesystem::path, std::wstring>> result;
    HKEY profiles = nullptr;
    const wchar_t profile_list[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, profile_list, 0U, KEY_ENUMERATE_SUB_KEYS, &profiles) != ERROR_SUCCESS)
        return result;
    for (DWORD index = 0U;; ++index) {
        std::array<wchar_t, 256> sid{};
        DWORD sid_size = static_cast<DWORD>(sid.size());
        const LONG enumerated = RegEnumKeyExW(profiles, index, sid.data(), &sid_size, nullptr, nullptr, nullptr, nullptr);
        if (enumerated == ERROR_NO_MORE_ITEMS) break;
        if (enumerated != ERROR_SUCCESS) continue;
        const auto profile = registry_string(HKEY_LOCAL_MACHINE,
            std::wstring(profile_list) + L"\\" + sid.data(), L"ProfileImagePath");
        if (!profile || profile->empty()) continue;
        std::wstring expanded_profile = *profile;
        DWORD required = ExpandEnvironmentStringsW(profile->c_str(), nullptr, 0U);
        if (required != 0U) {
            std::vector<wchar_t> expanded(required);
            if (ExpandEnvironmentStringsW(profile->c_str(), expanded.data(), required) != 0U)
                expanded_profile = expanded.data();
        }
        result.emplace_back(std::filesystem::path(expanded_profile), std::wstring(sid.data()));
    }
    RegCloseKey(profiles);
    return result;
}

class QuarantineManager final {
    enum class FileProcessingState : std::uint8_t {
        analyzed_clean,
        quarantined,
        release_pending,
        retry_pending,
        identity_rejected,
        permanently_unsupported
    };

    struct FileStamp final {
        std::uint64_t size = 0U;
        std::filesystem::file_time_type modified{};
        bool operator==(const FileStamp&) const = default;
    };

    struct ScanRoot final {
        std::filesystem::path path;
        bool downloads = false;
    };

public:
    explicit QuarantineManager(std::filesystem::path directory)
        : directory_(std::move(directory)), objects_(directory_ / L"objects"), journal_(directory_ / L"journal.jsonl"),
          provenance_(directory_ / L"provenance.jsonl"), health_(directory_ / L"scanner-health.jsonl") {}

    ~QuarantineManager() {
        if (objects_handle_ != INVALID_HANDLE_VALUE) CloseHandle(objects_handle_);
    }

    bool initialize() {
        policy_ = load_content_policy();
        trusted_publishers_ = load_trusted_publishers();
        std::error_code error;
        std::filesystem::create_directories(objects_, error);
        if (error) return false;
        objects_handle_ = CreateFileW(objects_.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (objects_handle_ == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(objects_handle_, &objects_info_))
            return false;
        constexpr wchar_t downloads_value[] = L"{374DE290-123F-4565-9164-39C4925E467B}";
        std::set<std::wstring> unique_roots;
        for (const auto& [profile, sid] : profile_roots()) {
            auto downloads = registry_string(HKEY_USERS, sid +
                L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                downloads_value).value_or((profile / L"Downloads").wstring());
            constexpr std::wstring_view marker = L"%USERPROFILE%";
            if (downloads.size() >= marker.size() &&
                _wcsnicmp(downloads.c_str(), marker.data(), marker.size()) == 0) {
                downloads.replace(0U, marker.size(), profile.wstring());
            }
            const auto add_root = [&unique_roots, this](std::filesystem::path path, bool is_downloads) {
                auto key = path.lexically_normal().wstring();
                std::ranges::transform(key, key.begin(), [](wchar_t value) { return towlower(value); });
                if (unique_roots.insert(key).second) roots_.push_back({std::move(path), is_downloads});
            };
            add_root(std::filesystem::path(downloads), true);
            add_root(profile / L"AppData" / L"Local" / L"Temp", false);
        }
        std::size_t baseline = 0U;
        for (const auto& root : roots_) {
            if (!std::filesystem::exists(root.path, error)) continue;
            const bool downloads_root = root.downloads;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     root.path, std::filesystem::directory_options::skip_permission_denied, error)) {
                if (!entry.is_regular_file(error)) continue;
                const bool executable = executable_extension(entry.path(), policy_.enabled_categories);
                if ((!downloads_root && !executable) ||
                    (downloads_root && !executable && !parser_risk_extension(entry.path(), policy_.enabled_categories))) continue;
                const auto modified = entry.last_write_time(error);
                if (error) continue;
                const auto size = entry.file_size(error);
                if (error) continue;
                processed_[entry.path().wstring()] = FileStamp{size, modified};
                ++baseline;
                if (baseline >= 20'000U) break;
            }
        }
        append_record(health_, "{\"event\":\"initialized\",\"roots\":" + std::to_string(roots_.size()) +
                               ",\"baseline\":" + std::to_string(baseline) + "}\r\n");
        return true;
    }

    void scan() {
        std::scoped_lock lock(mutex_);
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
            if (!std::filesystem::exists(root.path, error)) continue;
            const bool downloads_root = root.downloads;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     root.path, std::filesystem::directory_options::skip_permission_denied, error)) {
                if (++visited > 20'000U) return;
                if (error || !entry.is_regular_file(error)) continue;
                const bool executable = executable_extension(entry.path(), policy_.enabled_categories);
                if ((!downloads_root && !executable) ||
                    (downloads_root && !executable && !parser_risk_extension(entry.path(), policy_.enabled_categories))) continue;
                const auto modified = entry.last_write_time(error);
                if (error) continue;
                const auto size = entry.file_size(error);
                if (error || (!downloads_root && !has_external_zone(entry.path()))) continue;
                const auto key = entry.path().wstring();
                const FileStamp stamp{size, modified};
                const auto retry = retry_not_before_.find(key);
                if (retry != retry_not_before_.end() && GetTickCount64() < retry->second) continue;
                const auto processed = processed_.find(key);
                if (processed != processed_.end() && processed->second == stamp) continue;
                const auto found = stable_sizes_.find(key);
                if (found == stable_sizes_.end() || found->second != stamp) {
                    stable_sizes_[key] = stamp;
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
            classify(candidates[i].path, candidates[i].size, candidates[i].modified);
        }
    }

    std::uint32_t classify_pending(std::wstring_view normalized_path, std::uint64_t file_id,
                                   std::uint32_t volume_id) {
        std::scoped_lock lock(mutex_);
        if (normalized_path.empty() || file_id == 0U || volume_id == 0U) return AI_SHIELD_FILE_PENDING;
        std::wstring win32_path(normalized_path);
        constexpr std::wstring_view dos_prefix = L"\\??\\";
        constexpr std::wstring_view device_prefix = L"\\Device\\";
        if (win32_path.starts_with(dos_prefix)) {
            win32_path.replace(0U, dos_prefix.size(), L"\\\\?\\");
        } else if (win32_path.starts_with(device_prefix)) {
            win32_path.insert(0U, L"\\\\?\\GLOBALROOT");
        }
        const std::filesystem::path source(win32_path);
        std::error_code error;
        if (!std::filesystem::is_regular_file(source, error) || error) return AI_SHIELD_FILE_PENDING;
        const auto size = std::filesystem::file_size(source, error);
        if (error) return AI_SHIELD_FILE_PENDING;
        const auto modified = std::filesystem::last_write_time(source, error);
        if (error) return AI_SHIELD_FILE_PENDING;
        classify(source, size, modified, file_id, volume_id);
        const auto state = processing_states_.find(source.wstring());
        if (state == processing_states_.end()) return AI_SHIELD_FILE_PENDING;
        if (state->second == FileProcessingState::analyzed_clean) return AI_SHIELD_FILE_CLEAN;
        if (state->second == FileProcessingState::quarantined ||
            state->second == FileProcessingState::release_pending) return AI_SHIELD_FILE_QUARANTINED;
        return AI_SHIELD_FILE_PENDING;
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

    void classify(const std::filesystem::path& source, std::uint64_t size,
                  std::filesystem::file_time_type modified, std::uint64_t expected_file_id = 0U,
                  std::uint32_t expected_volume_id = 0U) {
        HANDLE source_handle = CreateFileW(source.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | DELETE,
                                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                                               FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                                           nullptr);
        if (source_handle == INVALID_HANDLE_VALUE) {
            append_record(health_, "{\"event\":\"open_failed\",\"error\":" +
                                   std::to_string(GetLastError()) + "}\r\n");
            processing_states_[source.wstring()] = FileProcessingState::retry_pending;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
        BY_HANDLE_FILE_INFORMATION source_info{};
        FILE_ATTRIBUTE_TAG_INFO tag_info{};
        const bool basic_info = GetFileInformationByHandle(source_handle, &source_info) != FALSE;
        const bool tag_safe = GetFileInformationByHandleEx(source_handle, FileAttributeTagInfo,
                                                           &tag_info, sizeof(tag_info)) != FALSE &&
                              (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U;
        const bool streams_safe = safe_stream_set(source_handle);
        const std::uint64_t handle_size = (static_cast<std::uint64_t>(source_info.nFileSizeHigh) << 32U) |
                                          source_info.nFileSizeLow;
        std::error_code stamp_error;
        const auto locked_modified = std::filesystem::last_write_time(source, stamp_error);
        const bool stable_identity = basic_info && !stamp_error && handle_size == size && locked_modified == modified;
        const std::uint64_t handle_file_id =
            (static_cast<std::uint64_t>(source_info.nFileIndexHigh) << 32U) | source_info.nFileIndexLow;
        const bool expected_identity =
            (expected_file_id == 0U || expected_file_id == handle_file_id) &&
            (expected_volume_id == 0U || expected_volume_id == source_info.dwVolumeSerialNumber);
        const bool identity_safe = stable_identity && expected_identity && tag_safe &&
                                   source_info.nNumberOfLinks == 1U && streams_safe;
        if (!identity_safe) {
            CloseHandle(source_handle);
            append_record(health_, "{\"event\":\"identity_rejected\"}\r\n");
            processing_states_[source.wstring()] = FileProcessingState::identity_rejected;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
        const std::array<std::uint64_t, 4> identity{
            source_info.dwVolumeSerialNumber,
            handle_file_id,
            size,
            (static_cast<std::uint64_t>(source_info.ftLastWriteTime.dwHighDateTime) << 32U) |
                source_info.ftLastWriteTime.dwLowDateTime};
        const auto digest = ai_shield::crypto::sha256(std::as_bytes(std::span(identity)));
        const std::string identifier = digest_hex(digest);
        ai_shield::crypto::Sha256Digest content_digest{};
        if (!hash_locked_file(source_handle, size, content_digest)) {
            CloseHandle(source_handle);
            append_record(health_, "{\"event\":\"content_hash_failed\"}\r\n");
            processing_states_[source.wstring()] = FileProcessingState::retry_pending;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
        const std::string content_sha256 = digest_hex(content_digest);
        const bool executable = executable_extension(source, policy_.enabled_categories);
        const bool parser_risk = parser_risk_extension(source, policy_.enabled_categories);
        const auto signature = executable ? inspect_signature(source, trusted_publishers_) : SignatureTrust{};
        const bool trusted = executable && signature.valid && signature.pinned;
        DWORD scanner_diagnostic = ERROR_SUCCESS;
        const auto defender = scan_with_defender(source, size, source_handle, scanner_diagnostic);
        append_record(health_, "{\"event\":\"defender_complete\",\"verdict\":" +
                               std::to_string(static_cast<unsigned int>(defender)) + ",\"diagnostic\":" +
                               std::to_string(scanner_diagnostic) + "}\r\n");
        const bool structure_suspicious = defender == DefenderVerdict::suspicious;
        const bool release_pending = parser_risk && policy_.release_required != 0U;
        const bool scan_unavailable = defender == DefenderVerdict::unavailable;
        const bool quarantine = release_pending || (executable && !trusted) || structure_suspicious ||
                                defender == DefenderVerdict::threat ||
                                (policy_.fail_closed != 0U && scan_unavailable);
        const std::string classification = defender == DefenderVerdict::threat ? "malware_detected" :
            structure_suspicious ? "suspicious_file_structure" :
            (policy_.fail_closed != 0U && scan_unavailable) ? "content_scan_unavailable" :
            (executable && signature.valid && !signature.pinned) ? "signed_unpinned_publisher" :
            (executable && !trusted) ? "external_untrusted_executable" :
            release_pending ? "pending_user_release" :
            trusted ? "external_trusted_scanned" : "external_content_scanned_safe";
        const std::string record = "{\"id\":\"" + identifier + "\",\"source\":\"" +
                                    json_escape(source.wstring()) + "\",\"size\":" + std::to_string(size) +
                                    ",\"sha256\":\"" + content_sha256 + "\"" +
                                    ",\"classification\":\"" + classification + "\",\"publisher_sha256\":\"" +
                                    signature.publisher_thumbprint + "\",\"publisher_pinned\":" +
                                    (signature.pinned ? "true" : "false") + ",\"defender\":\"" +
                                    (defender == DefenderVerdict::clean ? "clean" :
                                     defender == DefenderVerdict::threat ? "threat" :
                                     defender == DefenderVerdict::suspicious ? "structural_suspicious" : "unavailable") + "\"}\r\n";
        if (!append_record(provenance_, record)) {
            CloseHandle(source_handle);
            processing_states_[source.wstring()] = FileProcessingState::retry_pending;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
        if (!quarantine) {
            if (!submit_file_verdict(identity[1], static_cast<std::uint32_t>(identity[0]), AI_SHIELD_FILE_CLEAN)) {
                CloseHandle(source_handle);
                append_record(health_, "{\"event\":\"kernel_verdict_failed\"}\r\n");
                processing_states_[source.wstring()] = FileProcessingState::retry_pending;
                retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
                return;
            }
            CloseHandle(source_handle);
            processed_[source.wstring()] = FileStamp{size, modified};
            processing_states_[source.wstring()] = FileProcessingState::analyzed_clean;
            retry_not_before_.erase(source.wstring());
            return;
        }
        const std::string intent = record.substr(0, record.size() - 3U) + ",\"state\":\"intent\"}\r\n";
        if (!append_record(journal_, intent)) {
            CloseHandle(source_handle);
            processing_states_[source.wstring()] = FileProcessingState::retry_pending;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
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
        bool moved = false;
        if (source_info.dwVolumeSerialNumber == objects_info_.dwVolumeSerialNumber) {
            moved = SetFileInformationByHandle(source_handle, FileRenameInfo, rename,
                                               static_cast<DWORD>(rename_storage.size())) != FALSE;
        } else if (copy_locked_to_quarantine(source_handle, size, content_digest, destination)) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            moved = SetFileInformationByHandle(source_handle, FileDispositionInfo,
                                               &disposition, sizeof(disposition)) != FALSE;
            if (!moved) DeleteFileW(destination.c_str());
        }
        const DWORD move_error = moved ? ERROR_SUCCESS : GetLastError();
        if (!moved) append_record(health_, "{\"event\":\"rename_failed\",\"error\":" +
                                                   std::to_string(move_error) + "}\r\n");
        FlushFileBuffers(source_handle);
        CloseHandle(source_handle);
        if (!moved) {
            processing_states_[source.wstring()] = FileProcessingState::retry_pending;
            retry_not_before_[source.wstring()] = GetTickCount64() + 5'000U;
            return;
        }
        processing_states_[source.wstring()] = release_pending ? FileProcessingState::release_pending :
                                                                 FileProcessingState::quarantined;
        submit_file_verdict(identity[1], static_cast<std::uint32_t>(identity[0]), AI_SHIELD_FILE_QUARANTINED);
        retry_not_before_.erase(source.wstring());
        const std::string committed = record.substr(0, record.size() - 3U) + ",\"state\":\"committed\"}\r\n";
        append_record(journal_, committed);
    }

    std::filesystem::path directory_;
    std::filesystem::path objects_;
    std::filesystem::path journal_;
    std::filesystem::path provenance_;
    std::filesystem::path health_;
    std::vector<ScanRoot> roots_;
    std::map<std::wstring, FileStamp> stable_sizes_;
    std::map<std::wstring, FileStamp> processed_;
    std::map<std::wstring, FileProcessingState> processing_states_;
    std::map<std::wstring, ULONGLONG> retry_not_before_;
    HANDLE objects_handle_ = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION objects_info_{};
    ContentPolicy policy_{};
    std::set<std::string> trusted_publishers_;
    std::mutex mutex_;
};

class MinifilterAnalysisChannel final {
    struct Message final {
        FILTER_MESSAGE_HEADER header{};
        AI_SHIELD_FILE_ANALYSIS_REQUEST request{};
    };

    struct Reply final {
        FILTER_REPLY_HEADER header{};
        AI_SHIELD_FILE_ANALYSIS_REPLY reply{};
    };

public:
    MinifilterAnalysisChannel() = default;
    MinifilterAnalysisChannel(const MinifilterAnalysisChannel&) = delete;
    MinifilterAnalysisChannel& operator=(const MinifilterAnalysisChannel&) = delete;

    ~MinifilterAnalysisChannel() {
        stop();
        if (port_ != INVALID_HANDLE_VALUE) CloseHandle(port_);
    }

    bool connect(QuarantineManager& quarantine) {
        const HRESULT result = FilterConnectCommunicationPort(AI_SHIELD_MINIFILTER_PORT_NAME, 0U, nullptr, 0U,
                                                               nullptr, &port_);
        if (FAILED(result)) {
            std::wcerr << L"broker: minifilter analysis port unavailable hresult=0x" << std::hex
                       << static_cast<unsigned long>(static_cast<std::uint32_t>(result)) << std::dec << L'\n';
            port_ = INVALID_HANDLE_VALUE;
            return false;
        }
        analysis_worker_ = std::jthread([this, &quarantine](std::stop_token stop_token) {
            analysis_loop(quarantine, stop_token);
        });
        receiver_ = std::jthread([this](std::stop_token stop_token) {
            receive_loop(stop_token);
        });
        return true;
    }

    void stop() {
        if (!receiver_.joinable() && !analysis_worker_.joinable()) return;
        receiver_.request_stop();
        analysis_worker_.request_stop();
        queue_condition_.notify_all();
        if (port_ != INVALID_HANDLE_VALUE) CancelIoEx(port_, nullptr);
        if (receiver_.joinable()) receiver_.join();
        if (analysis_worker_.joinable()) analysis_worker_.join();
    }

private:
    bool enqueue(const AI_SHIELD_FILE_ANALYSIS_REQUEST& request) {
        std::lock_guard lock(queue_mutex_);
        if (queue_.size() >= kMaximumQueuedRequests) return false;
        queue_.push_back(request);
        queue_condition_.notify_one();
        return true;
    }

    void analysis_loop(QuarantineManager& quarantine, std::stop_token stop_token) {
        while (!stop_token.stop_requested()) {
            AI_SHIELD_FILE_ANALYSIS_REQUEST request{};
            {
                std::unique_lock lock(queue_mutex_);
                queue_condition_.wait_for(lock, std::chrono::milliseconds(250), [this, &stop_token] {
                    return stop_token.stop_requested() || !queue_.empty();
                });
                if (stop_token.stop_requested()) break;
                if (queue_.empty()) continue;
                request = queue_.front();
                queue_.pop_front();
            }
            (void)quarantine.classify_pending(std::wstring_view(request.Path, request.PathLength),
                                              request.FileId, request.VolumeId);
        }
    }

    void receive_loop(std::stop_token stop_token) {
        HANDLE completion = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (completion == nullptr) return;
        while (!stop_token.stop_requested()) {
            Message message{};
            OVERLAPPED overlapped{};
            overlapped.hEvent = completion;
            ResetEvent(completion);
            const HRESULT result = FilterGetMessage(port_, &message.header, sizeof(message), &overlapped);
            if (result != HRESULT_FROM_WIN32(ERROR_IO_PENDING) && FAILED(result)) break;
            if (result == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                while (!stop_token.stop_requested() && WaitForSingleObject(completion, 250U) == WAIT_TIMEOUT) {}
                if (stop_token.stop_requested()) {
                    CancelIoEx(port_, &overlapped);
                    WaitForSingleObject(completion, INFINITE);
                    break;
                }
                DWORD transferred = 0U;
                if (!GetOverlappedResult(port_, &overlapped, &transferred, FALSE)) break;
            }
            const bool valid = message.request.Version == AI_SHIELD_PROTOCOL_VERSION &&
                               message.request.Size == sizeof(message.request) &&
                               message.request.RequestId != 0U && message.request.FileId != 0U &&
                               message.request.VolumeId != 0U && message.request.PathLength > 0U &&
                               message.request.PathLength < AI_SHIELD_ANALYSIS_PATH_CHARS &&
                               message.request.Path[message.request.PathLength] == L'\0';
            const bool accepted = valid && enqueue(message.request);
            Reply reply{};
            reply.header.Status = accepted ? S_OK : HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
            reply.header.MessageId = message.header.MessageId;
            reply.reply.Version = AI_SHIELD_PROTOCOL_VERSION;
            reply.reply.Size = sizeof(reply.reply);
            reply.reply.RequestId = message.request.RequestId;
            reply.reply.Verdict = AI_SHIELD_FILE_PENDING;
            const HRESULT replied = FilterReplyMessage(port_, &reply.header, sizeof(reply));
            if (FAILED(replied)) continue;
        }
        CloseHandle(completion);
    }

    static constexpr std::size_t kMaximumQueuedRequests = 4096U;
    HANDLE port_ = INVALID_HANDLE_VALUE;
    std::jthread receiver_;
    std::jthread analysis_worker_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::deque<AI_SHIELD_FILE_ANALYSIS_REQUEST> queue_;
};

bool valid_event(const Sensor& sensor, const AI_SHIELD_DRIVER_EVENT& event, DWORD bytes) {
    return bytes == sizeof(event) && event.Version == AI_SHIELD_PROTOCOL_VERSION &&
           event.Size == sizeof(event) && event.Sensor == sensor.id && event.Kind >= AI_SHIELD_EVENT_CONNECT &&
           event.Kind <= AI_SHIELD_EVENT_HANDLE_FILTER && event.Sequence != 0ULL;
}

int run_broker(const std::filesystem::path& log_directory, bool once) {
    if (!open_sensors() || !register_broker_gate()) { close_sensors(); return 3; }
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
    MinifilterAnalysisChannel analysis_channel;
    if (!analysis_channel.connect(quarantine)) {
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
                for (unsigned int i = 0U; i < 10U && !stop.stop_requested(); ++i) Sleep(100U);
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
    analysis_channel.stop();
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
        !parser_risk_extension(L"notes.txt") || parser_risk_extension(L"notes.txt", kContentDocuments) ||
        parser_risk_extension(L"photo.webp", kContentDocuments) ||
        content_category(L"report.pdf") != kContentDocuments || content_category(L"track.mp3") != kContentAudio ||
        content_category(L"setup.msi") != kContentPrograms || content_category(L"notes.txt") != kContentUnknown ||
        content_category(L"deploy.ps1") != kContentWindowsScripts ||
        content_category(L"bootstrap.sh") != kContentDeveloperScripts || content_category(L"target.lnk") != kContentLaunchers ||
        !executable_extension(L"deploy.ps1") || !executable_extension(L"module.psm1") ||
        !executable_extension(L"tool.py") || !executable_extension(L"package.jar") ||
        executable_extension(L"deploy.ps1", kContentPrograms)) return 4;
    std::wcout << L"ai_shield_broker self-test passed\n";
    return 0;
}

int runtime_command(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"content-policy-status") {
        const auto policy = load_content_policy();
        std::wcout << L"{\"schema\":\"AIShieldContentPolicy/4\",\"enabled_categories\":"
                   << policy.enabled_categories << L",\"fail_closed\":"
                   << (policy.fail_closed != 0U ? L"true" : L"false") << L",\"release_required\":"
                   << (policy.release_required != 0U ? L"true" : L"false") << L"}\n";
        return 0;
    }
    if ((argc == 4 || argc == 5) && std::wstring_view(argv[1]) == L"content-policy-set") {
        if (!elevated_administrator()) return 5;
        wchar_t* mask_end = nullptr;
        wchar_t* fail_end = nullptr;
        wchar_t* release_end = nullptr;
        const auto mask = wcstoul(argv[2], &mask_end, 10);
        const auto fail_closed = wcstoul(argv[3], &fail_end, 10);
        const auto release_required = argc == 5 ? wcstoul(argv[4], &release_end, 10) : 1UL;
        if (mask_end == argv[2] || *mask_end != L'\0' || fail_end == argv[3] || *fail_end != L'\0' ||
            (argc == 5 && (release_end == argv[4] || *release_end != L'\0')) ||
            (mask & ~kContentAll) != 0U || fail_closed > 1U || release_required > 1U) return 2;
        ContentPolicy policy{};
        policy.enabled_categories = mask;
        policy.fail_closed = fail_closed;
        policy.release_required = release_required;
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
