#include <windows.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>

#include "ai_shield/siem.hpp"
#include "ai_shield/file_preflight.hpp"
#include "ai_shield/pdf_preflight.hpp"
#include "ai_shield/wav_preflight.hpp"
#include "ai_shield/zip_preflight.hpp"
#include "platform/windows/security/tpm_trust_anchor.hpp"
#include "platform/windows/sandbox/appcontainer_launcher.hpp"
#include "platform/windows/sensors/etw_amsi_adapter.hpp"
#include "platform/windows/siem/syslog_connector.hpp"

namespace {

bool structural_risk(std::span<const std::byte> content, const std::filesystem::path* path = nullptr) {
    std::wstring extension;
    if (path != nullptr) {
        extension = path->extension().wstring();
        for (auto& character : extension) character = static_cast<wchar_t>(towlower(character));
    }
    const std::wstring filename = path != nullptr ? path->filename().wstring() : std::wstring{};
    const auto universal = ai_shield::file_preflight::inspect(content, filename);
    if (universal.high_risk()) return true;
    const bool pdf_signature = content.size() >= 5U &&
        std::to_integer<unsigned char>(content[0]) == '%' && std::to_integer<unsigned char>(content[1]) == 'P' &&
        std::to_integer<unsigned char>(content[2]) == 'D' && std::to_integer<unsigned char>(content[3]) == 'F' &&
        std::to_integer<unsigned char>(content[4]) == '-';
    if (extension == L".pdf" || pdf_signature) {
        const auto parsed = ai_shield::protocols::pdf::preflight(content);
        if (!parsed.ok() || parsed.value().malformed || parsed.value().javascript || parsed.value().launch_action ||
            parsed.value().embedded_file || parsed.value().open_action) return true;
    }
    const bool zip_signature = content.size() >= 4U && std::to_integer<unsigned char>(content[0]) == 'P' &&
        std::to_integer<unsigned char>(content[1]) == 'K';
    if (extension == L".zip" || zip_signature) {
        const auto parsed = ai_shield::protocols::zip::preflight(content);
        if (!parsed.ok() || parsed.value().malformed || parsed.value().path_escape || parsed.value().bomb_risk ||
            parsed.value().encrypted_entry || parsed.value().unsupported_compression || parsed.value().executable_entry ||
            parsed.value().active_content_entry || parsed.value().nested_container || parsed.value().duplicate_name)
            return true;
    }
    if (extension == L".wav" || ai_shield::protocols::wav::has_wave_signature(content)) {
        const auto parsed = ai_shield::protocols::wav::preflight(content);
        if (!parsed.ok() || parsed.value().malformed || parsed.value().suspicious_metadata) return true;
    }
    return false;
}

int self_test() {
    const auto text = ai_shield::siem::format({.monotonic_ns = 1, .reason_mask = 2, .risk_score = 3,
        .action = "test", .correlation = {.flow_id = 4, .policy_version = 5, .model_version = 6}},
        ai_shield::siem::Format::json_lines);
    return text.find("\"flow_id\":4") != std::string::npos ? 0 : 2;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") return self_test();
    if (argc == 2 && std::wstring_view(argv[1]) == L"tpm-status") {
        const auto status = ai_shield::platform::windows::security::tpm_status();
        std::wcout << L"provider=" << status.provider_available << L" hardware=" << status.hardware_backed
                   << L" key=" << status.key_available << L'\n';
        return status.provider_available ? 0 : 3;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"tpm-provision")
        return ai_shield::platform::windows::security::ensure_tpm_anchor().ok() ? 0 : 3;
    if (argc == 2 && std::wstring_view(argv[1]) == L"appcontainer-sid") {
        const auto sid = ai_shield::platform::windows::sandbox::parser_profile_sid();
        if (!sid.ok()) return 3;
        std::wcout << sid.value() << L'\n';
        return 0;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"appcontainer-launch-test") {
        const std::wstring executable = L"C:\\Windows\\System32\\cmd.exe";
        const std::wstring command = L"\"" + executable + L"\" /d /c exit 7";
        auto launched = ai_shield::platform::windows::sandbox::launch_shadow_parser({
            .analysis_id = GetTickCount64() + 1U, .parser_id = 99U,
            .budget = {.wall_time_ns = 5'000'000'000ULL, .memory_bytes = 64ULL * 1024ULL * 1024ULL,
                       .max_processes = 1U, .network_allowed = false},
            .executable_path = executable, .command_line = command, .work_directory = L"C:\\Windows\\System32"});
        if (!launched.ok()) return 3;
        auto process = launched.value();
        if (!ai_shield::platform::windows::sandbox::resume_launched_process(process).ok()) {
            ai_shield::platform::windows::sandbox::close_launched_process(process);
            return 3;
        }
        const DWORD wait = WaitForSingleObject(process.process, 5'000U);
        DWORD exit_code = ERROR_GEN_FAILURE;
        const bool completed = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.process, &exit_code) != FALSE;
        ai_shield::platform::windows::sandbox::close_launched_process(process);
        std::wcout << L"exit=" << exit_code << L'\n';
        return completed && exit_code == 7U ? 0 : 3;
    }
    if (argc == 3 && std::wstring_view(argv[1]) == L"amsi-scan-file") {
        const std::filesystem::path path(argv[2]);
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (error || size == 0U || size > 256ULL * 1024ULL * 1024ULL) return 3;
        std::ifstream input(path, std::ios::binary);
        std::vector<std::byte> content(static_cast<std::size_t>(size));
        if (!input.read(reinterpret_cast<char*>(content.data()), static_cast<std::streamsize>(content.size()))) return 3;
        if (structural_risk(content, &path)) return 11;
        const auto result = ai_shield::platform::windows::sensors::scan_with_amsi(
            content, 1U, GetTickCount64() * 1'000'000ULL, 1U, 1U);
        if (!result.ok()) return 3;
        constexpr std::uint32_t blocked_by_administrator = 16'384U;
        return result.value().scan_result >= blocked_by_administrator ? 10 : 0;
    }
    if ((argc == 4 || argc == 5) && std::wstring_view(argv[1]) == L"amsi-scan-handle") {
        wchar_t* handle_end = nullptr;
        wchar_t* size_end = nullptr;
        const auto handle_value = _wcstoui64(argv[2], &handle_end, 10);
        const auto size = _wcstoui64(argv[3], &size_end, 10);
        if (handle_end == argv[2] || *handle_end != L'\0' || size_end == argv[3] || *size_end != L'\0' ||
            handle_value == 0U || size == 0U || size > 256ULL * 1024ULL * 1024ULL) return 3;
        const HANDLE file = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(handle_value));
        std::vector<std::byte> content(static_cast<std::size_t>(size));
        std::size_t offset = 0U;
        HANDLE read_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (read_event == nullptr) return 3;
        while (offset < content.size()) {
            const DWORD requested = static_cast<DWORD>((std::min)(content.size() - offset,
                                                                  static_cast<std::size_t>(1U << 20U)));
            DWORD received = 0U;
            OVERLAPPED operation{};
            operation.Offset = static_cast<DWORD>(offset & 0xffffffffULL);
            operation.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32U);
            operation.hEvent = read_event;
            ResetEvent(read_event);
            const BOOL immediate = ReadFile(file, content.data() + offset, requested, &received, &operation);
            if (!immediate && GetLastError() == ERROR_IO_PENDING) {
                if (WaitForSingleObject(read_event, 5'000U) != WAIT_OBJECT_0) {
                    CancelIoEx(file, &operation);
                    CloseHandle(read_event);
                    return 3;
                }
                if (!GetOverlappedResult(file, &operation, &received, FALSE)) {
                    CloseHandle(read_event);
                    return 3;
                }
            } else if (!immediate) {
                CloseHandle(read_event);
                return 3;
            }
            if (received == 0U) { CloseHandle(read_event); return 3; }
            offset += received;
        }
        CloseHandle(read_event);
        const std::filesystem::path path = argc == 5 ? std::filesystem::path(argv[4]) : std::filesystem::path{};
        if (structural_risk(content, argc == 5 ? &path : nullptr)) return 11;
        const auto result = ai_shield::platform::windows::sensors::scan_with_amsi(
            content, 1U, GetTickCount64() * 1'000'000ULL, 1U, 1U);
        if (!result.ok()) return 3;
        constexpr std::uint32_t blocked_by_administrator = 16'384U;
        return result.value().scan_result >= blocked_by_administrator ? 10 : 0;
    }
    if (argc == 5 && std::wstring_view(argv[1]) == L"siem-test") {
        wchar_t* end = nullptr;
        const auto port_value = wcstoul(argv[3], &end, 10);
        if (end == argv[3] || *end != L'\0' || port_value == 0U || port_value > 65535U) return 2;
        const auto format = std::wstring_view(argv[4]) == L"cef" ? ai_shield::siem::Format::cef
                           : std::wstring_view(argv[4]) == L"leef" ? ai_shield::siem::Format::leef
                                                                   : ai_shield::siem::Format::json_lines;
        const auto message = ai_shield::siem::format({.monotonic_ns = 1, .reason_mask = 0,
            .risk_score = 0, .action = "integration-test", .correlation = {.policy_version = 1, .model_version = 1}},
            format);
        std::string host;
        for (const wchar_t character : std::wstring_view(argv[2])) {
            if (character > 0x7f) return 2;
            host.push_back(static_cast<char>(character));
        }
        return ai_shield::platform::windows::siem::send_syslog(host, static_cast<std::uint16_t>(port_value),
            message, ai_shield::platform::windows::siem::Transport::tcp).ok() ? 0 : 3;
    }
    return 2;
}
