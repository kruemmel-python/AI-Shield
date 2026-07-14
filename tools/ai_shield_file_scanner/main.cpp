#include <windows.h>
#include <amsi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ai_shield/file_preflight.hpp"
#include "ai_shield/pdf_preflight.hpp"
#include "ai_shield/wav_preflight.hpp"
#include "ai_shield/zip_preflight.hpp"

namespace {

bool structural_risk(std::span<const std::byte> content, const std::filesystem::path& path) {
    const auto universal = ai_shield::file_preflight::inspect(content, path.filename().wstring());
    if (universal.high_risk()) return true;
    auto extension = path.extension().wstring();
    for (auto& character : extension) character = static_cast<wchar_t>(towlower(character));
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
            parsed.value().active_content_entry || parsed.value().nested_container || parsed.value().duplicate_name) return true;
    }
    if (extension == L".wav" || ai_shield::protocols::wav::has_wave_signature(content)) {
        const auto parsed = ai_shield::protocols::wav::preflight(content);
        if (!parsed.ok() || parsed.value().malformed || parsed.value().suspicious_metadata) return true;
    }
    return false;
}

int amsi_verdict(std::span<const std::byte> content) {
    const HMODULE module = LoadLibraryExW(L"amsi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr) return 3;
    const auto initialize = reinterpret_cast<decltype(&AmsiInitialize)>(GetProcAddress(module, "AmsiInitialize"));
    const auto scan = reinterpret_cast<decltype(&AmsiScanBuffer)>(GetProcAddress(module, "AmsiScanBuffer"));
    const auto uninitialize = reinterpret_cast<decltype(&AmsiUninitialize)>(GetProcAddress(module, "AmsiUninitialize"));
    if (initialize == nullptr || scan == nullptr || uninitialize == nullptr) { FreeLibrary(module); return 3; }
    HAMSICONTEXT context = nullptr;
    if (FAILED(initialize(L"AIShieldIsolatedFileScanner", &context))) { FreeLibrary(module); return 3; }
    AMSI_RESULT result = AMSI_RESULT_NOT_DETECTED;
    const HRESULT scanned = scan(context, const_cast<std::byte*>(content.data()), static_cast<ULONG>(content.size()),
                                 L"AIShieldDownload", nullptr, &result);
    uninitialize(context);
    FreeLibrary(module);
    if (FAILED(scanned)) return 3;
    return AmsiResultIsMalware(result) ? 10 : 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") return 0;
    if (argc != 5 || std::wstring_view(argv[1]) != L"scan-handle") return 2;
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
            if (WaitForSingleObject(read_event, 5'000U) != WAIT_OBJECT_0 ||
                !GetOverlappedResult(file, &operation, &received, FALSE)) {
                CancelIoEx(file, &operation);
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
    if (structural_risk(content, std::filesystem::path(argv[4]))) return 11;
    return amsi_verdict(content);
}
