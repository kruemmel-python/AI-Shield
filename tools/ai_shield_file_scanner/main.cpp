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

struct ProcessHandleEntry final {
    HANDLE handle_value;
    ULONG_PTR handle_count;
    ULONG_PTR pointer_count;
    ULONG granted_access;
    ULONG object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
};

struct ProcessHandleTable final {
    ULONG_PTR count;
    ULONG_PTR reserved;
    ProcessHandleEntry entries[1];
};

bool process_has_handle(std::uintptr_t value, bool& query_ok) {
    using QueryProcessInformation = LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query = ntdll == nullptr ? nullptr : reinterpret_cast<QueryProcessInformation>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query == nullptr) { query_ok = false; return false; }
    std::vector<std::byte> storage(64U * 1024U);
    ULONG required = 0U;
    LONG status = 0;
    for (unsigned int attempt = 0U; attempt < 8U; ++attempt) {
        status = query(GetCurrentProcess(), 51U, storage.data(), static_cast<ULONG>(storage.size()), &required);
        if (status != static_cast<LONG>(0xC0000004U)) break;
        storage.resize((std::max)(storage.size() * 2U, static_cast<std::size_t>(required) + 4096U));
    }
    if (status < 0) { query_ok = false; return false; }
    query_ok = true;
    const auto* table = reinterpret_cast<const ProcessHandleTable*>(storage.data());
    for (ULONG_PTR index = 0U; index < table->count; ++index) {
        if (reinterpret_cast<std::uintptr_t>(table->entries[index].handle_value) == value) return true;
    }
    return false;
}

int classify_amsi_result(AMSI_RESULT result) noexcept {
    if (AmsiResultIsMalware(result)) return 10;
    if (result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END) return 11;
    return 0;
}

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
    return classify_amsi_result(result);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") {
        return classify_amsi_result(AMSI_RESULT_NOT_DETECTED) == 0 &&
                       classify_amsi_result(AMSI_RESULT_BLOCKED_BY_ADMIN_START) == 11 &&
                       classify_amsi_result(AMSI_RESULT_DETECTED) == 10 ? 0 : 1;
    }
    if (argc == 4 && std::wstring_view(argv[1]) == L"probe-handles") {
        wchar_t* allowed_end = nullptr;
        wchar_t* forbidden_end = nullptr;
        const auto allowed_value = _wcstoui64(argv[2], &allowed_end, 10);
        const auto forbidden_value = _wcstoui64(argv[3], &forbidden_end, 10);
        if (*allowed_end != L'\0' || *forbidden_end != L'\0') return 2;
        bool allowed_query = false;
        bool forbidden_query = false;
        const bool allowed = process_has_handle(static_cast<std::uintptr_t>(allowed_value), allowed_query);
        const bool leaked = process_has_handle(static_cast<std::uintptr_t>(forbidden_value), forbidden_query);
        if (!allowed_query || !forbidden_query) return 4;
        if (!allowed) return 5;
        if (leaked) return 6;
        return 0;
    }
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
