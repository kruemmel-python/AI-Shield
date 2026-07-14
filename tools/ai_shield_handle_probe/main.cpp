#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <iostream>
#include <string_view>

namespace {

bool parse_pid(std::wstring_view text, DWORD& pid) {
    unsigned long long value = 0;
    if (text.empty()) return false;
    for (const wchar_t character : text) {
        if (character < L'0' || character > L'9') return false;
        value = value * 10ULL + static_cast<unsigned long long>(character - L'0');
        if (value > MAXDWORD) return false;
    }
    pid = static_cast<DWORD>(value);
    return pid != 0U;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") {
        DWORD pid = 0;
        if (!parse_pid(L"1234", pid) || pid != 1234U || parse_pid(L"0", pid) || parse_pid(L"x", pid)) return 2;
        std::wcout << L"ai_shield_handle_probe self-test passed\n";
        return 0;
    }
    if (argc != 2) return 2;
    DWORD pid = 0;
    if (!parse_pid(argv[1], pid)) return 2;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_WRITE |
                                 PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_TERMINATE |
                                 PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (process == nullptr) {
        std::wcerr << L"OpenProcess failed error=" << GetLastError() << L'\n';
        return 3;
    }
    CloseHandle(process);
    std::wcout << L"handle request completed pid=" << pid << L'\n';
    return 0;
}
