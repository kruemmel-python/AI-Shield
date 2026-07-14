#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include "platform/windows/common/ai_shield_driver_protocol.h"

namespace {

constexpr wchar_t kServiceName[] = L"AIShieldCore";
constexpr wchar_t kHealthFile[] = L"C:\\ProgramData\\AIShield\\health.json";
constexpr std::uint32_t kSafeModeThreshold = 5U;
std::atomic_bool g_stop{false};
std::atomic_bool g_reset{false};
SERVICE_STATUS_HANDLE g_handle = nullptr;
SERVICE_STATUS g_status{};

struct Component final {
    const wchar_t* service;
    const wchar_t* device;
    std::uint32_t failures = 0;
    std::uint64_t retry_after = 0;
};

std::array<Component, 4> g_components{{
    {L"AIShieldWfp", L"\\.\\AIShieldWfp"},
    {L"AIShieldMiniFilter", L"\\.\\AIShieldMiniFilter"},
    {L"AIShieldProcessGuard", L"\\.\\AIShieldProcessGuard"},
    {L"AIShieldBroker", nullptr}}};

std::uint64_t now_ms() noexcept { return GetTickCount64(); }

std::uint64_t retry_delay_ms(std::uint32_t failures) noexcept {
    const auto exponent = failures > 6U ? 6U : failures;
    return 1'000ULL << exponent;
}

void event_log(WORD type, const wchar_t* message) {
    HANDLE source = RegisterEventSourceW(nullptr, kServiceName);
    if (source == nullptr) return;
    const wchar_t* messages[] = {message};
    ReportEventW(source, type, 0, 1U, nullptr, 1U, 0U, messages, nullptr);
    DeregisterEventSource(source);
}

bool service_running(SC_HANDLE manager, const wchar_t* name) {
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS | SERVICE_START);
    if (service == nullptr) return false;
    SERVICE_STATUS status{};
    bool running = QueryServiceStatus(service, &status) &&
                   status.dwCurrentState == SERVICE_RUNNING;
    if (!running) {
        StartServiceW(service, 0U, nullptr);
        Sleep(250U);
        running = QueryServiceStatus(service, &status) &&
                  status.dwCurrentState == SERVICE_RUNNING;
    }
    CloseServiceHandle(service);
    return running;
}

bool set_kernel_audit(const wchar_t* device) {
    if (device == nullptr) return true;
    HANDLE handle = CreateFileW(device, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    AI_SHIELD_DRIVER_POLICY policy{};
    policy.Version = AI_SHIELD_PROTOCOL_VERSION;
    policy.Size = sizeof(policy);
    policy.Mode = AI_SHIELD_POLICY_AUDIT;
    DWORD bytes = 0;
    const bool ok = DeviceIoControl(handle, AI_SHIELD_IOCTL_SET_POLICY, &policy, sizeof(policy),
                                    nullptr, 0U, &bytes, nullptr) != FALSE;
    CloseHandle(handle);
    return ok;
}

bool policy_available() { return std::filesystem::exists(L"C:\\ProgramData\\AIShield\\policy\\current.aipolicy"); }

bool audit_writable() {
    const wchar_t path[] = L"C:\\ProgramData\\AIShield\\audit\\.health-probe";
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const unsigned char marker = 0x5aU;
    DWORD written = 0;
    const bool ok = WriteFile(file, &marker, 1U, &written, nullptr) && written == 1U && FlushFileBuffers(file);
    CloseHandle(file);
    DeleteFileW(path);
    return ok;
}

bool gateway_alive() {
    std::wifstream input(L"C:\\ProgramData\\AIShield\\gateway.pid");
    std::uint32_t pid = 0;
    if (!(input >> pid) || pid == 0U) return false;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (process == nullptr) return false;
    const bool alive = WaitForSingleObject(process, 0U) == WAIT_TIMEOUT;
    CloseHandle(process);
    return alive;
}

void write_health(bool safe_mode, std::uint32_t unhealthy) {
    std::filesystem::create_directories(L"C:\\ProgramData\\AIShield");
    const std::wstring temporary = std::wstring(kHealthFile) + L".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    output << "{\"schema\":2,\"safe_mode\":" << (safe_mode ? "true" : "false")
           << ",\"unhealthy_components\":" << unhealthy
           << ",\"policy_available\":" << (policy_available() ? "true" : "false")
           << ",\"audit_writable\":" << (audit_writable() ? "true" : "false")
           << ",\"gateway_alive\":" << (gateway_alive() ? "true" : "false")
           << ",\"updated_tick_ms\":" << now_ms() << "}";
    output.flush();
    output.close();
    MoveFileExW(temporary.c_str(), kHealthFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

int run() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) return 2;
    bool safe_mode = false;
    bool reported_safe_mode = false;
    while (!g_stop.load()) {
        if (g_reset.exchange(false)) {
            safe_mode = false;
            for (auto& component : g_components) { component.failures = 0; component.retry_after = 0; }
            event_log(EVENTLOG_INFORMATION_TYPE, L"AI Shield Safe Mode reset requested.");
        }
        std::uint32_t unhealthy = 0;
        for (auto& component : g_components) {
            if (now_ms() < component.retry_after) { ++unhealthy; continue; }
            if (service_running(manager, component.service)) {
                component.failures = 0;
                component.retry_after = 0;
            } else {
                ++unhealthy;
                ++component.failures;
                component.retry_after = now_ms() + retry_delay_ms(component.failures);
                if (component.failures >= kSafeModeThreshold) safe_mode = true;
            }
        }
        if (!policy_available() || !audit_writable()) safe_mode = true;
        if (safe_mode) {
            for (const auto& component : g_components) set_kernel_audit(component.device);
        }
        if (safe_mode != reported_safe_mode) {
            event_log(safe_mode ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE,
                      safe_mode ? L"AI Shield entered audit-only Safe Mode."
                                : L"AI Shield returned to normal supervision.");
            reported_safe_mode = safe_mode;
        }
        write_health(safe_mode, unhealthy);
        for (unsigned int elapsed = 0; elapsed < 50U && !g_stop.load(); ++elapsed) Sleep(100U);
    }
    CloseServiceHandle(manager);
    return 0;
}

void report(DWORD state, DWORD error = NO_ERROR) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = error;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0U;
    SetServiceStatus(g_handle, &g_status);
}

void WINAPI control(DWORD command) {
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        g_stop.store(true);
        report(SERVICE_STOP_PENDING);
    } else if (command == 128U) {
        g_reset.store(true);
    }
}

void WINAPI service_main(DWORD, wchar_t**) {
    g_handle = RegisterServiceCtrlHandlerW(kServiceName, control);
    if (g_handle == nullptr) return;
    report(SERVICE_START_PENDING);
    report(SERVICE_RUNNING);
    const int result = run();
    report(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") {
        return retry_delay_ms(1U) == 2'000U && retry_delay_ms(20U) == 64'000U ? 0 : 2;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"--console") return run();
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(kServiceName), service_main}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 2;
}
