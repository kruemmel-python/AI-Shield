#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>

#include <array>
#include <iostream>
#include <string_view>

#include "platform/windows/common/ai_shield_driver_protocol.h"

namespace {

struct DeviceSpec final {
    const wchar_t* name;
    const wchar_t* path;
};

constexpr std::array<DeviceSpec, 3> kDevices{{
    {L"wfp", L"\\\\.\\AIShieldWfp"},
    {L"minifilter", L"\\\\.\\AIShieldMiniFilter"},
    {L"process_guard", L"\\\\.\\AIShieldProcessGuard"}}};

struct Device final {
    HANDLE value = INVALID_HANDLE_VALUE;
    Device() = default;
    explicit Device(const wchar_t* path)
        : value(CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr)) {}
    Device(const Device&) = delete;
    Device& operator=(const Device&) = delete;
    ~Device() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

bool parse_port(std::wstring_view text, ULONG& port) {
    ULONG value = 0;
    if (text.empty()) return false;
    for (wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
        value = value * 10U + static_cast<ULONG>(ch - L'0');
        if (value > 65535U) return false;
    }
    port = value;
    return true;
}

bool parse_u32(std::wstring_view text, ULONG& value) {
    unsigned long long parsed = 0;
    if (text.empty()) return false;
    for (wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
        parsed = parsed * 10ULL + static_cast<unsigned long long>(ch - L'0');
        if (parsed > 0xffffffffULL) return false;
    }
    value = static_cast<ULONG>(parsed);
    return value != 0U;
}

bool set_policy_on(const DeviceSpec& spec, const AI_SHIELD_DRIVER_POLICY& policy) {
    Device device(spec.path);
    if (device.value == INVALID_HANDLE_VALUE) {
        std::wcerr << L"open " << spec.name << L" failed error=" << GetLastError() << L"\n";
        return false;
    }
    DWORD bytes = 0;
    if (!DeviceIoControl(device.value, AI_SHIELD_IOCTL_SET_POLICY,
                         const_cast<AI_SHIELD_DRIVER_POLICY*>(&policy), sizeof(policy),
                         nullptr, 0, &bytes, nullptr)) {
        std::wcerr << L"set " << spec.name << L" policy failed error=" << GetLastError() << L"\n";
        return false;
    }
    return true;
}

bool set_policy_all(const AI_SHIELD_DRIVER_POLICY& policy) {
    bool ok = true;
    for (const auto& spec : kDevices) ok = set_policy_on(spec, policy) && ok;
    return ok;
}

bool print_status_on(const DeviceSpec& spec) {
    Device device(spec.path);
    if (device.value == INVALID_HANDLE_VALUE) {
        std::wcerr << spec.name << L": unavailable error=" << GetLastError() << L"\n";
        return false;
    }
    AI_SHIELD_DRIVER_STATUS status{};
    DWORD bytes = 0;
    if (!DeviceIoControl(device.value, AI_SHIELD_IOCTL_GET_STATUS, nullptr, 0,
                         &status, sizeof(status), &bytes, nullptr) || bytes != sizeof(status) ||
        status.Version != AI_SHIELD_PROTOCOL_VERSION || status.Size != sizeof(status)) {
        std::wcerr << spec.name << L": invalid status error=" << GetLastError()
                   << L" bytes=" << bytes << L"\n";
        return false;
    }
    std::wcout << spec.name << L" mode="
               << (status.Mode == AI_SHIELD_POLICY_ENFORCE ? L"enforce" : L"audit")
               << L" observed=" << status.Observed << L" allowed=" << status.Allowed
               << L" blocked=" << status.Blocked << L" redirected=" << status.Redirected
               << L" telemetry_dropped=" << status.DroppedTelemetry << L"\n";
    return true;
}

int print_status() {
    bool ok = true;
    for (const auto& spec : kDevices) ok = print_status_on(spec) && ok;
    return ok ? 0 : 2;
}

void usage() {
    std::wcerr
        << L"usage: ai_shield_kernelctl status|audit|self-test\n"
        << L"       ai_shield_kernelctl enforce [--block-inbound PORT] "
           L"[--redirect-port PORT --proxy-port PORT --exempt-pid PID] --block-quarantine-execution "
           L"[--block-user-temp-execution] [--block-download-execution] [--block-risky-script-command] "
           L"[--block-office-child-process] "
           L"[--system-network-guard] [--block-unsolicited-inbound] [--block-browser-non-web] "
           L"--confirm-enforcement\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") {
        ULONG port = 0;
        if (!parse_port(L"18081", port) || port != 18081U || parse_port(L"70000", port) ||
            sizeof(AI_SHIELD_DRIVER_POLICY) != 32U || sizeof(AI_SHIELD_DRIVER_STATUS) != 56U ||
            sizeof(AI_SHIELD_DRIVER_EVENT) != 72U || AI_SHIELD_ABI_FREEZE_REVISION != 3U ||
            kDevices.size() != 3U) return 2;
        std::wcout << L"ai_shield_kernelctl self-test passed\n";
        return 0;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"status") return print_status();

    AI_SHIELD_DRIVER_POLICY policy{AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_POLICY),
                                   AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0};
    if (argc == 2 && std::wstring_view(argv[1]) == L"audit") {
        if (!set_policy_all(policy)) return 2;
        std::wcout << L"audit policy active on all kernel sensors\n";
        return 0;
    }
    if (argc >= 3 && std::wstring_view(argv[1]) == L"enforce") {
        bool confirmed = false;
        policy.Mode = AI_SHIELD_POLICY_ENFORCE;
        for (int i = 2; i < argc; ++i) {
            const std::wstring_view arg(argv[i]);
            if (arg == L"--confirm-enforcement") confirmed = true;
            else if (arg == L"--block-quarantine-execution")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_QUARANTINE_EXECUTION;
            else if (arg == L"--block-user-temp-execution")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_USER_TEMP_EXECUTION;
            else if (arg == L"--block-download-execution")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_DOWNLOAD_EXECUTION;
            else if (arg == L"--block-risky-script-command")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_RISKY_SCRIPT_COMMAND;
            else if (arg == L"--block-office-child-process")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_OFFICE_CHILD_PROCESS;
            else if (arg == L"--system-network-guard")
                policy.Flags |= AI_SHIELD_POLICY_SYSTEM_NETWORK_GUARD;
            else if (arg == L"--block-unsolicited-inbound")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_UNSOLICITED_INBOUND;
            else if (arg == L"--block-browser-non-web")
                policy.Flags |= AI_SHIELD_POLICY_BLOCK_BROWSER_NON_WEB;
            else if (arg == L"--block-inbound" && i + 1 < argc &&
                     parse_port(argv[++i], policy.BlockInboundPort)) {}
            else if (arg == L"--redirect-port" && i + 1 < argc &&
                     parse_port(argv[++i], policy.RedirectOutboundPort)) {}
            else if (arg == L"--proxy-port" && i + 1 < argc &&
                     parse_port(argv[++i], policy.ProxyPort)) {}
            else if (arg == L"--exempt-pid" && i + 1 < argc &&
                     parse_u32(argv[++i], policy.ExemptProcessId)) {}
            else { usage(); return 2; }
        }
        const bool has_rule = policy.BlockInboundPort != 0U || policy.RedirectOutboundPort != 0U ||
                              policy.Flags != 0U;
        const bool redirect_pair = (policy.RedirectOutboundPort == 0U) == (policy.ProxyPort == 0U);
        if (!confirmed || !has_rule || !redirect_pair ||
            (policy.RedirectOutboundPort != 0U && policy.ExemptProcessId == 0U) ||
            (policy.RedirectOutboundPort != 0U && policy.RedirectOutboundPort == policy.ProxyPort)) {
            std::wcerr << L"refusing unsafe or empty enforcement policy\n";
            return 2;
        }
        if (!set_policy_all(policy)) {
            AI_SHIELD_DRIVER_POLICY audit{AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_POLICY),
                                          AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0};
            set_policy_all(audit);
            std::wcerr << L"enforcement rolled back to audit after partial failure\n";
            return 2;
        }
        std::wcout << L"enforcement policy active on all kernel sensors\n";
        return 0;
    }
    usage();
    return 2;
}
