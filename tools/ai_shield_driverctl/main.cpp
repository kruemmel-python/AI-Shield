#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <cwctype>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

enum class DriverKind : std::uint32_t {
    kernel,
    minifilter
};

struct ServiceSpec final {
    std::wstring name;
    std::wstring display_name;
    DriverKind kind = DriverKind::kernel;
    std::wstring group;
};

struct DriverPath final {
    std::wstring service_name;
    std::wstring path;
};

struct ScHandle final {
    SC_HANDLE value = nullptr;

    ScHandle() = default;
    explicit ScHandle(SC_HANDLE handle) noexcept : value(handle) {}
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    ScHandle(ScHandle&& other) noexcept : value(other.value) { other.value = nullptr; }
    ScHandle& operator=(ScHandle&& other) noexcept {
        if (this != &other) {
            close();
            value = other.value;
            other.value = nullptr;
        }
        return *this;
    }
    ~ScHandle() { close(); }

    void close() noexcept {
        if (value != nullptr) {
            CloseServiceHandle(value);
            value = nullptr;
        }
    }

    [[nodiscard]] bool valid() const noexcept { return value != nullptr; }
};

const std::vector<ServiceSpec>& service_specs() {
    static const std::vector<ServiceSpec> specs = {
        ServiceSpec{L"AIShieldWfp", L"AI Shield WFP Telemetry Driver", DriverKind::kernel, L"NDIS"},
        ServiceSpec{L"AIShieldMiniFilter", L"AI Shield File Provenance Minifilter", DriverKind::minifilter, L"FSFilter Activity Monitor"},
        ServiceSpec{L"AIShieldProcessGuard", L"AI Shield Process Consequence Sensor", DriverKind::kernel, L""}};
    return specs;
}

const ServiceSpec* find_spec(std::wstring_view name) {
    for (const auto& spec : service_specs()) {
        if (spec.name == name) {
            return &spec;
        }
    }
    return nullptr;
}

void print_last_error(std::wstring_view operation) {
    std::wcerr << operation << L" failed error=" << GetLastError() << L"\n";
}

std::wstring_view service_error_hint(DWORD error) noexcept {
    switch (error) {
        case ERROR_INVALID_IMAGE_HASH:
            return L"driver signature rejected by Windows kernel policy; enable TESTSIGNING with Secure Boot off or use Microsoft-signed drivers";
        default:
            return L"";
    }
}

void print_service_error(std::wstring_view operation, DWORD error) {
    std::wcerr << operation << L" failed error=" << error;
    const auto hint = service_error_hint(error);
    if (!hint.empty()) {
        std::wcerr << L" (" << hint << L")";
    }
    std::wcerr << L"\n";
}

void print_usage() {
    std::wcerr << L"usage:\n";
    std::wcerr << L"  ai_shield_driverctl self-test\n";
    std::wcerr << L"  ai_shield_driverctl status\n";
    std::wcerr << L"  ai_shield_driverctl install --wfp <AIShieldWfp.sys> --minifilter <AIShieldMiniFilter.sys> --process <AIShieldProcessGuard.sys>\n";
    std::wcerr << L"  ai_shield_driverctl start|stop|uninstall\n";
}

bool file_exists(std::wstring_view path) {
    const DWORD attributes = GetFileAttributesW(std::wstring(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U;
}

bool set_registry_string(HKEY key, const wchar_t* name, std::wstring_view value) {
    const auto bytes = static_cast<DWORD>((value.size() + 1U) * sizeof(wchar_t));
    const LSTATUS status = RegSetValueExW(key,
                                         name,
                                         0,
                                         REG_SZ,
                                         static_cast<const BYTE*>(static_cast<const void*>(value.data())),
                                         bytes);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"RegSetValueEx failed error=" << status << L"\n";
        return false;
    }
    return true;
}

bool configure_minifilter_registry() {
    constexpr wchar_t instances_path[] =
        L"SYSTEM\\CurrentControlSet\\Services\\AIShieldMiniFilter\\Instances";
    constexpr wchar_t instance_path[] =
        L"SYSTEM\\CurrentControlSet\\Services\\AIShieldMiniFilter\\Instances\\AIShieldMiniFilter Instance";
    HKEY instances = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                     instances_path,
                                     0,
                                     nullptr,
                                     REG_OPTION_NON_VOLATILE,
                                     KEY_SET_VALUE,
                                     nullptr,
                                     &instances,
                                     nullptr);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"RegCreateKeyEx failed error=" << status << L"\n";
        return false;
    }
    const bool default_ok = set_registry_string(instances, L"DefaultInstance", L"AIShieldMiniFilter Instance");
    RegCloseKey(instances);

    HKEY instance = nullptr;
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                             instance_path,
                             0,
                             nullptr,
                             REG_OPTION_NON_VOLATILE,
                             KEY_SET_VALUE,
                             nullptr,
                             &instance,
                             nullptr);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"RegCreateKeyEx failed error=" << status << L"\n";
        return false;
    }
    const bool altitude_ok = set_registry_string(instance, L"Altitude", L"370120");
    const DWORD flags = 0;
    status = RegSetValueExW(instance,
                            L"Flags",
                            0,
                            REG_DWORD,
                            static_cast<const BYTE*>(static_cast<const void*>(&flags)),
                            sizeof(flags));
    RegCloseKey(instance);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"RegSetValueEx failed error=" << status << L"\n";
        return false;
    }
    return default_ok && altitude_ok;
}

DWORD service_type_for(DriverKind kind) noexcept {
    return kind == DriverKind::minifilter ? SERVICE_FILE_SYSTEM_DRIVER : SERVICE_KERNEL_DRIVER;
}

ScHandle open_manager(DWORD access) {
    return ScHandle(OpenSCManagerW(nullptr, nullptr, access));
}

ScHandle open_service(SC_HANDLE manager, const ServiceSpec& spec, DWORD access) {
    return ScHandle(OpenServiceW(manager, spec.name.c_str(), access));
}

bool install_service(SC_HANDLE manager, const ServiceSpec& spec, std::wstring_view sys_path) {
    if (!file_exists(sys_path)) {
        std::wcerr << L"driver file not found: " << sys_path << L"\n";
        return false;
    }

    ScHandle existing = open_service(manager, spec, SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if (existing.valid()) {
        if (!ChangeServiceConfigW(existing.value, SERVICE_NO_CHANGE, SERVICE_SYSTEM_START,
                                  SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            print_last_error(L"ChangeServiceConfig");
            return false;
        }
        if (spec.kind == DriverKind::minifilter && !configure_minifilter_registry()) {
            return false;
        }
        std::wcout << spec.name << L" already installed\n";
        return true;
    }

    const std::wstring path(sys_path);
    const wchar_t* group = spec.group.empty() ? nullptr : spec.group.c_str();
    ScHandle created(CreateServiceW(manager,
                                    spec.name.c_str(),
                                    spec.display_name.c_str(),
                                    SERVICE_ALL_ACCESS,
                                    service_type_for(spec.kind),
                                    SERVICE_SYSTEM_START,
                                    SERVICE_ERROR_NORMAL,
                                    path.c_str(),
                                    group,
                                    nullptr,
                                    nullptr,
                                    nullptr,
                                    nullptr));
    if (!created.valid()) {
        print_last_error(L"CreateService");
        return false;
    }
    if (spec.kind == DriverKind::minifilter && !configure_minifilter_registry()) {
        return false;
    }
    std::wcout << L"installed " << spec.name << L"\n";
    return true;
}

bool start_service(SC_HANDLE manager, const ServiceSpec& spec) {
    ScHandle service = open_service(manager, spec, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service.valid()) {
        print_last_error(L"OpenService");
        return false;
    }
    if (StartServiceW(service.value, 0, nullptr) == FALSE) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            print_service_error(L"StartService", error);
            return false;
        }
    }
    std::wcout << L"started " << spec.name << L"\n";
    return true;
}

bool stop_service(SC_HANDLE manager, const ServiceSpec& spec) {
    ScHandle service = open_service(manager, spec, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service.valid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcout << spec.name << L" not installed\n";
            return true;
        }
        std::wcerr << L"OpenService failed error=" << error << L"\n";
        return false;
    }
    SERVICE_STATUS status{};
    if (ControlService(service.value, SERVICE_CONTROL_STOP, &status) == FALSE) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            std::wcerr << L"ControlService failed error=" << error << L"\n";
            return false;
        }
    }
    std::wcout << L"stopped " << spec.name << L"\n";
    return true;
}

bool uninstall_service(SC_HANDLE manager, const ServiceSpec& spec) {
    ScHandle service = open_service(manager, spec, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service.valid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcout << spec.name << L" not installed\n";
            return true;
        }
        std::wcerr << L"OpenService failed error=" << error << L"\n";
        return false;
    }
    SERVICE_STATUS status{};
    ControlService(service.value, SERVICE_CONTROL_STOP, &status);
    if (DeleteService(service.value) == FALSE) {
        print_last_error(L"DeleteService");
        return false;
    }
    std::wcout << L"removed " << spec.name << L"\n";
    return true;
}

bool print_status(SC_HANDLE manager, const ServiceSpec& spec) {
    ScHandle service = open_service(manager, spec, SERVICE_QUERY_STATUS);
    if (!service.valid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcout << spec.name << L": not installed\n";
            return true;
        }
        std::wcerr << L"OpenService failed error=" << error << L"\n";
        return false;
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes_needed = 0;
    const BOOL ok = QueryServiceStatusEx(service.value,
                                         SC_STATUS_PROCESS_INFO,
                                         static_cast<LPBYTE>(static_cast<void*>(&status)),
                                         sizeof(status),
                                         &bytes_needed);
    if (ok == FALSE) {
        print_last_error(L"QueryServiceStatusEx");
        return false;
    }
    std::wcout << spec.name << L": state=" << status.dwCurrentState << L" win32_exit=" << status.dwWin32ExitCode;
    const auto hint = service_error_hint(status.dwWin32ExitCode);
    if (!hint.empty()) {
        std::wcout << L" hint=\"" << hint << L"\"";
    }
    std::wcout << L"\n";
    return true;
}

std::vector<DriverPath> parse_install_paths(int argc, wchar_t** argv) {
    std::vector<DriverPath> paths;
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::wstring_view flag(argv[i]);
        std::wstring service_name;
        if (flag == L"--wfp") {
            service_name = L"AIShieldWfp";
        } else if (flag == L"--minifilter") {
            service_name = L"AIShieldMiniFilter";
        } else if (flag == L"--process") {
            service_name = L"AIShieldProcessGuard";
        } else {
            return {};
        }
        paths.push_back(DriverPath{.service_name = service_name, .path = argv[i + 1]});
    }
    return paths;
}

int run_self_test() {
    if (find_spec(L"AIShieldWfp") == nullptr || find_spec(L"AIShieldMiniFilter") == nullptr ||
        find_spec(L"AIShieldProcessGuard") == nullptr) {
        std::wcerr << L"service spec lookup failed\n";
        return 2;
    }
    const auto paths = parse_install_paths(8,
                                           const_cast<wchar_t**>(std::vector<const wchar_t*>{
                                               L"ai_shield_driverctl",
                                               L"install",
                                               L"--wfp",
                                               L"a.sys",
                                               L"--minifilter",
                                               L"b.sys",
                                               L"--process",
                                               L"c.sys"}
                                                                  .data()));
    if (paths.size() != 3U) {
        std::wcerr << L"install parser failed\n";
        return 2;
    }
    std::wcout << L"ai_shield_driverctl self-test passed\n";
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    const std::wstring_view command(argv[1]);
    if (command == L"self-test") {
        return run_self_test();
    }

    DWORD manager_access = SC_MANAGER_CONNECT;
    if (command == L"install") {
        manager_access = SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT;
    }

    ScHandle manager = open_manager(manager_access);
    if (!manager.valid()) {
        print_last_error(L"OpenSCManager");
        return 2;
    }

    bool ok = true;
    if (command == L"status") {
        for (const auto& spec : service_specs()) {
            ok = print_status(manager.value, spec) && ok;
        }
    } else if (command == L"install") {
        const auto paths = parse_install_paths(argc, argv);
        if (paths.size() != 3U) {
            print_usage();
            return 2;
        }
        for (const auto& path : paths) {
            const auto* spec = find_spec(path.service_name);
            ok = spec != nullptr && install_service(manager.value, *spec, path.path) && ok;
        }
    } else if (command == L"start") {
        for (const auto& spec : service_specs()) {
            ok = start_service(manager.value, spec) && ok;
        }
    } else if (command == L"stop") {
        for (const auto& spec : service_specs()) {
            ok = stop_service(manager.value, spec) && ok;
        }
    } else if (command == L"uninstall") {
        for (const auto& spec : service_specs()) {
            ok = uninstall_service(manager.value, spec) && ok;
        }
    } else {
        print_usage();
        return 2;
    }

    return ok ? 0 : 2;
}
