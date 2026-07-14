#include "platform/windows/sandbox/appcontainer_launcher.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <vector>

namespace ai_shield::platform::windows::sandbox {
namespace {

struct SidHolder final {
    PSID sid = nullptr;
    ~SidHolder() {
        if (sid != nullptr) {
            FreeSid(sid);
        }
    }
};

struct AttributeListHolder final {
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    ~AttributeListHolder() {
        if (list != nullptr) {
            DeleteProcThreadAttributeList(list);
            HeapFree(GetProcessHeap(), 0, list);
        }
    }
};

struct LocalAclHolder final {
    PACL acl = nullptr;
    ~LocalAclHolder() {
        if (acl != nullptr) LocalFree(acl);
    }
};

bool inheritable_handle(HANDLE handle) noexcept {
    if (handle == INVALID_HANDLE_VALUE) return true;
    DWORD flags = 0U;
    return GetHandleInformation(handle, &flags) != FALSE && (flags & HANDLE_FLAG_INHERIT) != 0U;
}

bool grant_restricted_station_access(HWINSTA station, PSID restricted_sid) noexcept {
    PACL existing_acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD queried = GetSecurityInfo(station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                                          nullptr, nullptr, &existing_acl, nullptr, &descriptor);
    if (queried != ERROR_SUCCESS) return false;
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_READATTRIBUTES;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access.Trustee.ptstrName = static_cast<LPWSTR>(restricted_sid);
    PACL updated_acl = nullptr;
    const DWORD merged = SetEntriesInAclW(1U, &access, existing_acl, &updated_acl);
    DWORD applied = merged;
    if (merged == ERROR_SUCCESS) {
        applied = SetSecurityInfo(station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                                  nullptr, nullptr, updated_acl, nullptr);
    }
    if (updated_acl != nullptr) LocalFree(updated_acl);
    if (descriptor != nullptr) LocalFree(descriptor);
    return applied == ERROR_SUCCESS;
}

bool add_restricted_attributes(AttributeListHolder& attributes, DWORD count, HANDLE inherited_handle) noexcept {
    SIZE_T attribute_size = 0U;
    InitializeProcThreadAttributeList(nullptr, count, 0, &attribute_size);
    attributes.list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_size));
    if (attributes.list == nullptr ||
        InitializeProcThreadAttributeList(attributes.list, count, 0, &attribute_size) == FALSE) return false;
    DWORD64 mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
                                PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
                                PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    if (UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                  &mitigation_policy, sizeof(mitigation_policy), nullptr, nullptr) == FALSE) return false;
    return inherited_handle == INVALID_HANDLE_VALUE ||
           UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                     &inherited_handle, sizeof(inherited_handle), nullptr, nullptr) != FALSE;
}

std::wstring owned(std::wstring_view value) {
    return std::wstring(value.data(), value.size());
}

HRESULT obtain_parser_sid(SidHolder& sid) {
    constexpr auto profile_name = L"AIShieldShadowParser";
    HRESULT result = CreateAppContainerProfile(profile_name, L"AI Shield Shadow Parser",
                                               L"AI Shield isolated parser profile", nullptr, 0, &sid.sid);
    if (result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        result = DeriveAppContainerSidFromAppContainerName(profile_name, &sid.sid);
    return result;
}

}  // namespace

ai_shield::Result<std::wstring> parser_profile_sid() {
    SidHolder sid{};
    if (FAILED(obtain_parser_sid(sid)) || sid.sid == nullptr) return ai_shield::Status::integrity_failure;
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid.sid, &text) || text == nullptr) return ai_shield::Status::integrity_failure;
    std::wstring result(text);
    LocalFree(text);
    return result;
}

ai_shield::Result<void> validate_launch_spec(const AppContainerLaunchSpec& spec) noexcept {
    if (spec.analysis_id == 0U || spec.parser_id == 0U || spec.executable_path.empty() ||
        spec.work_directory.empty()) {
        return ai_shield::Status::invalid_argument;
    }
    if (spec.allow_network || spec.allow_child_processes) {
        return ai_shield::Status::invalid_state_transition;
    }
    if (spec.budget.memory_bytes == 0U || spec.budget.wall_time_ns == 0U || spec.budget.max_processes == 0U) {
        return ai_shield::Status::out_of_budget;
    }
    return {};
}

ai_shield::Result<LaunchedProcess> launch_shadow_parser(const AppContainerLaunchSpec& spec) noexcept {
    const auto valid = validate_launch_spec(spec);
    if (!valid.ok()) {
        return valid.status();
    }

    SidHolder sid{};
    const HRESULT profile_result = obtain_parser_sid(sid);
    if (FAILED(profile_result) || sid.sid == nullptr) {
        return ai_shield::Status::integrity_failure;
    }

    SECURITY_CAPABILITIES capabilities{};
    capabilities.AppContainerSid = sid.sid;
    capabilities.Capabilities = nullptr;
    capabilities.CapabilityCount = 0;
    capabilities.Reserved = 0;

    if (!inheritable_handle(spec.inherited_handle)) return ai_shield::Status::integrity_failure;
    const DWORD attribute_count = spec.inherited_handle != INVALID_HANDLE_VALUE ? 3U : 2U;
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, attribute_count, 0, &attribute_size);
    AttributeListHolder attributes{};
    attributes.list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_size));
    if (attributes.list == nullptr) {
        return ai_shield::Status::out_of_budget;
    }
    if (InitializeProcThreadAttributeList(attributes.list, attribute_count, 0, &attribute_size) == FALSE) {
        return ai_shield::Status::integrity_failure;
    }
    if (UpdateProcThreadAttribute(attributes.list,
                                  0,
                                  PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                  &capabilities,
                                  sizeof(capabilities),
                                  nullptr,
                                  nullptr) == FALSE) {
        return ai_shield::Status::integrity_failure;
    }
    if (spec.inherited_handle != INVALID_HANDLE_VALUE &&
        UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  const_cast<HANDLE*>(&spec.inherited_handle), sizeof(spec.inherited_handle),
                                  nullptr, nullptr) == FALSE) {
        return ai_shield::Status::integrity_failure;
    }
    DWORD64 mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
                                PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
                                PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
                                PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    if (UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                  &mitigation_policy, sizeof(mitigation_policy), nullptr, nullptr) == FALSE) {
        return ai_shield::Status::integrity_failure;
    }

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes.list;

    PROCESS_INFORMATION info{};
    auto command_line = owned(spec.command_line.empty() ? spec.executable_path : spec.command_line);
    const auto working_directory = owned(spec.work_directory);
    std::vector<wchar_t> environment;
    if (!spec.result_pipe_name.empty()) {
        constexpr std::wstring_view prefix = L"AI_SHIELD_RESULT_PIPE=";
        environment.insert(environment.end(), prefix.begin(), prefix.end());
        environment.insert(environment.end(), spec.result_pipe_name.begin(), spec.result_pipe_name.end());
        environment.push_back(L'\0');
        environment.push_back(L'\0');
    }
    const BOOL created = CreateProcessW(nullptr,
                                        command_line.data(),
                                        nullptr,
                                        nullptr,
                                        spec.inherited_handle != INVALID_HANDLE_VALUE,
                                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                                            (environment.empty() ? 0U : CREATE_UNICODE_ENVIRONMENT),
                                        environment.empty() ? nullptr : environment.data(),
                                        working_directory.c_str(),
                                        &startup.StartupInfo,
                                        &info);
    if (created == FALSE) {
        return ai_shield::Status::integrity_failure;
    }

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        TerminateProcess(info.hProcess, 1U);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return ai_shield::Status::integrity_failure;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                               JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                                               JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                               JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = spec.budget.max_processes;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(spec.budget.memory_bytes);
    if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) == FALSE ||
        AssignProcessToJobObject(job, info.hProcess) == FALSE) {
        TerminateProcess(info.hProcess, 1U);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        CloseHandle(job);
        return ai_shield::Status::integrity_failure;
    }

    return LaunchedProcess{.process = info.hProcess, .thread = info.hThread, .job = job,
                           .window_station = nullptr, .desktop = nullptr,
                           .process_id = info.dwProcessId};
}

ai_shield::Result<LaunchedProcess> launch_restricted_parser(const AppContainerLaunchSpec& spec) noexcept {
    const auto valid = validate_launch_spec(spec);
    if (!valid.ok()) return valid.status();
    if (!inheritable_handle(spec.inherited_handle)) return ai_shield::Status::integrity_failure;
    HANDLE process_token = nullptr;
    HANDLE restricted_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                          &process_token)) return ai_shield::Status::integrity_failure;
    DWORD user_size = 0U;
    GetTokenInformation(process_token, TokenUser, nullptr, 0U, &user_size);
    std::vector<std::byte> user_storage(user_size);
    if (user_size == 0U || !GetTokenInformation(process_token, TokenUser, user_storage.data(), user_size, &user_size)) {
        CloseHandle(process_token);
        return ai_shield::Status::integrity_failure;
    }
    const auto* token_user = reinterpret_cast<const TOKEN_USER*>(user_storage.data());
    std::array<std::array<std::byte, SECURITY_MAX_SID_SIZE>, 5> disabled_storage{};
    std::array<SID_AND_ATTRIBUTES, 5> disabled_sids{};
    const std::array<WELL_KNOWN_SID_TYPE, 5> disabled_types{
        WinBuiltinAdministratorsSid, WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid, WinServiceSid};
    DWORD groups_size = 0U;
    GetTokenInformation(process_token, TokenGroups, nullptr, 0U, &groups_size);
    std::vector<std::byte> groups_storage(groups_size);
    if (groups_size == 0U ||
        !GetTokenInformation(process_token, TokenGroups, groups_storage.data(), groups_size, &groups_size)) {
        CloseHandle(process_token);
        return ai_shield::Status::integrity_failure;
    }
    const auto* token_groups = reinterpret_cast<const TOKEN_GROUPS*>(groups_storage.data());
    DWORD disabled_count = 0U;
    for (std::size_t i = 0; i < disabled_types.size(); ++i) {
        DWORD sid_size = SECURITY_MAX_SID_SIZE;
        if (CreateWellKnownSid(disabled_types[i], nullptr, disabled_storage[i].data(), &sid_size)) {
            for (DWORD group = 0U; group < token_groups->GroupCount; ++group) {
                if (EqualSid(disabled_storage[i].data(), token_groups->Groups[group].Sid)) {
                    disabled_sids[disabled_count++].Sid = token_groups->Groups[group].Sid;
                    break;
                }
            }
        }
    }
    std::array<std::byte, SECURITY_MAX_SID_SIZE> restricted_storage{};
    DWORD restricted_size = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinRestrictedCodeSid, nullptr, restricted_storage.data(), &restricted_size)) {
        CloseHandle(process_token);
        return ai_shield::Status::integrity_failure;
    }
    SID_AND_ATTRIBUTES restricting_sid{restricted_storage.data(), 0U};
    const bool restricted = CreateRestrictedToken(process_token, DISABLE_MAX_PRIVILEGE, disabled_count,
                                                   disabled_sids.data(), 0U, nullptr, 1U, &restricting_sid,
                                                   &restricted_token) != FALSE;
    CloseHandle(process_token);
    if (!restricted) {
        std::fwprintf(stderr, L"restricted parser token creation failed error=%lu\n", GetLastError());
        return ai_shield::Status::integrity_failure;
    }
    PSID low_sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-4096", &low_sid)) { CloseHandle(restricted_token); return ai_shield::Status::integrity_failure; }
    TOKEN_MANDATORY_LABEL label{};
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = low_sid;
    const DWORD label_size = sizeof(label) + GetLengthSid(low_sid);
    if (!SetTokenInformation(restricted_token, TokenIntegrityLevel, &label, label_size)) {
        std::fwprintf(stderr, L"restricted parser integrity label failed error=%lu\n", GetLastError());
        LocalFree(low_sid); CloseHandle(restricted_token); return ai_shield::Status::integrity_failure;
    }
    LocalFree(low_sid);
    std::array<std::byte, SECURITY_MAX_SID_SIZE> system_storage{};
    DWORD system_size = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_storage.data(), &system_size)) {
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    std::array<EXPLICIT_ACCESSW, 3> access{};
    for (auto& entry : access) {
        entry.grfAccessPermissions = GENERIC_ALL;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    }
    access[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_storage.data());
    access[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    access[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(restricted_storage.data());
    access[2].Trustee.TrusteeType = TRUSTEE_IS_USER;
    access[2].Trustee.ptstrName = static_cast<LPWSTR>(token_user->User.Sid);
    LocalAclHolder acl{};
    if (SetEntriesInAclW(static_cast<ULONG>(access.size()), access.data(), nullptr, &acl.acl) != ERROR_SUCCESS) {
        std::fwprintf(stderr, L"restricted parser ACL creation failed error=%lu\n", GetLastError());
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    TOKEN_DEFAULT_DACL default_dacl{acl.acl};
    if (!SetTokenInformation(restricted_token, TokenDefaultDacl, &default_dacl, sizeof(default_dacl))) {
        std::fwprintf(stderr, L"restricted parser default DACL failed error=%lu\n", GetLastError());
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl.acl, FALSE)) {
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    SECURITY_ATTRIBUTES desktop_security{sizeof(desktop_security), &descriptor, FALSE};
    const std::wstring desktop_name = L"AIShieldParser-" + std::to_wstring(spec.analysis_id);
    HWINSTA station = GetProcessWindowStation();
    if (station == nullptr || !grant_restricted_station_access(station, restricted_storage.data())) {
        std::fwprintf(stderr, L"restricted parser window station ACL failed error=%lu\n", GetLastError());
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    HDESK desktop = CreateDesktopW(desktop_name.c_str(), nullptr, nullptr, 0U, GENERIC_ALL,
                                   &desktop_security);
    if (desktop == nullptr) {
        std::fwprintf(stderr, L"restricted parser desktop creation failed error=%lu\n", GetLastError());
        CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    auto command_line = owned(spec.command_line.empty() ? spec.executable_path : spec.command_line);
    const auto working_directory = owned(spec.work_directory);
    AttributeListHolder attributes{};
    const DWORD attribute_count = spec.inherited_handle != INVALID_HANDLE_VALUE ? 2U : 1U;
    if (!add_restricted_attributes(attributes, attribute_count, spec.inherited_handle)) {
        std::fwprintf(stderr, L"restricted parser attribute setup failed error=%lu\n", GetLastError());
        CloseDesktop(desktop); CloseHandle(restricted_token);
        return ai_shield::Status::integrity_failure;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.lpDesktop = const_cast<LPWSTR>(desktop_name.c_str());
    startup.lpAttributeList = attributes.list;
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessAsUserW(restricted_token, owned(spec.executable_path).c_str(), command_line.data(),
        nullptr, nullptr, spec.inherited_handle != INVALID_HANDLE_VALUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, working_directory.c_str(), &startup.StartupInfo, &info);
    CloseHandle(restricted_token);
    if (!created) {
        const DWORD create_error = GetLastError();
        std::fwprintf(stderr, L"restricted parser process creation failed error=%lu\n", create_error);
        CloseDesktop(desktop); SetLastError(create_error);
        return ai_shield::Status::integrity_failure;
    }
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) { TerminateProcess(info.hProcess, 1U); CloseHandle(info.hThread); CloseHandle(info.hProcess); CloseDesktop(desktop); return ai_shield::Status::integrity_failure; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = spec.budget.max_processes;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(spec.budget.memory_bytes);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job, info.hProcess)) {
        TerminateProcess(info.hProcess, 1U); CloseHandle(info.hThread); CloseHandle(info.hProcess); CloseHandle(job);
        CloseDesktop(desktop);
        return ai_shield::Status::integrity_failure;
    }
    return LaunchedProcess{.process = info.hProcess, .thread = info.hThread, .job = job,
                           .window_station = nullptr, .desktop = desktop,
                           .process_id = info.dwProcessId};
}

ai_shield::Result<void> resume_launched_process(LaunchedProcess& process) noexcept {
    if (process.process == nullptr || process.thread == nullptr || process.job == nullptr)
        return ai_shield::Status::invalid_state_transition;
    if (ResumeThread(process.thread) == static_cast<DWORD>(-1)) return ai_shield::Status::integrity_failure;
    return {};
}

void close_launched_process(LaunchedProcess& process) noexcept {
    if (process.thread != nullptr) {
        CloseHandle(process.thread);
        process.thread = nullptr;
    }
    if (process.process != nullptr) {
        TerminateProcess(process.process, 1);
        CloseHandle(process.process);
        process.process = nullptr;
    }
    if (process.job != nullptr) {
        CloseHandle(process.job);
        process.job = nullptr;
    }
    if (process.desktop != nullptr) {
        CloseDesktop(process.desktop);
        process.desktop = nullptr;
    }
    if (process.window_station != nullptr) {
        CloseWindowStation(process.window_station);
        process.window_station = nullptr;
    }
    process.process_id = 0;
}

}  // namespace ai_shield::platform::windows::sandbox
