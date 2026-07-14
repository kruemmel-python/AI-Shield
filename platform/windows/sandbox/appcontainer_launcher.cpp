#include "platform/windows/sandbox/appcontainer_launcher.hpp"

#include <string>
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

    const DWORD attribute_count = spec.inherited_handle != INVALID_HANDLE_VALUE ? 2U : 1U;
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, attribute_count, 0, &attribute_size);
    AttributeListHolder attributes{};
    attributes.list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attribute_size));
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
                           .process_id = info.dwProcessId};
}

ai_shield::Result<LaunchedProcess> launch_restricted_parser(const AppContainerLaunchSpec& spec) noexcept {
    const auto valid = validate_launch_spec(spec);
    if (!valid.ok()) return valid.status();
    HANDLE process_token = nullptr;
    HANDLE restricted_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                          &process_token)) return ai_shield::Status::integrity_failure;
    const bool restricted = CreateRestrictedToken(process_token, DISABLE_MAX_PRIVILEGE, 0U, nullptr, 0U, nullptr,
                                                   0U, nullptr, &restricted_token) != FALSE;
    CloseHandle(process_token);
    if (!restricted) return ai_shield::Status::integrity_failure;
    PSID low_sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-4096", &low_sid)) { CloseHandle(restricted_token); return ai_shield::Status::integrity_failure; }
    TOKEN_MANDATORY_LABEL label{};
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = low_sid;
    const DWORD label_size = sizeof(label) + GetLengthSid(low_sid);
    if (!SetTokenInformation(restricted_token, TokenIntegrityLevel, &label, label_size)) {
        LocalFree(low_sid); CloseHandle(restricted_token); return ai_shield::Status::integrity_failure;
    }
    LocalFree(low_sid);
    auto command_line = owned(spec.command_line.empty() ? spec.executable_path : spec.command_line);
    const auto working_directory = owned(spec.work_directory);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessAsUserW(restricted_token, owned(spec.executable_path).c_str(), command_line.data(),
        nullptr, nullptr, spec.inherited_handle != INVALID_HANDLE_VALUE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, working_directory.c_str(), &startup, &info);
    CloseHandle(restricted_token);
    if (!created) return ai_shield::Status::integrity_failure;
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) { TerminateProcess(info.hProcess, 1U); CloseHandle(info.hThread); CloseHandle(info.hProcess); return ai_shield::Status::integrity_failure; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = spec.budget.max_processes;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(spec.budget.memory_bytes);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job, info.hProcess)) {
        TerminateProcess(info.hProcess, 1U); CloseHandle(info.hThread); CloseHandle(info.hProcess); CloseHandle(job);
        return ai_shield::Status::integrity_failure;
    }
    return LaunchedProcess{.process = info.hProcess, .thread = info.hThread, .job = job, .process_id = info.dwProcessId};
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
    process.process_id = 0;
}

}  // namespace ai_shield::platform::windows::sandbox
