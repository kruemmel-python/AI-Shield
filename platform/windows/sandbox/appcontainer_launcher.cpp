#include "platform/windows/sandbox/appcontainer_launcher.hpp"

#include <string>
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

}  // namespace

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

    const auto profile_name = L"AIShieldShadowParser";
    SidHolder sid{};
    HRESULT profile_result = CreateAppContainerProfile(profile_name,
                                                       L"AI Shield Shadow Parser",
                                                       L"AI Shield isolated parser profile",
                                                       nullptr,
                                                       0,
                                                       &sid.sid);
    if (profile_result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        profile_result = DeriveAppContainerSidFromAppContainerName(profile_name, &sid.sid);
    }
    if (FAILED(profile_result) || sid.sid == nullptr) {
        return ai_shield::Status::integrity_failure;
    }

    SECURITY_CAPABILITIES capabilities{};
    capabilities.AppContainerSid = sid.sid;
    capabilities.Capabilities = nullptr;
    capabilities.CapabilityCount = 0;
    capabilities.Reserved = 0;

    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    AttributeListHolder attributes{};
    attributes.list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attribute_size));
    if (attributes.list == nullptr) {
        return ai_shield::Status::out_of_budget;
    }
    if (InitializeProcThreadAttributeList(attributes.list, 1, 0, &attribute_size) == FALSE) {
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

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes.list;

    PROCESS_INFORMATION info{};
    auto command_line = owned(spec.executable_path);
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
                                        FALSE,
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
