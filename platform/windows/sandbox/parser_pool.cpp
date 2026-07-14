#include "platform/windows/sandbox/parser_pool.hpp"

#include <sddl.h>
#include <objbase.h>

#include <array>
#include <limits>

namespace ai_shield::platform::windows::sandbox {

struct ParserPool::Worker final {
    std::uint64_t analysis_id = 0;
    LaunchedProcess process{};
    HANDLE pipe = INVALID_HANDLE_VALUE;
    std::wstring pipe_name;
    std::chrono::steady_clock::time_point deadline{};
    bool deadline_exceeded = false;
};

namespace {

std::wstring make_pipe_name(std::uint64_t analysis_id) {
    GUID value{};
    if (CoCreateGuid(&value) != S_OK) return {};
    std::array<wchar_t, 40> guid{};
    if (StringFromGUID2(value, guid.data(), static_cast<int>(guid.size())) == 0) return {};
    return L"\\\\.\\pipe\\AIShield.Parser." + std::to_wstring(analysis_id) + L"." + guid.data();
}

HANDLE create_result_pipe(const std::wstring& name) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, nullptr)) return INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT |
                                       PIPE_REJECT_REMOTE_CLIENTS,
                                   1U, 0U, 64U * 1024U, 0U, &attributes);
    LocalFree(descriptor);
    return pipe;
}

}  // namespace

ParserPool::ParserPool(std::uint32_t capacity) : capacity_(capacity) { workers_.reserve(capacity); }

ParserPool::~ParserPool() {
    for (auto& worker : workers_) {
        if (worker.pipe != INVALID_HANDLE_VALUE) CloseHandle(worker.pipe);
        close_launched_process(worker.process);
    }
}

Result<WorkerTicket> ParserPool::start(const AppContainerLaunchSpec& spec) {
    enforce_deadlines();
    if (capacity_ == 0U || workers_.size() >= capacity_) return Status::out_of_budget;
    for (const auto& worker : workers_) if (worker.analysis_id == spec.analysis_id) return Status::invalid_state_transition;
    const auto pipe_name = make_pipe_name(spec.analysis_id);
    if (pipe_name.empty()) return Status::integrity_failure;
    HANDLE pipe = create_result_pipe(pipe_name);
    if (pipe == INVALID_HANDLE_VALUE) return Status::integrity_failure;
    auto launch_spec = spec;
    launch_spec.result_pipe_name = pipe_name;
    auto launched = launch_shadow_parser(launch_spec);
    if (!launched.ok()) { CloseHandle(pipe); return launched.status(); }
    const auto resumed = resume_launched_process(launched.value());
    if (!resumed.ok()) {
        close_launched_process(launched.value());
        CloseHandle(pipe);
        return resumed.status();
    }
    const auto duration = std::chrono::nanoseconds(spec.budget.wall_time_ns);
    workers_.push_back(Worker{spec.analysis_id, launched.value(), pipe, pipe_name,
                              std::chrono::steady_clock::now() + duration, false});
    return WorkerTicket{spec.analysis_id, pipe_name};
}

Result<WorkerResult> ParserPool::collect(std::uint64_t analysis_id, std::uint32_t wait_ms) {
    for (auto iterator = workers_.begin(); iterator != workers_.end(); ++iterator) {
        if (iterator->analysis_id != analysis_id) continue;
        const DWORD wait = WaitForSingleObject(iterator->process.process, wait_ms);
        if (wait == WAIT_TIMEOUT) { enforce_deadlines(); return Status::out_of_budget; }
        if (wait != WAIT_OBJECT_0) return Status::integrity_failure;
        DWORD exit_code = 0;
        if (!GetExitCodeProcess(iterator->process.process, &exit_code)) return Status::integrity_failure;
        std::vector<std::byte> payload;
        if (ConnectNamedPipe(iterator->pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::array<std::byte, 64U * 1024U> buffer{};
            DWORD read = 0;
            if (ReadFile(iterator->pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
                payload.assign(buffer.begin(), buffer.begin() + read);
        }
        WorkerResult result{analysis_id, exit_code, std::move(payload), iterator->deadline_exceeded};
        CloseHandle(iterator->pipe);
        close_launched_process(iterator->process);
        workers_.erase(iterator);
        return result;
    }
    return Status::not_found;
}

void ParserPool::enforce_deadlines() {
    const auto now = std::chrono::steady_clock::now();
    for (auto& worker : workers_) {
        if (!worker.deadline_exceeded && now >= worker.deadline) {
            TerminateProcess(worker.process.process, ERROR_TIMEOUT);
            worker.deadline_exceeded = true;
        }
    }
}

std::size_t ParserPool::active_workers() const noexcept { return workers_.size(); }

}  // namespace ai_shield::platform::windows::sandbox
