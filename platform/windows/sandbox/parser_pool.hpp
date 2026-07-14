#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

#include "ai_shield/result.hpp"
#include "platform/windows/sandbox/appcontainer_launcher.hpp"

namespace ai_shield::platform::windows::sandbox {

struct WorkerTicket final {
    std::uint64_t analysis_id = 0;
    std::wstring result_pipe_name;
};

struct WorkerResult final {
    std::uint64_t analysis_id = 0;
    std::uint32_t exit_code = 0;
    std::vector<std::byte> payload;
    bool deadline_exceeded = false;
};

class ParserPool final {
public:
    explicit ParserPool(std::uint32_t capacity);
    ~ParserPool();
    [[nodiscard]] Result<WorkerTicket> start(const AppContainerLaunchSpec& spec);
    [[nodiscard]] Result<WorkerResult> collect(std::uint64_t analysis_id, std::uint32_t wait_ms);
    void enforce_deadlines();
    [[nodiscard]] std::size_t active_workers() const noexcept;

private:
    struct Worker;
    std::uint32_t capacity_;
    std::vector<Worker> workers_;
};

}  // namespace ai_shield::platform::windows::sandbox
