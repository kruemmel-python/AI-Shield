#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::worker {

enum class WorkerKind : std::uint32_t {
    http,
    dns,
    json,
    xml,
    zip,
    pe,
    pdf
};

enum class WorkerEvent : std::uint32_t {
    started,
    completed,
    crashed,
    timed_out
};

struct WorkerReport final {
    WorkerKind kind = WorkerKind::http;
    WorkerEvent event = WorkerEvent::started;
    std::uint64_t worker_id = 0;
    std::uint64_t monotonic_ns = 0;
};

class Supervisor final {
public:
    Supervisor(std::uint32_t crash_limit, std::uint64_t window_ns) noexcept;
    [[nodiscard]] detection::Evidence observe(const WorkerReport& report);
    [[nodiscard]] bool circuit_open(WorkerKind kind) const noexcept;

private:
    struct State final {
        WorkerKind kind = WorkerKind::http;
        std::uint32_t crashes = 0;
        std::uint64_t window_start_ns = 0;
        bool open = false;
    };

    [[nodiscard]] State& state_for(WorkerKind kind);

    std::uint32_t crash_limit_ = 0;
    std::uint64_t window_ns_ = 0;
    std::vector<State> states_;
};

}  // namespace ai_shield::worker
