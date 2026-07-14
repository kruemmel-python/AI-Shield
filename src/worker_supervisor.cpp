#include "ai_shield/worker_supervisor.hpp"

namespace ai_shield::worker {

Supervisor::Supervisor(std::uint32_t crash_limit, std::uint64_t window_ns) noexcept
    : crash_limit_(crash_limit), window_ns_(window_ns) {}

Supervisor::State& Supervisor::state_for(WorkerKind kind) {
    for (auto& state : states_) {
        if (state.kind == kind) {
            return state;
        }
    }
    states_.push_back(State{.kind = kind});
    return states_.back();
}

detection::Evidence Supervisor::observe(const WorkerReport& report) {
    detection::Evidence evidence{};
    auto& state = state_for(report.kind);
    if (report.event == WorkerEvent::completed) {
        state.crashes = 0;
        state.open = false;
        state.window_start_ns = report.monotonic_ns;
        return evidence;
    }
    if (report.event != WorkerEvent::crashed && report.event != WorkerEvent::timed_out) {
        return evidence;
    }
    if (state.window_start_ns == 0U || report.monotonic_ns - state.window_start_ns > window_ns_) {
        state.window_start_ns = report.monotonic_ns;
        state.crashes = 0;
        state.open = false;
    }
    ++state.crashes;
    evidence.sensor_integrity = 60;
    evidence.reason_mask |= abi::ReasonCode::worker_crash;
    if (state.crashes >= crash_limit_) {
        state.open = true;
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::degraded_mode;
    }
    return evidence;
}

bool Supervisor::circuit_open(WorkerKind kind) const noexcept {
    for (const auto& state : states_) {
        if (state.kind == kind) {
            return state.open;
        }
    }
    return false;
}

}  // namespace ai_shield::worker
