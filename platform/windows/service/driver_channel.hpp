#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/abi_validation.hpp"
#include "ai_shield/pending_decision.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::platform::windows::service {

struct ChannelLimits final {
    std::uint64_t max_clock_skew_ns = 1'000'000'000ULL;
    std::uint64_t decision_budget_ns = 250'000'000ULL;
};

struct DriverChannelState final {
    std::uint64_t next_sequence = 1;
    std::uint64_t now_monotonic_ns = 0;
    ChannelLimits limits{};
};

[[nodiscard]] ai_shield::Result<void> accept_flow_event(DriverChannelState& state,
                                                       const ai_shield::abi::FlowEvent& event) noexcept;
[[nodiscard]] ai_shield::Result<ai_shield::pending::Completion> complete_pending(
    ai_shield::pending::Manager& pending,
    std::uint64_t flow_id,
    ai_shield::abi::ShieldAction action,
    std::uint64_t now_monotonic_ns) noexcept;

}  // namespace ai_shield::platform::windows::service
