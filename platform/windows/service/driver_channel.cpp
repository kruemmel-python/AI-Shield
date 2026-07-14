#include "platform/windows/service/driver_channel.hpp"

namespace ai_shield::platform::windows::service {

ai_shield::Result<void> accept_flow_event(DriverChannelState& state,
                                         const ai_shield::abi::FlowEvent& event) noexcept {
    const auto valid = ai_shield::abi_validation::validate_flow_event(
        event,
        ai_shield::abi_validation::ValidationContext{.expected_next_sequence = state.next_sequence,
                                                     .now_monotonic_ns = state.now_monotonic_ns,
                                                     .max_clock_skew_ns = state.limits.max_clock_skew_ns,
                                                     .known_flow_id = 0});
    if (!valid.ok()) {
        return valid.status();
    }
    if (event.sequence != state.next_sequence) {
        return ai_shield::Status::integrity_failure;
    }
    ++state.next_sequence;
    return {};
}

ai_shield::Result<ai_shield::pending::Completion> complete_pending(ai_shield::pending::Manager& pending,
                                                                   std::uint64_t flow_id,
                                                                   ai_shield::abi::ShieldAction action,
                                                                   std::uint64_t now_monotonic_ns) noexcept {
    return pending.complete_at(flow_id, action, now_monotonic_ns);
}

}  // namespace ai_shield::platform::windows::service
