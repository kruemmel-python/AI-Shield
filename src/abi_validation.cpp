#include "ai_shield/abi_validation.hpp"

#include <type_traits>

namespace ai_shield::abi_validation {

namespace {

constexpr std::uint16_t kKnownFlowFlags = 0x0003U;

[[nodiscard]] bool valid_action(abi::ShieldAction action) noexcept {
    switch (action) {
    case abi::ShieldAction::allow:
    case abi::ShieldAction::allow_monitored:
    case abi::ShieldAction::rate_limit:
    case abi::ShieldAction::redirect_sandbox:
    case abi::ShieldAction::quarantine:
    case abi::ShieldAction::drop_flow:
    case abi::ShieldAction::block_origin:
    case abi::ShieldAction::suspend_target:
        return true;
    }
    return false;
}

}  // namespace

static_assert(std::is_standard_layout_v<abi::FlowEvent>);
static_assert(std::is_trivially_copyable_v<abi::FlowEvent>);
static_assert(std::is_standard_layout_v<abi::ShieldDecision>);
static_assert(std::is_trivially_copyable_v<abi::ShieldDecision>);
static_assert(sizeof(abi::FlowEvent) <= 256U);
static_assert(sizeof(abi::ShieldDecision) <= 256U);

Result<void> validate_flow_event_header(std::uint32_t abi_version,
                                        std::uint32_t structure_size,
                                        std::uint16_t flags) noexcept {
    if (abi_version != abi::kAbiVersion) {
        return Status::incompatible_version;
    }
    if (structure_size < sizeof(abi::FlowEvent) || structure_size > sizeof(abi::FlowEvent)) {
        return Status::malformed_input;
    }
    if ((flags & ~kKnownFlowFlags) != 0U) {
        return Status::malformed_input;
    }
    return {};
}

Result<void> validate_flow_event(const abi::FlowEvent& event, ValidationContext context) noexcept {
    const auto header = validate_flow_event_header(event.abi_version, event.structure_size, event.flags);
    if (!header.ok()) {
        return header.status();
    }
    if (event.sequence < context.expected_next_sequence) {
        return Status::integrity_failure;
    }
    if (event.flow_id == 0U || (context.known_flow_id != 0U && event.flow_id != context.known_flow_id)) {
        return Status::not_found;
    }
    if (event.monotonic_ns + context.max_clock_skew_ns < context.now_monotonic_ns) {
        return Status::invalid_state_transition;
    }
    return {};
}

Result<void> validate_shield_decision(const abi::ShieldDecision& decision, ValidationContext context) noexcept {
    if (decision.abi_version != abi::kAbiVersion) {
        return Status::incompatible_version;
    }
    if (decision.structure_size < sizeof(abi::ShieldDecision) || decision.structure_size > sizeof(abi::ShieldDecision)) {
        return Status::malformed_input;
    }
    if (!valid_action(decision.action)) {
        return Status::malformed_input;
    }
    if (decision.flow_id == 0U || (context.known_flow_id != 0U && decision.flow_id != context.known_flow_id)) {
        return Status::not_found;
    }
    if (decision.valid_until_monotonic_ns + context.max_clock_skew_ns < context.now_monotonic_ns) {
        return Status::invalid_state_transition;
    }
    return {};
}

}  // namespace ai_shield::abi_validation
