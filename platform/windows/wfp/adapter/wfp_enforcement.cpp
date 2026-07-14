#include "platform/windows/wfp/adapter/wfp_enforcement.hpp"

namespace ai_shield::platform::windows::wfp {

FastPolicyDecision decide_fast_path(const FastPolicyInput& input) noexcept {
    if (input.known_blocked_source) {
        return FastPolicyDecision{.action = KernelAction::block,
                                  .fallback_action = ai_shield::abi::ShieldAction::block_origin,
                                  .reason_mask = ai_shield::abi::ReasonCode::campaign_correlation};
    }
    if (input.admission.action == ai_shield::abi::ShieldAction::drop_flow) {
        return FastPolicyDecision{.action = KernelAction::block,
                                  .fallback_action = ai_shield::abi::ShieldAction::drop_flow,
                                  .reason_mask = input.admission.reason_mask};
    }
    if (!input.broker_available || !input.pending_capacity_available) {
        const auto fallback = ai_shield::fail_policy::decide(input.service_class,
                                                             ai_shield::fail_policy::FailureKind::core,
                                                             100);
        return FastPolicyDecision{.action = fallback.action == ai_shield::abi::ShieldAction::allow_monitored
                                                ? KernelAction::allow
                                                : KernelAction::block,
                                  .fallback_action = fallback.action,
                                  .reason_mask = fallback.reason_mask};
    }
    return FastPolicyDecision{.action = KernelAction::pend,
                              .fallback_action = ai_shield::abi::ShieldAction::drop_flow,
                              .reason_mask = 0};
}

}  // namespace ai_shield::platform::windows::wfp
