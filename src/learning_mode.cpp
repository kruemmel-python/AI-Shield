#include "ai_shield/learning_mode.hpp"

namespace ai_shield::learning {

DecisionOverride apply(LearningWindow window, std::uint32_t reason_mask, std::uint16_t risk_score) noexcept {
    const bool expired = window.now_monotonic_ns < window.started_monotonic_ns ||
                         (window.now_monotonic_ns - window.started_monotonic_ns) > kMaxLearningDurationNs;
    if (!window.enabled || window.mode == LearningMode::disabled || window.mode == LearningMode::offline_validation || expired) {
        return DecisionOverride{.action = abi::ShieldAction::allow_monitored,
                                .hard_rules_remain_active = true,
                                .expired = expired};
    }
    constexpr std::uint32_t hard_reasons = abi::ReasonCode::signature_match | abi::ReasonCode::command_execution |
                                           abi::ReasonCode::sandbox_escape_signal |
                                           abi::ReasonCode::policy_signature_invalid |
                                           abi::ReasonCode::model_signature_invalid |
                                           abi::ReasonCode::executable_format_anomaly |
                                           abi::ReasonCode::document_active_content;
    if ((reason_mask & hard_reasons) != 0U || risk_score >= 100U) {
        return DecisionOverride{.action = abi::ShieldAction::quarantine,
                                .hard_rules_remain_active = true,
                                .expired = false};
    }
    return DecisionOverride{.action = abi::ShieldAction::allow_monitored,
                            .hard_rules_remain_active = true,
                            .expired = false};
}

}  // namespace ai_shield::learning
