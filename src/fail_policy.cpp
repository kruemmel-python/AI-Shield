#include "ai_shield/fail_policy.hpp"

namespace ai_shield::fail_policy {

FailureDecision decide(ServiceClass service_class, FailureKind failure, std::uint16_t current_risk) noexcept {
    FailureDecision decision{};
    decision.reason_mask = abi::ReasonCode::degraded_mode;
    if (service_class == ServiceClass::unregistered) {
        decision.action = abi::ShieldAction::block_origin;
        decision.reason_mask |= abi::ReasonCode::unregistered_service;
        return decision;
    }
    if (failure == FailureKind::core) {
        decision.action = service_class == ServiceClass::media_game ? abi::ShieldAction::allow_monitored
                                                                    : abi::ShieldAction::block_origin;
        return decision;
    }
    if (service_class == ServiceClass::admin_management || service_class == ServiceClass::file_download) {
        decision.action = abi::ShieldAction::quarantine;
        return decision;
    }
    if (service_class == ServiceClass::web_api) {
        decision.action = current_risk >= 50U ? abi::ShieldAction::drop_flow : abi::ShieldAction::allow_monitored;
        return decision;
    }
    decision.action = current_risk >= 75U ? abi::ShieldAction::rate_limit : abi::ShieldAction::allow_monitored;
    return decision;
}

}  // namespace ai_shield::fail_policy
