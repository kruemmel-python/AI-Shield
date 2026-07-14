#include "ai_shield/policy.hpp"

#include <algorithm>

#include "ai_shield/risk.hpp"

namespace ai_shield::policy {

DecisionBand band_for_score(std::uint16_t risk_score) noexcept {
    if (risk_score >= 150U) {
        return DecisionBand::block_origin;
    }
    if (risk_score >= 100U) {
        return DecisionBand::quarantine_or_drop;
    }
    if (risk_score >= 75U) {
        return DecisionBand::redirect_sandbox;
    }
    if (risk_score >= 50U) {
        return DecisionBand::deep_inspection;
    }
    if (risk_score >= 25U) {
        return DecisionBand::allow_monitored;
    }
    return DecisionBand::allow;
}

abi::ShieldDecision decide(const PolicyContext& context,
                           const detection::Evidence& evidence,
                           const crypto::Sha256Digest& evidence_hash) noexcept {
    abi::ShieldDecision decision{};
    decision.abi_version = abi::kAbiVersion;
    decision.structure_size = sizeof(abi::ShieldDecision);
    decision.decision_id = context.decision_id;
    decision.flow_id = context.flow_id;
    const auto risk_score = risk::score(evidence);
    decision.risk_score = risk_score.total;
    decision.confidence = evidence.reason_mask == 0U ? 70U : 95U;
    decision.reason_mask = evidence.reason_mask;
    decision.valid_until_monotonic_ns = context.now_monotonic_ns + 5'000'000'000ULL;
    decision.evidence_hash = evidence_hash;

    const bool inconclusive = (evidence.reason_mask & abi::ReasonCode::sandbox_inconclusive) != 0U;

    if ((evidence.reason_mask & (abi::ReasonCode::policy_signature_invalid | abi::ReasonCode::model_signature_invalid |
                                 abi::ReasonCode::abi_violation)) != 0U) {
        decision.action = abi::ShieldAction::block_origin;
    } else if (risk_score.hard_block) {
        decision.action = abi::ShieldAction::quarantine;
    } else if (inconclusive && context.critical_service) {
        decision.action = abi::ShieldAction::quarantine;
    } else if (inconclusive && context.runtime_gate_active) {
        decision.action = abi::ShieldAction::allow_monitored;
    } else {
        switch (band_for_score(decision.risk_score)) {
            case DecisionBand::allow:
                decision.action = abi::ShieldAction::allow;
                break;
            case DecisionBand::allow_monitored:
                decision.action = abi::ShieldAction::allow_monitored;
                break;
            case DecisionBand::deep_inspection:
                decision.action = context.mode == ProtectionMode::strict ? abi::ShieldAction::redirect_sandbox
                                                                         : abi::ShieldAction::rate_limit;
                break;
            case DecisionBand::redirect_sandbox:
                decision.action = abi::ShieldAction::redirect_sandbox;
                break;
            case DecisionBand::quarantine_or_drop:
                decision.action = context.critical_service ? abi::ShieldAction::quarantine : abi::ShieldAction::drop_flow;
                break;
            case DecisionBand::block_origin:
                decision.action = abi::ShieldAction::block_origin;
                break;
        }
    }
    return decision;
}

}  // namespace ai_shield::policy
