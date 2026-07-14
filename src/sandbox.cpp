#include "ai_shield/sandbox.hpp"

namespace ai_shield::sandbox {

detection::Evidence evidence_from(const ResultSummary& summary) noexcept {
    detection::Evidence evidence{};
    switch (summary.outcome) {
        case Outcome::clean:
            break;
        case Outcome::suspicious:
            evidence.consequence = 60;
            evidence.reason_mask |= abi::ReasonCode::consequence_detected;
            break;
        case Outcome::exploit_signal:
            evidence.hard_rule = 100;
            evidence.consequence = 100;
            evidence.reason_mask |= abi::ReasonCode::sandbox_escape_signal | abi::ReasonCode::consequence_detected;
            break;
        case Outcome::timeout:
        case Outcome::crash:
        case Outcome::instrumentation_gap:
            evidence.reason_mask |= abi::ReasonCode::sandbox_inconclusive;
            evidence.sensor_integrity = 60;
            break;
    }
    if (summary.attempted_network || summary.attempted_host_profile || summary.created_executable) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 50U);
        evidence.reason_mask |= abi::ReasonCode::consequence_detected;
    }
    if (summary.event_count > 10'000U) {
        evidence.novelty = 30;
    }
    return evidence;
}

}  // namespace ai_shield::sandbox
