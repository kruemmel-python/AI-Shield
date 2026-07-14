#include "ai_shield/consequence_detector.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::consequence {

detection::Evidence evaluate(RuntimeEvent event) noexcept {
    detection::Evidence evidence{};
    const bool any = event.child_process || event.executable_file_created || event.executable_memory ||
                     event.sensitive_token_access || event.registry_persistence || event.unexpected_egress;
    if (!any) {
        return evidence;
    }
    evidence.consequence = 100;
    evidence.hard_rule = 100;
    evidence.reason_mask = abi::ReasonCode::consequence_detected;
    if (event.child_process || event.executable_file_created || event.executable_memory) {
        evidence.reason_mask |= abi::ReasonCode::command_execution;
    }
    if (event.unexpected_egress) {
        evidence.reason_mask |= abi::ReasonCode::degraded_mode;
    }
    return evidence;
}

}  // namespace ai_shield::consequence
