#include "ai_shield/egress_gate.hpp"

namespace ai_shield::egress {

Decision decide(Request request, std::span<const Rule> rules) noexcept {
    for (const auto& rule : rules) {
        if (rule.service_id == request.service_id && rule.destination_ipv4_be == request.destination_ipv4_be &&
            rule.destination_port_be == request.destination_port_be) {
            return Decision{.action = abi::ShieldAction::allow, .reason_mask = 0};
        }
    }
    if (request.externally_influenced) {
        return Decision{.action = abi::ShieldAction::drop_flow,
                        .reason_mask = abi::ReasonCode::consequence_detected};
    }
    return Decision{.action = abi::ShieldAction::allow_monitored,
                    .reason_mask = abi::ReasonCode::degraded_mode};
}

}  // namespace ai_shield::egress
