#include "ai_shield/backpressure.hpp"

namespace ai_shield::backpressure {

Decision decide(Limits limits, Usage usage) noexcept {
    const bool over_flow = limits.per_flow_bytes != 0U && usage.flow_bytes > limits.per_flow_bytes;
    const bool over_source = limits.per_source_flows != 0U && usage.source_flows > limits.per_source_flows;
    const bool over_service = limits.per_service_flows != 0U && usage.service_flows > limits.per_service_flows;
    const bool over_global = limits.global_flows != 0U && usage.total_flows > limits.global_flows;
    if (over_flow || over_source || over_service || over_global) {
        return Decision{.action = abi::ShieldAction::rate_limit,
                        .reason_mask = abi::ReasonCode::queue_overflow | abi::ReasonCode::rate_limited};
    }
    return Decision{.action = abi::ShieldAction::allow, .reason_mask = 0};
}

}  // namespace ai_shield::backpressure
