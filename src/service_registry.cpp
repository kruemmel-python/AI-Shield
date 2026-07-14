#include "ai_shield/service_registry.hpp"

namespace ai_shield::service_registry {

Result<void> Registry::register_service(ServicePolicy policy) {
    if (policy.port_be == 0U || policy.max_payload_bytes == 0U) {
        return Status::invalid_argument;
    }
    for (auto& existing : policies_) {
        if (existing.port_be == policy.port_be && existing.transport == policy.transport) {
            existing = policy;
            return {};
        }
    }
    policies_.push_back(policy);
    return {};
}

Admission Registry::admit(Transport transport, std::uint16_t port_be) const noexcept {
    for (const auto& policy : policies_) {
        if (policy.transport == transport && policy.port_be == port_be && policy.externally_reachable) {
            return Admission{abi::ShieldAction::allow_monitored, 0U, policy};
        }
    }
    return Admission{abi::ShieldAction::drop_flow, abi::ReasonCode::unregistered_service, ServicePolicy{}};
}

}  // namespace ai_shield::service_registry
