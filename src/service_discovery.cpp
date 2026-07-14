#include "ai_shield/service_discovery.hpp"

namespace ai_shield::service_discovery {

Result<service_registry::ServicePolicy> propose(ObservedListener listener) noexcept {
    if (listener.port_be == 0U || listener.protocol_id == 0U) {
        return Status::invalid_argument;
    }

    return service_registry::ServicePolicy{.port_be = listener.port_be,
                                           .transport = listener.transport,
                                           .protocol_id = listener.protocol_id,
                                           .externally_reachable = listener.externally_reachable,
                                           .critical_service = true,
                                           .fail_policy = service_registry::FailPolicy::fail_closed,
                                           .max_payload_bytes = 64U * 1024U};
}

Result<void> confirm(service_registry::Registry& registry, service_registry::ServicePolicy policy) noexcept {
    return registry.register_service(policy);
}

}  // namespace ai_shield::service_discovery
