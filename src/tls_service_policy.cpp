#include "ai_shield/tls_service_policy.hpp"

namespace ai_shield::tls_service {

Result<void> authorize_managed_endpoint(const ManagedEndpoint& endpoint,
                                        const service_identity::PinStore& pins) noexcept {
    if (endpoint.service_id == 0U || endpoint.policy.port_be == 0U || !endpoint.policy.externally_reachable) {
        return Status::invalid_argument;
    }
    if (!endpoint.administrator_provided_certificate) {
        return Status::integrity_failure;
    }
    if (!pins.verify(endpoint.service_id, endpoint.spki_sha256)) {
        return Status::integrity_failure;
    }
    return {};
}

}  // namespace ai_shield::tls_service
