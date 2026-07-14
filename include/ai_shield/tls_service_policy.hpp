#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"
#include "ai_shield/service_identity.hpp"
#include "ai_shield/service_registry.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::tls_service {

struct ManagedEndpoint final {
    std::uint64_t service_id = 0;
    service_registry::ServicePolicy policy{};
    crypto::Sha256Digest spki_sha256{};
    bool administrator_provided_certificate = false;
};

[[nodiscard]] Result<void> authorize_managed_endpoint(const ManagedEndpoint& endpoint,
                                                      const service_identity::PinStore& pins) noexcept;

}  // namespace ai_shield::tls_service
