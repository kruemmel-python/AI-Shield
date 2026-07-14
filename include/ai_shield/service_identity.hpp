#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"
#include "ai_shield/service_registry.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::service_identity {

struct CertificatePin final {
    std::uint64_t service_id = 0;
    crypto::Sha256Digest spki_sha256{};
};

class PinStore final {
public:
    [[nodiscard]] Result<void> add(CertificatePin pin);
    [[nodiscard]] bool verify(std::uint64_t service_id, const crypto::Sha256Digest& presented_spki) const noexcept;

private:
    std::vector<CertificatePin> pins_;
};

}  // namespace ai_shield::service_identity
