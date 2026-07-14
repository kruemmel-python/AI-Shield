#pragma once

#include <cstdint>

#include "ai_shield/diagnostics.hpp"
#include "ai_shield/incident_package.hpp"
#include "ai_shield/privacy.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::support {

struct SupportManifest final {
    std::uint64_t package_id = 0;
    crypto::Sha256Digest diagnostics_hash{};
    crypto::Sha256Digest incident_hash{};
    std::uint32_t reason_mask = 0;
    bool payload_redacted = true;
};

[[nodiscard]] SupportManifest build_manifest(std::uint64_t package_id,
                                             const diagnostics::Snapshot& snapshot,
                                             const incident::Package& incident_package) noexcept;

}  // namespace ai_shield::support
