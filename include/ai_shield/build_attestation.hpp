#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::build {

struct ArtifactHash final {
    std::uint64_t artifact_id = 0;
    crypto::Sha256Digest sha256{};
};

struct BuildManifest final {
    std::uint64_t build_id = 0;
    crypto::Sha256Digest compiler_manifest_hash{};
    crypto::Sha256Digest sdk_manifest_hash{};
    crypto::Sha256Digest sbom_hash{};
    bool pdbs_archived = false;
    bool reproducible_flags_enabled = false;
};

[[nodiscard]] Result<crypto::Sha256Digest> attest(BuildManifest manifest,
                                                  std::span<const ArtifactHash> artifacts) noexcept;

}  // namespace ai_shield::build
