#include "ai_shield/build_attestation.hpp"

#include <cstddef>
#include <vector>

namespace ai_shield::build {
namespace {

void append_u64(std::vector<std::byte>& out, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        out.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xffU));
    }
}

void append_hash(std::vector<std::byte>& out, const crypto::Sha256Digest& digest) {
    for (const auto byte : digest) {
        out.push_back(byte);
    }
}

}  // namespace

Result<crypto::Sha256Digest> attest(BuildManifest manifest, std::span<const ArtifactHash> artifacts) noexcept {
    if (manifest.build_id == 0U || artifacts.empty() || !manifest.pdbs_archived ||
        !manifest.reproducible_flags_enabled) {
        return Status::invalid_argument;
    }

    std::vector<std::byte> bytes;
    append_u64(bytes, manifest.build_id);
    append_hash(bytes, manifest.compiler_manifest_hash);
    append_hash(bytes, manifest.sdk_manifest_hash);
    append_hash(bytes, manifest.sbom_hash);
    for (const auto& artifact : artifacts) {
        if (artifact.artifact_id == 0U) {
            return Status::invalid_argument;
        }
        append_u64(bytes, artifact.artifact_id);
        append_hash(bytes, artifact.sha256);
    }
    return crypto::sha256(bytes);
}

}  // namespace ai_shield::build
