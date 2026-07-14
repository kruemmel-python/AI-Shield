#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::package {

enum class PackageKind : std::uint32_t {
    policy,
    model,
    update
};

struct FileEntry final {
    std::string_view path;
    crypto::Sha256Digest sha256{};
};

struct Manifest final {
    PackageKind kind = PackageKind::policy;
    std::uint32_t manifest_version = 1;
    std::uint32_t min_abi_version = abi::kAbiVersion;
    std::uint64_t security_version = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 0;
    std::span<const FileEntry> files;
    crypto::Sha256Digest manifest_digest{};
    crypto::Sha256Digest signature_fingerprint{};
};

struct TrustAnchor final {
    PackageKind kind = PackageKind::policy;
    std::uint64_t current_security_version = 0;
    crypto::Sha256Digest expected_signature_fingerprint{};
};

struct VerificationReport final {
    bool accepted = false;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] crypto::Sha256Digest compute_manifest_digest(const Manifest& manifest);
[[nodiscard]] Result<VerificationReport> verify_manifest(const Manifest& manifest, const TrustAnchor& trust);

}  // namespace ai_shield::package
