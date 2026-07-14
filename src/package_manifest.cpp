#include "ai_shield/package_manifest.hpp"

#include <algorithm>
#include <span>
#include <vector>

namespace ai_shield::package {
namespace {

template <typename T>
void append_le(std::vector<std::byte>& out, T value) {
    const auto u = static_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        out.push_back(static_cast<std::byte>((u >> (i * 8U)) & 0xffU));
    }
}

void append_bytes(std::vector<std::byte>& out, std::string_view text) {
    const auto bytes = std::as_bytes(std::span<const char>(text.data(), text.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

}  // namespace

crypto::Sha256Digest compute_manifest_digest(const Manifest& manifest) {
    std::vector<std::byte> bytes;
    bytes.reserve(128U + manifest.files.size() * 96U);
    append_le(bytes, manifest.kind);
    append_le(bytes, manifest.manifest_version);
    append_le(bytes, manifest.min_abi_version);
    append_le(bytes, manifest.security_version);
    append_le(bytes, manifest.policy_version);
    append_le(bytes, manifest.model_version);
    append_le(bytes, static_cast<std::uint64_t>(manifest.files.size()));
    for (const auto& file : manifest.files) {
        append_le(bytes, static_cast<std::uint64_t>(file.path.size()));
        append_bytes(bytes, file.path);
        bytes.insert(bytes.end(), file.sha256.begin(), file.sha256.end());
    }
    return crypto::sha256(bytes);
}

Result<VerificationReport> verify_manifest(const Manifest& manifest, const TrustAnchor& trust) {
    VerificationReport report{};
    if (manifest.kind != trust.kind || manifest.manifest_version == 0U || manifest.files.empty()) {
        report.reason_mask |= abi::ReasonCode::policy_signature_invalid;
        return Status::invalid_argument;
    }
    if (manifest.min_abi_version > abi::kAbiVersion) {
        report.reason_mask |= abi::ReasonCode::abi_violation;
        return Status::incompatible_version;
    }
    if (manifest.security_version <= trust.current_security_version) {
        report.reason_mask |= abi::ReasonCode::policy_signature_invalid;
        return Status::downgrade_attempt;
    }
    const auto digest = compute_manifest_digest(manifest);
    if (!crypto::constant_time_equal(digest, manifest.manifest_digest)) {
        report.reason_mask |= abi::ReasonCode::policy_signature_invalid;
        return Status::integrity_failure;
    }
    if (!crypto::constant_time_equal(manifest.signature_fingerprint, trust.expected_signature_fingerprint)) {
        report.reason_mask |= manifest.kind == PackageKind::model ? abi::ReasonCode::model_signature_invalid
                                                                  : abi::ReasonCode::policy_signature_invalid;
        return Status::integrity_failure;
    }
    report.accepted = true;
    return report;
}

}  // namespace ai_shield::package
