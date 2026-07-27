#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/enterprise_rbac.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::enterprise::policy {

enum class Scope : std::uint32_t { global, organization, site, group, device };
enum class Ring : std::uint32_t { canary, pilot, broad, stable };

struct Envelope final {
    std::uint64_t organization_id = 0;
    std::uint64_t site_id = 0;
    std::uint64_t group_id = 0;
    std::uint64_t device_id = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t security_version = 0;
    std::uint64_t parent_policy_version = 0;
    std::uint64_t issued_at_ns = 0;
    std::uint64_t expires_at_ns = 0;
    std::uint64_t minimum_agent_version = 0;
    Scope scope = Scope::global;
    Ring ring = Ring::canary;
    std::uint32_t rollout_percent = 0;
    crypto::Sha256Digest rules_hash{};
    crypto::Sha256Digest parent_hash{};
    crypto::Sha256Digest envelope_hash{};
    crypto::Sha256Digest signer_fingerprint{};
    bool break_glass = false;
};

struct VerificationContext final {
    std::uint64_t now_ns = 0;
    std::uint64_t agent_version = 0;
    std::uint64_t active_policy_version = 0;
    std::uint64_t active_security_version = 0;
    crypto::Sha256Digest trusted_signer{};
    bool signature_valid = false;
};

[[nodiscard]] crypto::Sha256Digest content_hash(const Envelope& envelope) noexcept;
[[nodiscard]] Result<void> validate(const Envelope& envelope, const VerificationContext& context,
                                    std::span<const rbac::Approval> approvals) noexcept;
[[nodiscard]] bool selected_for_rollout(const Envelope& envelope, std::uint64_t device_id) noexcept;

}  // namespace ai_shield::enterprise::policy
