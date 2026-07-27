#include "ai_shield/enterprise_policy.hpp"

#include <vector>

namespace ai_shield::enterprise::policy {
namespace {

void append(std::vector<std::byte>& bytes, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes.push_back(static_cast<std::byte>((value >> (index * 8U)) & 0xffU));
}
void append(std::vector<std::byte>& bytes, const crypto::Sha256Digest& value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
}
[[nodiscard]] bool zero(const crypto::Sha256Digest& value) noexcept {
    crypto::Sha256Digest empty{};
    return crypto::constant_time_equal(value, empty);
}

}  // namespace

crypto::Sha256Digest content_hash(const Envelope& envelope) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(176U);
    append(bytes, envelope.organization_id); append(bytes, envelope.site_id);
    append(bytes, envelope.group_id); append(bytes, envelope.device_id);
    append(bytes, envelope.policy_version); append(bytes, envelope.security_version);
    append(bytes, envelope.parent_policy_version); append(bytes, envelope.issued_at_ns);
    append(bytes, envelope.expires_at_ns); append(bytes, envelope.minimum_agent_version);
    append(bytes, static_cast<std::uint64_t>(envelope.scope));
    append(bytes, static_cast<std::uint64_t>(envelope.ring)); append(bytes, envelope.rollout_percent);
    append(bytes, envelope.rules_hash); append(bytes, envelope.parent_hash);
    append(bytes, envelope.break_glass ? 1U : 0U);
    return crypto::sha256(bytes);
}

Result<void> validate(const Envelope& envelope, const VerificationContext& context,
                      std::span<const rbac::Approval> approvals) noexcept {
    if (envelope.organization_id == 0U || envelope.policy_version == 0U ||
        envelope.security_version == 0U || envelope.issued_at_ns == 0U ||
        envelope.expires_at_ns <= envelope.issued_at_ns || context.now_ns < envelope.issued_at_ns ||
        context.now_ns >= envelope.expires_at_ns || envelope.rollout_percent == 0U ||
        envelope.rollout_percent > 100U || zero(envelope.rules_hash) ||
        zero(envelope.signer_fingerprint))
        return Status::invalid_argument;
    if (!context.signature_valid ||
        !crypto::constant_time_equal(envelope.signer_fingerprint, context.trusted_signer) ||
        !crypto::constant_time_equal(envelope.envelope_hash, content_hash(envelope)))
        return Status::integrity_failure;
    if (context.agent_version < envelope.minimum_agent_version) return Status::incompatible_version;
    if (envelope.policy_version <= context.active_policy_version ||
        envelope.security_version < context.active_security_version)
        return Status::downgrade_attempt;
    if (envelope.scope != Scope::global && envelope.parent_policy_version == 0U)
        return Status::invalid_argument;
    if (envelope.break_glass) {
        constexpr std::uint64_t maximum_break_glass_lease_ns = 3'600'000'000'000ULL;
        if (envelope.expires_at_ns - envelope.issued_at_ns > maximum_break_glass_lease_ns)
            return Status::invalid_argument;
        return rbac::require_dual_control(approvals, rbac::Capability::approve_policy,
                                          envelope.issued_at_ns, envelope.expires_at_ns);
    }
    return {};
}

bool selected_for_rollout(const Envelope& envelope, std::uint64_t device_id) noexcept {
    if (device_id == 0U || envelope.rollout_percent == 0U) return false;
    if (envelope.rollout_percent >= 100U) return true;
    std::vector<std::byte> selection;
    selection.reserve(48U);
    append(selection, device_id); append(selection, envelope.policy_version); append(selection, envelope.rules_hash);
    const auto digest = crypto::sha256(selection);
    return std::to_integer<std::uint32_t>(digest[0]) % 100U < envelope.rollout_percent;
}

}  // namespace ai_shield::enterprise::policy
