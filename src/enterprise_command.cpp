#include "ai_shield/enterprise_command.hpp"

#include <algorithm>

namespace ai_shield::enterprise::command {
namespace {

void append(std::vector<std::byte>& bytes, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes.push_back(static_cast<std::byte>((value >> (index * 8U)) & 0xffU));
}

[[nodiscard]] bool target_valid(const Envelope& envelope) noexcept {
    crypto::Sha256Digest empty{};
    const bool has_hash = !crypto::constant_time_equal(envelope.target_hash, empty);
    switch (envelope.target_kind) {
        case TargetKind::device:
        case TargetKind::process:
        case TargetKind::recovery_snapshot: return envelope.target_id != 0U;
        case TargetKind::file:
        case TargetKind::publisher:
        case TargetKind::destination: return has_hash;
    }
    return false;
}

}  // namespace

crypto::Sha256Digest hash(const Envelope& envelope) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(128U);
    append(bytes, envelope.command_id); append(bytes, envelope.organization_id);
    append(bytes, envelope.device_id); append(bytes, envelope.actor_id);
    append(bytes, envelope.issued_at_ns); append(bytes, envelope.expires_at_ns);
    append(bytes, envelope.nonce); append(bytes, envelope.target_id);
    append(bytes, static_cast<std::uint64_t>(envelope.action));
    append(bytes, static_cast<std::uint64_t>(envelope.target_kind));
    bytes.insert(bytes.end(), envelope.target_hash.begin(), envelope.target_hash.end());
    return crypto::sha256(bytes);
}

bool high_impact(Action action) noexcept {
    return action == Action::release_network_isolation || action == Action::terminate_process ||
           action == Action::start_approved_restore || action == Action::rotate_device_certificate ||
           action == Action::enter_safe_mode;
}

Result<void> validate(const Envelope& envelope, const VerificationContext& context,
                      const rbac::Principal& actor, std::span<const rbac::Approval> approvals) noexcept {
    constexpr std::uint64_t maximum_lease_ns = 900'000'000'000ULL;
    if (envelope.command_id == 0U || envelope.organization_id == 0U || envelope.device_id == 0U ||
        envelope.actor_id == 0U || envelope.nonce == 0U || envelope.issued_at_ns == 0U ||
        envelope.expires_at_ns <= envelope.issued_at_ns ||
        envelope.expires_at_ns - envelope.issued_at_ns > maximum_lease_ns ||
        context.now_ns < envelope.issued_at_ns || context.now_ns >= envelope.expires_at_ns ||
        !target_valid(envelope))
        return Status::invalid_argument;
    if (!context.signature_valid ||
        !crypto::constant_time_equal(envelope.signer_fingerprint, context.trusted_signer) ||
        !crypto::constant_time_equal(envelope.content_hash, hash(envelope)) ||
        actor.actor_id != envelope.actor_id)
        return Status::integrity_failure;
    const auto actor_authorized = rbac::authorize(actor, rbac::Capability::execute_response);
    if (!actor_authorized.ok()) return actor_authorized.status();
    if (high_impact(envelope.action))
        return rbac::require_dual_control(approvals, rbac::Capability::approve_high_impact_response,
                                          envelope.issued_at_ns, envelope.expires_at_ns);
    return {};
}

Result<void> ReplayGuard::accept(std::uint64_t command_id, std::uint64_t nonce) {
    if (capacity_ == 0U || command_id == 0U || nonce == 0U) return Status::invalid_argument;
    if (std::find(command_ids_.begin(), command_ids_.end(), command_id) != command_ids_.end() ||
        std::find(nonces_.begin(), nonces_.end(), nonce) != nonces_.end())
        return Status::integrity_failure;
    if (command_ids_.size() == capacity_) {
        command_ids_.erase(command_ids_.begin());
        nonces_.erase(nonces_.begin());
    }
    command_ids_.push_back(command_id);
    nonces_.push_back(nonce);
    return {};
}

}  // namespace ai_shield::enterprise::command
