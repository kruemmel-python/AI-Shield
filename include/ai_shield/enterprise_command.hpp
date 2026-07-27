#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/enterprise_rbac.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::enterprise::command {

enum class Action : std::uint32_t {
    isolate_network, release_network_isolation, quarantine_file, block_file_hash, block_publisher,
    block_destination, suspend_process, terminate_process, collect_incident, capture_user_data_snapshot,
    verify_recovery_vault, start_approved_restore, rotate_device_certificate, enter_safe_mode
};

enum class TargetKind : std::uint32_t { device, process, file, publisher, destination, recovery_snapshot };

struct Envelope final {
    std::uint64_t command_id = 0;
    std::uint64_t organization_id = 0;
    std::uint64_t device_id = 0;
    std::uint64_t actor_id = 0;
    std::uint64_t issued_at_ns = 0;
    std::uint64_t expires_at_ns = 0;
    std::uint64_t nonce = 0;
    std::uint64_t target_id = 0;
    Action action = Action::collect_incident;
    TargetKind target_kind = TargetKind::device;
    crypto::Sha256Digest target_hash{};
    crypto::Sha256Digest content_hash{};
    crypto::Sha256Digest signer_fingerprint{};
};

struct VerificationContext final {
    std::uint64_t now_ns = 0;
    crypto::Sha256Digest trusted_signer{};
    bool signature_valid = false;
};

[[nodiscard]] crypto::Sha256Digest hash(const Envelope& envelope) noexcept;
[[nodiscard]] bool high_impact(Action action) noexcept;
[[nodiscard]] Result<void> validate(const Envelope& envelope, const VerificationContext& context,
                                    const rbac::Principal& actor,
                                    std::span<const rbac::Approval> approvals) noexcept;

class ReplayGuard final {
public:
    explicit ReplayGuard(std::size_t capacity) : capacity_(capacity) {}
    [[nodiscard]] Result<void> accept(std::uint64_t command_id, std::uint64_t nonce);

private:
    std::size_t capacity_ = 0;
    std::vector<std::uint64_t> command_ids_;
    std::vector<std::uint64_t> nonces_;
};

}  // namespace ai_shield::enterprise::command
