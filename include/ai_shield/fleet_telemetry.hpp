#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::enterprise::fleet {

enum class Priority : std::uint32_t { critical = 0, response = 1, security = 2, operational = 3, diagnostic = 4 };

struct Batch final {
    std::uint64_t organization_id = 0;
    std::uint64_t device_id = 0;
    std::uint64_t boot_id = 0;
    std::uint64_t batch_sequence = 0;
    std::uint64_t first_event_sequence = 0;
    std::uint64_t last_event_sequence = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 0;
    std::uint64_t agent_version = 0;
    std::uint64_t created_at_ns = 0;
    Priority priority = Priority::security;
    crypto::Sha256Digest previous_batch_hash{};
    crypto::Sha256Digest payload_hash{};
    crypto::Sha256Digest batch_hash{};
    crypto::Sha256Digest signer_fingerprint{};
};

struct VerificationContext final {
    std::uint64_t expected_device_id = 0;
    std::uint64_t expected_boot_id = 0;
    std::uint64_t expected_batch_sequence = 0;
    std::uint64_t expected_event_sequence = 0;
    crypto::Sha256Digest expected_previous_hash{};
    crypto::Sha256Digest trusted_signer{};
    bool signature_valid = false;
};

[[nodiscard]] crypto::Sha256Digest hash(const Batch& batch) noexcept;
[[nodiscard]] Result<void> validate(const Batch& batch, const VerificationContext& context) noexcept;

class StoreForwardQueue final {
public:
    explicit StoreForwardQueue(std::size_t capacity) : capacity_(capacity) {}
    [[nodiscard]] Result<void> push(Batch batch);
    [[nodiscard]] Result<void> acknowledge(std::uint64_t through_batch_sequence);
    [[nodiscard]] const std::vector<Batch>& pending() const noexcept { return pending_; }
    [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_; }

private:
    std::size_t capacity_ = 0;
    std::uint64_t dropped_ = 0;
    std::vector<Batch> pending_;
};

}  // namespace ai_shield::enterprise::fleet
