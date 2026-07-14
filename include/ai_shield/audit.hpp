#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/correlation.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::audit {

struct AuditRecord final {
    std::uint64_t sequence = 0;
    std::uint64_t monotonic_ns = 0;
    std::uint32_t reason_mask = 0;
    crypto::Sha256Digest evidence_hash{};
    correlation::Context correlation{};
};

struct AuditSegment final {
    std::uint64_t sequence = 0;
    crypto::Sha256Digest previous_hash{};
    crypto::Sha256Digest segment_hash{};
    std::vector<AuditRecord> records;
};

struct Checkpoint final {
    std::uint64_t sequence = 0;
    crypto::Sha256Digest segment_root{};
    crypto::Sha256Digest signer_fingerprint{};
    crypto::Sha256Digest checkpoint_hash{};
};

class AuditChain final {
public:
    [[nodiscard]] Result<void> append(AuditRecord record);
    [[nodiscard]] Result<void> verify() const noexcept;
    [[nodiscard]] Result<Checkpoint> checkpoint(crypto::Sha256Digest signer_fingerprint) const noexcept;
    [[nodiscard]] Result<void> verify_checkpoint(const Checkpoint& checkpoint) const noexcept;
    [[nodiscard]] const std::vector<AuditSegment>& segments() const noexcept { return segments_; }

private:
    friend Result<AuditChain> deserialize(std::span<const std::byte> bytes);

    std::vector<AuditSegment> segments_;
};

[[nodiscard]] crypto::Sha256Digest hash_record(const AuditRecord& record) noexcept;
[[nodiscard]] crypto::Sha256Digest hash_segment(const crypto::Sha256Digest& previous,
                                                std::span<const AuditRecord> records) noexcept;
[[nodiscard]] crypto::Sha256Digest hash_checkpoint(std::uint64_t sequence,
                                                   const crypto::Sha256Digest& segment_root,
                                                   const crypto::Sha256Digest& signer_fingerprint) noexcept;
[[nodiscard]] std::vector<std::byte> serialize(const AuditChain& chain);
[[nodiscard]] Result<AuditChain> deserialize(std::span<const std::byte> bytes);

}  // namespace ai_shield::audit
