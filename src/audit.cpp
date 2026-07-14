#include "ai_shield/audit.hpp"

#include <array>
#include <cstring>
#include <span>
#include <type_traits>

namespace ai_shield::audit {
namespace {

template <typename T>
void append_scalar(std::vector<std::byte>& bytes, T value) {
    static_assert(std::is_integral_v<T>);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes.push_back(static_cast<std::byte>((static_cast<std::uint64_t>(value) >> (i * 8U)) & 0xffU));
    }
}

void append_u32(std::vector<std::byte>& bytes, std::uint32_t value) {
    append_scalar(bytes, value);
}

void append_u64(std::vector<std::byte>& bytes, std::uint64_t value) {
    append_scalar(bytes, value);
}

void append_digest(std::vector<std::byte>& bytes, const crypto::Sha256Digest& digest) {
    bytes.insert(bytes.end(), digest.begin(), digest.end());
}

[[nodiscard]] Result<std::uint32_t> read_u32(std::span<const std::byte> bytes, std::size_t& offset) noexcept {
    if (offset + sizeof(std::uint32_t) > bytes.size()) {
        return Status::malformed_input;
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i) {
        value |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (i * 8U);
    }
    offset += sizeof(std::uint32_t);
    return value;
}

[[nodiscard]] Result<std::uint64_t> read_u64(std::span<const std::byte> bytes, std::size_t& offset) noexcept {
    if (offset + sizeof(std::uint64_t) > bytes.size()) {
        return Status::malformed_input;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        value |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (i * 8U);
    }
    offset += sizeof(std::uint64_t);
    return value;
}

[[nodiscard]] Result<crypto::Sha256Digest> read_digest(std::span<const std::byte> bytes, std::size_t& offset) noexcept {
    if (offset + 32U > bytes.size()) {
        return Status::malformed_input;
    }
    crypto::Sha256Digest digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        digest[i] = bytes[offset + i];
    }
    offset += digest.size();
    return digest;
}

}  // namespace

crypto::Sha256Digest hash_record(const AuditRecord& record) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(8U + 8U + 4U + 32U);
    append_scalar(bytes, record.sequence);
    append_scalar(bytes, record.monotonic_ns);
    append_scalar(bytes, record.reason_mask);
    bytes.insert(bytes.end(), record.evidence_hash.begin(), record.evidence_hash.end());
    const auto& context = record.correlation;
    if (context.flow_id != 0U || context.object_id != 0U || context.file_id != 0U || context.volume_id != 0U ||
        context.provenance_id != 0U || context.process_id != 0U || context.parent_process_id != 0U ||
        context.policy_version != 0U || context.model_version != 0U) {
        append_u64(bytes, context.flow_id); append_u64(bytes, context.object_id); append_u64(bytes, context.file_id);
        append_u64(bytes, context.volume_id); append_u64(bytes, context.provenance_id);
        append_u64(bytes, context.process_id); append_u64(bytes, context.parent_process_id);
        append_u64(bytes, context.policy_version); append_u64(bytes, context.model_version);
    }
    return crypto::sha256(bytes);
}

crypto::Sha256Digest hash_segment(const crypto::Sha256Digest& previous, std::span<const AuditRecord> records) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(32U + records.size() * 76U);
    bytes.insert(bytes.end(), previous.begin(), previous.end());
    for (const auto& record : records) {
        const auto digest = hash_record(record);
        bytes.insert(bytes.end(), digest.begin(), digest.end());
    }
    return crypto::sha256(bytes);
}

crypto::Sha256Digest hash_checkpoint(std::uint64_t sequence,
                                      const crypto::Sha256Digest& segment_root,
                                      const crypto::Sha256Digest& signer_fingerprint) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(8U + 32U + 32U);
    append_scalar(bytes, sequence);
    append_digest(bytes, segment_root);
    append_digest(bytes, signer_fingerprint);
    return crypto::sha256(bytes);
}

Result<void> AuditChain::append(AuditRecord record) {
    const std::uint64_t next_sequence = segments_.empty() ? 1ULL : segments_.back().sequence + 1ULL;
    if (record.sequence != next_sequence) {
        return Status::integrity_failure;
    }
    AuditSegment segment{};
    segment.sequence = record.sequence;
    if (!segments_.empty()) {
        segment.previous_hash = segments_.back().segment_hash;
    }
    segment.records.push_back(record);
    segment.segment_hash = hash_segment(segment.previous_hash, segment.records);
    segments_.push_back(segment);
    return {};
}

Result<Checkpoint> AuditChain::checkpoint(crypto::Sha256Digest signer_fingerprint) const noexcept {
    if (segments_.empty()) {
        return Status::not_found;
    }
    const auto& last = segments_.back();
    return Checkpoint{.sequence = last.sequence,
                      .segment_root = last.segment_hash,
                      .signer_fingerprint = signer_fingerprint,
                      .checkpoint_hash = hash_checkpoint(last.sequence, last.segment_hash, signer_fingerprint)};
}

Result<void> AuditChain::verify_checkpoint(const Checkpoint& checkpoint) const noexcept {
    if (segments_.empty()) {
        return Status::not_found;
    }
    const auto& last = segments_.back();
    if (checkpoint.sequence != last.sequence || !crypto::constant_time_equal(checkpoint.segment_root, last.segment_hash)) {
        return Status::integrity_failure;
    }
    const auto actual = hash_checkpoint(checkpoint.sequence, checkpoint.segment_root, checkpoint.signer_fingerprint);
    if (!crypto::constant_time_equal(actual, checkpoint.checkpoint_hash)) {
        return Status::integrity_failure;
    }
    return {};
}

Result<void> AuditChain::verify() const noexcept {
    crypto::Sha256Digest previous{};
    std::uint64_t expected = 1ULL;
    for (const auto& segment : segments_) {
        if (segment.sequence != expected || !crypto::constant_time_equal(segment.previous_hash, previous)) {
            return Status::integrity_failure;
        }
        const auto actual = hash_segment(segment.previous_hash, segment.records);
        if (!crypto::constant_time_equal(actual, segment.segment_hash)) {
            return Status::integrity_failure;
        }
        previous = segment.segment_hash;
        ++expected;
    }
    return {};
}

std::vector<std::byte> serialize(const AuditChain& chain) {
    std::vector<std::byte> bytes;
    bytes.reserve(16U + chain.segments().size() * 128U);
    const std::array<std::byte, 8> magic = {static_cast<std::byte>('A'), static_cast<std::byte>('I'),
                                           static_cast<std::byte>('S'), static_cast<std::byte>('H'),
                                           static_cast<std::byte>('A'), static_cast<std::byte>('D'),
                                           static_cast<std::byte>('0'), static_cast<std::byte>('2')};
    bytes.insert(bytes.end(), magic.begin(), magic.end());
    append_u64(bytes, static_cast<std::uint64_t>(chain.segments().size()));
    for (const auto& segment : chain.segments()) {
        append_u64(bytes, segment.sequence);
        append_digest(bytes, segment.previous_hash);
        append_digest(bytes, segment.segment_hash);
        append_u64(bytes, static_cast<std::uint64_t>(segment.records.size()));
        for (const auto& record : segment.records) {
            append_u64(bytes, record.sequence);
            append_u64(bytes, record.monotonic_ns);
            append_u32(bytes, record.reason_mask);
            append_digest(bytes, record.evidence_hash);
            append_u64(bytes, record.correlation.flow_id);
            append_u64(bytes, record.correlation.object_id);
            append_u64(bytes, record.correlation.file_id);
            append_u64(bytes, record.correlation.volume_id);
            append_u64(bytes, record.correlation.provenance_id);
            append_u64(bytes, record.correlation.process_id);
            append_u64(bytes, record.correlation.parent_process_id);
            append_u64(bytes, record.correlation.policy_version);
            append_u64(bytes, record.correlation.model_version);
        }
    }
    return bytes;
}

Result<AuditChain> deserialize(std::span<const std::byte> bytes) {
    const std::array<std::byte, 8> magic = {static_cast<std::byte>('A'), static_cast<std::byte>('I'),
                                           static_cast<std::byte>('S'), static_cast<std::byte>('H'),
                                           static_cast<std::byte>('A'), static_cast<std::byte>('D'),
                                           static_cast<std::byte>('0'), static_cast<std::byte>('2')};
    if (bytes.size() < magic.size() + sizeof(std::uint64_t)) {
        return Status::malformed_input;
    }
    for (std::size_t index = 0; index < magic.size(); ++index)
        if (bytes[index] != magic[index]) return Status::malformed_input;
    std::size_t offset = magic.size();
    const auto segment_count = read_u64(bytes, offset);
    if (!segment_count.ok() || segment_count.value() > 1'000'000ULL) {
        return Status::malformed_input;
    }

    AuditChain chain;
    chain.segments_.reserve(static_cast<std::size_t>(segment_count.value()));
    for (std::uint64_t i = 0; i < segment_count.value(); ++i) {
        AuditSegment segment{};
        auto sequence = read_u64(bytes, offset);
        auto previous = read_digest(bytes, offset);
        auto segment_hash = read_digest(bytes, offset);
        auto record_count = read_u64(bytes, offset);
        if (!sequence.ok() || !previous.ok() || !segment_hash.ok() || !record_count.ok() || record_count.value() > 4096ULL) {
            return Status::malformed_input;
        }
        segment.sequence = sequence.value();
        segment.previous_hash = previous.value();
        segment.segment_hash = segment_hash.value();
        segment.records.reserve(static_cast<std::size_t>(record_count.value()));
        for (std::uint64_t r = 0; r < record_count.value(); ++r) {
            AuditRecord record{};
            auto record_sequence = read_u64(bytes, offset);
            auto monotonic = read_u64(bytes, offset);
            auto reason = read_u32(bytes, offset);
            auto evidence = read_digest(bytes, offset);
            if (!record_sequence.ok() || !monotonic.ok() || !reason.ok() || !evidence.ok()) {
                return Status::malformed_input;
            }
            record.sequence = record_sequence.value();
            record.monotonic_ns = monotonic.value();
            record.reason_mask = reason.value();
            record.evidence_hash = evidence.value();
            const auto flow = read_u64(bytes, offset); const auto object = read_u64(bytes, offset);
            const auto file = read_u64(bytes, offset); const auto volume = read_u64(bytes, offset);
            const auto provenance = read_u64(bytes, offset); const auto process = read_u64(bytes, offset);
            const auto parent = read_u64(bytes, offset); const auto policy = read_u64(bytes, offset);
            const auto model = read_u64(bytes, offset);
            if (!flow.ok() || !object.ok() || !file.ok() || !volume.ok() || !provenance.ok() ||
                !process.ok() || !parent.ok() || !policy.ok() || !model.ok()) return Status::malformed_input;
            record.correlation = {.flow_id = flow.value(), .object_id = object.value(), .file_id = file.value(),
                .volume_id = volume.value(), .provenance_id = provenance.value(), .process_id = process.value(),
                .parent_process_id = parent.value(), .policy_version = policy.value(), .model_version = model.value()};
            segment.records.push_back(record);
        }
        chain.segments_.push_back(segment);
    }
    if (offset != bytes.size()) {
        return Status::malformed_input;
    }
    const auto verified = chain.verify();
    if (!verified.ok()) {
        return verified.status();
    }
    return chain;
}

}  // namespace ai_shield::audit
