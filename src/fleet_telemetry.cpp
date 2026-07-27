#include "ai_shield/fleet_telemetry.hpp"

#include <algorithm>

namespace ai_shield::enterprise::fleet {
namespace {

void append(std::vector<std::byte>& bytes, std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes.push_back(static_cast<std::byte>((value >> (index * 8U)) & 0xffU));
}

}  // namespace

crypto::Sha256Digest hash(const Batch& batch) noexcept {
    std::vector<std::byte> bytes;
    bytes.reserve(176U);
    append(bytes, batch.organization_id); append(bytes, batch.device_id); append(bytes, batch.boot_id);
    append(bytes, batch.batch_sequence); append(bytes, batch.first_event_sequence);
    append(bytes, batch.last_event_sequence); append(bytes, batch.policy_version);
    append(bytes, batch.model_version); append(bytes, batch.agent_version); append(bytes, batch.created_at_ns);
    append(bytes, static_cast<std::uint64_t>(batch.priority));
    bytes.insert(bytes.end(), batch.previous_batch_hash.begin(), batch.previous_batch_hash.end());
    bytes.insert(bytes.end(), batch.payload_hash.begin(), batch.payload_hash.end());
    return crypto::sha256(bytes);
}

Result<void> validate(const Batch& batch, const VerificationContext& context) noexcept {
    crypto::Sha256Digest empty{};
    if (batch.organization_id == 0U || batch.device_id == 0U || batch.boot_id == 0U ||
        batch.batch_sequence == 0U || batch.first_event_sequence == 0U ||
        batch.last_event_sequence < batch.first_event_sequence || batch.policy_version == 0U ||
        batch.agent_version == 0U || batch.created_at_ns == 0U ||
        crypto::constant_time_equal(batch.payload_hash, empty))
        return Status::invalid_argument;
    if (batch.device_id != context.expected_device_id || batch.boot_id != context.expected_boot_id ||
        batch.batch_sequence != context.expected_batch_sequence ||
        batch.first_event_sequence != context.expected_event_sequence ||
        !crypto::constant_time_equal(batch.previous_batch_hash, context.expected_previous_hash) ||
        !context.signature_valid ||
        !crypto::constant_time_equal(batch.signer_fingerprint, context.trusted_signer) ||
        !crypto::constant_time_equal(batch.batch_hash, hash(batch)))
        return Status::integrity_failure;
    return {};
}

Result<void> StoreForwardQueue::push(Batch batch) {
    if (capacity_ == 0U || batch.batch_sequence == 0U) return Status::invalid_argument;
    if (!pending_.empty() && batch.batch_sequence <= pending_.back().batch_sequence)
        return Status::integrity_failure;
    if (pending_.size() == capacity_) {
        auto candidate = pending_.end();
        for (auto item = pending_.begin(); item != pending_.end(); ++item) {
            if (item->priority > Priority::response &&
                (candidate == pending_.end() || item->priority > candidate->priority))
                candidate = item;
        }
        if (candidate == pending_.end()) return Status::out_of_budget;
        if (batch.priority > candidate->priority) {
            ++dropped_;
            return Status::out_of_budget;
        }
        pending_.erase(candidate);
        ++dropped_;
    }
    pending_.push_back(batch);
    return {};
}

Result<void> StoreForwardQueue::acknowledge(std::uint64_t through_batch_sequence) {
    if (through_batch_sequence == 0U) return Status::invalid_argument;
    const auto before = pending_.size();
    std::erase_if(pending_, [through_batch_sequence](const Batch& batch) {
        return batch.batch_sequence <= through_batch_sequence;
    });
    return before == pending_.size() ? Result<void>{Status::not_found} : Result<void>{};
}

}  // namespace ai_shield::enterprise::fleet
