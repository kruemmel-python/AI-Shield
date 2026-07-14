#include "ai_shield/abi2.hpp"

#include <vector>

namespace ai_shield::abi2 {
namespace {

template <typename T>
void append(std::vector<std::byte>& bytes, T value) {
    const auto converted = static_cast<std::uint64_t>(value);
    for (std::size_t index = 0; index < sizeof(T); ++index)
        bytes.push_back(static_cast<std::byte>((converted >> (index * 8U)) & 0xffU));
}

template <std::size_t N>
void append_array(std::vector<std::byte>& bytes, const std::array<std::byte, N>& value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
}

std::vector<std::byte> authenticated_bytes(const SensorEvent& event) {
    std::vector<std::byte> bytes;
    bytes.reserve(216U);
    const auto& header = event.header;
    append(bytes, header.magic); append(bytes, header.abi_major); append(bytes, header.abi_minor);
    append(bytes, header.message_type); append(bytes, header.header_size); append(bytes, header.structure_size);
    append(bytes, header.sequence); append(bytes, header.monotonic_ns); append(bytes, header.payload_length);
    append(bytes, header.flags); append(bytes, header.flow_id); append(bytes, header.object_id);
    append(bytes, header.policy_version); append(bytes, header.model_version);
    append(bytes, event.sensor); append(bytes, event.kind); append(bytes, event.process_id);
    append(bytes, event.parent_process_id); append(bytes, event.provenance_id); append(bytes, event.volume_id);
    append(bytes, event.file_id); append(bytes, event.subject_id); append(bytes, event.local_port);
    append(bytes, event.remote_port); append(bytes, event.address_family); append(bytes, event.protocol);
    append(bytes, event.decision); append(bytes, event.event_flags); append_array(bytes, event.source_address);
    append_array(bytes, event.target_address); append_array(bytes, event.evidence_hash);
    return bytes;
}

crypto::Sha256Digest hmac_sha256(std::span<const std::byte> message, const crypto::Sha256Digest& key) {
    std::array<std::byte, 64> inner_key{};
    std::array<std::byte, 64> outer_key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        inner_key[index] = key[index] ^ std::byte{0x36};
        outer_key[index] = key[index] ^ std::byte{0x5c};
    }
    for (std::size_t index = key.size(); index < inner_key.size(); ++index) {
        inner_key[index] = std::byte{0x36};
        outer_key[index] = std::byte{0x5c};
    }
    std::vector<std::byte> inner(inner_key.begin(), inner_key.end());
    inner.insert(inner.end(), message.begin(), message.end());
    const auto inner_hash = crypto::sha256(inner);
    std::vector<std::byte> outer(outer_key.begin(), outer_key.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return crypto::sha256(outer);
}

}  // namespace

crypto::Sha256Digest compute_mac(const SensorEvent& event, const crypto::Sha256Digest& key) {
    return hmac_sha256(authenticated_bytes(event), key);
}

void seal(SensorEvent& event, const crypto::Sha256Digest& key) {
    event.header.magic = kMagic;
    event.header.abi_major = kMajor;
    event.header.abi_minor = kMinor;
    event.header.message_type = MessageType::sensor_event;
    event.header.header_size = sizeof(MessageHeader);
    event.header.structure_size = sizeof(SensorEvent);
    event.header.payload_length = sizeof(SensorEvent) - sizeof(MessageHeader);
    event.header.message_mac = compute_mac(event, key);
}

Result<void> validate(const SensorEvent& event, const ValidationContext& context) noexcept {
    const auto& header = event.header;
    if (header.magic != kMagic || header.abi_major != kMajor || header.abi_minor > kMinor ||
        header.message_type != MessageType::sensor_event || header.header_size != sizeof(MessageHeader) ||
        header.structure_size != sizeof(SensorEvent) ||
        header.payload_length != sizeof(SensorEvent) - sizeof(MessageHeader) ||
        (header.flags & ~kKnownHeaderFlags) != 0U || (event.event_flags & ~kKnownEventFlags) != 0U ||
        header.sequence != context.expected_sequence || event.sensor == 0U || event.kind == 0U) {
        return Status::integrity_failure;
    }
    const auto lower = context.now_monotonic_ns > context.maximum_clock_skew_ns
                           ? context.now_monotonic_ns - context.maximum_clock_skew_ns : 0ULL;
    if (header.monotonic_ns < lower || header.monotonic_ns > context.now_monotonic_ns + context.maximum_clock_skew_ns)
        return Status::integrity_failure;
    if (!crypto::constant_time_equal(compute_mac(event, context.channel_key), header.message_mac))
        return Status::integrity_failure;
    return {};
}

}  // namespace ai_shield::abi2
