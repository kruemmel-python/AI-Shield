#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::abi2 {

inline constexpr std::uint32_t kMagic = 0x32485341U;
inline constexpr std::uint16_t kMajor = 2U;
inline constexpr std::uint16_t kMinor = 0U;
inline constexpr std::uint32_t kKnownHeaderFlags = 0U;
inline constexpr std::uint32_t kKnownEventFlags = 0x0000001fU;

enum class MessageType : std::uint16_t { sensor_event = 1U, health = 2U, decision = 3U };

#pragma pack(push, 8)
struct MessageHeader final {
    std::uint32_t magic = kMagic;
    std::uint16_t abi_major = kMajor;
    std::uint16_t abi_minor = kMinor;
    MessageType message_type = MessageType::sensor_event;
    std::uint16_t header_size = sizeof(MessageHeader);
    std::uint32_t structure_size = 0;
    std::uint64_t sequence = 0;
    std::uint64_t monotonic_ns = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t flags = 0;
    std::uint64_t flow_id = 0;
    std::uint64_t object_id = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 0;
    crypto::Sha256Digest message_mac{};
};

struct SensorEvent final {
    MessageHeader header{};
    std::uint32_t sensor = 0;
    std::uint32_t kind = 0;
    std::uint64_t process_id = 0;
    std::uint64_t parent_process_id = 0;
    std::uint64_t provenance_id = 0;
    std::uint64_t volume_id = 0;
    std::uint64_t file_id = 0;
    std::uint64_t subject_id = 0;
    std::uint32_t local_port = 0;
    std::uint32_t remote_port = 0;
    std::uint16_t address_family = 0;
    std::uint16_t protocol = 0;
    std::uint32_t decision = 0;
    std::uint32_t event_flags = 0;
    std::array<std::byte, 16> source_address{};
    std::array<std::byte, 16> target_address{};
    crypto::Sha256Digest evidence_hash{};
};
#pragma pack(pop)

struct ValidationContext final {
    std::uint64_t expected_sequence = 0;
    std::uint64_t now_monotonic_ns = 0;
    std::uint64_t maximum_clock_skew_ns = 0;
    crypto::Sha256Digest channel_key{};
};

[[nodiscard]] crypto::Sha256Digest compute_mac(const SensorEvent& event,
                                                const crypto::Sha256Digest& key);
void seal(SensorEvent& event, const crypto::Sha256Digest& key);
[[nodiscard]] Result<void> validate(const SensorEvent& event, const ValidationContext& context) noexcept;

static_assert(std::is_standard_layout_v<MessageHeader> && std::is_trivially_copyable_v<MessageHeader>);
static_assert(std::is_standard_layout_v<SensorEvent> && std::is_trivially_copyable_v<SensorEvent>);
static_assert(sizeof(MessageHeader) == 104U);
static_assert(sizeof(SensorEvent) == 248U);
static_assert(offsetof(MessageHeader, message_mac) == 72U);
static_assert(offsetof(SensorEvent, sensor) == 104U);
static_assert(offsetof(SensorEvent, evidence_hash) == 212U);

}  // namespace ai_shield::abi2
