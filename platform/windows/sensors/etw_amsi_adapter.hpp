#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/abi2.hpp"
#include "ai_shield/correlation.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::platform::windows::sensors {

inline constexpr std::uint32_t kEtwSensor = 4U;
inline constexpr std::uint32_t kAmsiSensor = 5U;

struct EtwObservation final {
    std::uint64_t sequence = 0;
    std::uint64_t monotonic_ns = 0;
    std::array<std::byte, 16> provider_id{};
    std::uint16_t event_id = 0;
    std::uint8_t version = 0;
    std::uint8_t level = 0;
    correlation::Context correlation{};
    crypto::Sha256Digest evidence_hash{};
};

struct AmsiObservation final {
    std::uint64_t sequence = 0;
    std::uint64_t monotonic_ns = 0;
    std::uint64_t process_id = 0;
    std::uint32_t scan_result = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 0;
    crypto::Sha256Digest content_hash{};
};

[[nodiscard]] Result<abi2::SensorEvent> translate_etw(const EtwObservation& observation,
                                                       const crypto::Sha256Digest& channel_key) noexcept;
[[nodiscard]] Result<abi2::SensorEvent> translate_amsi(const AmsiObservation& observation,
                                                        const crypto::Sha256Digest& channel_key) noexcept;
[[nodiscard]] Result<AmsiObservation> scan_with_amsi(std::span<const std::byte> content,
                                                     std::uint64_t sequence,
                                                     std::uint64_t monotonic_ns,
                                                     std::uint64_t policy_version,
                                                     std::uint64_t model_version) noexcept;

}  // namespace ai_shield::platform::windows::sensors
