#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include "ai_shield/abi.hpp"

namespace ai_shield::detection {

struct Evidence final {
    std::uint16_t hard_rule = 0;
    std::uint16_t signature = 0;
    std::uint16_t protocol = 0;
    std::uint16_t novelty = 0;
    std::uint16_t adaptivity = 0;
    std::uint16_t campaign = 0;
    std::uint16_t consequence = 0;
    std::uint16_t target_criticality = 0;
    std::uint16_t sensor_integrity = 0;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] Evidence inspect_payload(std::span<const std::byte> payload) noexcept;
[[nodiscard]] Evidence inspect_text(std::string_view payload) noexcept;
[[nodiscard]] std::uint16_t clipped_score(std::uint32_t value) noexcept;

}  // namespace ai_shield::detection
