#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::pe {

struct ImageSummary final {
    std::uint16_t machine = 0;
    std::uint16_t section_count = 0;
    std::uint16_t optional_magic = 0;
    std::uint32_t size_of_image = 0;
    bool malformed = false;
    bool executable = false;
    bool dll = false;
    bool driver_like = false;
    bool unusual_sections = false;
    bool overlay_present = false;
};

[[nodiscard]] Result<ImageSummary> preflight(std::span<const std::byte> data) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ImageSummary& summary) noexcept;

}  // namespace ai_shield::protocols::pe
