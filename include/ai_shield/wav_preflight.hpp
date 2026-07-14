#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/result.hpp"

namespace ai_shield::protocols::wav {

struct ParseSummary final {
    std::uint32_t chunk_count = 0;
    bool malformed = false;
    bool format_present = false;
    bool audio_data_present = false;
    bool suspicious_metadata = false;
};

[[nodiscard]] bool has_wave_signature(std::span<const std::byte> data) noexcept;
[[nodiscard]] Result<ParseSummary> preflight(std::span<const std::byte> data) noexcept;

}  // namespace ai_shield::protocols::wav
