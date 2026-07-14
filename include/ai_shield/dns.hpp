#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::dns {

struct ParseSummary final {
    std::uint16_t question_count = 0;
    std::uint16_t answer_count = 0;
    std::uint16_t authority_count = 0;
    std::uint16_t additional_count = 0;
    std::uint16_t max_name_depth = 0;
    bool malformed = false;
    bool compression_pointer_seen = false;
    bool compression_loop_risk = false;
    bool trailing_bytes = false;
};

[[nodiscard]] Result<ParseSummary> parse_message(std::span<const std::byte> packet) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ParseSummary& summary) noexcept;

}  // namespace ai_shield::protocols::dns
