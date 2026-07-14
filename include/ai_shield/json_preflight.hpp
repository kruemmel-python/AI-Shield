#pragma once

#include <cstdint>
#include <string_view>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::json {

struct ParseSummary final {
    std::uint32_t max_depth = 0;
    std::uint32_t string_count = 0;
    std::uint32_t number_count = 0;
    bool malformed = false;
    bool duplicate_object_key_risk = false;
    bool control_character = false;
    bool depth_budget_exceeded = false;
};

[[nodiscard]] Result<ParseSummary> preflight(std::string_view input, std::uint32_t depth_budget = 64) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ParseSummary& summary) noexcept;

}  // namespace ai_shield::protocols::json
