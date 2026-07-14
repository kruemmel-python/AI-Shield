#pragma once

#include <cstdint>
#include <string>

#include "ai_shield/correlation.hpp"

namespace ai_shield::siem {

enum class Format : std::uint32_t { json_lines, cef, leef };

struct Event final {
    std::uint64_t monotonic_ns = 0;
    std::uint32_t reason_mask = 0;
    std::uint16_t risk_score = 0;
    std::string action;
    correlation::Context correlation{};
};

[[nodiscard]] std::string format(const Event& event, Format output_format);

}  // namespace ai_shield::siem
