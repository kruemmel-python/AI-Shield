#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::pdf {

struct ParseSummary final {
    std::uint32_t object_count = 0;
    bool malformed = false;
    bool javascript = false;
    bool launch_action = false;
    bool embedded_file = false;
    bool open_action = false;
    bool xref_missing = false;
    bool eof_missing = false;
};

[[nodiscard]] Result<ParseSummary> preflight(std::span<const std::byte> data) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ParseSummary& summary) noexcept;

}  // namespace ai_shield::protocols::pdf
