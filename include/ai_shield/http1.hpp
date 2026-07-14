#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::http1 {

struct ParseSummary final {
    std::uint16_t header_count = 0;
    std::uint32_t content_length_count = 0;
    std::uint64_t content_length = 0;
    bool chunked = false;
    bool ambiguous_framing = false;
    bool malformed = false;
    bool path_traversal = false;
    bool command_marker = false;
};

[[nodiscard]] Result<ParseSummary> parse_request(std::string_view data) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ParseSummary& summary) noexcept;

}  // namespace ai_shield::protocols::http1
