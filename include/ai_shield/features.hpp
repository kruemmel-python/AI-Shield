#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/http1.hpp"

namespace ai_shield::features {

struct NetworkFeatures final {
    std::uint32_t payload_bytes = 0;
    std::uint32_t printable_ratio_percent = 0;
    std::uint32_t zero_byte_count = 0;
    std::uint32_t high_byte_count = 0;
};

struct ProtocolFeatures final {
    std::uint16_t header_count = 0;
    std::uint64_t content_length = 0;
    bool ambiguous_framing = false;
    bool path_traversal = false;
};

[[nodiscard]] NetworkFeatures extract_network(std::span<const std::byte> payload) noexcept;
[[nodiscard]] ProtocolFeatures extract_http(const protocols::http1::ParseSummary& summary) noexcept;

}  // namespace ai_shield::features
