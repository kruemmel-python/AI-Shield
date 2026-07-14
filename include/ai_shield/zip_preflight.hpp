#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::zip {

struct EntrySummary final {
    std::uint32_t entry_count = 0;
    std::uint64_t compressed_bytes = 0;
    std::uint64_t uncompressed_bytes = 0;
    bool malformed = false;
    bool path_escape = false;
    bool bomb_risk = false;
    bool encrypted_entry = false;
    bool unsupported_compression = false;
    bool executable_entry = false;
    bool active_content_entry = false;
    bool nested_container = false;
    bool duplicate_name = false;
};

[[nodiscard]] Result<EntrySummary> preflight(std::span<const std::byte> data) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const EntrySummary& summary) noexcept;

}  // namespace ai_shield::protocols::zip
