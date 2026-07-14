#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::zip {

struct EntrySummary final {
    std::uint32_t entry_count = 0;
    std::uint32_t inspected_entry_count = 0;
    std::uint32_t maximum_depth = 0;
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
    bool crc_mismatch = false;
    bool budget_exhausted = false;
    bool header_mismatch = false;
};

struct InspectionBudget final {
    std::uint32_t maximum_entries = 10'000U;
    std::uint32_t maximum_depth = 6U;
    std::uint64_t maximum_entry_bytes = 128ULL * 1024ULL * 1024ULL;
    std::uint64_t maximum_total_bytes = 512ULL * 1024ULL * 1024ULL;
    std::uint32_t maximum_ratio = 200U;
};

[[nodiscard]] Result<EntrySummary> preflight(std::span<const std::byte> data) noexcept;
[[nodiscard]] Result<EntrySummary> inspect_deep(std::span<const std::byte> data,
                                                const InspectionBudget& budget) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const EntrySummary& summary) noexcept;

}  // namespace ai_shield::protocols::zip
