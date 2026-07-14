#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::http2 {

struct FrameSummary final {
    std::uint32_t frame_count = 0;
    std::uint32_t header_bytes = 0;
    std::uint32_t max_stream_id = 0;
    bool malformed = false;
    bool header_budget_exceeded = false;
    bool stream_state_anomaly = false;
};

[[nodiscard]] Result<FrameSummary> preflight(std::span<const std::byte> data,
                                             std::uint32_t header_budget_bytes,
                                             std::uint32_t max_stream_id) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const FrameSummary& summary) noexcept;

}  // namespace ai_shield::protocols::http2
