#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::baseline {

struct FlowSample final {
    std::uint64_t service_id = 0;
    std::uint32_t bytes_in = 0;
    std::uint32_t bytes_out = 0;
    std::uint32_t segment_count = 0;
    std::uint32_t duration_ms = 0;
};

class FlowBaseline final {
public:
    [[nodiscard]] Result<void> learn(const FlowSample& sample);
    [[nodiscard]] detection::Evidence score(const FlowSample& sample) const;

private:
    struct State final {
        std::uint64_t service_id = 0;
        double mean_bytes = 0.0;
        double mean_segments = 0.0;
        std::uint32_t count = 0;
    };

    [[nodiscard]] State* find(std::uint64_t service_id) noexcept;
    [[nodiscard]] const State* find(std::uint64_t service_id) const noexcept;

    std::vector<State> states_;
};

}  // namespace ai_shield::baseline
