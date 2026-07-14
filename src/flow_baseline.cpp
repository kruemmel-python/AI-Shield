#include "ai_shield/flow_baseline.hpp"

#include <cmath>

namespace ai_shield::baseline {
namespace {

[[nodiscard]] std::uint32_t total_bytes(const FlowSample& sample) noexcept {
    return sample.bytes_in + sample.bytes_out;
}

}  // namespace

FlowBaseline::State* FlowBaseline::find(std::uint64_t service_id) noexcept {
    for (auto& state : states_) {
        if (state.service_id == service_id) {
            return &state;
        }
    }
    return nullptr;
}

const FlowBaseline::State* FlowBaseline::find(std::uint64_t service_id) const noexcept {
    for (const auto& state : states_) {
        if (state.service_id == service_id) {
            return &state;
        }
    }
    return nullptr;
}

Result<void> FlowBaseline::learn(const FlowSample& sample) {
    if (sample.service_id == 0U) {
        return Status::invalid_argument;
    }
    auto* state = find(sample.service_id);
    if (state == nullptr) {
        states_.push_back(State{.service_id = sample.service_id,
                                .mean_bytes = static_cast<double>(total_bytes(sample)),
                                .mean_segments = static_cast<double>(sample.segment_count),
                                .count = 1});
        return {};
    }
    constexpr double alpha = 0.2;
    state->mean_bytes = (1.0 - alpha) * state->mean_bytes + alpha * static_cast<double>(total_bytes(sample));
    state->mean_segments = (1.0 - alpha) * state->mean_segments + alpha * static_cast<double>(sample.segment_count);
    ++state->count;
    return {};
}

detection::Evidence FlowBaseline::score(const FlowSample& sample) const {
    detection::Evidence evidence{};
    const auto* state = find(sample.service_id);
    if (state == nullptr || state->count < 3U) {
        evidence.novelty = 25;
        return evidence;
    }
    const auto bytes_ratio = state->mean_bytes > 0.0 ? static_cast<double>(total_bytes(sample)) / state->mean_bytes : 1.0;
    const auto segments_ratio = state->mean_segments > 0.0 ? static_cast<double>(sample.segment_count) / state->mean_segments : 1.0;
    const auto deviation = std::abs(bytes_ratio - 1.0) + std::abs(segments_ratio - 1.0);
    evidence.novelty = detection::clipped_score(static_cast<std::uint32_t>(deviation * 50.0));
    return evidence;
}

}  // namespace ai_shield::baseline
