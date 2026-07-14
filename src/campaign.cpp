#include "ai_shield/campaign.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::campaign {

detection::Evidence Tracker::observe(const Observation& observation) noexcept {
    detection::Evidence evidence{};
    std::uint32_t same_target_count = 0;
    std::uint32_t source_spread = 0;
    bool response_adaptive = false;
    for (std::uint32_t i = 0; i < count_ && i < ring_.size(); ++i) {
        const auto& previous = ring_[i];
        if (previous.target_service_id == observation.target_service_id) {
            ++same_target_count;
            if (previous.source_id != observation.source_id) {
                ++source_spread;
            }
            if (observation.follows_previous_response && previous.response_class == observation.response_class &&
                observation.mutation_distance > previous.mutation_distance) {
                response_adaptive = true;
            }
        }
    }
    if (same_target_count >= 3U && source_spread >= 2U) {
        evidence.campaign = 80;
        evidence.reason_mask |= abi::ReasonCode::campaign_correlation;
    }
    if (response_adaptive || observation.mutation_distance > 50U) {
        evidence.adaptivity = 80;
        evidence.reason_mask |= abi::ReasonCode::adaptive_mutation;
    }
    ring_[cursor_] = observation;
    cursor_ = (cursor_ + 1U) % static_cast<std::uint32_t>(ring_.size());
    if (count_ < ring_.size()) {
        ++count_;
    }
    return evidence;
}

}  // namespace ai_shield::campaign
