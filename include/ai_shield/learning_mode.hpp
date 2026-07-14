#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"

namespace ai_shield::learning {

constexpr std::uint64_t kMaxLearningDurationNs = 14ULL * 24ULL * 60ULL * 60ULL * 1'000'000'000ULL;

enum class LearningMode : std::uint8_t {
    disabled,
    observation_only,
    shadow_candidate_generation,
    offline_validation
};

struct LearningWindow final {
    bool enabled = false;
    LearningMode mode = LearningMode::disabled;
    std::uint64_t started_monotonic_ns = 0;
    std::uint64_t now_monotonic_ns = 0;
};

struct DecisionOverride final {
    abi::ShieldAction action = abi::ShieldAction::allow;
    bool hard_rules_remain_active = true;
    bool expired = false;
};

[[nodiscard]] DecisionOverride apply(LearningWindow window,
                                     std::uint32_t reason_mask,
                                     std::uint16_t risk_score) noexcept;

}  // namespace ai_shield::learning
