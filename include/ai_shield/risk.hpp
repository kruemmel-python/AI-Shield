#pragma once

#include <cstdint>

#include "ai_shield/detection.hpp"

namespace ai_shield::risk {

struct RiskScore final {
    std::uint16_t total = 0;
    bool hard_block = false;
};

[[nodiscard]] RiskScore score(const detection::Evidence& evidence) noexcept;

}  // namespace ai_shield::risk
