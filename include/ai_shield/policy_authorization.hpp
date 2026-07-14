#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"

namespace ai_shield::policy_authorization {

struct PolicyChange final {
    std::uint64_t actor_id = 0;
    bool admin = false;
    bool high_risk = false;
    bool local_confirmation = false;
    std::uint32_t requested_reason_mask = 0;
};

[[nodiscard]] Result<void> authorize(PolicyChange change) noexcept;

}  // namespace ai_shield::policy_authorization
