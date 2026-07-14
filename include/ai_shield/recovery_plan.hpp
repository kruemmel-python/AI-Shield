#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"

namespace ai_shield::recovery {

enum class Severity : std::uint32_t {
    informational,
    suspicious,
    high,
    critical
};

struct ActionPlan final {
    abi::ShieldAction flow_action = abi::ShieldAction::allow;
    bool create_incident = false;
    bool reduce_network_access = false;
    bool suspend_target = false;
    bool lock_updates = false;
    bool local_alarm = false;
};

[[nodiscard]] ActionPlan plan_for(Severity severity) noexcept;

}  // namespace ai_shield::recovery
