#pragma once

#include <cstdint>

#include "ai_shield/health.hpp"

namespace ai_shield::diagnostics {

struct Snapshot final {
    std::uint32_t active_flows = 0;
    std::uint32_t pending_decisions = 0;
    std::uint32_t sandbox_capacity = 0;
    std::uint32_t worker_circuits_open = 0;
    health::Degradation health{};
};

[[nodiscard]] bool protection_degraded(const Snapshot& snapshot) noexcept;

}  // namespace ai_shield::diagnostics
