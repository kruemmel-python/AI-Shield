#pragma once

#include <cstdint>

#include "ai_shield/sandbox.hpp"

namespace ai_shield::sandbox_budget {

struct Budget final {
    std::uint64_t wall_time_ns = 0;
    std::uint64_t memory_bytes = 0;
    std::uint32_t max_processes = 0;
    bool network_allowed = false;
};

[[nodiscard]] Budget budget_for(sandbox::Tier tier, std::uint16_t risk_score) noexcept;
[[nodiscard]] bool exceeded(const Budget& budget,
                            std::uint64_t elapsed_ns,
                            std::uint64_t memory_bytes,
                            std::uint32_t process_count) noexcept;

}  // namespace ai_shield::sandbox_budget
