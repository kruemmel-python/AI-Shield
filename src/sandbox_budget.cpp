#include "ai_shield/sandbox_budget.hpp"

namespace ai_shield::sandbox_budget {

Budget budget_for(sandbox::Tier tier, std::uint16_t risk_score) noexcept {
    if (tier == sandbox::Tier::hyperv_isolated) {
        return Budget{risk_score >= 90U ? 2'000'000'000ULL : 750'000'000ULL,
                      1536ULL * 1024ULL * 1024ULL,
                      8,
                      false};
    }
    return Budget{risk_score >= 75U ? 250'000'000ULL : 80'000'000ULL, 512ULL * 1024ULL * 1024ULL, 4, false};
}

bool exceeded(const Budget& budget, std::uint64_t elapsed_ns, std::uint64_t memory_bytes, std::uint32_t process_count) noexcept {
    return elapsed_ns > budget.wall_time_ns || memory_bytes > budget.memory_bytes || process_count > budget.max_processes;
}

}  // namespace ai_shield::sandbox_budget
