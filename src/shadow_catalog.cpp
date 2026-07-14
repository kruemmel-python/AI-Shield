#include "ai_shield/shadow_catalog.hpp"

namespace ai_shield::shadow {

Result<void> Catalog::add(Target target) {
    if (target.service_id == 0U || target.p99_budget_ns == 0U) {
        return Status::invalid_argument;
    }
    targets_.push_back(target);
    return {};
}

Result<Target> Catalog::select(std::uint64_t service_id, std::uint16_t risk_score) const noexcept {
    for (const auto& target : targets_) {
        if (target.service_id == service_id) {
            auto selected = target;
            if (risk_score >= 90U) {
                selected.tier = sandbox::Tier::hyperv_isolated;
                selected.p99_budget_ns = selected.p99_budget_ns < 2'000'000'000ULL ? 2'000'000'000ULL : selected.p99_budget_ns;
            }
            return selected;
        }
    }
    return Status::not_found;
}

}  // namespace ai_shield::shadow
