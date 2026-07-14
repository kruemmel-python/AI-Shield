#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/sandbox.hpp"

namespace ai_shield::shadow {

enum class TargetKind : std::uint32_t {
    http_service,
    parser,
    download,
    multi_flow
};

struct Target final {
    std::uint64_t service_id = 0;
    TargetKind kind = TargetKind::parser;
    sandbox::Tier tier = sandbox::Tier::appcontainer_fast;
    std::uint64_t p99_budget_ns = 250'000'000ULL;
};

class Catalog final {
public:
    [[nodiscard]] Result<void> add(Target target);
    [[nodiscard]] Result<Target> select(std::uint64_t service_id, std::uint16_t risk_score) const noexcept;

private:
    std::vector<Target> targets_;
};

}  // namespace ai_shield::shadow
