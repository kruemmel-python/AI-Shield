#pragma once

#include <cstdint>

namespace ai_shield::broker {

struct HostCapacity final {
    std::uint32_t logical_cores = 0;
    std::uint32_t reserved_cores = 0;
};

struct RuntimePlan final {
    std::uint32_t worker_count = 0;
    bool iocp_model = true;
};

[[nodiscard]] RuntimePlan plan_workers(HostCapacity capacity) noexcept;

}  // namespace ai_shield::broker
