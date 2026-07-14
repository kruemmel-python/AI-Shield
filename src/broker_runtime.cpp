#include "ai_shield/broker_runtime.hpp"

namespace ai_shield::broker {

RuntimePlan plan_workers(HostCapacity capacity) noexcept {
    std::uint32_t usable = capacity.logical_cores > capacity.reserved_cores
                               ? capacity.logical_cores - capacity.reserved_cores
                               : 0U;
    if (usable < 2U) {
        usable = 2U;
    }
    if (usable > 16U) {
        usable = 16U;
    }
    return RuntimePlan{.worker_count = usable, .iocp_model = true};
}

}  // namespace ai_shield::broker
