#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"

namespace ai_shield::backpressure {

struct Limits final {
    std::uint32_t per_flow_bytes = 0;
    std::uint32_t per_source_flows = 0;
    std::uint32_t per_service_flows = 0;
    std::uint32_t global_flows = 0;
};

struct Usage final {
    std::uint32_t flow_bytes = 0;
    std::uint32_t source_flows = 0;
    std::uint32_t service_flows = 0;
    std::uint32_t total_flows = 0;
};

struct Decision final {
    abi::ShieldAction action = abi::ShieldAction::allow;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] Decision decide(Limits limits, Usage usage) noexcept;

}  // namespace ai_shield::backpressure
