#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::abi_validation {

struct ValidationContext final {
    std::uint64_t expected_next_sequence = 0;
    std::uint64_t now_monotonic_ns = 0;
    std::uint64_t max_clock_skew_ns = 0;
    std::uint64_t known_flow_id = 0;
};

[[nodiscard]] Result<void> validate_flow_event_header(std::uint32_t abi_version,
                                                      std::uint32_t structure_size,
                                                      std::uint16_t flags) noexcept;
[[nodiscard]] Result<void> validate_flow_event(const abi::FlowEvent& event,
                                               ValidationContext context) noexcept;
[[nodiscard]] Result<void> validate_shield_decision(const abi::ShieldDecision& decision,
                                                    ValidationContext context) noexcept;

}  // namespace ai_shield::abi_validation
