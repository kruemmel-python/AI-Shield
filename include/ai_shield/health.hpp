#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/abi.hpp"

namespace ai_shield::health {

enum class SensorKind : std::uint32_t {
    wfp,
    filesystem,
    process_guard,
    etw,
    sandbox,
    audit
};

enum class SensorState : std::uint32_t {
    healthy,
    delayed,
    degraded,
    failed
};

struct SensorReport final {
    SensorKind kind = SensorKind::wfp;
    SensorState state = SensorState::healthy;
    std::uint64_t last_sequence = 0;
    std::uint64_t missing_sequences = 0;
    std::uint64_t last_monotonic_ns = 0;
};

struct Degradation final {
    std::uint16_t sensor_integrity_score = 0;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] Degradation assess(const SensorReport& report) noexcept;
[[nodiscard]] Degradation aggregate(std::span<const SensorReport> reports) noexcept;

}  // namespace ai_shield::health
