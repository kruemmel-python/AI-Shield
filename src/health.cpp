#include "ai_shield/health.hpp"

namespace ai_shield::health {

Degradation assess(const SensorReport& report) noexcept {
    Degradation degradation{};
    if (report.missing_sequences > 0U) {
        degradation.sensor_integrity_score = 60;
        degradation.reason_mask |= abi::ReasonCode::sensor_integrity_gap;
    }
    switch (report.state) {
        case SensorState::healthy:
            break;
        case SensorState::delayed:
            degradation.sensor_integrity_score = degradation.sensor_integrity_score < 35U ? 35U : degradation.sensor_integrity_score;
            degradation.reason_mask |= abi::ReasonCode::degraded_mode;
            break;
        case SensorState::degraded:
            degradation.sensor_integrity_score = degradation.sensor_integrity_score < 70U ? 70U : degradation.sensor_integrity_score;
            degradation.reason_mask |= abi::ReasonCode::degraded_mode;
            break;
        case SensorState::failed:
            degradation.sensor_integrity_score = 100;
            degradation.reason_mask |= abi::ReasonCode::degraded_mode | abi::ReasonCode::sensor_integrity_gap;
            break;
    }
    return degradation;
}

Degradation aggregate(std::span<const SensorReport> reports) noexcept {
    Degradation aggregate_result{};
    for (const auto& report : reports) {
        const auto one = assess(report);
        if (one.sensor_integrity_score > aggregate_result.sensor_integrity_score) {
            aggregate_result.sensor_integrity_score = one.sensor_integrity_score;
        }
        aggregate_result.reason_mask |= one.reason_mask;
    }
    return aggregate_result;
}

}  // namespace ai_shield::health
