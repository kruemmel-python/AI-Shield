#include "ai_shield/diagnostics.hpp"

namespace ai_shield::diagnostics {

bool protection_degraded(const Snapshot& snapshot) noexcept {
    return snapshot.health.sensor_integrity_score >= 70U || snapshot.sandbox_capacity == 0U ||
           snapshot.worker_circuits_open > 0U;
}

}  // namespace ai_shield::diagnostics
