#include "ai_shield/release_gate.hpp"

namespace ai_shield::release_gate {

GateReport evaluate(Metrics metrics) noexcept {
    std::uint32_t failed = 0;
    failed += metrics.soak_days >= 30U ? 0U : 1U;
    failed += metrics.hardware_profiles >= 10U ? 0U : 1U;
    failed += metrics.bugcheck_free ? 0U : 1U;
    failed += metrics.deadlock_free ? 0U : 1U;
    failed += metrics.known_attack_corpus_blocked ? 0U : 1U;
    failed += metrics.benign_false_block_ppm < 100U ? 0U : 1U;
    failed += metrics.mutation_campaign_detection_percent >= 95U ? 0U : 1U;
    failed += metrics.consequence_guard_complete ? 0U : 1U;
    failed += metrics.throughput_percent >= 90U ? 0U : 1U;
    failed += metrics.p99_fastpath_us <= 250U ? 0U : 1U;
    failed += metrics.recovery_drill_passed ? 0U : 1U;
    return GateReport{.release_allowed = failed == 0U, .failed_checks = failed};
}

}  // namespace ai_shield::release_gate
