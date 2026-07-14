#include "ai_shield/fuzz_plan.hpp"

namespace ai_shield::fuzz_plan {

Readiness assess(CorpusStatus status) noexcept {
    std::uint32_t missing = 0;
    missing += status.has_seed_corpus ? 0U : 1U;
    missing += status.has_roundtrip_invariants ? 0U : 1U;
    missing += status.has_length_offset_invariants ? 0U : 1U;
    missing += status.has_unicode_cases ? 0U : 1U;
    const bool volume_ok = status.aggregate_test_cases >= 1'000'000'000ULL || status.cpu_days >= 30U;
    missing += volume_ok ? 0U : 1U;
    return Readiness{.accepted = missing == 0U, .missing_checks = missing};
}

}  // namespace ai_shield::fuzz_plan
