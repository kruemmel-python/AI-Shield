#pragma once

#include <cstdint>

namespace ai_shield::fuzz_plan {

struct CorpusStatus final {
    bool has_seed_corpus = false;
    bool has_roundtrip_invariants = false;
    bool has_length_offset_invariants = false;
    bool has_unicode_cases = false;
    std::uint64_t aggregate_test_cases = 0;
    std::uint32_t cpu_days = 0;
};

struct Readiness final {
    bool accepted = false;
    std::uint32_t missing_checks = 0;
};

[[nodiscard]] Readiness assess(CorpusStatus status) noexcept;

}  // namespace ai_shield::fuzz_plan
