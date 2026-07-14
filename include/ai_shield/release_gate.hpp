#pragma once

#include <cstdint>

namespace ai_shield::release_gate {

struct Metrics final {
    std::uint32_t soak_days = 0;
    std::uint32_t hardware_profiles = 0;
    bool bugcheck_free = false;
    bool deadlock_free = false;
    bool known_attack_corpus_blocked = false;
    std::uint32_t benign_false_block_ppm = 0;
    std::uint32_t mutation_campaign_detection_percent = 0;
    bool consequence_guard_complete = false;
    std::uint32_t throughput_percent = 0;
    std::uint32_t p99_fastpath_us = 0;
    bool recovery_drill_passed = false;
};

struct GateReport final {
    bool release_allowed = false;
    std::uint32_t failed_checks = 0;
};

[[nodiscard]] GateReport evaluate(Metrics metrics) noexcept;

}  // namespace ai_shield::release_gate
