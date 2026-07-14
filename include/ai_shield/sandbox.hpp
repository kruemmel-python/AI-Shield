#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/detection.hpp"

namespace ai_shield::sandbox {

enum class Tier : std::uint32_t {
    appcontainer_fast,
    hyperv_isolated
};

enum class Outcome : std::uint32_t {
    clean,
    suspicious,
    exploit_signal,
    timeout,
    crash,
    instrumentation_gap
};

struct ResultSummary final {
    Tier tier = Tier::appcontainer_fast;
    Outcome outcome = Outcome::instrumentation_gap;
    bool attempted_network = false;
    bool attempted_host_profile = false;
    bool created_executable = false;
    std::uint32_t event_count = 0;
};

[[nodiscard]] detection::Evidence evidence_from(const ResultSummary& summary) noexcept;

}  // namespace ai_shield::sandbox
