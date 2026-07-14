#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/detection.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::policy {

enum class ProtectionMode : std::uint32_t {
    learning,
    balanced,
    strict
};

enum class DecisionBand : std::uint32_t {
    allow,
    allow_monitored,
    deep_inspection,
    redirect_sandbox,
    quarantine_or_drop,
    block_origin
};

struct PolicyContext final {
    std::uint64_t decision_id = 0;
    std::uint64_t flow_id = 0;
    std::uint64_t now_monotonic_ns = 0;
    bool critical_service = true;
    bool runtime_gate_active = true;
    ProtectionMode mode = ProtectionMode::balanced;
};

[[nodiscard]] abi::ShieldDecision decide(const PolicyContext& context,
                                         const detection::Evidence& evidence,
                                         const crypto::Sha256Digest& evidence_hash) noexcept;
[[nodiscard]] DecisionBand band_for_score(std::uint16_t risk_score) noexcept;

}  // namespace ai_shield::policy
