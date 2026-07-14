#include "ai_shield/risk.hpp"

namespace ai_shield::risk {

RiskScore score(const detection::Evidence& evidence) noexcept {
    const std::uint32_t total = static_cast<std::uint32_t>(evidence.hard_rule) + evidence.signature + evidence.protocol +
                                evidence.novelty + evidence.adaptivity + evidence.campaign + evidence.consequence +
                                evidence.target_criticality + evidence.sensor_integrity;
    return RiskScore{static_cast<std::uint16_t>(total > 65535U ? 65535U : total),
                     evidence.hard_rule >= 100U || evidence.signature >= 100U || evidence.consequence >= 100U};
}

}  // namespace ai_shield::risk
