#include "ai_shield/compatibility_lab.hpp"

namespace ai_shield::compat {

Gate evaluate(LabResult result) noexcept {
    std::uint32_t failed = 0;
    failed += result.hvci_enabled ? 0U : 1U;
    failed += result.secure_boot_enabled ? 0U : 1U;
    failed += result.verifier_72h_passed ? 0U : 1U;
    failed += result.hlk_passed ? 0U : 1U;
    failed += result.vpn_clients_passed ? 0U : 1U;
    failed += result.hyperv_passed ? 0U : 1U;
    failed += result.defender_passed ? 0U : 1U;
    failed += result.hardware_profiles >= 10U ? 0U : 1U;
    return Gate{.accepted = failed == 0U, .failed_checks = failed};
}

}  // namespace ai_shield::compat
