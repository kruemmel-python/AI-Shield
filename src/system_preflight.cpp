#include "ai_shield/system_preflight.hpp"

namespace ai_shield::system_preflight {

PreflightReport evaluate(SystemFacts facts) noexcept {
    std::uint32_t failures = 0;
    failures += facts.supported_edition ? 0U : 1U;
    failures += facts.secure_boot ? 0U : 1U;
    failures += facts.tpm2 ? 0U : 1U;
    failures += facts.virtualization ? 0U : 1U;
    failures += facts.hvci_compatible ? 0U : 1U;
    failures += facts.enough_disk ? 0U : 1U;
    failures += facts.conflicting_driver ? 1U : 0U;
    return PreflightReport{.install_allowed = failures == 0U, .failure_count = failures};
}

}  // namespace ai_shield::system_preflight
