#pragma once

#include <cstdint>

namespace ai_shield::system_preflight {

struct SystemFacts final {
    bool supported_edition = false;
    bool secure_boot = false;
    bool tpm2 = false;
    bool virtualization = false;
    bool hvci_compatible = false;
    bool enough_disk = false;
    bool conflicting_driver = false;
};

struct PreflightReport final {
    bool install_allowed = false;
    std::uint32_t failure_count = 0;
};

[[nodiscard]] PreflightReport evaluate(SystemFacts facts) noexcept;

}  // namespace ai_shield::system_preflight
