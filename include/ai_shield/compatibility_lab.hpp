#pragma once

#include <cstdint>

namespace ai_shield::compat {

struct LabResult final {
    bool hvci_enabled = false;
    bool secure_boot_enabled = false;
    bool verifier_72h_passed = false;
    bool hlk_passed = false;
    bool vpn_clients_passed = false;
    bool hyperv_passed = false;
    bool defender_passed = false;
    std::uint32_t hardware_profiles = 0;
};

struct Gate final {
    bool accepted = false;
    std::uint32_t failed_checks = 0;
};

[[nodiscard]] Gate evaluate(LabResult result) noexcept;

}  // namespace ai_shield::compat
