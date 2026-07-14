#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "ai_shield/result.hpp"

namespace ai_shield::platform::windows::security {

struct TpmStatus final {
    bool provider_available = false;
    bool hardware_backed = false;
    bool key_available = false;
};

[[nodiscard]] TpmStatus tpm_status() noexcept;
[[nodiscard]] Result<void> ensure_tpm_anchor() noexcept;
[[nodiscard]] Result<std::vector<std::byte>> sign_tpm_challenge(std::span<const std::byte> challenge_hash) noexcept;

}  // namespace ai_shield::platform::windows::security
