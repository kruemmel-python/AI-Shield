#pragma once

#include <cstdint>

#include "ai_shield/package_manifest.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::policy_store {

enum class PolicySlotState : std::uint32_t {
    empty,
    staged,
    active,
    rolled_back
};

struct ActivePolicy final {
    std::uint64_t policy_version = 0;
    std::uint64_t security_version = 0;
};

class Store final {
public:
    [[nodiscard]] Result<void> stage(const package::Manifest& manifest, const package::TrustAnchor& trust);
    [[nodiscard]] Result<void> activate(std::uint64_t expected_current_policy_version) noexcept;
    [[nodiscard]] Result<void> rollback() noexcept;
    [[nodiscard]] ActivePolicy active() const noexcept { return active_; }
    [[nodiscard]] PolicySlotState staged_state() const noexcept { return staged_state_; }

private:
    ActivePolicy active_{.policy_version = 1, .security_version = 1};
    ActivePolicy previous_{.policy_version = 1, .security_version = 1};
    ActivePolicy staged_{};
    PolicySlotState staged_state_ = PolicySlotState::empty;
};

}  // namespace ai_shield::policy_store
