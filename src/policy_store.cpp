#include "ai_shield/policy_store.hpp"

namespace ai_shield::policy_store {

Result<void> Store::stage(const package::Manifest& manifest, const package::TrustAnchor& trust) {
    if (manifest.kind != package::PackageKind::policy) {
        return Status::invalid_argument;
    }
    const auto verified = package::verify_manifest(manifest, trust);
    if (!verified.ok()) {
        return verified.status();
    }
    staged_ = ActivePolicy{.policy_version = manifest.policy_version, .security_version = manifest.security_version};
    staged_state_ = PolicySlotState::staged;
    return {};
}

Result<void> Store::activate(std::uint64_t expected_current_policy_version) noexcept {
    if (staged_state_ != PolicySlotState::staged || staged_.policy_version == 0U) {
        return Status::invalid_state_transition;
    }
    if (active_.policy_version != expected_current_policy_version) {
        staged_state_ = PolicySlotState::rolled_back;
        return Status::integrity_failure;
    }
    previous_ = active_;
    active_ = staged_;
    staged_ = {};
    staged_state_ = PolicySlotState::active;
    return {};
}

Result<void> Store::rollback() noexcept {
    if (active_.policy_version == previous_.policy_version) {
        return Status::invalid_state_transition;
    }
    active_ = previous_;
    staged_state_ = PolicySlotState::rolled_back;
    return {};
}

}  // namespace ai_shield::policy_store
