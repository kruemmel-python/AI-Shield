#include "ai_shield/update_manager.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::update {
namespace {

[[nodiscard]] std::size_t index_of(Slot slot) noexcept {
    return slot == Slot::a ? 0U : (slot == Slot::b ? 1U : 2U);
}

[[nodiscard]] bool healthy(const BootHealth& health) noexcept {
    return health.drivers_loaded && health.core_started && health.audit_writable && health.policy_loaded;
}

}  // namespace

Result<void> Manager::stage(const package::Manifest& manifest, const package::TrustAnchor& trust) {
    const auto verified = package::verify_manifest(manifest, trust);
    if (!verified.ok()) {
        return verified.status();
    }
    const auto target = active_ == Slot::a ? Slot::b : Slot::a;
    staged_ = target;
    auto& slot = slots_[index_of(target)];
    slot.state = SlotState::staged;
    slot.security_version = manifest.security_version;
    return {};
}

Result<void> Manager::activate_staged() noexcept {
    auto& staged = slots_[index_of(staged_)];
    if (staged.state != SlotState::staged) {
        return Status::invalid_state_transition;
    }
    previous_active_ = active_;
    slots_[index_of(active_)].state = SlotState::empty;
    active_ = staged_;
    staged.state = SlotState::active;
    return {};
}

Result<void> Manager::commit_boot(const BootHealth& health) noexcept {
    if (healthy(health)) {
        previous_active_ = active_;
        return {};
    }
    slots_[index_of(active_)].state = SlotState::failed;
    active_ = previous_active_;
    slots_[index_of(active_)].state = SlotState::active;
    return Status::integrity_failure;
}

SlotInfo Manager::slot_info(Slot slot) const noexcept {
    return slots_[index_of(slot)];
}

}  // namespace ai_shield::update
