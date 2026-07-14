#pragma once

#include <cstdint>

#include "ai_shield/package_manifest.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::update {

enum class Slot : std::uint32_t {
    a,
    b,
    recovery
};

enum class SlotState : std::uint32_t {
    empty,
    staged,
    active,
    failed,
    recovery
};

struct SlotInfo final {
    Slot slot = Slot::a;
    SlotState state = SlotState::empty;
    std::uint64_t security_version = 0;
};

struct BootHealth final {
    bool drivers_loaded = false;
    bool core_started = false;
    bool audit_writable = false;
    bool policy_loaded = false;
};

class Manager final {
public:
    [[nodiscard]] Result<void> stage(const package::Manifest& manifest, const package::TrustAnchor& trust);
    [[nodiscard]] Result<void> activate_staged() noexcept;
    [[nodiscard]] Result<void> commit_boot(const BootHealth& health) noexcept;
    [[nodiscard]] Slot active_slot() const noexcept { return active_; }
    [[nodiscard]] Slot staged_slot() const noexcept { return staged_; }
    [[nodiscard]] SlotInfo slot_info(Slot slot) const noexcept;

private:
    Slot active_ = Slot::a;
    Slot staged_ = Slot::b;
    Slot previous_active_ = Slot::a;
    SlotInfo slots_[3] = {{Slot::a, SlotState::active, 1}, {Slot::b, SlotState::empty, 0}, {Slot::recovery, SlotState::recovery, 1}};
};

}  // namespace ai_shield::update
