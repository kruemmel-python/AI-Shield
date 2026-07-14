#pragma once

#include "ai_shield/result.hpp"

namespace ai_shield {

enum class FlowState {
    fresh,
    authorized,
    proxied,
    classifying,
    inspecting,
    sandbox_pending,
    allowed,
    active,
    blocked,
    quarantined,
    closed
};

[[nodiscard]] constexpr bool can_transition(FlowState from, FlowState to) noexcept {
    switch (from) {
        case FlowState::fresh:
            return to == FlowState::authorized || to == FlowState::blocked;
        case FlowState::authorized:
            return to == FlowState::proxied || to == FlowState::classifying || to == FlowState::blocked;
        case FlowState::proxied:
            return to == FlowState::classifying || to == FlowState::inspecting || to == FlowState::closed;
        case FlowState::classifying:
            return to == FlowState::inspecting || to == FlowState::sandbox_pending || to == FlowState::allowed ||
                   to == FlowState::blocked || to == FlowState::quarantined;
        case FlowState::inspecting:
            return to == FlowState::sandbox_pending || to == FlowState::allowed || to == FlowState::blocked ||
                   to == FlowState::quarantined;
        case FlowState::sandbox_pending:
            return to == FlowState::allowed || to == FlowState::blocked || to == FlowState::quarantined;
        case FlowState::allowed:
            return to == FlowState::active || to == FlowState::closed;
        case FlowState::active:
            return to == FlowState::closed || to == FlowState::blocked || to == FlowState::quarantined;
        case FlowState::blocked:
        case FlowState::quarantined:
            return to == FlowState::closed;
        case FlowState::closed:
            return false;
    }
    return false;
}

class FlowStateMachine final {
public:
    [[nodiscard]] constexpr FlowState state() const noexcept { return state_; }

    constexpr Result<void> transition(FlowState next) noexcept {
        if (!can_transition(state_, next)) {
            return Status::invalid_state_transition;
        }
        state_ = next;
        return {};
    }

private:
    FlowState state_ = FlowState::fresh;
};

}  // namespace ai_shield
