#include "ai_shield/policy_authorization.hpp"

namespace ai_shield::policy_authorization {

Result<void> authorize(PolicyChange change) noexcept {
    if (change.actor_id == 0U || !change.admin) {
        return Status::integrity_failure;
    }
    if (change.high_risk && !change.local_confirmation) {
        return Status::invalid_state_transition;
    }
    return {};
}

}  // namespace ai_shield::policy_authorization
