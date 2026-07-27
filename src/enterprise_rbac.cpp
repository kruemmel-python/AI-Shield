#include "ai_shield/enterprise_rbac.hpp"

namespace ai_shield::enterprise::rbac {

bool permits(Role role, Capability capability) noexcept {
    switch (capability) {
        case Capability::read_telemetry: return role != Role::policy_author;
        case Capability::export_audit:
            return role == Role::auditor || role == Role::analyst || role == Role::platform_admin;
        case Capability::execute_response: return role == Role::responder || role == Role::platform_admin;
        case Capability::author_policy: return role == Role::policy_author;
        case Capability::approve_policy: return role == Role::policy_approver;
        case Capability::approve_high_impact_response:
            return role == Role::policy_approver || role == Role::recovery_operator;
        case Capability::start_restore: return role == Role::recovery_operator;
        case Capability::approve_restore: return role == Role::policy_approver;
        case Capability::manage_devices: return role == Role::platform_admin;
    }
    return false;
}

Result<void> authorize(const Principal& principal, Capability capability) noexcept {
    if (principal.actor_id == 0U || !principal.enabled || !permits(principal.role, capability))
        return Status::integrity_failure;
    return {};
}

Result<void> require_dual_control(std::span<const Approval> approvals, Capability capability,
                                  std::uint64_t issued_at_ns, std::uint64_t expires_at_ns) noexcept {
    if (issued_at_ns == 0U || expires_at_ns <= issued_at_ns)
        return Status::invalid_argument;
    if (approvals.size() < 2U) return Status::integrity_failure;
    std::uint64_t first_actor = 0;
    std::uint64_t second_actor = 0;
    for (const auto& approval : approvals) {
        if (approval.actor_id == 0U || approval.approved_at_ns < issued_at_ns ||
            approval.approved_at_ns >= expires_at_ns || !permits(approval.role, capability))
            continue;
        if (first_actor == 0U) first_actor = approval.actor_id;
        else if (approval.actor_id != first_actor) {
            second_actor = approval.actor_id;
            break;
        }
    }
    return first_actor != 0U && second_actor != 0U ? Result<void>{}
                                                   : Result<void>{Status::integrity_failure};
}

}  // namespace ai_shield::enterprise::rbac
