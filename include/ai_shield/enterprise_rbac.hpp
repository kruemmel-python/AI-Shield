#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/result.hpp"

namespace ai_shield::enterprise::rbac {

enum class Role : std::uint32_t {
    viewer, analyst, responder, policy_author, policy_approver, recovery_operator, auditor, platform_admin
};

enum class Capability : std::uint32_t {
    read_telemetry, export_audit, execute_response, author_policy, approve_policy,
    approve_high_impact_response, start_restore, approve_restore, manage_devices
};

struct Principal final {
    std::uint64_t actor_id = 0;
    Role role = Role::viewer;
    bool enabled = true;
};

struct Approval final {
    std::uint64_t actor_id = 0;
    Role role = Role::viewer;
    std::uint64_t approved_at_ns = 0;
};

[[nodiscard]] bool permits(Role role, Capability capability) noexcept;
[[nodiscard]] Result<void> authorize(const Principal& principal, Capability capability) noexcept;
[[nodiscard]] Result<void> require_dual_control(std::span<const Approval> approvals,
                                                Capability capability,
                                                std::uint64_t issued_at_ns,
                                                std::uint64_t expires_at_ns) noexcept;

}  // namespace ai_shield::enterprise::rbac
