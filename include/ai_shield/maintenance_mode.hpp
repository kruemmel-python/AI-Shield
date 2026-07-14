#pragma once

namespace ai_shield::maintenance {

struct MaintenanceGuard final {
    bool maintenance_mode = false;
    bool local_admin = false;
    bool audit_delete_confirmed = false;
};

[[nodiscard]] bool can_uninstall(MaintenanceGuard guard) noexcept;
[[nodiscard]] bool can_delete_audit(MaintenanceGuard guard) noexcept;

}  // namespace ai_shield::maintenance
