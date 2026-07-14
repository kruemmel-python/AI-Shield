#include "ai_shield/maintenance_mode.hpp"

namespace ai_shield::maintenance {

bool can_uninstall(MaintenanceGuard guard) noexcept {
    return guard.local_admin && guard.maintenance_mode;
}

bool can_delete_audit(MaintenanceGuard guard) noexcept {
    return can_uninstall(guard) && guard.audit_delete_confirmed;
}

}  // namespace ai_shield::maintenance
