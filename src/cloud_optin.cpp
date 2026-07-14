#include "ai_shield/cloud_optin.hpp"

namespace ai_shield::cloud {

Result<void> authorize_transfer(TransferRequest request) noexcept {
    if (!request.admin_opt_in) {
        return Status::integrity_failure;
    }
    if (request.requested_bytes == 0U || request.requested_bytes > request.max_bytes) {
        return Status::out_of_budget;
    }
    if (request.contains_payload && !request.payload_export_enabled) {
        return Status::invalid_state_transition;
    }
    return {};
}

}  // namespace ai_shield::cloud
