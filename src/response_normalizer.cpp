#include "ai_shield/response_normalizer.hpp"

namespace ai_shield::response {

std::string external_response_for(abi::ShieldAction action) noexcept {
    switch (action) {
        case abi::ShieldAction::allow:
        case abi::ShieldAction::allow_monitored:
            return "ok";
        case abi::ShieldAction::rate_limit:
            return "temporary_unavailable";
        case abi::ShieldAction::redirect_sandbox:
        case abi::ShieldAction::quarantine:
        case abi::ShieldAction::drop_flow:
        case abi::ShieldAction::block_origin:
        case abi::ShieldAction::suspend_target:
            return "request_not_processed";
    }
    return "request_not_processed";
}

}  // namespace ai_shield::response
