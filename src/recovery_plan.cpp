#include "ai_shield/recovery_plan.hpp"

namespace ai_shield::recovery {

ActionPlan plan_for(Severity severity) noexcept {
    switch (severity) {
    case Severity::informational:
        return ActionPlan{.flow_action = abi::ShieldAction::allow_monitored};
    case Severity::suspicious:
        return ActionPlan{.flow_action = abi::ShieldAction::rate_limit};
    case Severity::high:
        return ActionPlan{.flow_action = abi::ShieldAction::drop_flow,
                          .create_incident = true,
                          .suspend_target = true};
    case Severity::critical:
        return ActionPlan{.flow_action = abi::ShieldAction::block_origin,
                          .create_incident = true,
                          .reduce_network_access = true,
                          .suspend_target = true,
                          .lock_updates = true,
                          .local_alarm = true};
    }
    return ActionPlan{.flow_action = abi::ShieldAction::drop_flow, .create_incident = true};
}

}  // namespace ai_shield::recovery
