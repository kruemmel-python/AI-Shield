#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/fail_policy.hpp"
#include "ai_shield/pending_decision.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/service_registry.hpp"

namespace ai_shield::platform::windows::wfp {

enum class KernelAction : std::uint32_t {
    allow,
    block,
    pend
};

struct FastPolicyInput final {
    ai_shield::service_registry::Admission admission{};
    bool broker_available = true;
    bool known_blocked_source = false;
    bool pending_capacity_available = true;
    ai_shield::fail_policy::ServiceClass service_class = ai_shield::fail_policy::ServiceClass::unregistered;
};

struct FastPolicyDecision final {
    KernelAction action = KernelAction::block;
    ai_shield::abi::ShieldAction fallback_action = ai_shield::abi::ShieldAction::drop_flow;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] FastPolicyDecision decide_fast_path(const FastPolicyInput& input) noexcept;

}  // namespace ai_shield::platform::windows::wfp
