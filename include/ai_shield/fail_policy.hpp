#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"

namespace ai_shield::fail_policy {

enum class ServiceClass : std::uint32_t {
    admin_management,
    file_download,
    web_api,
    media_game,
    unregistered
};

enum class FailureKind : std::uint32_t {
    ai,
    sandbox,
    core
};

struct FailureDecision final {
    abi::ShieldAction action = abi::ShieldAction::block_origin;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] FailureDecision decide(ServiceClass service_class, FailureKind failure, std::uint16_t current_risk) noexcept;

}  // namespace ai_shield::fail_policy
