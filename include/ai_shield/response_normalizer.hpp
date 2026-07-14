#pragma once

#include <string>

#include "ai_shield/abi.hpp"

namespace ai_shield::response {

[[nodiscard]] std::string external_response_for(abi::ShieldAction action) noexcept;

}  // namespace ai_shield::response
