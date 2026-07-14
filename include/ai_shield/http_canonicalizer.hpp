#pragma once

#include <string>
#include <string_view>

#include "ai_shield/result.hpp"

namespace ai_shield::protocols::http1 {

[[nodiscard]] Result<std::string> canonicalize_request(std::string_view request);

}  // namespace ai_shield::protocols::http1
