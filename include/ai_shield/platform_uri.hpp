#pragma once

#include <string>
#include <string_view>

#include "ai_shield/result.hpp"

namespace ai_shield::platform {

[[nodiscard]] Result<std::string> normalize_path_uri(std::string_view platform_path);

}  // namespace ai_shield::platform
