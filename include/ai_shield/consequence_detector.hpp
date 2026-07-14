#pragma once

#include <cstdint>

#include "ai_shield/detection.hpp"

namespace ai_shield::consequence {

struct RuntimeEvent final {
    bool child_process = false;
    bool executable_file_created = false;
    bool executable_memory = false;
    bool sensitive_token_access = false;
    bool registry_persistence = false;
    bool unexpected_egress = false;
};

[[nodiscard]] detection::Evidence evaluate(RuntimeEvent event) noexcept;

}  // namespace ai_shield::consequence
