#pragma once

#include <cstdint>
#include <string_view>

#include "ai_shield/detection.hpp"

namespace ai_shield::process_consequence {

enum class SignatureState : std::uint32_t {
    unknown,
    unsigned_image,
    trusted_signed,
    invalid_signature
};

struct ProcessEvidence final {
    std::uint64_t parent_process_id = 0;
    std::uint64_t child_process_id = 0;
    std::uint64_t inherited_flow_id = 0;
    bool parent_external_influenced = false;
    SignatureState child_signature = SignatureState::unknown;
    std::string_view image_path;
    std::string_view command_line;
};

[[nodiscard]] detection::Evidence evaluate_create_process(const ProcessEvidence& event) noexcept;

}  // namespace ai_shield::process_consequence
