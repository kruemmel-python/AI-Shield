#pragma once

#include "ai_shield/process_consequence.hpp"

namespace ai_shield::process_guard {

using SignatureState = process_consequence::SignatureState;
using ProcessEvent = process_consequence::ProcessEvidence;

[[nodiscard]] inline detection::Evidence evaluate_create_process(const ProcessEvent& event) noexcept {
    return process_consequence::evaluate_create_process(event);
}

}  // namespace ai_shield::process_guard
