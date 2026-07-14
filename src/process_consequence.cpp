#include "ai_shield/process_consequence.hpp"

#include <algorithm>
#include <cctype>
#include <string>

#include "ai_shield/abi.hpp"

namespace ai_shield::process_consequence {
namespace {

[[nodiscard]] std::string lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char ch : text) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

[[nodiscard]] bool contains_forbidden_interpreter(std::string_view image, std::string_view command) {
    const auto haystack = lower_copy(std::string(image) + " " + std::string(command));
    return haystack.find("powershell") != std::string::npos || haystack.find("cmd.exe") != std::string::npos ||
           haystack.find("mshta") != std::string::npos || haystack.find("wscript") != std::string::npos ||
           haystack.find("cscript") != std::string::npos || haystack.find("rundll32") != std::string::npos;
}

}  // namespace

detection::Evidence evaluate_create_process(const ProcessEvidence& event) noexcept {
    detection::Evidence evidence{};
    if (!event.parent_external_influenced) {
        return evidence;
    }
    if (contains_forbidden_interpreter(event.image_path, event.command_line)) {
        evidence.hard_rule = 100;
        evidence.consequence = 100;
        evidence.reason_mask |= abi::ReasonCode::command_execution | abi::ReasonCode::consequence_detected;
    }
    if (event.child_signature == SignatureState::unsigned_image || event.child_signature == SignatureState::invalid_signature) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 70U);
        evidence.reason_mask |= abi::ReasonCode::external_exec_pending;
    }
    return evidence;
}

}  // namespace ai_shield::process_consequence
