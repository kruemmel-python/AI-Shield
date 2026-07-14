#include "ai_shield/detection.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <string>

namespace ai_shield::detection {

std::uint16_t clipped_score(std::uint32_t value) noexcept {
    return static_cast<std::uint16_t>(std::min<std::uint32_t>(value, 100U));
}

Evidence inspect_text(std::string_view payload) noexcept {
    Evidence evidence{};
    std::string lower;
    lower.reserve(payload.size());
    for (const unsigned char ch : payload) {
        lower.push_back(static_cast<char>(std::tolower(ch)));
    }

    const auto contains = [&](std::string_view needle) noexcept {
        return lower.find(needle) != std::string::npos;
    };

    if (contains("../") || contains("..%2f") || contains("%2e%2e")) {
        evidence.hard_rule = 100;
        evidence.protocol = clipped_score(evidence.protocol + 45U);
        evidence.reason_mask |= abi::ReasonCode::path_traversal;
    }
    if (contains("cmd.exe") || contains("powershell") || contains("/bin/sh") || contains("mshta")) {
        evidence.hard_rule = 100;
        evidence.consequence = clipped_score(evidence.consequence + 80U);
        evidence.reason_mask |= abi::ReasonCode::command_execution;
    }
    if (contains("content-length:") && contains("transfer-encoding: chunked")) {
        evidence.protocol = clipped_score(evidence.protocol + 70U);
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    if (contains("jndi:ldap") || contains("meterpreter") || contains("mimikatz")) {
        evidence.signature = 100;
        evidence.reason_mask |= abi::ReasonCode::signature_match;
    }
    if (payload.size() > 64U * 1024U) {
        evidence.novelty = clipped_score(evidence.novelty + 20U);
    }
    return evidence;
}

Evidence inspect_payload(std::span<const std::byte> payload) noexcept {
    std::string text;
    text.reserve(payload.size());
    for (const auto byte : payload) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return inspect_text(text);
}

}  // namespace ai_shield::detection
