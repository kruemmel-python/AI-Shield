#include "ai_shield/signature_detector.hpp"

#include <string>

namespace ai_shield::signatures {

bool Detector::add_rule(Rule rule) {
    if (rule.rule_id == 0U || rule.severity == 0U) {
        return false;
    }
    if (rule.kind == RuleKind::substring && rule.pattern.empty()) {
        return false;
    }
    rules_.push_back(rule);
    return true;
}

detection::Evidence Detector::inspect(std::span<const std::byte> payload) const {
    detection::Evidence evidence{};
    std::string text;
    text.reserve(payload.size());
    for (const auto byte : payload) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    const auto payload_hash = crypto::sha256(payload);
    for (const auto& rule : rules_) {
        bool matched = false;
        if (rule.kind == RuleKind::payload_hash) {
            matched = crypto::constant_time_equal(payload_hash, rule.hash);
        } else {
            matched = text.find(rule.pattern) != std::string::npos;
        }
        if (matched) {
            evidence.signature = detection::clipped_score(static_cast<std::uint32_t>(evidence.signature) + rule.severity);
            evidence.reason_mask |= abi::ReasonCode::signature_match;
            if (rule.severity >= 100U) {
                evidence.hard_rule = 100;
            }
        }
    }
    return evidence;
}

}  // namespace ai_shield::signatures
