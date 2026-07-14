#include "ai_shield/json_preflight.hpp"

#include <cctype>

namespace ai_shield::protocols::json {

Result<ParseSummary> preflight(std::string_view input, std::uint32_t depth_budget) noexcept {
    ParseSummary summary{};
    if (depth_budget == 0U || input.size() > 1024U * 1024U) {
        return Status::out_of_budget;
    }

    std::uint32_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    bool expecting_key = false;
    bool key_has_colon = false;

    for (const unsigned char ch : input) {
        if (in_string) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                in_string = false;
                ++summary.string_count;
                if (expecting_key && !key_has_colon) {
                    key_has_colon = true;
                }
                continue;
            }
            if (ch < 0x20U) {
                summary.control_character = true;
                summary.malformed = true;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (ch == '{' || ch == '[') {
            ++depth;
            if (depth > summary.max_depth) {
                summary.max_depth = depth;
            }
            if (depth > depth_budget) {
                summary.depth_budget_exceeded = true;
                summary.malformed = true;
                return summary;
            }
            expecting_key = ch == '{';
            key_has_colon = false;
            continue;
        }
        if (ch == '}' || ch == ']') {
            if (depth == 0U) {
                summary.malformed = true;
                return summary;
            }
            --depth;
            expecting_key = false;
            key_has_colon = false;
            continue;
        }
        if (ch == ':') {
            key_has_colon = true;
            continue;
        }
        if (ch == ',') {
            if (expecting_key && !key_has_colon) {
                summary.duplicate_object_key_risk = true;
            }
            key_has_colon = false;
            continue;
        }
        if (std::isdigit(ch) != 0) {
            ++summary.number_count;
            continue;
        }
        if (std::isspace(ch) != 0 || ch == '-' || ch == '.' || ch == 't' || ch == 'f' || ch == 'n' ||
            ch == 'r' || ch == 'u' || ch == 'e' || ch == 'a' || ch == 'l' || ch == 's') {
            continue;
        }
        summary.malformed = true;
        return summary;
    }
    if (in_string || depth != 0U) {
        summary.malformed = true;
    }
    return summary;
}

detection::Evidence evidence_from(const ParseSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 70;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.depth_budget_exceeded) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    if (summary.duplicate_object_key_risk || summary.max_depth > 32U) {
        evidence.novelty = 35;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::json
