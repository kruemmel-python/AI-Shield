#include "ai_shield/xml_preflight.hpp"

#include "ai_shield/abi.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace ai_shield::protocols::xml {
namespace {

[[nodiscard]] std::string lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char ch : text) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

}  // namespace

Result<ParseSummary> preflight(std::string_view input, std::uint32_t depth_budget) noexcept {
    ParseSummary summary{};
    if (depth_budget == 0U || input.size() > 2U * 1024U * 1024U) {
        return Status::out_of_budget;
    }
    const auto lower = lower_copy(input);
    summary.doctype_seen = lower.find("<!doctype") != std::string::npos;
    summary.external_entity_risk = lower.find("system") != std::string::npos || lower.find("public") != std::string::npos;
    std::uint32_t depth = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '&') {
            ++summary.entity_reference_count;
        }
        if (input[i] != '<') {
            continue;
        }
        if (i + 1U >= input.size()) {
            summary.malformed = true;
            return summary;
        }
        const char next = input[i + 1U];
        if (next == '?' || next == '!') {
            continue;
        }
        if (next == '/') {
            if (depth == 0U) {
                summary.malformed = true;
                return summary;
            }
            --depth;
            continue;
        }
        ++summary.element_count;
        ++depth;
        summary.max_depth = std::max(summary.max_depth, depth);
        if (depth > depth_budget) {
            summary.depth_budget_exceeded = true;
            summary.malformed = true;
            return summary;
        }
        const auto close = input.find('>', i + 1U);
        if (close == std::string_view::npos) {
            summary.malformed = true;
            return summary;
        }
        if (close > i && input[close - 1U] == '/') {
            --depth;
        }
        i = close;
    }
    summary.entity_expansion_risk = summary.doctype_seen && summary.entity_reference_count > 16U;
    if (depth != 0U) {
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
    if (summary.entity_expansion_risk || summary.external_entity_risk) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::xml_entity_expansion;
    }
    if (summary.depth_budget_exceeded) {
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::xml
