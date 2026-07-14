#include "ai_shield/http1.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <string>

namespace ai_shield::protocols::http1 {
namespace {

[[nodiscard]] std::string lower_copy(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (const unsigned char ch : v) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

[[nodiscard]] bool has_ctl(std::string_view v) noexcept {
    for (const unsigned char ch : v) {
        if (ch < 0x20U && ch != '\t' && ch != '\r' && ch != '\n') {
            return true;
        }
    }
    return false;
}

}  // namespace

Result<ParseSummary> parse_request(std::string_view data) noexcept {
    ParseSummary summary{};
    if (data.size() > 128U * 1024U) {
        return Status::out_of_budget;
    }
    const auto header_end = data.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return Status::malformed_input;
    }
    const auto head = data.substr(0, header_end);
    if (has_ctl(head)) {
        summary.malformed = true;
        return summary;
    }

    const auto first_line_end = head.find("\r\n");
    if (first_line_end == std::string_view::npos) {
        return Status::malformed_input;
    }
    const auto request_line = head.substr(0, first_line_end);
    if (request_line.find("..") != std::string_view::npos || request_line.find("%2e") != std::string_view::npos ||
        request_line.find("%2E") != std::string_view::npos) {
        summary.path_traversal = true;
    }
    if (request_line.find("cmd") != std::string_view::npos || request_line.find("powershell") != std::string_view::npos) {
        summary.command_marker = true;
    }

    std::size_t cursor = first_line_end + 2U;
    while (cursor < head.size()) {
        const auto next = head.find("\r\n", cursor);
        const auto line = head.substr(cursor, next == std::string_view::npos ? std::string_view::npos : next - cursor);
        if (line.empty()) {
            break;
        }
        ++summary.header_count;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0U) {
            summary.malformed = true;
            break;
        }
        const auto name = lower_copy(line.substr(0, colon));
        auto value = line.substr(colon + 1U);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.remove_prefix(1);
        }
        if (name == "content-length") {
            ++summary.content_length_count;
            std::uint64_t parsed = 0;
            const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (ec != std::errc{} || ptr != value.data() + value.size()) {
                summary.malformed = true;
            } else if (summary.content_length_count == 1U) {
                summary.content_length = parsed;
            } else if (summary.content_length != parsed) {
                summary.ambiguous_framing = true;
            }
        } else if (name == "transfer-encoding") {
            const auto lv = lower_copy(value);
            if (lv.find("chunked") != std::string::npos) {
                summary.chunked = true;
            }
        }
        if (next == std::string_view::npos) {
            break;
        }
        cursor = next + 2U;
    }
    if (summary.chunked && summary.content_length_count > 0U) {
        summary.ambiguous_framing = true;
    }
    return summary;
}

detection::Evidence evidence_from(const ParseSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = detection::clipped_score(evidence.protocol + 60U);
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.ambiguous_framing) {
        evidence.hard_rule = 100;
        evidence.protocol = 100;
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    if (summary.path_traversal) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::path_traversal;
    }
    if (summary.command_marker) {
        evidence.hard_rule = 100;
        evidence.consequence = 80;
        evidence.reason_mask |= abi::ReasonCode::command_execution;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::http1
