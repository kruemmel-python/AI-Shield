#include "ai_shield/http_canonicalizer.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace ai_shield::protocols::http1 {
namespace {

[[nodiscard]] std::string trim_lower(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    std::string out;
    out.reserve(text.size());
    for (const unsigned char ch : text) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

struct Header final {
    std::string name;
    std::string value;
};

}  // namespace

Result<std::string> canonicalize_request(std::string_view request) {
    if (request.size() > 1024U * 1024U) {
        return Status::out_of_budget;
    }
    const auto header_end = request.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return Status::malformed_input;
    }
    const auto head = request.substr(0, header_end);
    const auto first_end = head.find("\r\n");
    if (first_end == std::string_view::npos) {
        return Status::malformed_input;
    }
    std::string canonical = trim_lower(head.substr(0, first_end));
    canonical.push_back('\n');
    std::vector<Header> headers;
    std::size_t cursor = first_end + 2U;
    while (cursor < head.size()) {
        const auto next = head.find("\r\n", cursor);
        const auto line = head.substr(cursor, next == std::string_view::npos ? std::string_view::npos : next - cursor);
        if (line.empty()) {
            break;
        }
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0U) {
            return Status::malformed_input;
        }
        headers.push_back(Header{trim_lower(line.substr(0, colon)), trim_lower(line.substr(colon + 1U))});
        if (next == std::string_view::npos) {
            break;
        }
        cursor = next + 2U;
    }
    std::sort(headers.begin(), headers.end(), [](const Header& a, const Header& b) {
        if (a.name == b.name) {
            return a.value < b.value;
        }
        return a.name < b.name;
    });
    for (const auto& header : headers) {
        canonical += header.name;
        canonical.push_back(':');
        canonical += header.value;
        canonical.push_back('\n');
    }
    return canonical;
}

}  // namespace ai_shield::protocols::http1
