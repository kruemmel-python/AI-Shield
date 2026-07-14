#include "ai_shield/platform_uri.hpp"

#include <cctype>
#include <vector>

namespace ai_shield::platform {

Result<std::string> normalize_path_uri(std::string_view platform_path) {
    if (platform_path.empty() || platform_path.size() > 4096U) {
        return Status::invalid_argument;
    }
    std::string path;
    path.reserve(platform_path.size());
    for (const unsigned char ch : platform_path) {
        path.push_back(ch == '\\' ? '/' : static_cast<char>(std::tolower(ch)));
    }
    std::size_t start = 0;
    if (path.size() >= 2U && path[1] == ':') {
        start = 2U;
    }
    while (start < path.size() && path[start] == '/') {
        ++start;
    }
    std::vector<std::string> parts;
    std::size_t cursor = start;
    while (cursor <= path.size()) {
        const auto next = path.find('/', cursor);
        const auto part = path.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        if (part == "..") {
            return Status::ambiguous_input;
        }
        if (!part.empty() && part != ".") {
            parts.push_back(part);
        }
        if (next == std::string::npos) {
            break;
        }
        cursor = next + 1U;
    }
    std::string uri = "file:///";
    if (path.size() >= 2U && path[1] == ':') {
        uri.push_back(path[0]);
        uri.push_back('/');
    }
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0U) {
            uri.push_back('/');
        }
        uri += parts[i];
    }
    return uri;
}

}  // namespace ai_shield::platform
