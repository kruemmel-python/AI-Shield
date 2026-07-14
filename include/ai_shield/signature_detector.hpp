#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "ai_shield/detection.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::signatures {

enum class RuleKind : std::uint32_t {
    payload_hash,
    substring
};

struct Rule final {
    std::uint32_t rule_id = 0;
    RuleKind kind = RuleKind::substring;
    std::uint16_t severity = 0;
    crypto::Sha256Digest hash{};
    std::string_view pattern;
};

class Detector final {
public:
    [[nodiscard]] bool add_rule(Rule rule);
    [[nodiscard]] detection::Evidence inspect(std::span<const std::byte> payload) const;

private:
    std::vector<Rule> rules_;
};

}  // namespace ai_shield::signatures
