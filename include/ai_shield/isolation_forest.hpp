#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::isolation_forest {

struct Node final {
    std::uint16_t feature_index = 0;
    float threshold = 0.0F;
    std::int32_t left = -1;
    std::int32_t right = -1;
    bool leaf = true;
};

struct Tree final {
    std::vector<Node> nodes;
};

class Forest final {
public:
    [[nodiscard]] Result<void> add_tree(Tree tree);
    [[nodiscard]] detection::Evidence score(std::span<const float> features) const noexcept;

private:
    std::vector<Tree> trees_;
};

}  // namespace ai_shield::isolation_forest
