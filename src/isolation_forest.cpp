#include "ai_shield/isolation_forest.hpp"

#include <algorithm>

namespace ai_shield::isolation_forest {
namespace {

[[nodiscard]] std::uint32_t path_length(const Tree& tree, std::span<const float> features) noexcept {
    std::uint32_t depth = 0;
    std::int32_t index = 0;
    while (index >= 0 && static_cast<std::size_t>(index) < tree.nodes.size()) {
        const auto& node = tree.nodes[static_cast<std::size_t>(index)];
        if (node.leaf) {
            return depth;
        }
        if (node.feature_index >= features.size()) {
            return depth;
        }
        index = features[node.feature_index] < node.threshold ? node.left : node.right;
        ++depth;
        if (depth > 64U) {
            return depth;
        }
    }
    return depth;
}

}  // namespace

Result<void> Forest::add_tree(Tree tree) {
    if (tree.nodes.empty()) {
        return Status::invalid_argument;
    }
    trees_.push_back(std::move(tree));
    return {};
}

detection::Evidence Forest::score(std::span<const float> features) const noexcept {
    detection::Evidence evidence{};
    if (trees_.empty() || features.empty()) {
        evidence.novelty = 50;
        return evidence;
    }
    std::uint32_t total_depth = 0;
    for (const auto& tree : trees_) {
        total_depth += path_length(tree, features);
    }
    const auto average_depth = total_depth / static_cast<std::uint32_t>(trees_.size());
    evidence.novelty = average_depth <= 1U ? 90U : (average_depth <= 3U ? 55U : 15U);
    return evidence;
}

}  // namespace ai_shield::isolation_forest
