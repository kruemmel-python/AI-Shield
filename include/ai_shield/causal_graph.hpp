#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/correlation.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::causal {

enum class NodeKind : std::uint32_t {
    flow,
    file,
    process,
    egress
};

struct Node final {
    std::uint64_t id = 0;
    NodeKind kind = NodeKind::flow;
    crypto::Sha256Digest identity_hash{};
    correlation::Context correlation{};
};

struct Edge final {
    std::uint64_t from = 0;
    std::uint64_t to = 0;
};

class Graph final {
public:
    [[nodiscard]] Result<void> add_node(Node node);
    [[nodiscard]] Result<void> add_edge(std::uint64_t from, std::uint64_t to);
    [[nodiscard]] Result<std::vector<Node>> chain_to(std::uint64_t node_id) const;
    [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t edge_count() const noexcept { return edges_.size(); }

private:
    [[nodiscard]] const Node* find_node(std::uint64_t id) const noexcept;

    std::vector<Node> nodes_;
    std::vector<Edge> edges_;
};

}  // namespace ai_shield::causal
