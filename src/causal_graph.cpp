#include "ai_shield/causal_graph.hpp"

#include <algorithm>

namespace ai_shield::causal {

const Node* Graph::find_node(std::uint64_t id) const noexcept {
    for (const auto& node : nodes_) {
        if (node.id == id) {
            return &node;
        }
    }
    return nullptr;
}

Result<void> Graph::add_node(Node node) {
    if (node.id == 0U || find_node(node.id) != nullptr) {
        return Status::invalid_argument;
    }
    nodes_.push_back(node);
    return {};
}

Result<void> Graph::add_edge(std::uint64_t from, std::uint64_t to) {
    if (find_node(from) == nullptr || find_node(to) == nullptr || from == to) {
        return Status::invalid_argument;
    }
    edges_.push_back(Edge{from, to});
    return {};
}

Result<std::vector<Node>> Graph::chain_to(std::uint64_t node_id) const {
    std::vector<Node> chain;
    auto current = find_node(node_id);
    if (current == nullptr) {
        return Status::not_found;
    }
    chain.push_back(*current);
    while (true) {
        const Edge* parent_edge = nullptr;
        for (const auto& edge : edges_) {
            if (edge.to == current->id) {
                parent_edge = &edge;
                break;
            }
        }
        if (parent_edge == nullptr) {
            break;
        }
        current = find_node(parent_edge->from);
        if (current == nullptr) {
            return Status::integrity_failure;
        }
        chain.push_back(*current);
        if (chain.size() > nodes_.size()) {
            return Status::integrity_failure;
        }
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

}  // namespace ai_shield::causal
