#include "ai_shield/pending_decision.hpp"

#include <algorithm>

namespace ai_shield::pending {

Result<void> Manager::pend(std::uint64_t flow_id, std::uint64_t now_ns, std::uint64_t budget_ns) {
    return pend_for_service(flow_id, 0U, now_ns, budget_ns, 0U);
}

Result<void> Manager::pend_for_service(std::uint64_t flow_id,
                                       std::uint64_t service_id,
                                       std::uint64_t now_ns,
                                       std::uint64_t budget_ns,
                                       std::uint64_t reserved_bytes) {
    if (flow_id == 0U || budget_ns == 0U || budget_ns > limits_.max_budget_ns ||
        budget_ns > limits_.max_service_budget_ns || reserved_bytes > limits_.max_reserved_bytes) {
        return Status::invalid_argument;
    }
    if (pending_.size() >= limits_.max_pending) {
        return Status::out_of_budget;
    }
    for (const auto& pending : pending_) {
        if (pending.flow_id == flow_id) {
            return Status::invalid_state_transition;
        }
    }
    pending_.push_back(PendingFlow{.flow_id = flow_id,
                                   .service_id = service_id,
                                   .deadline_ns = now_ns + budget_ns,
                                   .bytes_reserved = reserved_bytes,
                                   .completed = false});
    return {};
}

Result<Completion> Manager::complete(std::uint64_t flow_id, abi::ShieldAction action) {
    return complete_at(flow_id, action, 0U);
}

Result<Completion> Manager::complete_at(std::uint64_t flow_id, abi::ShieldAction action, std::uint64_t now_ns) {
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (it->flow_id == flow_id) {
            if (now_ns != 0U && now_ns >= it->deadline_ns) {
                pending_.erase(it);
                return Status::invalid_state_transition;
            }
            pending_.erase(it);
            return Completion{action, 0U};
        }
    }
    return Status::not_found;
}

std::vector<Completion> Manager::expire(std::uint64_t now_ns) {
    std::vector<Completion> expired;
    auto it = pending_.begin();
    while (it != pending_.end()) {
        if (now_ns >= it->deadline_ns) {
            expired.push_back(Completion{abi::ShieldAction::drop_flow, abi::ReasonCode::decision_timeout});
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

}  // namespace ai_shield::pending
