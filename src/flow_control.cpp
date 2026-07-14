#include "ai_shield/flow_control.hpp"

#include <algorithm>

namespace ai_shield::flow_control {
namespace {

[[nodiscard]] bool same_key(const UdpFlowKey& a, const UdpFlowKey& b) noexcept {
    return a.source_id == b.source_id && a.target_service_id == b.target_service_id &&
           a.source_port_be == b.source_port_be && a.target_port_be == b.target_port_be;
}

}  // namespace

Result<void> TokenBucket::consume(std::uint64_t now_ns, std::uint32_t cost) noexcept {
    if (capacity_ == 0U || refill_per_second_ == 0U || cost > capacity_) {
        return Status::invalid_argument;
    }
    if (last_refill_ns_ == 0U) {
        last_refill_ns_ = now_ns;
    }
    if (now_ns > last_refill_ns_) {
        const auto elapsed = now_ns - last_refill_ns_;
        const auto refill = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            capacity_, (elapsed * static_cast<std::uint64_t>(refill_per_second_)) / 1'000'000'000ULL));
        tokens_ = std::min<std::uint32_t>(capacity_, tokens_ + refill);
        if (refill > 0U) {
            last_refill_ns_ = now_ns;
        }
    }
    if (tokens_ < cost) {
        return Status::out_of_budget;
    }
    tokens_ -= cost;
    return {};
}

UdpSessionLimiter::UdpSessionLimiter(std::uint32_t max_sessions, std::uint64_t idle_timeout_ns) noexcept
    : max_sessions_(max_sessions), idle_timeout_ns_(idle_timeout_ns) {}

FlowAdmission UdpSessionLimiter::admit(const UdpFlowKey& key, std::uint64_t now_ns) {
    sessions_.erase(std::remove_if(sessions_.begin(),
                                   sessions_.end(),
                                   [&](const Session& session) {
                                       return now_ns > session.last_seen_ns &&
                                              now_ns - session.last_seen_ns > idle_timeout_ns_;
                                   }),
                    sessions_.end());
    for (auto& session : sessions_) {
        if (same_key(session.key, key)) {
            session.last_seen_ns = now_ns;
            return {};
        }
    }
    if (sessions_.size() >= max_sessions_) {
        return FlowAdmission{abi::ShieldAction::rate_limit, abi::ReasonCode::rate_limited};
    }
    sessions_.push_back(Session{key, now_ns});
    return {};
}

FlowAdmission RedirectTracker::record_redirect(std::uint64_t flow_id) noexcept {
    for (auto& redirect : redirects_) {
        if (redirect.flow_id == flow_id) {
            ++redirect.count;
            if (redirect.count > max_redirects_) {
                return FlowAdmission{abi::ShieldAction::drop_flow, abi::ReasonCode::proxy_loop};
            }
            return {};
        }
    }
    redirects_.push_back(FlowRedirect{flow_id, 1});
    return {};
}

}  // namespace ai_shield::flow_control
