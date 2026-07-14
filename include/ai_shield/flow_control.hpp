#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::flow_control {

class TokenBucket final {
public:
    constexpr TokenBucket(std::uint32_t capacity, std::uint32_t refill_per_second) noexcept
        : capacity_(capacity), refill_per_second_(refill_per_second), tokens_(capacity) {}

    [[nodiscard]] Result<void> consume(std::uint64_t now_ns, std::uint32_t cost) noexcept;
    [[nodiscard]] std::uint32_t tokens() const noexcept { return tokens_; }

private:
    std::uint32_t capacity_ = 0;
    std::uint32_t refill_per_second_ = 0;
    std::uint32_t tokens_ = 0;
    std::uint64_t last_refill_ns_ = 0;
};

struct UdpFlowKey final {
    std::uint64_t source_id = 0;
    std::uint64_t target_service_id = 0;
    std::uint16_t source_port_be = 0;
    std::uint16_t target_port_be = 0;
};

struct FlowAdmission final {
    abi::ShieldAction action = abi::ShieldAction::allow;
    std::uint32_t reason_mask = 0;
};

class UdpSessionLimiter final {
public:
    UdpSessionLimiter(std::uint32_t max_sessions, std::uint64_t idle_timeout_ns) noexcept;
    [[nodiscard]] FlowAdmission admit(const UdpFlowKey& key, std::uint64_t now_ns);
    [[nodiscard]] std::size_t active_sessions() const noexcept { return sessions_.size(); }

private:
    struct Session final {
        UdpFlowKey key{};
        std::uint64_t last_seen_ns = 0;
    };

    std::uint32_t max_sessions_ = 0;
    std::uint64_t idle_timeout_ns_ = 0;
    std::vector<Session> sessions_;
};

class RedirectTracker final {
public:
    explicit RedirectTracker(std::uint32_t max_redirects) noexcept : max_redirects_(max_redirects) {}
    [[nodiscard]] FlowAdmission record_redirect(std::uint64_t flow_id) noexcept;

private:
    struct FlowRedirect final {
        std::uint64_t flow_id = 0;
        std::uint32_t count = 0;
    };

    std::uint32_t max_redirects_ = 0;
    std::vector<FlowRedirect> redirects_;
};

}  // namespace ai_shield::flow_control
