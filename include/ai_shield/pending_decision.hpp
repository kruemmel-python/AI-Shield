#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::pending {

struct PendingFlow final {
    std::uint64_t flow_id = 0;
    std::uint64_t service_id = 0;
    std::uint64_t deadline_ns = 0;
    std::uint64_t bytes_reserved = 0;
    bool completed = false;
};

struct Completion final {
    abi::ShieldAction action = abi::ShieldAction::allow;
    std::uint32_t reason_mask = 0;
};

class Manager final {
public:
    struct Limits final {
        std::size_t max_pending = 4096;
        std::uint64_t max_budget_ns = 1'000'000'000ULL;
        std::uint64_t max_service_budget_ns = 1'000'000'000ULL;
        std::uint64_t max_reserved_bytes = 4ULL * 1024ULL * 1024ULL;
    };

    Manager() = default;
    explicit Manager(Limits limits) noexcept : limits_(limits) {}
    [[nodiscard]] Result<void> pend(std::uint64_t flow_id, std::uint64_t now_ns, std::uint64_t budget_ns);
    [[nodiscard]] Result<void> pend_for_service(std::uint64_t flow_id,
                                                std::uint64_t service_id,
                                                std::uint64_t now_ns,
                                                std::uint64_t budget_ns,
                                                std::uint64_t reserved_bytes);
    [[nodiscard]] Result<Completion> complete(std::uint64_t flow_id, abi::ShieldAction action);
    [[nodiscard]] Result<Completion> complete_at(std::uint64_t flow_id,
                                                 abi::ShieldAction action,
                                                 std::uint64_t now_ns);
    [[nodiscard]] std::vector<Completion> expire(std::uint64_t now_ns);
    [[nodiscard]] std::size_t pending_count() const noexcept { return pending_.size(); }

private:
    Limits limits_{};
    std::vector<PendingFlow> pending_;
};

}  // namespace ai_shield::pending
