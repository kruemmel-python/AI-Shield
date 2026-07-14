#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::ipc {

struct ValidationContext final {
    std::uint64_t expected_next_sequence = 0;
    std::uint64_t now_monotonic_ns = 0;
    std::uint64_t max_clock_skew_ns = 0;
    crypto::Sha256Digest mac_key{};
};

[[nodiscard]] crypto::Sha256Digest compute_flow_event_mac(const abi::FlowEvent& event,
                                                          const crypto::Sha256Digest& key);
[[nodiscard]] Result<void> validate_flow_event(const abi::FlowEvent& event, const ValidationContext& context) noexcept;

}  // namespace ai_shield::ipc
