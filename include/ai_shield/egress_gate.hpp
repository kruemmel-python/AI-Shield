#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/abi.hpp"

namespace ai_shield::egress {

struct Rule final {
    std::uint64_t service_id = 0;
    std::uint32_t destination_ipv4_be = 0;
    std::uint16_t destination_port_be = 0;
};

struct Request final {
    std::uint64_t service_id = 0;
    std::uint32_t destination_ipv4_be = 0;
    std::uint16_t destination_port_be = 0;
    bool externally_influenced = false;
};

struct Decision final {
    abi::ShieldAction action = abi::ShieldAction::drop_flow;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] Decision decide(Request request, std::span<const Rule> rules) noexcept;

}  // namespace ai_shield::egress
