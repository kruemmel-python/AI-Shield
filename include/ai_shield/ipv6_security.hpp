#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/result.hpp"

namespace ai_shield::ipv6_security {

struct Metadata final {
    std::uint8_t terminal_protocol = 0;
    std::uint8_t extension_count = 0;
    std::uint8_t icmpv6_type = 0;
    std::uint8_t icmpv6_code = 0;
    std::uint32_t fragment_id = 0;
    std::uint16_t fragment_offset = 0;
    bool more_fragments = false;
    bool atomic_fragment = false;
    bool routing_header = false;
    bool destination_options = false;
};

struct QuicMetadata final {
    std::uint32_t version = 0;
    std::uint8_t packet_type = 0;
    std::uint8_t destination_connection_id_length = 0;
    std::uint8_t source_connection_id_length = 0;
    std::uint64_t token_length = 0;
    bool long_header = false;
};

[[nodiscard]] Result<Metadata> inspect_ipv6(std::span<const std::byte> packet) noexcept;
[[nodiscard]] Result<QuicMetadata> inspect_quic(std::span<const std::byte> datagram) noexcept;

}  // namespace ai_shield::ipv6_security
