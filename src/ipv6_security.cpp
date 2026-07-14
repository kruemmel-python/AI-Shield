#include "ai_shield/ipv6_security.hpp"

namespace ai_shield::ipv6_security {
namespace {

std::uint16_t be16(std::span<const std::byte> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(bytes[offset]) << 8U) |
                                      std::to_integer<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t be32(std::span<const std::byte> bytes, std::size_t offset) {
    return (std::to_integer<std::uint32_t>(bytes[offset]) << 24U) |
           (std::to_integer<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (std::to_integer<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           std::to_integer<std::uint32_t>(bytes[offset + 3U]);
}

Result<std::uint64_t> quic_varint(std::span<const std::byte> bytes, std::size_t& offset) {
    if (offset >= bytes.size()) return Status::malformed_input;
    const auto first = std::to_integer<std::uint8_t>(bytes[offset]);
    const std::size_t length = std::size_t{1} << (first >> 6U);
    if (offset + length > bytes.size()) return Status::malformed_input;
    std::uint64_t value = first & 0x3fU;
    for (std::size_t index = 1; index < length; ++index)
        value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + index]);
    offset += length;
    return value;
}

}  // namespace

Result<Metadata> inspect_ipv6(std::span<const std::byte> packet) noexcept {
    if (packet.size() < 40U || (std::to_integer<std::uint8_t>(packet[0]) >> 4U) != 6U)
        return Status::malformed_input;
    const auto payload_length = be16(packet, 4U);
    if (payload_length != 0U && packet.size() != 40U + payload_length) return Status::malformed_input;
    Metadata result{};
    std::uint8_t next = std::to_integer<std::uint8_t>(packet[6]);
    std::size_t offset = 40U;
    while (next == 0U || next == 43U || next == 44U || next == 60U || next == 51U) {
        if (++result.extension_count > 8U || offset + 2U > packet.size()) return Status::out_of_budget;
        const auto current = next;
        next = std::to_integer<std::uint8_t>(packet[offset]);
        std::size_t length = 0;
        if (current == 44U) {
            length = 8U;
            if (offset + length > packet.size()) return Status::malformed_input;
            const auto fragment = be16(packet, offset + 2U);
            result.fragment_offset = static_cast<std::uint16_t>((fragment & 0xfff8U) >> 3U);
            result.more_fragments = (fragment & 1U) != 0U;
            result.fragment_id = be32(packet, offset + 4U);
            result.atomic_fragment = result.fragment_offset == 0U && !result.more_fragments;
        } else if (current == 51U) {
            length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(packet[offset + 1U])) + 2U) * 4U;
        } else {
            length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(packet[offset + 1U])) + 1U) * 8U;
        }
        if (length < 8U || offset + length > packet.size()) return Status::malformed_input;
        if (current == 43U) result.routing_header = true;
        if (current == 60U) result.destination_options = true;
        offset += length;
    }
    result.terminal_protocol = next;
    if (next == 58U) {
        if (offset + 4U > packet.size()) return Status::malformed_input;
        result.icmpv6_type = std::to_integer<std::uint8_t>(packet[offset]);
        result.icmpv6_code = std::to_integer<std::uint8_t>(packet[offset + 1U]);
    }
    return result;
}

Result<QuicMetadata> inspect_quic(std::span<const std::byte> datagram) noexcept {
    if (datagram.size() < 7U) return Status::malformed_input;
    const auto first = std::to_integer<std::uint8_t>(datagram[0]);
    if ((first & 0x80U) == 0U || (first & 0x40U) == 0U) return Status::malformed_input;
    QuicMetadata result{};
    result.long_header = true;
    result.packet_type = static_cast<std::uint8_t>((first >> 4U) & 0x03U);
    result.version = be32(datagram, 1U);
    std::size_t offset = 5U;
    result.destination_connection_id_length = std::to_integer<std::uint8_t>(datagram[offset++]);
    if (result.destination_connection_id_length > 20U || offset + result.destination_connection_id_length >= datagram.size())
        return Status::malformed_input;
    offset += result.destination_connection_id_length;
    result.source_connection_id_length = std::to_integer<std::uint8_t>(datagram[offset++]);
    if (result.source_connection_id_length > 20U || offset + result.source_connection_id_length > datagram.size())
        return Status::malformed_input;
    offset += result.source_connection_id_length;
    if (result.packet_type == 0U && result.version != 0U) {
        const auto token = quic_varint(datagram, offset);
        if (!token.ok() || token.value() > datagram.size() - offset) return Status::malformed_input;
        result.token_length = token.value();
    }
    return result;
}

}  // namespace ai_shield::ipv6_security
