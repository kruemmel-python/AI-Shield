#include "ai_shield/dns.hpp"

#include <algorithm>

namespace ai_shield::protocols::dns {
namespace {

[[nodiscard]] std::uint16_t read_be16(std::span<const std::byte> packet, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(packet[offset]) << 8U) |
                                      std::to_integer<std::uint16_t>(packet[offset + 1U]));
}

[[nodiscard]] Result<std::size_t> skip_name(std::span<const std::byte> packet,
                                            std::size_t offset,
                                            ParseSummary& summary) noexcept {
    std::uint16_t depth = 0;
    while (offset < packet.size()) {
        if (++depth > 64U) {
            summary.compression_loop_risk = true;
            return Status::out_of_budget;
        }
        summary.max_name_depth = std::max(summary.max_name_depth, depth);
        const auto len = std::to_integer<std::uint8_t>(packet[offset]);
        if ((len & 0xC0U) == 0xC0U) {
            if (offset + 1U >= packet.size()) {
                summary.malformed = true;
                return Status::malformed_input;
            }
            const auto pointer = static_cast<std::uint16_t>(((len & 0x3FU) << 8U) |
                                                            std::to_integer<std::uint8_t>(packet[offset + 1U]));
            summary.compression_pointer_seen = true;
            if (pointer >= offset || pointer >= packet.size()) {
                summary.compression_loop_risk = true;
                return Status::ambiguous_input;
            }
            return offset + 2U;
        }
        if ((len & 0xC0U) != 0U) {
            summary.malformed = true;
            return Status::malformed_input;
        }
        ++offset;
        if (len == 0U) {
            return offset;
        }
        if (len > 63U || offset + len > packet.size()) {
            summary.malformed = true;
            return Status::malformed_input;
        }
        offset += len;
    }
    summary.malformed = true;
    return Status::malformed_input;
}

}  // namespace

Result<ParseSummary> parse_message(std::span<const std::byte> packet) noexcept {
    ParseSummary summary{};
    if (packet.size() < 12U || packet.size() > 4096U) {
        return Status::malformed_input;
    }
    summary.question_count = read_be16(packet, 4);
    summary.answer_count = read_be16(packet, 6);
    summary.authority_count = read_be16(packet, 8);
    summary.additional_count = read_be16(packet, 10);
    if (summary.question_count > 16U || summary.answer_count > 64U || summary.authority_count > 64U ||
        summary.additional_count > 64U) {
        summary.malformed = true;
        return summary;
    }

    std::size_t offset = 12U;
    for (std::uint16_t i = 0; i < summary.question_count; ++i) {
        auto name = skip_name(packet, offset, summary);
        if (!name.ok()) {
            return summary;
        }
        offset = name.value();
        if (offset + 4U > packet.size()) {
            summary.malformed = true;
            return summary;
        }
        offset += 4U;
    }

    const auto skip_rr = [&](std::uint16_t count) noexcept -> Result<void> {
        for (std::uint16_t i = 0; i < count; ++i) {
            auto name = skip_name(packet, offset, summary);
            if (!name.ok()) {
                return name.status();
            }
            offset = name.value();
            if (offset + 10U > packet.size()) {
                summary.malformed = true;
                return Status::malformed_input;
            }
            const auto rdlength = read_be16(packet, offset + 8U);
            offset += 10U;
            if (offset + rdlength > packet.size()) {
                summary.malformed = true;
                return Status::malformed_input;
            }
            offset += rdlength;
        }
        return {};
    };

    auto rr = skip_rr(summary.answer_count);
    if (!rr.ok()) {
        return summary;
    }
    rr = skip_rr(summary.authority_count);
    if (!rr.ok()) {
        return summary;
    }
    rr = skip_rr(summary.additional_count);
    if (!rr.ok()) {
        return summary;
    }
    summary.trailing_bytes = offset != packet.size();
    return summary;
}

detection::Evidence evidence_from(const ParseSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 80;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.compression_loop_risk || summary.trailing_bytes) {
        evidence.hard_rule = 100;
        evidence.protocol = 100;
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    if (summary.max_name_depth > 32U) {
        evidence.novelty = 40;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::dns
