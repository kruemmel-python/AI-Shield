#include "ai_shield/tlsmeta.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::protocols::tlsmeta {
namespace {

[[nodiscard]] std::uint16_t read_be16(std::span<const std::byte> data, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(data[offset]) << 8U) |
                                      std::to_integer<std::uint16_t>(data[offset + 1U]));
}

}  // namespace

Result<ClientHelloSummary> parse_client_hello(std::span<const std::byte> record) noexcept {
    ClientHelloSummary summary{};
    if (record.size() < 5U || std::to_integer<unsigned char>(record[0]) != 0x16U) {
        return Status::malformed_input;
    }
    const auto record_len = read_be16(record, 3U);
    if (record_len + 5U > record.size() || record_len < 42U) {
        summary.malformed = true;
        return summary;
    }
    if (std::to_integer<unsigned char>(record[5]) != 0x01U) {
        summary.malformed = true;
        return summary;
    }
    summary.legacy_version = read_be16(record, 9U);
    summary.weak_legacy_version = summary.legacy_version < 0x0303U;
    std::size_t offset = 11U + 32U;
    if (offset >= record.size()) {
        summary.malformed = true;
        return summary;
    }
    const auto session_len = std::to_integer<std::uint8_t>(record[offset]);
    offset += 1U + session_len;
    if (offset + 2U > record.size()) {
        summary.malformed = true;
        return summary;
    }
    const auto cipher_bytes = read_be16(record, offset);
    offset += 2U;
    if ((cipher_bytes % 2U) != 0U || offset + cipher_bytes + 1U > record.size()) {
        summary.malformed = true;
        return summary;
    }
    summary.cipher_count = static_cast<std::uint16_t>(cipher_bytes / 2U);
    offset += cipher_bytes;
    const auto compression_len = std::to_integer<std::uint8_t>(record[offset]);
    offset += 1U + compression_len;
    if (offset == 5U + record_len) {
        summary.missing_sni = true;
        summary.missing_supported_versions = true;
        return summary;
    }
    if (offset + 2U > record.size()) {
        summary.malformed = true;
        return summary;
    }
    const auto extensions_len = read_be16(record, offset);
    offset += 2U;
    const auto extensions_end = offset + extensions_len;
    if (extensions_end > record.size()) {
        summary.malformed = true;
        return summary;
    }
    while (offset + 4U <= extensions_end) {
        const auto type = read_be16(record, offset);
        const auto len = read_be16(record, offset + 2U);
        offset += 4U;
        if (offset + len > extensions_end) {
            summary.malformed = true;
            return summary;
        }
        ++summary.extension_count;
        if (type == 0U) {
            summary.missing_sni = false;
        }
        if (type == 43U) {
            summary.missing_supported_versions = false;
        }
        offset += len;
    }
    summary.missing_sni = summary.extension_count > 0U && summary.missing_sni;
    summary.downgrade_marker = summary.weak_legacy_version || summary.missing_supported_versions;
    return summary;
}

detection::Evidence evidence_from(const ClientHelloSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 80;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.downgrade_marker || summary.weak_legacy_version) {
        evidence.protocol = detection::clipped_score(evidence.protocol + 60U);
        evidence.reason_mask |= abi::ReasonCode::tls_downgrade;
    }
    if (summary.missing_sni) {
        evidence.novelty = detection::clipped_score(evidence.novelty + 20U);
    }
    return evidence;
}

}  // namespace ai_shield::protocols::tlsmeta
