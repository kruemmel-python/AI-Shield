#include "ai_shield/pe_preflight.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::protocols::pe {
namespace {

[[nodiscard]] std::uint16_t read_le16(std::span<const std::byte> data, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(data[offset]) |
                                      (std::to_integer<std::uint16_t>(data[offset + 1U]) << 8U));
}

[[nodiscard]] std::uint32_t read_le32(std::span<const std::byte> data, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= std::to_integer<std::uint32_t>(data[offset + i]) << (i * 8U);
    }
    return value;
}

}  // namespace

Result<ImageSummary> preflight(std::span<const std::byte> data) noexcept {
    ImageSummary summary{};
    if (data.size() < 0x100U || std::to_integer<unsigned char>(data[0]) != 'M' || std::to_integer<unsigned char>(data[1]) != 'Z') {
        return Status::malformed_input;
    }
    const auto pe_offset = read_le32(data, 0x3CU);
    if (pe_offset > data.size() || pe_offset + 0x18U > data.size()) {
        summary.malformed = true;
        return summary;
    }
    if (std::to_integer<unsigned char>(data[pe_offset]) != 'P' || std::to_integer<unsigned char>(data[pe_offset + 1U]) != 'E' ||
        data[pe_offset + 2U] != std::byte{0} || data[pe_offset + 3U] != std::byte{0}) {
        summary.malformed = true;
        return summary;
    }
    summary.machine = read_le16(data, pe_offset + 4U);
    summary.section_count = read_le16(data, pe_offset + 6U);
    const auto optional_size = read_le16(data, pe_offset + 20U);
    const auto characteristics = read_le16(data, pe_offset + 22U);
    const auto optional_offset = pe_offset + 24U;
    if (optional_size < 0x60U || optional_offset + optional_size > data.size() || summary.section_count == 0U ||
        summary.section_count > 96U) {
        summary.malformed = true;
        return summary;
    }
    summary.optional_magic = read_le16(data, optional_offset);
    summary.size_of_image = read_le32(data, optional_offset + 56U);
    summary.executable = (characteristics & 0x0002U) != 0U;
    summary.dll = (characteristics & 0x2000U) != 0U;
    summary.driver_like = summary.machine == 0x8664U && summary.executable && !summary.dll && summary.section_count <= 3U;
    summary.unusual_sections = summary.section_count > 32U || summary.size_of_image == 0U;
    const auto section_table = optional_offset + optional_size;
    std::uint32_t max_end = 0;
    for (std::uint16_t i = 0; i < summary.section_count; ++i) {
        const auto section = section_table + static_cast<std::size_t>(i) * 40U;
        if (section + 40U > data.size()) {
            summary.malformed = true;
            return summary;
        }
        const auto raw_size = read_le32(data, section + 16U);
        const auto raw_ptr = read_le32(data, section + 20U);
        if (raw_size > 0U && raw_ptr + raw_size > data.size()) {
            summary.malformed = true;
            return summary;
        }
        if (raw_ptr + raw_size > max_end) {
            max_end = raw_ptr + raw_size;
        }
    }
    summary.overlay_present = max_end > 0U && max_end + 1024U < data.size();
    return summary;
}

detection::Evidence evidence_from(const ImageSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 80;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.executable || summary.dll || summary.driver_like) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 70U);
        evidence.reason_mask |= abi::ReasonCode::external_exec_pending;
    }
    if (summary.unusual_sections || summary.overlay_present) {
        evidence.novelty = detection::clipped_score(evidence.novelty + 40U);
        evidence.reason_mask |= abi::ReasonCode::executable_format_anomaly;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::pe
