#include "ai_shield/http2_preflight.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::protocols::http2 {
namespace {

std::uint32_t read24(std::span<const std::byte> data, std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + 1U])) << 8U) |
           static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + 2U]));
}

std::uint32_t read31(std::span<const std::byte> data, std::size_t offset) noexcept {
    return ((static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset])) & 0x7fU) << 24U) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + 1U])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + 2U])) << 8U) |
           static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + 3U]));
}

}  // namespace

Result<FrameSummary> preflight(std::span<const std::byte> data,
                               std::uint32_t header_budget_bytes,
                               std::uint32_t max_stream_id) noexcept {
    FrameSummary summary{};
    std::size_t offset = 0;
    while (offset < data.size()) {
        if (data.size() - offset < 9U) {
            summary.malformed = true;
            return summary;
        }
        const std::uint32_t length = read24(data, offset);
        const auto type = std::to_integer<unsigned char>(data[offset + 3U]);
        const std::uint32_t stream_id = read31(data, offset + 5U);
        offset += 9U;
        if (length > data.size() - offset) {
            summary.malformed = true;
            return summary;
        }
        ++summary.frame_count;
        if (stream_id > summary.max_stream_id) {
            summary.max_stream_id = stream_id;
        }
        if (stream_id > max_stream_id) {
            summary.stream_state_anomaly = true;
        }
        if (type == 0x01U || type == 0x09U) {
            summary.header_bytes += length;
            if (summary.header_bytes > header_budget_bytes) {
                summary.header_budget_exceeded = true;
            }
        }
        offset += length;
    }
    return summary;
}

detection::Evidence evidence_from(const FrameSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 100;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.header_budget_exceeded || summary.stream_state_anomaly) {
        evidence.protocol = detection::clipped_score(evidence.protocol + 70U);
        evidence.reason_mask |= abi::ReasonCode::proto_ambiguous;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::http2
