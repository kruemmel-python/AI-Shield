#include "ai_shield/features.hpp"

namespace ai_shield::features {

NetworkFeatures extract_network(std::span<const std::byte> payload) noexcept {
    NetworkFeatures features{};
    features.payload_bytes = static_cast<std::uint32_t>(payload.size() > 0xffffffffULL ? 0xffffffffULL : payload.size());
    std::uint32_t printable = 0;
    for (const auto byte : payload) {
        const auto v = std::to_integer<unsigned char>(byte);
        if (v == 0U) {
            ++features.zero_byte_count;
        }
        if (v >= 0x80U) {
            ++features.high_byte_count;
        }
        if (v >= 0x20U && v <= 0x7eU) {
            ++printable;
        }
    }
    features.printable_ratio_percent = payload.empty() ? 0U : (printable * 100U) / static_cast<std::uint32_t>(payload.size());
    return features;
}

ProtocolFeatures extract_http(const protocols::http1::ParseSummary& summary) noexcept {
    return ProtocolFeatures{summary.header_count, summary.content_length, summary.ambiguous_framing, summary.path_traversal};
}

}  // namespace ai_shield::features
