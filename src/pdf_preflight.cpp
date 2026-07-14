#include "ai_shield/pdf_preflight.hpp"

#include "ai_shield/abi.hpp"

#include <string>

namespace ai_shield::protocols::pdf {

Result<ParseSummary> preflight(std::span<const std::byte> data) noexcept {
    ParseSummary summary{};
    if (data.size() < 8U || data.size() > 256U * 1024U * 1024U) {
        return Status::malformed_input;
    }
    std::string text;
    text.reserve(data.size());
    for (const auto byte : data) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    if (text.rfind("%PDF-", 0U) != 0U) {
        summary.malformed = true;
        return summary;
    }
    std::size_t pos = 0;
    while ((pos = text.find(" obj", pos)) != std::string::npos) {
        ++summary.object_count;
        pos += 4U;
    }
    summary.javascript = text.find("/JavaScript") != std::string::npos || text.find("/JS") != std::string::npos;
    summary.launch_action = text.find("/Launch") != std::string::npos;
    summary.embedded_file = text.find("/EmbeddedFile") != std::string::npos;
    summary.open_action = text.find("/OpenAction") != std::string::npos;
    summary.xref_missing = text.find("xref") == std::string::npos;
    summary.eof_missing = text.find("%%EOF") == std::string::npos;
    summary.malformed = summary.object_count == 0U || summary.eof_missing;
    return summary;
}

detection::Evidence evidence_from(const ParseSummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed || summary.xref_missing) {
        evidence.protocol = 60;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.javascript || summary.launch_action || summary.embedded_file || summary.open_action) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 80U);
        evidence.reason_mask |= abi::ReasonCode::document_active_content | abi::ReasonCode::consequence_detected;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::pdf
