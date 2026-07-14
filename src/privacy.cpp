#include "ai_shield/privacy.hpp"

#include <algorithm>

namespace ai_shield::privacy {

crypto::Sha256Digest stable_pseudonym(const crypto::Sha256Digest& key, std::string_view value) {
    std::vector<std::byte> bytes;
    bytes.reserve(key.size() + value.size());
    bytes.insert(bytes.end(), key.begin(), key.end());
    const auto value_bytes = std::as_bytes(std::span<const char>(value.data(), value.size()));
    bytes.insert(bytes.end(), value_bytes.begin(), value_bytes.end());
    return crypto::sha256(bytes);
}

SanitizedPayload sanitize_payload(std::span<const std::byte> payload, const ExportPolicy& policy) {
    SanitizedPayload sanitized{};
    sanitized.full_payload_hash = crypto::sha256(payload);
    if (policy.include_payload_excerpt && policy.max_excerpt_bytes > 0U) {
        const auto count = std::min<std::size_t>(payload.size(), policy.max_excerpt_bytes);
        sanitized.excerpt.insert(sanitized.excerpt.end(), payload.begin(), payload.begin() + count);
        if (count < payload.size()) {
            sanitized.reason_mask |= abi::ReasonCode::privacy_redacted;
        }
    } else if (!payload.empty()) {
        sanitized.reason_mask |= abi::ReasonCode::privacy_redacted;
    }
    return sanitized;
}

}  // namespace ai_shield::privacy
