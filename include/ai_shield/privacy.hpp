#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::privacy {

struct ExportPolicy final {
    bool include_payload_excerpt = false;
    std::size_t max_excerpt_bytes = 0;
    crypto::Sha256Digest pseudonym_key{};
};

struct SanitizedPayload final {
    crypto::Sha256Digest full_payload_hash{};
    std::vector<std::byte> excerpt;
    std::uint32_t reason_mask = 0;
};

[[nodiscard]] crypto::Sha256Digest stable_pseudonym(const crypto::Sha256Digest& key, std::string_view value);
[[nodiscard]] SanitizedPayload sanitize_payload(std::span<const std::byte> payload, const ExportPolicy& policy);

}  // namespace ai_shield::privacy
