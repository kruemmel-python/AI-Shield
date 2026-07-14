#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::protocols::tlsmeta {

struct ClientHelloSummary final {
    std::uint16_t legacy_version = 0;
    std::uint16_t cipher_count = 0;
    std::uint16_t extension_count = 0;
    bool malformed = false;
    bool weak_legacy_version = false;
    bool missing_sni = false;
    bool missing_supported_versions = false;
    bool downgrade_marker = false;
};

[[nodiscard]] Result<ClientHelloSummary> parse_client_hello(std::span<const std::byte> record) noexcept;
[[nodiscard]] detection::Evidence evidence_from(const ClientHelloSummary& summary) noexcept;

}  // namespace ai_shield::protocols::tlsmeta
