#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace ai_shield::crypto {

using Sha256Digest = std::array<std::byte, 32>;

[[nodiscard]] Sha256Digest sha256(std::span<const std::byte> data) noexcept;
[[nodiscard]] Sha256Digest sha256(std::string_view text) noexcept;
[[nodiscard]] bool constant_time_equal(const Sha256Digest& a, const Sha256Digest& b) noexcept;

}  // namespace ai_shield::crypto
