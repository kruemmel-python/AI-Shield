#pragma once

#include <cstdint>
#include <span>

#include "ai_shield/detection.hpp"

namespace ai_shield::mutation {

[[nodiscard]] std::uint64_t simhash64(std::span<const std::byte> payload) noexcept;
[[nodiscard]] std::uint32_t hamming_distance(std::uint64_t a, std::uint64_t b) noexcept;
[[nodiscard]] detection::Evidence compare_payloads(std::span<const std::byte> previous,
                                                   std::span<const std::byte> current) noexcept;

}  // namespace ai_shield::mutation
