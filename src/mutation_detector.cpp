#include "ai_shield/mutation_detector.hpp"

#include <array>

namespace ai_shield::mutation {

std::uint64_t simhash64(std::span<const std::byte> payload) noexcept {
    std::array<std::int32_t, 64> weights{};
    std::uint64_t rolling = 1469598103934665603ULL;
    for (const auto byte : payload) {
        rolling ^= std::to_integer<std::uint64_t>(byte);
        rolling *= 1099511628211ULL;
        for (std::size_t bit = 0; bit < weights.size(); ++bit) {
            weights[bit] += ((rolling >> bit) & 1ULL) != 0ULL ? 1 : -1;
        }
    }
    std::uint64_t result = 0;
    for (std::size_t bit = 0; bit < weights.size(); ++bit) {
        if (weights[bit] > 0) {
            result |= (1ULL << bit);
        }
    }
    return result;
}

std::uint32_t hamming_distance(std::uint64_t a, std::uint64_t b) noexcept {
    std::uint64_t v = a ^ b;
    std::uint32_t count = 0;
    while (v != 0ULL) {
        v &= (v - 1ULL);
        ++count;
    }
    return count;
}

detection::Evidence compare_payloads(std::span<const std::byte> previous, std::span<const std::byte> current) noexcept {
    detection::Evidence evidence{};
    const auto distance = hamming_distance(simhash64(previous), simhash64(current));
    if (distance >= 8U && distance <= 32U) {
        evidence.adaptivity = detection::clipped_score(distance * 3U);
        evidence.reason_mask |= abi::ReasonCode::adaptive_mutation;
    } else if (distance > 32U) {
        evidence.novelty = detection::clipped_score(distance * 2U);
    }
    return evidence;
}

}  // namespace ai_shield::mutation
