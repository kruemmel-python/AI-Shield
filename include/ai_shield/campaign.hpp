#pragma once

#include <array>
#include <cstdint>

#include "ai_shield/detection.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::campaign {

struct Observation final {
    std::uint64_t source_id = 0;
    std::uint64_t target_service_id = 0;
    crypto::Sha256Digest normalized_payload_hash{};
    std::uint16_t response_class = 0;
    std::uint16_t mutation_distance = 0;
    bool follows_previous_response = false;
};

class Tracker final {
public:
    [[nodiscard]] detection::Evidence observe(const Observation& observation) noexcept;
    [[nodiscard]] std::uint32_t observation_count() const noexcept { return count_; }

private:
    std::array<Observation, 16> ring_{};
    std::uint32_t count_ = 0;
    std::uint32_t cursor_ = 0;
};

}  // namespace ai_shield::campaign
