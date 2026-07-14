#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::dataset {

struct DatasetVersion final {
    std::uint64_t version = 0;
    crypto::Sha256Digest source_fingerprint{};
    bool privacy_filter_applied = false;
    bool human_reviewed_edge_cases = false;
};

struct CanaryEvaluation final {
    std::uint64_t production_model_version = 0;
    std::uint64_t canary_model_version = 0;
    bool monitor_mode_only = false;
    std::uint32_t attack_detection_percent = 0;
    std::uint32_t false_block_ppm = 0;
    bool rollback_available = false;
};

[[nodiscard]] Result<void> accept_dataset(DatasetVersion dataset) noexcept;
[[nodiscard]] Result<void> approve_canary_promotion(CanaryEvaluation evaluation) noexcept;

}  // namespace ai_shield::dataset
