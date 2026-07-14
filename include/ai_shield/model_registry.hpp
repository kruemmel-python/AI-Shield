#pragma once

#include <cstdint>

#include "ai_shield/package_manifest.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::model {

struct ModelMetadata final {
    std::uint64_t model_version = 0;
    crypto::Sha256Digest feature_schema_hash{};
    crypto::Sha256Digest training_data_fingerprint{};
};

class Registry final {
public:
    [[nodiscard]] Result<void> load_production_model(const package::Manifest& manifest,
                                                     const package::TrustAnchor& trust,
                                                     const ModelMetadata& metadata);
    [[nodiscard]] Result<void> observe_live_sample() const noexcept;
    [[nodiscard]] bool has_active_model() const noexcept { return active_.model_version != 0U; }
    [[nodiscard]] ModelMetadata active() const noexcept { return active_; }

private:
    ModelMetadata active_{};
};

}  // namespace ai_shield::model
