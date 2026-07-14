#include "ai_shield/model_registry.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::model {

Result<void> Registry::load_production_model(const package::Manifest& manifest,
                                             const package::TrustAnchor& trust,
                                             const ModelMetadata& metadata) {
    if (manifest.kind != package::PackageKind::model || metadata.model_version == 0U) {
        return Status::invalid_argument;
    }
    const auto verified = package::verify_manifest(manifest, trust);
    if (!verified.ok()) {
        return verified.status();
    }
    if (metadata.model_version != manifest.model_version) {
        return Status::integrity_failure;
    }
    active_ = metadata;
    return {};
}

Result<void> Registry::observe_live_sample() const noexcept {
    return Status::invalid_state_transition;
}

}  // namespace ai_shield::model
