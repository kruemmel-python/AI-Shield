#include "ai_shield/dataset_governance.hpp"

namespace ai_shield::dataset {

Result<void> accept_dataset(DatasetVersion dataset) noexcept {
    if (dataset.version == 0U) {
        return Status::invalid_argument;
    }
    if (!dataset.privacy_filter_applied || !dataset.human_reviewed_edge_cases) {
        return Status::integrity_failure;
    }
    return {};
}

Result<void> approve_canary_promotion(CanaryEvaluation evaluation) noexcept {
    if (evaluation.canary_model_version <= evaluation.production_model_version) {
        return Status::downgrade_attempt;
    }
    if (!evaluation.monitor_mode_only || !evaluation.rollback_available) {
        return Status::invalid_state_transition;
    }
    if (evaluation.attack_detection_percent < 100U || evaluation.false_block_ppm >= 100U) {
        return Status::integrity_failure;
    }
    return {};
}

}  // namespace ai_shield::dataset
