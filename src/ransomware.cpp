#include "ai_shield/ransomware.hpp"

#include <algorithm>
#include <set>

namespace ai_shield::ransomware {

Detector::Detector(Policy policy) : policy_(policy) {
    if (policy_.window_ns == 0U) policy_.window_ns = 1U;
    if (policy_.write_threshold == 0U) policy_.write_threshold = 1U;
    if (policy_.destructive_threshold == 0U) policy_.destructive_threshold = 1U;
    if (policy_.distinct_object_threshold == 0U) policy_.distinct_object_threshold = 1U;
    if (policy_.suspicious_score > 100U) policy_.suspicious_score = 100U;
    if (policy_.containment_score < policy_.suspicious_score) policy_.containment_score = policy_.suspicious_score;
    if (policy_.containment_score > 100U) policy_.containment_score = 100U;
}

Verdict Detector::observe(const Observation& observation) {
    if (observation.process_id == 0U || observation.monotonic_ns == 0U) return {};
    auto& values = windows_[observation.process_id].observations;
    const auto oldest = observation.monotonic_ns > policy_.window_ns ? observation.monotonic_ns - policy_.window_ns : 0U;
    std::erase_if(values, [oldest, &observation](const Observation& item) {
        return item.monotonic_ns < oldest || item.monotonic_ns > observation.monotonic_ns;
    });
    values.push_back(observation);

    Verdict verdict{};
    std::set<std::uint64_t> objects;
    bool canary = false;
    bool recovery_tamper = false;
    bool entropy = false;
    bool trusted = true;
    for (const auto& item : values) {
        trusted = trusted && item.trusted_process;
        if (item.object_id != 0U) objects.insert(item.object_id);
        if (item.kind == MutationKind::write || item.kind == MutationKind::truncate) ++verdict.writes;
        if (item.kind == MutationKind::rename || item.kind == MutationKind::remove || item.kind == MutationKind::truncate)
            ++verdict.destructive_operations;
        canary = canary || item.kind == MutationKind::canary;
        recovery_tamper = recovery_tamper || item.kind == MutationKind::recovery_tamper;
        entropy = entropy || (item.entropy_after_milli > item.entropy_before_milli &&
            item.entropy_after_milli - item.entropy_before_milli >= policy_.entropy_delta_milli);
    }
    verdict.distinct_objects = static_cast<std::uint32_t>(objects.size());
    if (verdict.writes >= policy_.write_threshold) {
        verdict.score += 30U;
        verdict.reason_mask |= Reason::write_burst;
    }
    if (verdict.destructive_operations >= policy_.destructive_threshold) {
        verdict.score += 35U;
        verdict.reason_mask |= Reason::destructive_burst;
    }
    if (verdict.distinct_objects >= policy_.distinct_object_threshold) {
        verdict.score += 20U;
        verdict.reason_mask |= Reason::broad_target_set;
    }
    if (entropy) {
        verdict.score += 25U;
        verdict.reason_mask |= Reason::entropy_increase;
    }
    if (canary) {
        verdict.score = std::max(verdict.score, 90U);
        verdict.reason_mask |= Reason::canary_modified;
    }
    if (recovery_tamper) {
        verdict.score = 100U;
        verdict.reason_mask |= Reason::recovery_tamper;
    }
    verdict.score = std::min(verdict.score, 100U);
    if (trusted && !canary && !recovery_tamper) verdict.score = verdict.score > 25U ? verdict.score - 25U : 0U;
    if (verdict.score >= policy_.containment_score) verdict.severity = Severity::confirmed;
    else if (verdict.score >= policy_.suspicious_score) verdict.severity = Severity::suspicious;
    verdict.create_incident = verdict.severity != Severity::normal;
    verdict.contain_process_tree = verdict.severity == Severity::confirmed && (!trusted || canary || recovery_tamper);
    return verdict;
}

void Detector::reset(std::uint64_t process_id) { windows_.erase(process_id); }

}  // namespace ai_shield::ransomware

