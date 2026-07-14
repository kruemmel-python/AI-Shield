#include "ai_shield/recovery_vault.hpp"

#include <limits>

namespace ai_shield::recovery_vault {

Catalog::Catalog(std::uint64_t maximum_bytes) : maximum_bytes_(maximum_bytes) {}

Result<void> Catalog::add(Version version) {
    if (version.snapshot_id == 0U || version.captured_ns == 0U || version.path.empty()) return Status::invalid_argument;
    if (version.bytes > maximum_bytes_ || stored_bytes_ > maximum_bytes_ - version.bytes) return Status::out_of_budget;
    for (const auto& existing : versions_) {
        if (existing.snapshot_id == version.snapshot_id && existing.path == version.path) return Status::invalid_state_transition;
    }
    stored_bytes_ += version.bytes;
    versions_.push_back(std::move(version));
    return {};
}

Result<Version> Catalog::latest_before(std::string_view path, std::uint64_t cutoff_ns) const {
    const Version* selected = nullptr;
    for (const auto& version : versions_) {
        if (version.path == path && version.captured_ns <= cutoff_ns &&
            (selected == nullptr || version.captured_ns > selected->captured_ns)) selected = &version;
    }
    return selected == nullptr ? Result<Version>(Status::not_found) : Result<Version>(*selected);
}

RestorePlan Catalog::plan(std::span<const std::string> paths, std::uint64_t cutoff_ns) const {
    RestorePlan result{};
    for (const auto& path : paths) {
        const auto selected = latest_before(path, cutoff_ns);
        if (!selected.ok()) {
            result.missing_paths.push_back(path);
            continue;
        }
        if (result.total_bytes <= std::numeric_limits<std::uint64_t>::max() - selected.value().bytes)
            result.total_bytes += selected.value().bytes;
        result.versions.push_back(selected.value());
    }
    return result;
}

}  // namespace ai_shield::recovery_vault

