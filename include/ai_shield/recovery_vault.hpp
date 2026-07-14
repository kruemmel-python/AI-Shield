#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::recovery_vault {

struct Version final {
    std::uint64_t snapshot_id = 0;
    std::uint64_t captured_ns = 0;
    std::uint64_t bytes = 0;
    std::string path;
    crypto::Sha256Digest content_hash{};
};

struct RestorePlan final {
    std::vector<Version> versions;
    std::vector<std::string> missing_paths;
    std::uint64_t total_bytes = 0;
};

class Catalog final {
public:
    explicit Catalog(std::uint64_t maximum_bytes);
    [[nodiscard]] Result<void> add(Version version);
    [[nodiscard]] Result<Version> latest_before(std::string_view path, std::uint64_t cutoff_ns) const;
    [[nodiscard]] RestorePlan plan(std::span<const std::string> paths, std::uint64_t cutoff_ns) const;
    [[nodiscard]] std::uint64_t stored_bytes() const noexcept { return stored_bytes_; }
    [[nodiscard]] std::size_t version_count() const noexcept { return versions_.size(); }

private:
    std::uint64_t maximum_bytes_ = 0;
    std::uint64_t stored_bytes_ = 0;
    std::vector<Version> versions_;
};

}  // namespace ai_shield::recovery_vault

