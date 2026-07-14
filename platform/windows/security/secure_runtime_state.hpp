#pragma once

#include <cstdint>
#include <filesystem>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::platform::windows::security {

struct RuntimeState final {
    std::uint64_t generation = 1;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 1;
    std::uint64_t previous_generation = 0;
    crypto::Sha256Digest channel_key{};
    crypto::Sha256Digest previous_channel_key{};
};

class SecureRuntimeStore final {
public:
    explicit SecureRuntimeStore(std::filesystem::path directory);
    [[nodiscard]] Result<RuntimeState> load_or_create() const;
    [[nodiscard]] Result<RuntimeState> update_versions(std::uint64_t policy_version,
                                                       std::uint64_t model_version) const;
    [[nodiscard]] Result<RuntimeState> rotate_key() const;

private:
    [[nodiscard]] Result<RuntimeState> load() const;
    [[nodiscard]] Result<void> save(const RuntimeState& state) const;
    std::filesystem::path directory_;
};

}  // namespace ai_shield::platform::windows::security
