#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/detection.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::sequence {

class NGramModel final {
public:
    explicit NGramModel(std::uint32_t order) noexcept : order_(order) {}
    [[nodiscard]] Result<void> learn(std::span<const std::uint32_t> tokens);
    [[nodiscard]] detection::Evidence score(std::span<const std::uint32_t> tokens) const;

private:
    struct NGram final {
        std::vector<std::uint32_t> tokens;
        std::uint32_t count = 0;
    };

    [[nodiscard]] const NGram* find(std::span<const std::uint32_t> ngram) const noexcept;
    [[nodiscard]] NGram* find(std::span<const std::uint32_t> ngram) noexcept;

    std::uint32_t order_ = 0;
    std::vector<NGram> grams_;
};

}  // namespace ai_shield::sequence
