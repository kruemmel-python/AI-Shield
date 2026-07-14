#include "ai_shield/sequence_model.hpp"

#include <algorithm>

namespace ai_shield::sequence {

const NGramModel::NGram* NGramModel::find(std::span<const std::uint32_t> ngram) const noexcept {
    for (const auto& known : grams_) {
        if (known.tokens.size() == ngram.size() && std::equal(known.tokens.begin(), known.tokens.end(), ngram.begin())) {
            return &known;
        }
    }
    return nullptr;
}

NGramModel::NGram* NGramModel::find(std::span<const std::uint32_t> ngram) noexcept {
    for (auto& known : grams_) {
        if (known.tokens.size() == ngram.size() && std::equal(known.tokens.begin(), known.tokens.end(), ngram.begin())) {
            return &known;
        }
    }
    return nullptr;
}

Result<void> NGramModel::learn(std::span<const std::uint32_t> tokens) {
    if (order_ == 0U || tokens.size() < order_) {
        return Status::invalid_argument;
    }
    for (std::size_t i = 0; i + order_ <= tokens.size(); ++i) {
        const auto gram = tokens.subspan(i, order_);
        auto* existing = find(gram);
        if (existing != nullptr) {
            ++existing->count;
        } else {
            grams_.push_back(NGram{std::vector<std::uint32_t>(gram.begin(), gram.end()), 1});
        }
    }
    return {};
}

detection::Evidence NGramModel::score(std::span<const std::uint32_t> tokens) const {
    detection::Evidence evidence{};
    if (order_ == 0U || tokens.size() < order_) {
        evidence.novelty = 50;
        return evidence;
    }
    std::uint32_t unknown = 0;
    std::uint32_t total = 0;
    for (std::size_t i = 0; i + order_ <= tokens.size(); ++i) {
        ++total;
        if (find(tokens.subspan(i, order_)) == nullptr) {
            ++unknown;
        }
    }
    evidence.novelty = total == 0U ? 50 : detection::clipped_score((unknown * 100U) / total);
    return evidence;
}

}  // namespace ai_shield::sequence
