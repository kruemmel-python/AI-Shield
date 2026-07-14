#pragma once

#include <array>
#include <cstddef>
#include <utility>

#include "ai_shield/result.hpp"

namespace ai_shield {

template <typename T, std::size_t Capacity>
class BoundedRing final {
public:
    static_assert(Capacity > 0);

    [[nodiscard]] constexpr std::size_t capacity() const noexcept { return Capacity; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] constexpr bool full() const noexcept { return size_ == Capacity; }

    constexpr Result<void> push(const T& value) noexcept {
        if (full()) {
            return Status::out_of_budget;
        }
        values_[tail_] = value;
        tail_ = (tail_ + 1U) % Capacity;
        ++size_;
        return {};
    }

    constexpr Result<T> pop() noexcept {
        if (empty()) {
            return Status::not_found;
        }
        T value = values_[head_];
        head_ = (head_ + 1U) % Capacity;
        --size_;
        return value;
    }

private:
    std::array<T, Capacity> values_{};
    std::size_t head_ = 0;
    std::size_t tail_ = 0;
    std::size_t size_ = 0;
};

}  // namespace ai_shield
