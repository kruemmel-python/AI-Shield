#pragma once

#include <limits>
#include <type_traits>

#include "ai_shield/result.hpp"

namespace ai_shield::checked {

template <typename T>
[[nodiscard]] constexpr Result<T> add(T a, T b) noexcept {
    static_assert(std::is_integral_v<T>);
    if constexpr (std::is_unsigned_v<T>) {
        if (a > std::numeric_limits<T>::max() - b) {
            return Status::overflow;
        }
    } else {
        if ((b > 0 && a > std::numeric_limits<T>::max() - b) ||
            (b < 0 && a < std::numeric_limits<T>::min() - b)) {
            return Status::overflow;
        }
    }
    return static_cast<T>(a + b);
}

template <typename T>
[[nodiscard]] constexpr Result<T> multiply(T a, T b) noexcept {
    static_assert(std::is_integral_v<T>);
    if (a == 0 || b == 0) {
        return static_cast<T>(0);
    }
    if constexpr (std::is_unsigned_v<T>) {
        if (a > std::numeric_limits<T>::max() / b) {
            return Status::overflow;
        }
        return static_cast<T>(a * b);
    } else {
        const auto wide = static_cast<long long>(a) * static_cast<long long>(b);
        if (wide > static_cast<long long>(std::numeric_limits<T>::max()) ||
            wide < static_cast<long long>(std::numeric_limits<T>::min())) {
            return Status::overflow;
        }
        return static_cast<T>(wide);
    }
}

}  // namespace ai_shield::checked
