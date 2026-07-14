#pragma once

#include <cstdint>

namespace ai_shield {

enum class Status : std::uint32_t {
    ok = 0,
    invalid_argument,
    overflow,
    out_of_budget,
    malformed_input,
    ambiguous_input,
    invalid_state_transition,
    integrity_failure,
    incompatible_version,
    downgrade_attempt,
    not_found
};

template <typename T>
class Result final {
public:
    constexpr Result(T value) noexcept : status_(Status::ok), value_(value) {}
    constexpr Result(Status status) noexcept : status_(status), value_{} {}

    [[nodiscard]] constexpr bool ok() const noexcept { return status_ == Status::ok; }
    [[nodiscard]] constexpr Status status() const noexcept { return status_; }
    [[nodiscard]] constexpr const T& value() const noexcept { return value_; }
    [[nodiscard]] constexpr T& value() noexcept { return value_; }

private:
    Status status_;
    T value_;
};

template <>
class Result<void> final {
public:
    constexpr Result() noexcept : status_(Status::ok) {}
    constexpr Result(Status status) noexcept : status_(status) {}

    [[nodiscard]] constexpr bool ok() const noexcept { return status_ == Status::ok; }
    [[nodiscard]] constexpr Status status() const noexcept { return status_; }

private:
    Status status_;
};

}  // namespace ai_shield
