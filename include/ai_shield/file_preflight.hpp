#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace ai_shield::file_preflight {

enum class Format : std::uint32_t {
    unknown = 0U,
    pe = 1U << 0U,
    pdf = 1U << 1U,
    zip = 1U << 2U,
    wave = 1U << 3U,
    png = 1U << 4U,
    jpeg = 1U << 5U,
    gif = 1U << 6U,
    tiff = 1U << 7U,
    webp = 1U << 8U,
    mp4 = 1U << 9U,
    ole = 1U << 10U,
    rtf = 1U << 11U,
    markup = 1U << 12U,
};

struct Summary final {
    std::uint32_t formats = 0U;
    std::uint32_t strong_header_count = 0U;
    std::uint32_t external_reference_count = 0U;
    std::uint32_t command_indicator_count = 0U;
    std::uint32_t entropy_milli = 0U;
    bool extension_mismatch = false;
    bool polyglot = false;
    bool trailing_data = false;
    bool embedded_executable = false;
    bool active_content = false;
    bool automatic_action = false;
    bool unsafe_deserialization = false;
    bool suspicious_filename = false;
    bool resource_risk = false;

    [[nodiscard]] bool high_risk() const noexcept;
};

[[nodiscard]] Summary inspect(std::span<const std::byte> data, std::wstring_view filename) noexcept;

}  // namespace ai_shield::file_preflight
