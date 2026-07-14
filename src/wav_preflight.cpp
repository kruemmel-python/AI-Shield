#include "ai_shield/wav_preflight.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>

namespace ai_shield::protocols::wav {
namespace {

constexpr std::uint32_t read_u32(std::span<const std::byte> data, std::size_t offset) noexcept {
    return std::to_integer<std::uint32_t>(data[offset]) |
           (std::to_integer<std::uint32_t>(data[offset + 1U]) << 8U) |
           (std::to_integer<std::uint32_t>(data[offset + 2U]) << 16U) |
           (std::to_integer<std::uint32_t>(data[offset + 3U]) << 24U);
}

bool tag_is(std::span<const std::byte> data, std::size_t offset, std::string_view tag) noexcept {
    if (offset > data.size() || tag.size() > data.size() - offset) return false;
    for (std::size_t i = 0; i < tag.size(); ++i) {
        if (std::to_integer<unsigned char>(data[offset + i]) != static_cast<unsigned char>(tag[i])) return false;
    }
    return true;
}

bool command_bearing_metadata(std::span<const std::byte> payload) {
    constexpr std::size_t maximum_metadata_scan = 1024U * 1024U;
    const auto bounded = payload.first((std::min)(payload.size(), maximum_metadata_scan));
    std::string text;
    text.reserve(bounded.size());
    for (const auto value : bounded) {
        const auto character = std::to_integer<unsigned char>(value);
        text.push_back(character >= 0x20U && character <= 0x7eU
                           ? static_cast<char>(character >= 'A' && character <= 'Z' ? character + 0x20U : character)
                           : ' ');
    }
    constexpr auto launch_tokens = std::to_array<std::string_view>({
        "cmd.exe", "powershell", "pwsh", "curl.exe", "wget.exe", "mshta", "rundll32",
        "regsvr32", "wscript", "cscript", "certutil", "bitsadmin"});
    return std::ranges::any_of(launch_tokens, [&text](std::string_view token) {
        return text.find(token) != std::string::npos;
    });
}

}  // namespace

bool has_wave_signature(std::span<const std::byte> data) noexcept {
    return data.size() >= 12U && tag_is(data, 0U, "RIFF") && tag_is(data, 8U, "WAVE");
}

Result<ParseSummary> preflight(std::span<const std::byte> data) noexcept {
    constexpr std::size_t maximum_size = 256U * 1024U * 1024U;
    if (!has_wave_signature(data) || data.size() > maximum_size) return Status::malformed_input;

    ParseSummary summary{};
    const std::uint64_t declared_end = static_cast<std::uint64_t>(read_u32(data, 4U)) + 8ULL;
    if (declared_end != data.size() || declared_end < 12U) summary.malformed = true;
    const std::size_t parse_end = static_cast<std::size_t>((std::min<std::uint64_t>)(declared_end, data.size()));

    std::size_t offset = 12U;
    while (offset < parse_end) {
        if (parse_end - offset < 8U) {
            summary.malformed = true;
            break;
        }
        const std::uint32_t chunk_size = read_u32(data, offset + 4U);
        const std::size_t payload_offset = offset + 8U;
        if (chunk_size > parse_end - payload_offset) {
            summary.malformed = true;
            break;
        }
        const auto payload = data.subspan(payload_offset, chunk_size);
        ++summary.chunk_count;
        if (tag_is(data, offset, "fmt ")) {
            summary.format_present = chunk_size >= 16U;
            if (!summary.format_present) summary.malformed = true;
        } else if (tag_is(data, offset, "data")) {
            summary.audio_data_present = true;
        } else if (tag_is(data, offset, "LIST") || tag_is(data, offset, "INFO") ||
                   tag_is(data, offset, "ICMT") || tag_is(data, offset, "IART") ||
                   tag_is(data, offset, "INAM") || tag_is(data, offset, "ISFT")) {
            summary.suspicious_metadata = summary.suspicious_metadata || command_bearing_metadata(payload);
        }

        const std::uint64_t padded_size = static_cast<std::uint64_t>(chunk_size) + (chunk_size & 1U);
        if (padded_size > std::numeric_limits<std::size_t>::max() - payload_offset ||
            payload_offset + static_cast<std::size_t>(padded_size) > parse_end) {
            summary.malformed = true;
            break;
        }
        offset = payload_offset + static_cast<std::size_t>(padded_size);
    }
    if (!summary.format_present || !summary.audio_data_present || offset != parse_end) summary.malformed = true;
    return summary;
}

}  // namespace ai_shield::protocols::wav
