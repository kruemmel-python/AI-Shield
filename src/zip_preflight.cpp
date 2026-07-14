#include "ai_shield/zip_preflight.hpp"

#include "ai_shield/abi.hpp"

#include <algorithm>
#include <set>
#include <string>

namespace ai_shield::protocols::zip {
namespace {

[[nodiscard]] std::uint16_t read_le16(std::span<const std::byte> data, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(data[offset]) |
                                      (std::to_integer<std::uint16_t>(data[offset + 1U]) << 8U));
}

[[nodiscard]] std::uint32_t read_le32(std::span<const std::byte> data, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= std::to_integer<std::uint32_t>(data[offset + i]) << (i * 8U);
    }
    return value;
}

[[nodiscard]] bool unsafe_name(std::string_view name) noexcept {
    return name.find("..") != std::string_view::npos || name.find(':') != std::string_view::npos ||
           (!name.empty() && (name.front() == '/' || name.front() == '\\')) || name.find("\\\\") != std::string_view::npos;
}

}  // namespace

Result<EntrySummary> preflight(std::span<const std::byte> data) noexcept {
    EntrySummary summary{};
    std::set<std::string> names;
    if (data.size() < 30U || data.size() > 128U * 1024U * 1024U) {
        return Status::malformed_input;
    }
    std::size_t offset = 0;
    while (offset + 30U <= data.size()) {
        if (read_le32(data, offset) != 0x04034b50U) {
            break;
        }
        const auto flags = read_le16(data, offset + 6U);
        const auto method = read_le16(data, offset + 8U);
        const auto compressed = read_le32(data, offset + 18U);
        const auto uncompressed = read_le32(data, offset + 22U);
        const auto name_len = read_le16(data, offset + 26U);
        const auto extra_len = read_le16(data, offset + 28U);
        const auto name_start = offset + 30U;
        const auto data_start = name_start + name_len + extra_len;
        if (name_len == 0U || data_start > data.size() || data_start + compressed > data.size()) {
            summary.malformed = true;
            return summary;
        }
        std::string name;
        name.reserve(name_len);
        for (std::size_t i = 0; i < name_len; ++i) {
            name.push_back(static_cast<char>(std::to_integer<unsigned char>(data[name_start + i])));
        }
        summary.path_escape = summary.path_escape || unsafe_name(name);
        summary.encrypted_entry = summary.encrypted_entry || ((flags & 0x0001U) != 0U);
        // This preflight never inflates payloads. Any compressed child therefore requires a deeper isolated parser.
        summary.unsupported_compression = summary.unsupported_compression || method != 0U;
        std::ranges::transform(name, name.begin(), [](char value) {
            return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
        });
        summary.duplicate_name = summary.duplicate_name || !names.insert(name).second;
        const auto dot = name.rfind('.');
        const std::string_view extension = dot == std::string::npos ? std::string_view{} : std::string_view(name).substr(dot);
        const auto is_extension = [extension](std::initializer_list<std::string_view> values) {
            return std::ranges::find(values, extension) != values.end();
        };
        summary.executable_entry = summary.executable_entry || is_extension(
            {".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk"});
        summary.active_content_entry = summary.active_content_entry || is_extension(
            {".docm", ".xlsm", ".pptm", ".xlam", ".ppam", ".sct", ".chm", ".jar"});
        summary.nested_container = summary.nested_container || is_extension(
            {".zip", ".7z", ".rar", ".cab", ".iso", ".vhd", ".vhdx", ".img"});
        summary.compressed_bytes += compressed;
        summary.uncompressed_bytes += uncompressed;
        ++summary.entry_count;
        if (summary.entry_count > 10000U || (compressed > 0U && uncompressed / compressed > 100U) ||
            summary.uncompressed_bytes > 2ULL * 1024ULL * 1024ULL * 1024ULL) {
            summary.bomb_risk = true;
        }
        offset = data_start + compressed;
    }
    if (summary.entry_count == 0U) {
        summary.malformed = true;
    }
    return summary;
}

detection::Evidence evidence_from(const EntrySummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed) {
        evidence.protocol = 80;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.path_escape) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::archive_path_escape | abi::ReasonCode::path_traversal;
    }
    if (summary.bomb_risk) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::archive_bomb_risk;
    }
    if (summary.encrypted_entry) {
        evidence.novelty = detection::clipped_score(evidence.novelty + 30U);
    }
    if (summary.unsupported_compression || summary.executable_entry || summary.active_content_entry ||
        summary.nested_container || summary.duplicate_name) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 70U);
        evidence.reason_mask |= abi::ReasonCode::consequence_detected;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::zip
