#include "ai_shield/file_preflight.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <filesystem>
#include <string>

namespace ai_shield::file_preflight {
namespace {

constexpr std::uint32_t bit(Format format) noexcept { return static_cast<std::uint32_t>(format); }

bool starts_with(std::span<const std::byte> data, std::initializer_list<unsigned int> bytes) noexcept {
    if (data.size() < bytes.size()) return false;
    std::size_t index = 0U;
    for (const auto expected : bytes) {
        if (std::to_integer<unsigned int>(data[index++]) != expected) return false;
    }
    return true;
}

bool ascii_at(std::span<const std::byte> data, std::size_t offset, std::string_view value) noexcept {
    if (offset > data.size() || value.size() > data.size() - offset) return false;
    for (std::size_t i = 0U; i < value.size(); ++i)
        if (std::to_integer<unsigned char>(data[offset + i]) != static_cast<unsigned char>(value[i])) return false;
    return true;
}

std::size_t find_bytes(std::span<const std::byte> data, std::string_view value, std::size_t begin = 0U) noexcept {
    if (value.empty() || begin > data.size() || value.size() > data.size() - begin) return std::string_view::npos;
    for (std::size_t offset = begin; offset + value.size() <= data.size(); ++offset)
        if (ascii_at(data, offset, value)) return offset;
    return std::string_view::npos;
}

std::wstring lower_extension(std::wstring_view filename) {
    auto extension = std::filesystem::path(filename).extension().wstring();
    std::ranges::transform(extension, extension.begin(), [](wchar_t value) {
        return value >= L'A' && value <= L'Z' ? static_cast<wchar_t>(value + (L'a' - L'A')) : value;
    });
    return extension;
}

bool is_one_of(std::wstring_view value, std::initializer_list<std::wstring_view> values) noexcept {
    return std::ranges::find(values, value) != values.end();
}

std::uint32_t expected_formats(std::wstring_view extension) noexcept {
    if (is_one_of(extension, {L".exe", L".dll", L".sys", L".scr", L".cpl", L".ocx", L".drv", L".efi"}))
        return bit(Format::pe);
    if (is_one_of(extension, {L".pdf", L".fdf"})) return bit(Format::pdf);
    if (is_one_of(extension, {L".zip", L".docx", L".docm", L".xlsx", L".xlsm", L".pptx", L".pptm",
                              L".odt", L".ods", L".odp", L".epub", L".jar", L".apk", L".nupkg",
                              L".vsix", L".crx", L".xpi", L".kmz", L".3mf"})) return bit(Format::zip);
    if (extension == L".wav") return bit(Format::wave);
    if (extension == L".png") return bit(Format::png);
    if (is_one_of(extension, {L".jpg", L".jpeg", L".jpe"})) return bit(Format::jpeg);
    if (extension == L".gif") return bit(Format::gif);
    if (is_one_of(extension, {L".tif", L".tiff"})) return bit(Format::tiff);
    if (extension == L".webp") return bit(Format::webp);
    if (is_one_of(extension, {L".mp4", L".m4a", L".m4v", L".mov", L".heif", L".heic", L".avif"}))
        return bit(Format::mp4);
    if (is_one_of(extension, {L".doc", L".dot", L".xls", L".xlt", L".ppt", L".pot", L".msi", L".msp", L".msg"}))
        return bit(Format::ole);
    if (extension == L".rtf") return bit(Format::rtf);
    if (is_one_of(extension, {L".html", L".htm", L".svg", L".xml", L".xsl", L".xslt", L".xhtml"}))
        return bit(Format::markup);
    return 0U;
}

std::string searchable_text(std::span<const std::byte> data) {
    constexpr std::size_t maximum = 8U * 1024U * 1024U;
    const auto bounded = data.first((std::min)(data.size(), maximum));
    std::string text;
    text.reserve(bounded.size());
    for (const auto byte : bounded) {
        auto value = std::to_integer<unsigned char>(byte);
        if (value >= 'A' && value <= 'Z') value = static_cast<unsigned char>(value + ('a' - 'A'));
        text.push_back(value >= 0x20U && value <= 0x7eU ? static_cast<char>(value) : ' ');
    }
    return text;
}

std::uint32_t count_tokens(std::string_view text, std::initializer_list<std::string_view> tokens) noexcept {
    std::uint32_t count = 0U;
    for (const auto token : tokens) if (text.find(token) != std::string_view::npos) ++count;
    return count;
}

std::uint32_t entropy_milli(std::span<const std::byte> data) noexcept {
    if (data.empty()) return 0U;
    constexpr std::size_t maximum = 4U * 1024U * 1024U;
    const auto sample = data.first((std::min)(data.size(), maximum));
    std::array<std::uint32_t, 256> counts{};
    for (const auto byte : sample) ++counts[std::to_integer<unsigned char>(byte)];
    double entropy = 0.0;
    for (const auto count : counts) {
        if (count == 0U) continue;
        const double probability = static_cast<double>(count) / static_cast<double>(sample.size());
        entropy -= probability * std::log2(probability);
    }
    return static_cast<std::uint32_t>(entropy * 1000.0 + 0.5);
}

bool deceptive_name(std::wstring_view filename) noexcept {
    if (filename.size() > 240U || filename.empty() || filename.back() == L'.' || filename.back() == L' ') return true;
    for (const wchar_t value : filename) {
        if (value < 0x20 || value == 0x202a || value == 0x202b || value == 0x202d || value == 0x202e ||
            value == 0x202c || value == 0x2066 || value == 0x2067 || value == 0x2068 || value == 0x2069)
            return true;
    }
    const auto name = std::filesystem::path(filename).filename().wstring();
    const auto final_extension = lower_extension(name);
    const auto first_dot = name.find(L'.');
    const auto last_dot = name.rfind(L'.');
    const bool multiple_extensions = first_dot != std::wstring::npos && last_dot != first_dot;
    return multiple_extensions && is_one_of(final_extension,
        {L".exe", L".com", L".scr", L".cpl", L".bat", L".cmd", L".ps1", L".vbs", L".js", L".hta", L".lnk"});
}

}  // namespace

bool Summary::high_risk() const noexcept {
    return extension_mismatch || polyglot || trailing_data || embedded_executable || active_content ||
           automatic_action || unsafe_deserialization || suspicious_filename || resource_risk;
}

Summary inspect(std::span<const std::byte> data, std::wstring_view filename) noexcept {
    Summary summary{};
    const auto extension = lower_extension(filename);
    summary.suspicious_filename = deceptive_name(filename);
    summary.resource_risk = data.empty() || data.size() > 256U * 1024U * 1024U;
    if (data.empty()) return summary;

    if (starts_with(data, {'M', 'Z'})) summary.formats |= bit(Format::pe);
    if (ascii_at(data, 0U, "%PDF-")) summary.formats |= bit(Format::pdf);
    if (starts_with(data, {'P', 'K', 3U, 4U}) || starts_with(data, {'P', 'K', 5U, 6U}) ||
        starts_with(data, {'P', 'K', 7U, 8U})) summary.formats |= bit(Format::zip);
    if (ascii_at(data, 0U, "RIFF") && ascii_at(data, 8U, "WAVE")) summary.formats |= bit(Format::wave);
    if (starts_with(data, {0x89U, 'P', 'N', 'G', 0x0dU, 0x0aU, 0x1aU, 0x0aU})) summary.formats |= bit(Format::png);
    if (starts_with(data, {0xffU, 0xd8U, 0xffU})) summary.formats |= bit(Format::jpeg);
    if (ascii_at(data, 0U, "GIF87a") || ascii_at(data, 0U, "GIF89a")) summary.formats |= bit(Format::gif);
    if (starts_with(data, {'I', 'I', 42U, 0U}) || starts_with(data, {'M', 'M', 0U, 42U})) summary.formats |= bit(Format::tiff);
    if (ascii_at(data, 0U, "RIFF") && ascii_at(data, 8U, "WEBP")) summary.formats |= bit(Format::webp);
    if (data.size() >= 12U && ascii_at(data, 4U, "ftyp")) summary.formats |= bit(Format::mp4);
    if (starts_with(data, {0xd0U, 0xcfU, 0x11U, 0xe0U, 0xa1U, 0xb1U, 0x1aU, 0xe1U})) summary.formats |= bit(Format::ole);
    if (ascii_at(data, 0U, "{\\rtf")) summary.formats |= bit(Format::rtf);

    const auto text = searchable_text(data);
    if (text.starts_with("<!doctype html") || text.starts_with("<html") || text.starts_with("<?xml") ||
        text.starts_with("<svg")) summary.formats |= bit(Format::markup);

    const auto expected = expected_formats(extension);
    summary.extension_mismatch = expected != 0U && (summary.formats & expected) == 0U;
    summary.strong_header_count = static_cast<std::uint32_t>(std::popcount(summary.formats));

    const bool embedded_pe = find_bytes(data, "MZ", 1U) != std::string_view::npos;
    summary.embedded_executable = embedded_pe;
    const bool embedded_pdf = find_bytes(data, "%PDF-", 1U) != std::string_view::npos;
    const bool embedded_zip = find_bytes(data, "PK\x03\x04", 1U) != std::string_view::npos;
    const bool embedded_riff = find_bytes(data, "RIFF", 1U) != std::string_view::npos;
    const std::uint32_t embedded_types = static_cast<std::uint32_t>(embedded_pe) +
        static_cast<std::uint32_t>(embedded_pdf) + static_cast<std::uint32_t>(embedded_zip) +
        static_cast<std::uint32_t>(embedded_riff);
    summary.polyglot = summary.strong_header_count > 1U ||
        ((summary.formats & (bit(Format::zip) | bit(Format::ole))) == 0U && embedded_types > 0U);

    if ((summary.formats & bit(Format::pdf)) != 0U) {
        const auto eof = text.rfind("%%eof");
        if (eof != std::string::npos) {
            const auto tail = text.substr(eof + 5U);
            summary.trailing_data = tail.find_first_not_of(" \t\r\n") != std::string_view::npos;
        }
    }
    if ((summary.formats & bit(Format::png)) != 0U) {
        const auto iend = find_bytes(data, "IEND", 8U);
        summary.trailing_data = iend != std::string_view::npos && iend + 8U < data.size();
    }

    summary.external_reference_count = count_tokens(text,
        {"http://", "https://", "file://", "ftp://", "webdav", "\\\\", "targetmode=\"external\""});
    summary.command_indicator_count = count_tokens(text,
        {"cmd.exe", "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
         "certutil", "bitsadmin", "curl.exe", "wget.exe", "invoke-expression", "downloadstring"});

    const bool script_type = is_one_of(extension,
        {L".bat", L".cmd", L".ps1", L".psm1", L".vbs", L".vbe", L".js", L".jse", L".wsf", L".hta",
         L".sct", L".py", L".pyw", L".sh", L".pl", L".rb", L".php", L".lua", L".tcl"});
    const bool office_active = count_tokens(text,
        {"vbaproject.bin", "ddeauto", "oleobject", "attachedtemplate", "xl/macrosheets", "activex"}) > 0U;
    const bool web_active = count_tokens(text,
        {"<script", "javascript:", "onload=", "onerror=", "<foreignobject", "data:text/html"}) > 0U;
    summary.active_content = office_active || web_active || (script_type && summary.command_indicator_count > 0U);
    summary.automatic_action = count_tokens(text,
        {"openaction", "ddeauto", "autoopen", "document_open", "workbook_open", "onload=", "autorun"}) > 0U;
    summary.unsafe_deserialization = is_one_of(extension,
        {L".pkl", L".pickle", L".joblib", L".dill", L".pt", L".pth", L".ckpt"});
    summary.entropy_milli = entropy_milli(data);
    if ((summary.formats & bit(Format::pe)) != 0U && data.size() >= 4096U && summary.entropy_milli >= 7800U)
        summary.resource_risk = true;
    return summary;
}

}  // namespace ai_shield::file_preflight
