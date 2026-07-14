#include "ai_shield/zip_preflight.hpp"

#include "ai_shield/abi.hpp"
#include "ai_shield/file_preflight.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace ai_shield::protocols::zip {
namespace {

constexpr std::uint32_t kLocalHeader = 0x04034b50U;
constexpr std::uint32_t kCentralHeader = 0x02014b50U;
constexpr std::uint32_t kEndOfCentralDirectory = 0x06054b50U;
constexpr std::uint32_t kZip64EndOfCentralDirectory = 0x06064b50U;
constexpr std::uint32_t kZip64Locator = 0x07064b50U;
constexpr std::uint32_t kDataDescriptor = 0x08074b50U;

struct SharedBudget final {
    InspectionBudget limits{};
    std::uint32_t entries = 0U;
    std::uint64_t expanded = 0U;
};

struct DirectoryLocation final {
    std::uint64_t entries = 0U;
    std::uint64_t offset = 0U;
    std::uint64_t size = 0U;
};

struct Zip64Values final {
    std::uint64_t uncompressed = 0U;
    std::uint64_t compressed = 0U;
    std::uint64_t local_offset = 0U;
    std::uint32_t disk = 0U;
    bool valid = true;
};

[[nodiscard]] bool has(std::span<const std::byte> data, std::size_t offset, std::size_t count) noexcept {
    return offset <= data.size() && count <= data.size() - offset;
}

[[nodiscard]] std::uint16_t read16(std::span<const std::byte> data, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(data[offset]) |
                                      (std::to_integer<std::uint16_t>(data[offset + 1U]) << 8U));
}

[[nodiscard]] std::uint32_t read32(std::span<const std::byte> data, std::size_t offset) noexcept {
    std::uint32_t value = 0U;
    for (std::size_t index = 0U; index < 4U; ++index)
        value |= std::to_integer<std::uint32_t>(data[offset + index]) << (index * 8U);
    return value;
}

[[nodiscard]] std::uint64_t read64(std::span<const std::byte> data, std::size_t offset) noexcept {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 8U; ++index)
        value |= std::to_integer<std::uint64_t>(data[offset + index]) << (index * 8U);
    return value;
}

[[nodiscard]] std::uint32_t crc32(std::span<const std::byte> data) noexcept {
    std::uint32_t crc = 0xffffffffU;
    for (const auto byte : data) {
        crc ^= std::to_integer<std::uint8_t>(byte);
        for (unsigned int bit = 0U; bit < 8U; ++bit)
            crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

[[nodiscard]] bool valid_utf8(std::string_view value) noexcept {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto first = static_cast<unsigned char>(value[offset++]);
        if (first < 0x80U) {
            if (first == 0U) return false;
            continue;
        }
        unsigned int remaining = 0U;
        std::uint32_t scalar = 0U;
        if ((first & 0xe0U) == 0xc0U) { remaining = 1U; scalar = first & 0x1fU; }
        else if ((first & 0xf0U) == 0xe0U) { remaining = 2U; scalar = first & 0x0fU; }
        else if ((first & 0xf8U) == 0xf0U) { remaining = 3U; scalar = first & 0x07U; }
        else return false;
        if (offset + remaining > value.size()) return false;
        for (unsigned int index = 0U; index < remaining; ++index) {
            const auto continuation = static_cast<unsigned char>(value[offset++]);
            if ((continuation & 0xc0U) != 0x80U) return false;
            scalar = (scalar << 6U) | (continuation & 0x3fU);
        }
        if ((remaining == 1U && scalar < 0x80U) || (remaining == 2U && scalar < 0x800U) ||
            (remaining == 3U && scalar < 0x10000U) || scalar > 0x10ffffU ||
            (scalar >= 0xd800U && scalar <= 0xdfffU)) return false;
    }
    return true;
}

[[nodiscard]] std::optional<std::string> canonical_name(std::string_view name) {
    if (name.empty() || name.front() == '/' || name.front() == '\\') return std::nullopt;
    std::string result;
    result.reserve(name.size());
    std::size_t segment_start = 0U;
    for (std::size_t index = 0U; index <= name.size(); ++index) {
        const bool separator = index == name.size() || name[index] == '/' || name[index] == '\\';
        if (!separator) {
            const auto value = static_cast<unsigned char>(name[index]);
            if (value == 0U || value < 0x20U || name[index] == ':') return std::nullopt;
            continue;
        }
        const auto segment = name.substr(segment_start, index - segment_start);
        if (segment == "." || segment == "..") return std::nullopt;
        if (!segment.empty()) {
            if (!result.empty()) result.push_back('/');
            for (const char value : segment)
                result.push_back(value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value);
        }
        segment_start = index + 1U;
    }
    return result.empty() ? std::nullopt : std::optional<std::string>(std::move(result));
}

[[nodiscard]] bool extension_is(std::string_view name,
                                std::initializer_list<std::string_view> extensions) noexcept {
    const auto dot = name.rfind('.');
    const auto extension = dot == std::string_view::npos ? std::string_view{} : name.substr(dot);
    return std::ranges::find(extensions, extension) != extensions.end();
}

class BitReader final {
public:
    explicit BitReader(std::span<const std::byte> input) : input_(input) {}

    [[nodiscard]] std::optional<std::uint32_t> read(unsigned int count) noexcept {
        if (count > 24U || bit_ + count > input_.size() * 8U) return std::nullopt;
        std::uint32_t value = 0U;
        for (unsigned int index = 0U; index < count; ++index) {
            const auto byte = std::to_integer<std::uint8_t>(input_[(bit_ + index) / 8U]);
            value |= ((byte >> ((bit_ + index) % 8U)) & 1U) << index;
        }
        bit_ += count;
        return value;
    }

    void align() noexcept { bit_ = (bit_ + 7U) & ~std::size_t{7U}; }
    [[nodiscard]] std::size_t byte_offset() const noexcept { return (bit_ + 7U) / 8U; }

private:
    std::span<const std::byte> input_;
    std::size_t bit_ = 0U;
};

struct HuffmanCode final {
    std::uint16_t reversed = 0U;
    std::uint16_t symbol = 0U;
    std::uint8_t length = 0U;
};

class Huffman final {
public:
    [[nodiscard]] bool build(std::span<const std::uint8_t> lengths) {
        std::array<std::uint16_t, 16> counts{};
        for (const auto length : lengths) {
            if (length > 15U) return false;
            if (length != 0U) ++counts[length];
        }
        std::int32_t available = 1;
        for (std::size_t length = 1U; length < counts.size(); ++length) {
            available = available * 2 - counts[length];
            if (available < 0) return false;
        }
        std::array<std::uint16_t, 16> next{};
        std::uint16_t code = 0U;
        for (std::size_t length = 1U; length < counts.size(); ++length) {
            code = static_cast<std::uint16_t>((code + counts[length - 1U]) << 1U);
            next[length] = code;
        }
        codes_.clear();
        for (std::size_t symbol = 0U; symbol < lengths.size(); ++symbol) {
            const auto length = lengths[symbol];
            if (length == 0U) continue;
            const auto canonical = next[length]++;
            std::uint16_t reversed = 0U;
            for (unsigned int bit = 0U; bit < length; ++bit)
                reversed = static_cast<std::uint16_t>((reversed << 1U) | ((canonical >> bit) & 1U));
            codes_.push_back({reversed, static_cast<std::uint16_t>(symbol), length});
            maximum_length_ = (std::max)(maximum_length_, length);
        }
        return !codes_.empty();
    }

    [[nodiscard]] std::optional<std::uint16_t> decode(BitReader& reader) const noexcept {
        std::uint16_t code = 0U;
        for (std::uint8_t length = 1U; length <= maximum_length_; ++length) {
            const auto bit = reader.read(1U);
            if (!bit) return std::nullopt;
            code = static_cast<std::uint16_t>(code | (*bit << (length - 1U)));
            for (const auto& candidate : codes_)
                if (candidate.length == length && candidate.reversed == code) return candidate.symbol;
        }
        return std::nullopt;
    }

private:
    std::vector<HuffmanCode> codes_;
    std::uint8_t maximum_length_ = 0U;
};

[[nodiscard]] bool dynamic_tables(BitReader& reader, Huffman& literals, Huffman& distances) {
    const auto hlit_bits = reader.read(5U);
    const auto hdist_bits = reader.read(5U);
    const auto hclen_bits = reader.read(4U);
    if (!hlit_bits || !hdist_bits || !hclen_bits) return false;
    const std::size_t literal_count = *hlit_bits + 257U;
    const std::size_t distance_count = *hdist_bits + 1U;
    const std::size_t code_count = *hclen_bits + 4U;
    constexpr std::array<std::uint8_t, 19> order{16U, 17U, 18U, 0U, 8U, 7U, 9U, 6U, 10U,
        5U, 11U, 4U, 12U, 3U, 13U, 2U, 14U, 1U, 15U};
    std::array<std::uint8_t, 19> code_lengths{};
    for (std::size_t index = 0U; index < code_count; ++index) {
        const auto value = reader.read(3U);
        if (!value) return false;
        code_lengths[order[index]] = static_cast<std::uint8_t>(*value);
    }
    Huffman code_table;
    if (!code_table.build(code_lengths)) return false;
    std::vector<std::uint8_t> lengths;
    lengths.reserve(literal_count + distance_count);
    while (lengths.size() < literal_count + distance_count) {
        const auto symbol = code_table.decode(reader);
        if (!symbol) return false;
        if (*symbol <= 15U) lengths.push_back(static_cast<std::uint8_t>(*symbol));
        else {
            unsigned int extra_bits = 0U;
            std::size_t base = 0U;
            std::uint8_t repeated = 0U;
            if (*symbol == 16U) {
                if (lengths.empty()) return false;
                extra_bits = 2U; base = 3U; repeated = lengths.back();
            } else if (*symbol == 17U) { extra_bits = 3U; base = 3U; }
            else if (*symbol == 18U) { extra_bits = 7U; base = 11U; }
            else return false;
            const auto extra = reader.read(extra_bits);
            if (!extra || lengths.size() + base + *extra > literal_count + distance_count) return false;
            lengths.insert(lengths.end(), base + *extra, repeated);
        }
    }
    if (lengths[256U] == 0U) return false;
    return literals.build(std::span(lengths).first(literal_count)) &&
           distances.build(std::span(lengths).subspan(literal_count, distance_count));
}

[[nodiscard]] bool fixed_tables(Huffman& literals, Huffman& distances) {
    std::array<std::uint8_t, 288> literal_lengths{};
    std::fill_n(literal_lengths.begin(), 144U, std::uint8_t{8U});
    std::fill_n(literal_lengths.begin() + 144U, 112U, std::uint8_t{9U});
    std::fill_n(literal_lengths.begin() + 256U, 24U, std::uint8_t{7U});
    std::fill_n(literal_lengths.begin() + 280U, 8U, std::uint8_t{8U});
    std::array<std::uint8_t, 32> distance_lengths{};
    distance_lengths.fill(5U);
    return literals.build(literal_lengths) && distances.build(distance_lengths);
}

[[nodiscard]] bool inflate_raw(std::span<const std::byte> input, std::size_t expected,
                               std::vector<std::byte>& output) {
    constexpr std::array<std::uint16_t, 29> length_base{3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U,
        13U, 15U, 17U, 19U, 23U, 27U, 31U, 35U, 43U, 51U, 59U, 67U, 83U, 99U, 115U, 131U,
        163U, 195U, 227U, 258U};
    constexpr std::array<std::uint8_t, 29> length_extra{0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        1U, 1U, 1U, 1U, 2U, 2U, 2U, 2U, 3U, 3U, 3U, 3U, 4U, 4U, 4U, 4U, 5U, 5U, 5U, 5U, 0U};
    constexpr std::array<std::uint16_t, 30> distance_base{1U, 2U, 3U, 4U, 5U, 7U, 9U, 13U,
        17U, 25U, 33U, 49U, 65U, 97U, 129U, 193U, 257U, 385U, 513U, 769U, 1025U, 1537U,
        2049U, 3073U, 4097U, 6145U, 8193U, 12289U, 16385U, 24577U};
    constexpr std::array<std::uint8_t, 30> distance_extra{0U, 0U, 0U, 0U, 1U, 1U, 2U, 2U,
        3U, 3U, 4U, 4U, 5U, 5U, 6U, 6U, 7U, 7U, 8U, 8U, 9U, 9U, 10U, 10U, 11U, 11U,
        12U, 12U, 13U, 13U};
    BitReader reader(input);
    output.clear();
    output.reserve(expected);
    bool final_block = false;
    while (!final_block) {
        const auto final = reader.read(1U);
        const auto type = reader.read(2U);
        if (!final || !type || *type == 3U) return false;
        final_block = *final != 0U;
        if (*type == 0U) {
            reader.align();
            const auto length = reader.read(16U);
            const auto complement = reader.read(16U);
            if (!length || !complement || static_cast<std::uint16_t>(*length ^ 0xffffU) != *complement ||
                output.size() + *length > expected) return false;
            for (std::uint32_t index = 0U; index < *length; ++index) {
                const auto value = reader.read(8U);
                if (!value) return false;
                output.push_back(static_cast<std::byte>(*value));
            }
            continue;
        }
        Huffman literals;
        Huffman distances;
        if ((*type == 1U && !fixed_tables(literals, distances)) ||
            (*type == 2U && !dynamic_tables(reader, literals, distances))) return false;
        for (;;) {
            const auto symbol = literals.decode(reader);
            if (!symbol) return false;
            if (*symbol < 256U) {
                if (output.size() >= expected) return false;
                output.push_back(static_cast<std::byte>(*symbol));
                continue;
            }
            if (*symbol == 256U) break;
            if (*symbol < 257U || *symbol > 285U) return false;
            const auto length_index = static_cast<std::size_t>(*symbol - 257U);
            const auto length_bits = reader.read(length_extra[length_index]);
            if (!length_bits) return false;
            const std::size_t length = length_base[length_index] + *length_bits;
            const auto distance_symbol = distances.decode(reader);
            if (!distance_symbol || *distance_symbol >= distance_base.size()) return false;
            const auto distance_bits = reader.read(distance_extra[*distance_symbol]);
            if (!distance_bits) return false;
            const std::size_t distance = distance_base[*distance_symbol] + *distance_bits;
            if (distance == 0U || distance > output.size() || output.size() + length > expected) return false;
            for (std::size_t index = 0U; index < length; ++index)
                output.push_back(output[output.size() - distance]);
        }
    }
    return output.size() == expected && reader.byte_offset() == input.size();
}

[[nodiscard]] std::optional<std::size_t> find_eocd(std::span<const std::byte> data) noexcept {
    if (data.size() < 22U) return std::nullopt;
    const auto earliest = data.size() > 22U + 65535U ? data.size() - (22U + 65535U) : 0U;
    for (std::size_t offset = data.size() - 22U;; --offset) {
        if (read32(data, offset) == kEndOfCentralDirectory &&
            has(data, offset, 22U + read16(data, offset + 20U)) &&
            offset + 22U + read16(data, offset + 20U) == data.size()) return offset;
        if (offset == earliest) break;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<DirectoryLocation> directory_location(std::span<const std::byte> data,
                                                                  std::size_t eocd) noexcept {
    if (read16(data, eocd + 4U) != 0U || read16(data, eocd + 6U) != 0U) return std::nullopt;
    DirectoryLocation result{read16(data, eocd + 10U), read32(data, eocd + 16U), read32(data, eocd + 12U)};
    if (read16(data, eocd + 8U) != result.entries) return std::nullopt;
    const bool zip64 = result.entries == 0xffffU || result.offset == 0xffffffffU || result.size == 0xffffffffU;
    if (!zip64) return result;
    if (eocd < 20U || read32(data, eocd - 20U) != kZip64Locator || read32(data, eocd - 16U) != 0U ||
        read32(data, eocd - 4U) != 1U) return std::nullopt;
    const auto zip64_offset = read64(data, eocd - 12U);
    if (zip64_offset > std::numeric_limits<std::size_t>::max()) return std::nullopt;
    const auto zip64_record = static_cast<std::size_t>(zip64_offset);
    if (!has(data, zip64_record, 12U)) return std::nullopt;
    const auto record_size = read64(data, zip64_record + 4U);
    if (record_size < 44U || record_size > std::numeric_limits<std::size_t>::max() - 12U ||
        !has(data, zip64_record, 12U + static_cast<std::size_t>(record_size)) ||
        zip64_record + 12U + static_cast<std::size_t>(record_size) != eocd - 20U) return std::nullopt;
    if (read32(data, zip64_record) != kZip64EndOfCentralDirectory ||
        read32(data, zip64_record + 16U) != 0U || read32(data, zip64_record + 20U) != 0U) return std::nullopt;
    result.entries = read64(data, zip64_record + 32U);
    if (read64(data, zip64_record + 24U) != result.entries) return std::nullopt;
    result.size = read64(data, zip64_record + 40U);
    result.offset = read64(data, zip64_record + 48U);
    return result;
}

[[nodiscard]] Zip64Values parse_zip64(std::span<const std::byte> extra,
                                      std::uint32_t uncompressed32, std::uint32_t compressed32,
                                      std::uint32_t local32, std::uint16_t disk16) noexcept {
    Zip64Values result{uncompressed32, compressed32, local32, disk16, true};
    std::size_t offset = 0U;
    while (offset + 4U <= extra.size()) {
        const auto id = read16(extra, offset);
        const auto size = read16(extra, offset + 2U);
        offset += 4U;
        if (!has(extra, offset, size)) { result.valid = false; return result; }
        if (id == 0x0001U) {
            std::size_t field = offset;
            auto take64 = [&](std::uint64_t& value) {
                if (!has(extra, field, 8U) || field + 8U > offset + size) return false;
                value = read64(extra, field); field += 8U; return true;
            };
            if (uncompressed32 == 0xffffffffU && !take64(result.uncompressed)) result.valid = false;
            if (compressed32 == 0xffffffffU && !take64(result.compressed)) result.valid = false;
            if (local32 == 0xffffffffU && !take64(result.local_offset)) result.valid = false;
            if (disk16 == 0xffffU) {
                if (!has(extra, field, 4U) || field + 4U > offset + size) result.valid = false;
                else result.disk = read32(extra, field);
            }
            return result;
        }
        offset += size;
    }
    if (uncompressed32 == 0xffffffffU || compressed32 == 0xffffffffU || local32 == 0xffffffffU ||
        disk16 == 0xffffU) result.valid = false;
    return result;
}

void merge_nested(EntrySummary& target, const EntrySummary& nested) noexcept {
    target.entry_count += nested.entry_count;
    target.inspected_entry_count += nested.inspected_entry_count;
    target.maximum_depth = (std::max)(target.maximum_depth, nested.maximum_depth);
    target.compressed_bytes += nested.compressed_bytes;
    target.uncompressed_bytes += nested.uncompressed_bytes;
    target.malformed = target.malformed || nested.malformed;
    target.path_escape = target.path_escape || nested.path_escape;
    target.bomb_risk = target.bomb_risk || nested.bomb_risk;
    target.encrypted_entry = target.encrypted_entry || nested.encrypted_entry;
    target.unsupported_compression = target.unsupported_compression || nested.unsupported_compression;
    target.executable_entry = target.executable_entry || nested.executable_entry;
    target.active_content_entry = target.active_content_entry || nested.active_content_entry;
    target.nested_container = true;
    target.duplicate_name = target.duplicate_name || nested.duplicate_name;
    target.crc_mismatch = target.crc_mismatch || nested.crc_mismatch;
    target.budget_exhausted = target.budget_exhausted || nested.budget_exhausted;
    target.header_mismatch = target.header_mismatch || nested.header_mismatch;
}

[[nodiscard]] EntrySummary inspect_impl(std::span<const std::byte> data, SharedBudget& shared,
                                        std::uint32_t depth) {
    EntrySummary summary{};
    summary.maximum_depth = depth;
    if (depth > shared.limits.maximum_depth || data.size() < 22U) {
        summary.budget_exhausted = depth > shared.limits.maximum_depth;
        summary.malformed = data.size() < 22U;
        return summary;
    }
    const auto eocd = find_eocd(data);
    if (!eocd) { summary.malformed = true; return summary; }
    const auto directory = directory_location(data, *eocd);
    if (!directory || directory->entries > shared.limits.maximum_entries ||
        directory->offset > std::numeric_limits<std::size_t>::max() ||
        directory->size > std::numeric_limits<std::size_t>::max() ||
        directory->offset > *eocd || directory->size > *eocd - directory->offset) {
        summary.malformed = true;
        summary.budget_exhausted = directory && directory->entries > shared.limits.maximum_entries;
        return summary;
    }
    std::set<std::string> names;
    std::size_t central = static_cast<std::size_t>(directory->offset);
    const auto central_end = central + static_cast<std::size_t>(directory->size);
    for (std::uint64_t ordinal = 0U; ordinal < directory->entries; ++ordinal) {
        if (!has(data, central, 46U) || central + 46U > central_end || read32(data, central) != kCentralHeader) {
            summary.malformed = true; return summary;
        }
        const auto flags = read16(data, central + 8U);
        const auto method = read16(data, central + 10U);
        const auto expected_crc = read32(data, central + 16U);
        const auto compressed32 = read32(data, central + 20U);
        const auto uncompressed32 = read32(data, central + 24U);
        const auto name_length = read16(data, central + 28U);
        const auto extra_length = read16(data, central + 30U);
        const auto comment_length = read16(data, central + 32U);
        const auto disk = read16(data, central + 34U);
        const auto local32 = read32(data, central + 42U);
        const std::size_t name_offset = central + 46U;
        const std::size_t extra_offset = name_offset + name_length;
        const std::size_t next = extra_offset + extra_length + comment_length;
        if (name_length == 0U || !has(data, name_offset, name_length) || !has(data, extra_offset, extra_length) ||
            next > central_end) { summary.malformed = true; return summary; }
        std::string name(reinterpret_cast<const char*>(data.data() + name_offset), name_length);
        if ((flags & 0x0800U) != 0U && !valid_utf8(name)) summary.malformed = true;
        const auto canonical = canonical_name(name);
        if (!canonical) summary.path_escape = true;
        else if (!names.insert(*canonical).second) summary.duplicate_name = true;
        const auto values = parse_zip64(data.subspan(extra_offset, extra_length), uncompressed32,
                                        compressed32, local32, disk);
        if (!values.valid || values.disk != 0U || values.local_offset > std::numeric_limits<std::size_t>::max()) {
            summary.malformed = true; return summary;
        }
        ++summary.entry_count;
        ++shared.entries;
        summary.compressed_bytes = values.compressed > std::numeric_limits<std::uint64_t>::max() - summary.compressed_bytes
            ? std::numeric_limits<std::uint64_t>::max() : summary.compressed_bytes + values.compressed;
        summary.uncompressed_bytes = values.uncompressed > std::numeric_limits<std::uint64_t>::max() - summary.uncompressed_bytes
            ? std::numeric_limits<std::uint64_t>::max() : summary.uncompressed_bytes + values.uncompressed;
        const bool ratio_exceeded = values.compressed == 0U ? values.uncompressed != 0U :
            values.uncompressed / values.compressed > shared.limits.maximum_ratio ||
            (values.uncompressed / values.compressed == shared.limits.maximum_ratio &&
             values.uncompressed % values.compressed != 0U);
        if (shared.entries > shared.limits.maximum_entries || values.uncompressed > shared.limits.maximum_entry_bytes ||
            shared.expanded > shared.limits.maximum_total_bytes ||
            values.uncompressed > shared.limits.maximum_total_bytes - shared.expanded || ratio_exceeded) {
            summary.bomb_risk = true;
            summary.budget_exhausted = true;
            central = next;
            continue;
        }
        constexpr std::uint16_t supported_flags = 0x284fU;
        const bool encrypted = (flags & 0x2041U) != 0U;
        if ((flags & ~supported_flags) != 0U) summary.malformed = true;
        summary.encrypted_entry = summary.encrypted_entry || encrypted;
        summary.unsupported_compression = summary.unsupported_compression || (method != 0U && method != 8U);
        const std::string effective = canonical.value_or(name);
        summary.executable_entry = summary.executable_entry || extension_is(effective,
            {".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi", ".bat", ".cmd", ".ps1",
             ".vbs", ".js", ".hta", ".lnk"});
        summary.active_content_entry = summary.active_content_entry || extension_is(effective,
            {".docm", ".xlsm", ".pptm", ".xlam", ".ppam", ".sct", ".chm", ".jar"});
        const std::size_t local = static_cast<std::size_t>(values.local_offset);
        if (!has(data, local, 30U) || read32(data, local) != kLocalHeader ||
            read16(data, local + 6U) != flags || read16(data, local + 8U) != method) {
            summary.header_mismatch = true; summary.malformed = true; central = next; continue;
        }
        const auto local_name_length = read16(data, local + 26U);
        const auto local_extra_length = read16(data, local + 28U);
        const std::size_t local_name = local + 30U;
        const std::size_t payload_offset = local_name + local_name_length + local_extra_length;
        if (local_name_length != name_length || !has(data, local_name, local_name_length) ||
            !std::equal(data.begin() + static_cast<std::ptrdiff_t>(local_name),
                        data.begin() + static_cast<std::ptrdiff_t>(local_name + local_name_length),
                        data.begin() + static_cast<std::ptrdiff_t>(name_offset)) ||
            values.compressed > std::numeric_limits<std::size_t>::max() ||
            !has(data, payload_offset, static_cast<std::size_t>(values.compressed)) ||
            payload_offset + static_cast<std::size_t>(values.compressed) > directory->offset) {
            summary.header_mismatch = true; summary.malformed = true; central = next; continue;
        }
        if ((flags & 0x0008U) == 0U) {
            const auto local_values = parse_zip64(data.subspan(local_name + local_name_length, local_extra_length),
                                                  read32(data, local + 22U), read32(data, local + 18U), 0U, 0U);
            if (!local_values.valid || read32(data, local + 14U) != expected_crc ||
                local_values.compressed != values.compressed || local_values.uncompressed != values.uncompressed) {
                summary.header_mismatch = true; summary.malformed = true; central = next; continue;
            }
        }
        const auto compressed = data.subspan(payload_offset, static_cast<std::size_t>(values.compressed));
        std::vector<std::byte> content;
        bool decoded = false;
        if (!encrypted && method == 0U && values.compressed == values.uncompressed) {
            content.assign(compressed.begin(), compressed.end()); decoded = true;
        } else if (!encrypted && method == 8U &&
                   values.uncompressed <= std::numeric_limits<std::size_t>::max()) {
            decoded = inflate_raw(compressed, static_cast<std::size_t>(values.uncompressed), content);
        }
        if (!decoded) {
            if (method == 0U || method == 8U) summary.malformed = true;
            central = next;
            continue;
        }
        ++summary.inspected_entry_count;
        shared.expanded += content.size();
        if (crc32(content) != expected_crc) summary.crc_mismatch = true;
        if ((flags & 0x0008U) != 0U) {
            std::size_t descriptor = payload_offset + static_cast<std::size_t>(values.compressed);
            if (has(data, descriptor, 4U) && read32(data, descriptor) == kDataDescriptor) descriptor += 4U;
            const bool descriptor64 = compressed32 == 0xffffffffU || uncompressed32 == 0xffffffffU;
            const std::size_t descriptor_size = descriptor64 ? 20U : 12U;
            if (!has(data, descriptor, descriptor_size) || descriptor + descriptor_size > directory->offset ||
                read32(data, descriptor) != expected_crc ||
                (descriptor64 ? read64(data, descriptor + 4U) != values.compressed ||
                                read64(data, descriptor + 12U) != values.uncompressed
                              : read32(data, descriptor + 4U) != values.compressed ||
                                read32(data, descriptor + 8U) != values.uncompressed)) {
                summary.header_mismatch = true;
                summary.malformed = true;
            }
        }
        std::wstring wide_name;
        wide_name.reserve(effective.size());
        for (const unsigned char value : effective) wide_name.push_back(static_cast<wchar_t>(value));
        const auto child = ai_shield::file_preflight::inspect(content, wide_name);
        summary.executable_entry = summary.executable_entry || child.embedded_executable;
        summary.active_content_entry = summary.active_content_entry || child.active_content ||
                                       child.automatic_action || child.unsafe_deserialization;
        const bool archive_magic = content.size() >= 4U && read32(content, 0U) == kLocalHeader;
        const bool archive_extension = extension_is(effective,
            {".zip", ".jar", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".apk",
             ".nupkg", ".whl", ".epub", ".odt", ".ods", ".odp"});
        if (archive_magic || archive_extension) {
            summary.nested_container = true;
            if (depth >= shared.limits.maximum_depth) {
                summary.budget_exhausted = true;
                summary.bomb_risk = true;
            } else {
                const auto nested = inspect_impl(content, shared, depth + 1U);
                merge_nested(summary, nested);
            }
        }
        central = next;
    }
    if (central != central_end) summary.malformed = true;
    return summary;
}

}  // namespace

Result<EntrySummary> inspect_deep(std::span<const std::byte> data, const InspectionBudget& budget) noexcept {
    if (data.empty() || data.size() > 256U * 1024U * 1024U || budget.maximum_entries == 0U ||
        budget.maximum_depth == 0U || budget.maximum_entry_bytes == 0U ||
        budget.maximum_total_bytes == 0U || budget.maximum_ratio == 0U) return Status::invalid_argument;
    try {
        SharedBudget shared{budget};
        return inspect_impl(data, shared, 0U);
    } catch (...) {
        return Status::out_of_budget;
    }
}

Result<EntrySummary> preflight(std::span<const std::byte> data) noexcept {
    return inspect_deep(data, InspectionBudget{});
}

detection::Evidence evidence_from(const EntrySummary& summary) noexcept {
    detection::Evidence evidence{};
    if (summary.malformed || summary.header_mismatch || summary.crc_mismatch) {
        evidence.protocol = 80;
        evidence.reason_mask |= abi::ReasonCode::proto_malformed;
    }
    if (summary.path_escape) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::archive_path_escape | abi::ReasonCode::path_traversal;
    }
    if (summary.bomb_risk || summary.budget_exhausted) {
        evidence.hard_rule = 100;
        evidence.reason_mask |= abi::ReasonCode::archive_bomb_risk;
    }
    if (summary.encrypted_entry) evidence.novelty = detection::clipped_score(evidence.novelty + 30U);
    if (summary.unsupported_compression || summary.executable_entry || summary.active_content_entry ||
        summary.nested_container || summary.duplicate_name) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 70U);
        evidence.reason_mask |= abi::ReasonCode::consequence_detected;
    }
    return evidence;
}

}  // namespace ai_shield::protocols::zip
