#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::provenance {

enum class FileDisposition : std::uint32_t {
    unknown,
    trusted,
    execution_pending,
    allowed,
    quarantined
};

struct FileIdentity final {
    std::uint64_t volume_id = 0;
    std::uint64_t file_id = 0;
    std::uint64_t stream_id = 0;
    crypto::Sha256Digest content_hash{};
    std::uint64_t provenance_id = 0;
    std::uint64_t creation_sequence = 0;
    std::uint64_t parent_provenance_id = 0;
};

struct FileVerdict final {
    FileIdentity identity{};
    FileDisposition disposition = FileDisposition::unknown;
    std::uint32_t reason_mask = 0;
};

class Store final {
public:
    [[nodiscard]] Result<void> record_external(FileIdentity identity) noexcept;
    [[nodiscard]] Result<void> propagate_archive(FileIdentity archive, FileIdentity extracted_child) noexcept;
    [[nodiscard]] Result<void> propagate_copy(FileIdentity source, FileIdentity destination) noexcept;
    [[nodiscard]] Result<void> propagate_rename(FileIdentity source, FileIdentity destination) noexcept;
    [[nodiscard]] Result<void> approve(FileIdentity identity) noexcept;
    [[nodiscard]] Result<void> quarantine(FileIdentity identity, std::uint32_t reason_mask) noexcept;
    [[nodiscard]] Result<bool> execution_allowed(const FileIdentity& identity) const noexcept;
    [[nodiscard]] Result<FileVerdict> lookup(const FileIdentity& identity) const noexcept;

private:
    std::vector<FileVerdict> entries_;
};

[[nodiscard]] bool same_file_version(const FileIdentity& a, const FileIdentity& b) noexcept;

}  // namespace ai_shield::provenance
