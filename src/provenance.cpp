#include "ai_shield/provenance.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::provenance {

bool same_file_version(const FileIdentity& a, const FileIdentity& b) noexcept {
    return a.volume_id == b.volume_id && a.file_id == b.file_id && a.stream_id == b.stream_id &&
           a.provenance_id == b.provenance_id && crypto::constant_time_equal(a.content_hash, b.content_hash);
}

Result<void> Store::record_external(FileIdentity identity) noexcept {
    entries_.push_back(FileVerdict{identity, FileDisposition::execution_pending, abi::ReasonCode::external_exec_pending});
    return {};
}

Result<void> Store::propagate_archive(FileIdentity archive, FileIdentity extracted_child) noexcept {
    const auto parent = lookup(archive);
    if (!parent.ok()) {
        return parent.status();
    }
    if (parent.value().disposition == FileDisposition::trusted) {
        return {};
    }
    entries_.push_back(FileVerdict{extracted_child,
                                   FileDisposition::execution_pending,
                                   parent.value().reason_mask | abi::ReasonCode::external_exec_pending});
    return {};
}

Result<void> Store::propagate_copy(FileIdentity source, FileIdentity destination) noexcept {
    const auto parent = lookup(source);
    if (!parent.ok()) {
        return parent.status();
    }
    destination.parent_provenance_id = source.provenance_id;
    entries_.push_back(FileVerdict{destination, parent.value().disposition, parent.value().reason_mask});
    return {};
}

Result<void> Store::propagate_rename(FileIdentity source, FileIdentity destination) noexcept {
    for (auto& entry : entries_) {
        if (same_file_version(entry.identity, source)) {
            destination.parent_provenance_id = source.parent_provenance_id;
            entry.identity = destination;
            return {};
        }
    }
    return Status::not_found;
}

Result<void> Store::approve(FileIdentity identity) noexcept {
    for (auto& entry : entries_) {
        if (same_file_version(entry.identity, identity)) {
            entry.disposition = FileDisposition::allowed;
            entry.reason_mask = 0;
            return {};
        }
    }
    return Status::not_found;
}

Result<void> Store::quarantine(FileIdentity identity, std::uint32_t reason_mask) noexcept {
    for (auto& entry : entries_) {
        if (same_file_version(entry.identity, identity)) {
            entry.disposition = FileDisposition::quarantined;
            entry.reason_mask = reason_mask;
            return {};
        }
    }
    entries_.push_back(FileVerdict{identity, FileDisposition::quarantined, reason_mask});
    return {};
}

Result<bool> Store::execution_allowed(const FileIdentity& identity) const noexcept {
    const auto verdict = lookup(identity);
    if (!verdict.ok()) {
        return verdict.status();
    }
    return verdict.value().disposition == FileDisposition::allowed ||
           verdict.value().disposition == FileDisposition::trusted;
}

Result<FileVerdict> Store::lookup(const FileIdentity& identity) const noexcept {
    for (const auto& entry : entries_) {
        if (same_file_version(entry.identity, identity)) {
            return entry;
        }
        if (entry.identity.volume_id == identity.volume_id && entry.identity.file_id == identity.file_id &&
            entry.identity.stream_id == identity.stream_id && entry.identity.provenance_id == identity.provenance_id) {
            return FileVerdict{identity, FileDisposition::execution_pending, abi::ReasonCode::external_exec_pending};
        }
    }
    return Status::not_found;
}

}  // namespace ai_shield::provenance
