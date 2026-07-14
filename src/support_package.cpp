#include "ai_shield/support_package.hpp"

#include <array>
#include <cstddef>
#include <vector>

namespace ai_shield::support {
namespace {

void append_u64(std::vector<std::byte>& out, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        out.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xffU));
    }
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
    for (std::size_t i = 0; i < 4U; ++i) {
        out.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xffU));
    }
}

void append_hash(std::vector<std::byte>& out, const crypto::Sha256Digest& digest) {
    for (const auto byte : digest) {
        out.push_back(byte);
    }
}

}  // namespace

SupportManifest build_manifest(std::uint64_t package_id,
                               const diagnostics::Snapshot& snapshot,
                               const incident::Package& incident_package) noexcept {
    std::vector<std::byte> diagnostics_bytes;
    append_u32(diagnostics_bytes, snapshot.active_flows);
    append_u32(diagnostics_bytes, snapshot.pending_decisions);
    append_u32(diagnostics_bytes, snapshot.sandbox_capacity);
    append_u32(diagnostics_bytes, snapshot.worker_circuits_open);
    append_u32(diagnostics_bytes, snapshot.health.reason_mask);

    std::vector<std::byte> incident_bytes;
    append_u64(incident_bytes, incident_package.incident_id);
    append_u32(incident_bytes, incident_package.aggregate_reason_mask);
    append_hash(incident_bytes, incident_package.timeline_hash);
    append_hash(incident_bytes, incident_package.audit_export_hash);

    return SupportManifest{.package_id = package_id,
                           .diagnostics_hash = crypto::sha256(diagnostics_bytes),
                           .incident_hash = crypto::sha256(incident_bytes),
                           .reason_mask = snapshot.health.reason_mask | incident_package.aggregate_reason_mask,
                           .payload_redacted = (incident_package.payload.reason_mask & abi::ReasonCode::privacy_redacted) != 0U};
}

}  // namespace ai_shield::support
