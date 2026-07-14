#include "ai_shield/incident_package.hpp"

#include "ai_shield/abi.hpp"

namespace ai_shield::incident {
namespace {

template <typename T>
void append_le(std::vector<std::byte>& out, T value) {
    const auto u = static_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        out.push_back(static_cast<std::byte>((u >> (i * 8U)) & 0xffU));
    }
}

void append_digest(std::vector<std::byte>& out, const crypto::Sha256Digest& digest) {
    out.insert(out.end(), digest.begin(), digest.end());
}

}  // namespace

Result<Package> build(std::uint64_t incident_id,
                      const audit::AuditChain& audit_chain,
                      std::span<const sandbox::ResultSummary> sandbox_results,
                      std::span<const std::byte> payload,
                      const privacy::ExportPolicy& export_policy) {
    return build_correlated(incident_id, {}, audit_chain, sandbox_results, payload, export_policy);
}

Result<Package> build_correlated(std::uint64_t incident_id,
                                 const correlation::Context& correlation,
                                 const audit::AuditChain& audit_chain,
                                 std::span<const sandbox::ResultSummary> sandbox_results,
                                 std::span<const std::byte> payload,
                                 const privacy::ExportPolicy& export_policy) {
    const auto audit_verify = audit_chain.verify();
    if (!audit_verify.ok()) {
        return audit_verify.status();
    }
    Package package{};
    package.incident_id = incident_id;
    package.correlation = correlation;
    const auto audit_bytes = audit::serialize(audit_chain);
    package.audit_export_hash = crypto::sha256(audit_bytes);
    package.payload = privacy::sanitize_payload(payload, export_policy);
    package.aggregate_reason_mask = package.payload.reason_mask;

    for (const auto& segment : audit_chain.segments()) {
        for (const auto& record : segment.records) {
            const auto& event_correlation = record.correlation.flow_id != 0U || record.correlation.object_id != 0U
                                                ? record.correlation : correlation;
            package.events.push_back(IncidentEvent{record.monotonic_ns, record.reason_mask,
                                                   record.evidence_hash, event_correlation});
            package.aggregate_reason_mask |= record.reason_mask;
        }
    }
    if (!package.events.empty() && package.correlation.flow_id == 0U && package.correlation.object_id == 0U)
        package.correlation = package.events.front().correlation;
    for (const auto& sandbox_result : sandbox_results) {
        const auto evidence = sandbox::evidence_from(sandbox_result);
        package.aggregate_reason_mask |= evidence.reason_mask;
    }
    std::vector<std::byte> timeline;
    timeline.reserve(package.events.size() * 48U);
    for (const auto& event : package.events) {
        append_le(timeline, event.monotonic_ns);
        append_le(timeline, event.reason_mask);
        append_digest(timeline, event.evidence_hash);
        append_le(timeline, event.correlation.flow_id);
        append_le(timeline, event.correlation.object_id);
        append_le(timeline, event.correlation.file_id);
        append_le(timeline, event.correlation.volume_id);
        append_le(timeline, event.correlation.provenance_id);
        append_le(timeline, event.correlation.process_id);
        append_le(timeline, event.correlation.parent_process_id);
        append_le(timeline, event.correlation.policy_version);
        append_le(timeline, event.correlation.model_version);
    }
    package.timeline_hash = crypto::sha256(timeline);
    return package;
}

}  // namespace ai_shield::incident
