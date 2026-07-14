#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/audit.hpp"
#include "ai_shield/correlation.hpp"
#include "ai_shield/privacy.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sandbox.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::incident {

struct IncidentEvent final {
    std::uint64_t monotonic_ns = 0;
    std::uint32_t reason_mask = 0;
    crypto::Sha256Digest evidence_hash{};
    correlation::Context correlation{};
};

struct Package final {
    std::uint64_t incident_id = 0;
    crypto::Sha256Digest timeline_hash{};
    crypto::Sha256Digest audit_export_hash{};
    std::uint32_t aggregate_reason_mask = 0;
    privacy::SanitizedPayload payload{};
    std::vector<IncidentEvent> events;
    correlation::Context correlation{};
};

[[nodiscard]] Result<Package> build(std::uint64_t incident_id,
                                    const audit::AuditChain& audit_chain,
                                    std::span<const sandbox::ResultSummary> sandbox_results,
                                    std::span<const std::byte> payload,
                                    const privacy::ExportPolicy& export_policy);
[[nodiscard]] Result<Package> build_correlated(std::uint64_t incident_id,
                                               const correlation::Context& correlation,
                                               const audit::AuditChain& audit_chain,
                                               std::span<const sandbox::ResultSummary> sandbox_results,
                                               std::span<const std::byte> payload,
                                               const privacy::ExportPolicy& export_policy);

}  // namespace ai_shield::incident
