#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/correlation.hpp"
#include "ai_shield/process_consequence.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::replay {

enum class EventKind : std::uint32_t {
    flow_open = 1,
    flow_data = 2,
    service_identity = 3,
    protocol_hint = 4,
    process_evidence = 5,
    file_evidence = 6,
    flow_close = 7,
    correlation_context = 8
};

enum class ProtocolHint : std::uint32_t {
    unknown = 0,
    http1 = 1,
    http2 = 2
};

struct Scenario final {
    std::uint64_t flow_id = 0;
    std::uint64_t service_id = 0;
    std::uint64_t policy_version = 0;
    bool critical_service = true;
    std::span<const std::byte> payload;
    ProtocolHint protocol_hint = ProtocolHint::http1;
    bool service_identity_verified = true;
    bool file_external = false;
    process_consequence::ProcessEvidence process{};
    correlation::Context correlation{};
};

struct ReplayResult final {
    abi::ShieldDecision decision{};
    crypto::Sha256Digest audit_root{};
    std::uint64_t audit_records = 0;
    std::uint64_t causal_nodes = 0;
    std::uint64_t causal_edges = 0;
    std::uint64_t policy_version = 0;
    bool audit_verifiable = false;
    bool causal_graph_complete = false;
    correlation::Context correlation{};
};

[[nodiscard]] Result<ReplayResult> execute(const Scenario& scenario) noexcept;
[[nodiscard]] Result<ReplayResult> parse_and_execute(std::span<const std::byte> bytes) noexcept;

}  // namespace ai_shield::replay
