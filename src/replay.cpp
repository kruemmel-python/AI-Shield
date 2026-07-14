#include "ai_shield/replay.hpp"

#include <cstddef>
#include <string>
#include <vector>

#include "ai_shield/audit.hpp"
#include "ai_shield/causal_graph.hpp"
#include "ai_shield/detection.hpp"
#include "ai_shield/features.hpp"
#include "ai_shield/http2_preflight.hpp"
#include "ai_shield/http1.hpp"
#include "ai_shield/http_canonicalizer.hpp"
#include "ai_shield/policy.hpp"
#include "ai_shield/policy_authorization.hpp"
#include "ai_shield/process_consequence.hpp"
#include "ai_shield/signature_detector.hpp"

namespace ai_shield::replay {
namespace {

constexpr std::uint64_t kMaxReplayPayload = 1024ULL * 1024ULL;
constexpr std::uint64_t kMaxReplayEvents = 4096ULL;
constexpr std::uint32_t kMaxReplayEventBytes = 1024U * 1024U;

Result<std::uint32_t> read_u32(std::span<const std::byte> bytes, std::size_t& offset) noexcept {
    if (offset + 4U > bytes.size()) {
        return Status::malformed_input;
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (i * 8U);
    }
    offset += 4U;
    return value;
}

Result<std::uint64_t> read_u64(std::span<const std::byte> bytes, std::size_t& offset) noexcept {
    const auto low = read_u32(bytes, offset);
    const auto high = read_u32(bytes, offset);
    if (!low.ok() || !high.ok()) {
        return Status::malformed_input;
    }
    return static_cast<std::uint64_t>(low.value()) | (static_cast<std::uint64_t>(high.value()) << 32U);
}

detection::Evidence merge(detection::Evidence left, const detection::Evidence& right) noexcept {
    left.hard_rule = detection::clipped_score(left.hard_rule + right.hard_rule);
    left.signature = detection::clipped_score(left.signature + right.signature);
    left.protocol = detection::clipped_score(left.protocol + right.protocol);
    left.novelty = detection::clipped_score(left.novelty + right.novelty);
    left.adaptivity = detection::clipped_score(left.adaptivity + right.adaptivity);
    left.campaign = detection::clipped_score(left.campaign + right.campaign);
    left.consequence = detection::clipped_score(left.consequence + right.consequence);
    left.reason_mask |= right.reason_mask;
    return left;
}

Result<EventKind> event_kind_from(std::uint32_t value) noexcept {
    switch (static_cast<EventKind>(value)) {
    case EventKind::flow_open:
    case EventKind::flow_data:
    case EventKind::service_identity:
    case EventKind::protocol_hint:
    case EventKind::process_evidence:
    case EventKind::file_evidence:
    case EventKind::flow_close:
    case EventKind::correlation_context:
        return static_cast<EventKind>(value);
    }
    return Status::malformed_input;
}

Result<ProtocolHint> protocol_hint_from(std::uint32_t value) noexcept {
    switch (static_cast<ProtocolHint>(value)) {
    case ProtocolHint::unknown:
    case ProtocolHint::http1:
    case ProtocolHint::http2:
        return static_cast<ProtocolHint>(value);
    }
    return Status::malformed_input;
}

Result<process_consequence::SignatureState> signature_from(std::uint32_t value) noexcept {
    switch (static_cast<process_consequence::SignatureState>(value)) {
    case process_consequence::SignatureState::unknown:
    case process_consequence::SignatureState::unsigned_image:
    case process_consequence::SignatureState::trusted_signed:
    case process_consequence::SignatureState::invalid_signature:
        return static_cast<process_consequence::SignatureState>(value);
    }
    return Status::malformed_input;
}

}  // namespace

Result<ReplayResult> execute(const Scenario& scenario) noexcept {
    if (scenario.flow_id == 0U || scenario.service_id == 0U || scenario.policy_version == 0U ||
        scenario.payload.empty() || scenario.payload.size() > kMaxReplayPayload) {
        return Status::invalid_argument;
    }

    std::string payload_text;
    payload_text.reserve(scenario.payload.size());
    for (const auto byte : scenario.payload) {
        payload_text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }

    detection::Evidence evidence = detection::inspect_payload(scenario.payload);
    if (!scenario.service_identity_verified) {
        evidence.sensor_integrity = 100;
        evidence.reason_mask |= abi::ReasonCode::unregistered_service;
    }
    if (scenario.file_external) {
        evidence.consequence = detection::clipped_score(evidence.consequence + 50U);
        evidence.reason_mask |= abi::ReasonCode::external_exec_pending;
    }
    if (scenario.process.parent_process_id != 0U || scenario.process.child_process_id != 0U) {
        evidence = merge(evidence, process_consequence::evaluate_create_process(scenario.process));
    }

    if (scenario.protocol_hint == ProtocolHint::http2) {
        const auto parsed_h2 = protocols::http2::preflight(scenario.payload, 16U * 1024U, 1'000'000U);
        if (parsed_h2.ok()) {
            evidence = merge(evidence, protocols::http2::evidence_from(parsed_h2.value()));
        }
    } else {
        const auto parsed = protocols::http1::parse_request(payload_text);
        if (parsed.ok()) {
            evidence = merge(evidence, protocols::http1::evidence_from(parsed.value()));
        }
    }
    const auto canonical = protocols::http1::canonicalize_request(payload_text);
    const auto evidence_hash = canonical.ok() ? crypto::sha256(canonical.value()) : crypto::sha256(scenario.payload);

    signatures::Detector detector;
    const bool rule_added = detector.add_rule(signatures::Rule{
        .rule_id = 1, .kind = signatures::RuleKind::substring, .severity = 100, .pattern = "../"});
    if (!rule_added) {
        return Status::integrity_failure;
    }
    evidence = merge(evidence, detector.inspect(scenario.payload));

    const auto feature_sample = features::extract_network(scenario.payload);
    if (feature_sample.payload_bytes > 512U) {
        evidence.novelty = detection::clipped_score(evidence.novelty + 20U);
    }

    const auto authorized = policy_authorization::authorize(policy_authorization::PolicyChange{
        .actor_id = 1, .admin = true, .high_risk = evidence.hard_rule >= 100U, .local_confirmation = true});
    if (!authorized.ok()) {
        return authorized.status();
    }

    const auto decision = policy::decide(policy::PolicyContext{.decision_id = scenario.flow_id,
                                                               .flow_id = scenario.flow_id,
                                                               .now_monotonic_ns = 1'000'000ULL,
                                                               .critical_service = scenario.critical_service},
                                         evidence,
                                         evidence_hash);

    audit::AuditChain audit_chain;
    const auto appended = audit_chain.append(audit::AuditRecord{
        .sequence = 1, .monotonic_ns = 1'000'000ULL, .reason_mask = decision.reason_mask, .evidence_hash = evidence_hash});
    if (!appended.ok()) {
        return appended.status();
    }

    causal::Graph graph;
    correlation::Context context = scenario.correlation;
    context.flow_id = scenario.flow_id;
    context.policy_version = scenario.policy_version;
    if (context.model_version == 0U) context.model_version = 1U;
    if (context.process_id == 0U) context.process_id = scenario.process.child_process_id;
    if (context.parent_process_id == 0U) context.parent_process_id = scenario.process.parent_process_id;
    const auto flow_node = graph.add_node(causal::Node{.id = scenario.flow_id,
                                                       .kind = causal::NodeKind::flow,
                                                       .identity_hash = crypto::sha256("flow"),
                                                       .correlation = context});
    const auto process_id = context.process_id != 0U ? context.process_id : scenario.flow_id + 1U;
    const auto process_node = graph.add_node(causal::Node{.id = process_id,
                                                          .kind = causal::NodeKind::process,
                                                          .identity_hash = crypto::sha256("process"),
                                                          .correlation = context});
    const auto edge = graph.add_edge(scenario.flow_id, process_id);
    if (!flow_node.ok() || !process_node.ok() || !edge.ok()) {
        return Status::integrity_failure;
    }

    const auto audit_verified = audit_chain.verify();
    const auto graph_chain = graph.chain_to(process_id);

    return ReplayResult{.decision = decision,
                        .audit_root = audit_chain.segments().back().segment_hash,
                        .audit_records = 1,
                        .causal_nodes = static_cast<std::uint64_t>(graph.node_count()),
                        .causal_edges = static_cast<std::uint64_t>(graph.edge_count()),
                        .policy_version = scenario.policy_version,
                        .audit_verifiable = audit_verified.ok(),
                        .causal_graph_complete = graph_chain.ok() && graph_chain.value().size() == 2U,
                        .correlation = context};
}

Result<ReplayResult> parse_and_execute(std::span<const std::byte> bytes) noexcept {
    if (bytes.size() >= 24U && bytes[0] == std::byte{'A'} && bytes[1] == std::byte{'I'} &&
        bytes[2] == std::byte{'S'} && bytes[3] == std::byte{'H'} && bytes[4] == std::byte{'R'} &&
        bytes[5] == std::byte{'P'} && bytes[6] == std::byte{'0'} && bytes[7] == std::byte{'2'}) {
        constexpr char magic[] = {'A', 'I', 'S', 'H', 'R', 'P', '0', '2'};
        for (std::size_t i = 0; i < 8U; ++i) {
            if (bytes[i] != static_cast<std::byte>(magic[i])) {
                return Status::malformed_input;
            }
        }
        std::size_t offset = 8U;
        const auto policy_version = read_u64(bytes, offset);
        const auto event_count = read_u64(bytes, offset);
        if (!policy_version.ok() || !event_count.ok() || policy_version.value() == 0U ||
            event_count.value() == 0U || event_count.value() > kMaxReplayEvents) {
            return Status::malformed_input;
        }

        std::uint64_t flow_id = 0;
        std::uint64_t service_id = 0;
        bool critical_service = true;
        bool service_identity_verified = false;
        bool flow_opened = false;
        bool flow_closed = false;
        bool file_external = false;
        ProtocolHint protocol_hint = ProtocolHint::unknown;
        process_consequence::ProcessEvidence process{};
        correlation::Context correlation{};
        std::vector<std::byte> payload;

        for (std::uint64_t index = 0; index < event_count.value(); ++index) {
            const auto raw_kind = read_u32(bytes, offset);
            const auto raw_size = read_u32(bytes, offset);
            if (!raw_kind.ok() || !raw_size.ok() || raw_size.value() > kMaxReplayEventBytes ||
                offset + raw_size.value() > bytes.size()) {
                return Status::malformed_input;
            }
            const auto kind = event_kind_from(raw_kind.value());
            if (!kind.ok()) {
                return kind.status();
            }
            auto body = bytes.subspan(offset, raw_size.value());
            offset += raw_size.value();
            std::size_t body_offset = 0;

            switch (kind.value()) {
            case EventKind::flow_open: {
                if (flow_opened || raw_size.value() != 32U) {
                    return Status::invalid_state_transition;
                }
                const auto parsed_flow = read_u64(body, body_offset);
                const auto parsed_service = read_u64(body, body_offset);
                const auto critical = read_u64(body, body_offset);
                const auto monotonic = read_u64(body, body_offset);
                if (!parsed_flow.ok() || !parsed_service.ok() || !critical.ok() || !monotonic.ok() ||
                    parsed_flow.value() == 0U || parsed_service.value() == 0U) {
                    return Status::malformed_input;
                }
                flow_id = parsed_flow.value();
                service_id = parsed_service.value();
                critical_service = critical.value() != 0U;
                flow_opened = true;
                break;
            }
            case EventKind::flow_data:
                if (!flow_opened || flow_closed || payload.size() + body.size() > kMaxReplayPayload) {
                    return Status::invalid_state_transition;
                }
                payload.insert(payload.end(), body.begin(), body.end());
                break;
            case EventKind::service_identity: {
                if (!flow_opened || raw_size.value() != 16U) {
                    return Status::invalid_state_transition;
                }
                const auto parsed_service = read_u64(body, body_offset);
                const auto verified = read_u64(body, body_offset);
                if (!parsed_service.ok() || !verified.ok() || parsed_service.value() != service_id) {
                    return Status::integrity_failure;
                }
                service_identity_verified = verified.value() != 0U;
                break;
            }
            case EventKind::protocol_hint: {
                if (raw_size.value() != 4U) {
                    return Status::malformed_input;
                }
                const auto parsed_hint = read_u32(body, body_offset);
                if (!parsed_hint.ok()) {
                    return parsed_hint.status();
                }
                const auto hint = protocol_hint_from(parsed_hint.value());
                if (!hint.ok()) {
                    return hint.status();
                }
                protocol_hint = hint.value();
                break;
            }
            case EventKind::process_evidence: {
                if (!flow_opened || raw_size.value() != 40U) {
                    return Status::invalid_state_transition;
                }
                const auto parent = read_u64(body, body_offset);
                const auto child = read_u64(body, body_offset);
                const auto external = read_u64(body, body_offset);
                const auto signature = read_u32(body, body_offset);
                const auto reserved = read_u32(body, body_offset);
                const auto command_marker = read_u64(body, body_offset);
                if (!parent.ok() || !child.ok() || !external.ok() || !signature.ok() || !reserved.ok() ||
                    !command_marker.ok()) {
                    return Status::malformed_input;
                }
                const auto sig = signature_from(signature.value());
                if (!sig.ok() || reserved.value() != 0U) {
                    return Status::malformed_input;
                }
                process.parent_process_id = parent.value();
                process.child_process_id = child.value();
                process.inherited_flow_id = flow_id;
                process.parent_external_influenced = external.value() != 0U;
                process.child_signature = sig.value();
                process.image_path = command_marker.value() != 0U ? "powershell.exe" : "service.exe";
                process.command_line = command_marker.value() != 0U ? "powershell -EncodedCommand AAAA" : "service";
                break;
            }
            case EventKind::file_evidence: {
                if (!flow_opened || raw_size.value() != 8U) {
                    return Status::invalid_state_transition;
                }
                const auto external = read_u64(body, body_offset);
                if (!external.ok()) {
                    return Status::malformed_input;
                }
                file_external = external.value() != 0U;
                break;
            }
            case EventKind::flow_close:
                if (!flow_opened || flow_closed || raw_size.value() != 8U) {
                    return Status::invalid_state_transition;
                }
                flow_closed = true;
                break;
            case EventKind::correlation_context: {
                if (!flow_opened || raw_size.value() != sizeof(correlation::Context))
                    return Status::invalid_state_transition;
                const auto object_id = read_u64(body, body_offset);
                const auto file_id = read_u64(body, body_offset);
                const auto volume_id = read_u64(body, body_offset);
                const auto provenance_id = read_u64(body, body_offset);
                const auto process_id = read_u64(body, body_offset);
                const auto parent_process_id = read_u64(body, body_offset);
                const auto correlated_policy = read_u64(body, body_offset);
                const auto model_version = read_u64(body, body_offset);
                const auto correlated_flow = read_u64(body, body_offset);
                if (!object_id.ok() || !file_id.ok() || !volume_id.ok() || !provenance_id.ok() ||
                    !process_id.ok() || !parent_process_id.ok() || !correlated_policy.ok() ||
                    !model_version.ok() || !correlated_flow.ok() || correlated_flow.value() != flow_id ||
                    correlated_policy.value() != policy_version.value() || model_version.value() == 0U)
                    return Status::integrity_failure;
                correlation = {.flow_id = correlated_flow.value(), .object_id = object_id.value(),
                               .file_id = file_id.value(), .volume_id = volume_id.value(),
                               .provenance_id = provenance_id.value(), .process_id = process_id.value(),
                               .parent_process_id = parent_process_id.value(),
                               .policy_version = correlated_policy.value(), .model_version = model_version.value()};
                break;
            }
            }
        }

        if (offset != bytes.size() || !flow_opened || !flow_closed || payload.empty()) {
            return Status::malformed_input;
        }
        Scenario scenario{.flow_id = flow_id,
                          .service_id = service_id,
                          .policy_version = policy_version.value(),
                          .critical_service = critical_service,
                          .payload = std::span<const std::byte>{payload.data(), payload.size()},
                          .protocol_hint = protocol_hint == ProtocolHint::unknown ? ProtocolHint::http1 : protocol_hint,
                          .service_identity_verified = service_identity_verified,
                          .file_external = file_external,
                          .process = process,
                          .correlation = correlation};
        return execute(scenario);
    }

    constexpr char magic[] = {'A', 'I', 'S', 'H', 'R', 'P', 'L', 'Y'};
    if (bytes.size() < 8U + 8U + 8U + 8U + 8U) {
        return Status::malformed_input;
    }
    for (std::size_t i = 0; i < 8U; ++i) {
        if (bytes[i] != static_cast<std::byte>(magic[i])) {
            return Status::malformed_input;
        }
    }
    std::size_t offset = 8U;
    const auto flow_id = read_u64(bytes, offset);
    const auto service_id = read_u64(bytes, offset);
    const auto policy_version = read_u64(bytes, offset);
    const auto payload_size = read_u64(bytes, offset);
    if (!flow_id.ok() || !service_id.ok() || !policy_version.ok() || !payload_size.ok() ||
        payload_size.value() > kMaxReplayPayload || offset + payload_size.value() != bytes.size()) {
        return Status::malformed_input;
    }
    return execute(Scenario{.flow_id = flow_id.value(),
                            .service_id = service_id.value(),
                            .policy_version = policy_version.value(),
                            .critical_service = true,
                            .payload = bytes.subspan(offset, static_cast<std::size_t>(payload_size.value()))});
}

}  // namespace ai_shield::replay
