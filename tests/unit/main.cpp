#include <cstddef>
#include <cstdlib>
#include <string_view>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <vector>

#include "ai_shield/abi_validation.hpp"
#include "ai_shield/abi2.hpp"
#include "ai_shield/audit.hpp"
#include "ai_shield/backpressure.hpp"
#include "ai_shield/broker_runtime.hpp"
#include "ai_shield/build_attestation.hpp"
#include "ai_shield/campaign.hpp"
#include "ai_shield/causal_graph.hpp"
#include "ai_shield/checked.hpp"
#include "ai_shield/cloud_optin.hpp"
#include "ai_shield/compatibility_lab.hpp"
#include "ai_shield/consequence_detector.hpp"
#include "ai_shield/dataset_governance.hpp"
#include "ai_shield/diagnostics.hpp"
#include "ai_shield/dns.hpp"
#include "ai_shield/egress_gate.hpp"
#include "ai_shield/fail_policy.hpp"
#include "ai_shield/features.hpp"
#include "ai_shield/flow_baseline.hpp"
#include "ai_shield/flow_control.hpp"
#include "ai_shield/flow_state.hpp"
#include "ai_shield/fuzz_plan.hpp"
#include "ai_shield/http1.hpp"
#include "ai_shield/http2_preflight.hpp"
#include "ai_shield/http_canonicalizer.hpp"
#include "ai_shield/health.hpp"
#include "ai_shield/incident_package.hpp"
#include "ai_shield/ipv6_security.hpp"
#include "ai_shield/isolation_forest.hpp"
#include "ai_shield/ipc_validator.hpp"
#include "ai_shield/json_preflight.hpp"
#include "ai_shield/learning_mode.hpp"
#include "ai_shield/maintenance_mode.hpp"
#include "ai_shield/model_registry.hpp"
#include "ai_shield/mutation_detector.hpp"
#include "ai_shield/package_manifest.hpp"
#include "ai_shield/pe_preflight.hpp"
#include "ai_shield/pdf_preflight.hpp"
#include "ai_shield/policy.hpp"
#include "ai_shield/policy_authorization.hpp"
#include "ai_shield/policy_store.hpp"
#include "ai_shield/pending_decision.hpp"
#include "ai_shield/platform_uri.hpp"
#include "ai_shield/privacy.hpp"
#include "ai_shield/response_normalizer.hpp"
#include "ai_shield/recovery_plan.hpp"
#include "ai_shield/recovery_vault.hpp"
#include "ai_shield/release_gate.hpp"
#include "ai_shield/replay.hpp"
#include "ai_shield/retention.hpp"
#include "ai_shield/risk.hpp"
#include "ai_shield/ransomware.hpp"
#include "ai_shield/process_guard.hpp"
#include "ai_shield/provenance.hpp"
#include "ai_shield/ring_buffer.hpp"
#include "ai_shield/sandbox.hpp"
#include "ai_shield/sandbox_budget.hpp"
#include "ai_shield/service_discovery.hpp"
#include "ai_shield/service_registry.hpp"
#include "ai_shield/service_identity.hpp"
#include "ai_shield/sha256.hpp"
#include "ai_shield/shadow_catalog.hpp"
#include "ai_shield/sequence_model.hpp"
#include "ai_shield/signature_detector.hpp"
#include "ai_shield/siem.hpp"
#include "ai_shield/support_package.hpp"
#include "ai_shield/system_preflight.hpp"
#include "ai_shield/tls_service_policy.hpp"
#include "ai_shield/tlsmeta.hpp"
#include "ai_shield/update_manager.hpp"
#include "ai_shield/worker_supervisor.hpp"
#include "ai_shield/xml_preflight.hpp"
#include "ai_shield/zip_preflight.hpp"

namespace {

void check(bool condition, std::string_view expression, const char* file, int line) {
    if (!condition) {
        std::cerr << "check failed: " << expression << " at " << file << ":" << line << "\n";
        std::exit(1);
    }
}

#define AI_SHIELD_CHECK(expr) check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

void test_abi() {
    using ai_shield::abi::FlowEvent;
    using ai_shield::abi::ShieldDecision;
    static_assert(std::is_standard_layout_v<ShieldDecision>);
    static_assert(std::is_trivially_copyable_v<ShieldDecision>);
    static_assert(std::is_standard_layout_v<FlowEvent>);
    static_assert(std::is_trivially_copyable_v<FlowEvent>);
    AI_SHIELD_CHECK(ai_shield::abi::valid_header(ai_shield::abi::kAbiVersion, sizeof(ShieldDecision), sizeof(ShieldDecision)));
}

void test_checked() {
    const auto ok = ai_shield::checked::add<std::uint32_t>(2, 3);
    AI_SHIELD_CHECK(ok.ok() && ok.value() == 5);
    const auto overflow = ai_shield::checked::add<std::uint32_t>(std::numeric_limits<std::uint32_t>::max(), 1);
    AI_SHIELD_CHECK(!overflow.ok() && overflow.status() == ai_shield::Status::overflow);
}

void test_flow_state() {
    ai_shield::FlowStateMachine machine;
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::authorized).ok());
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::allowed).status() == ai_shield::Status::invalid_state_transition);
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::classifying).ok());
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::blocked).ok());
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::active).status() == ai_shield::Status::invalid_state_transition);
    AI_SHIELD_CHECK(machine.transition(ai_shield::FlowState::closed).ok());
}

void test_http_policy() {
    const std::string request =
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    const auto parsed = ai_shield::protocols::http1::parse_request(request);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::http1::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::proto_ambiguous) != 0U);
    const auto decision = ai_shield::policy::decide(
        ai_shield::policy::PolicyContext{.decision_id = 7, .flow_id = 9, .critical_service = true},
        evidence,
        ai_shield::crypto::sha256(request));
    AI_SHIELD_CHECK(decision.action == ai_shield::abi::ShieldAction::quarantine);
    AI_SHIELD_CHECK(decision.risk_score >= 100);
}

void test_audit_chain() {
    ai_shield::audit::AuditChain chain;
    const auto hash = ai_shield::crypto::sha256("evidence");
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{.sequence = 1, .monotonic_ns = 10, .reason_mask = 1, .evidence_hash = hash}).ok());
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{.sequence = 2, .monotonic_ns = 11, .reason_mask = 2, .evidence_hash = hash}).ok());
    AI_SHIELD_CHECK(chain.verify().ok());
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{.sequence = 4, .monotonic_ns = 12, .reason_mask = 3, .evidence_hash = hash}).status() ==
           ai_shield::Status::integrity_failure);
}

void test_audit_export_roundtrip_and_tamper() {
    ai_shield::audit::AuditChain chain;
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{
               .sequence = 1,
               .monotonic_ns = 100,
               .reason_mask = ai_shield::abi::ReasonCode::proto_malformed,
               .evidence_hash = ai_shield::crypto::sha256("audit-1")})
               .ok());
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{
               .sequence = 2,
               .monotonic_ns = 101,
               .reason_mask = ai_shield::abi::ReasonCode::command_execution,
               .evidence_hash = ai_shield::crypto::sha256("audit-2")})
               .ok());

    const auto bytes = ai_shield::audit::serialize(chain);
    const auto parsed = ai_shield::audit::deserialize(bytes);
    AI_SHIELD_CHECK(parsed.ok());
    AI_SHIELD_CHECK(parsed.value().segments().size() == 2U);

    auto tampered = bytes;
    tampered.back() ^= std::byte{0x01};
    AI_SHIELD_CHECK(ai_shield::audit::deserialize(tampered).status() == ai_shield::Status::integrity_failure);
    auto obsolete_format = bytes;
    obsolete_format[7] = std::byte{'1'};
    AI_SHIELD_CHECK(ai_shield::audit::deserialize(obsolete_format).status() == ai_shield::Status::malformed_input);
}

void test_provenance() {
    ai_shield::provenance::Store store;
    ai_shield::provenance::FileIdentity id{.volume_id = 1,
                                           .file_id = 2,
                                           .stream_id = 3,
                                           .content_hash = ai_shield::crypto::sha256("file-v1"),
                                           .provenance_id = 4};
    AI_SHIELD_CHECK(store.record_external(id).ok());
    const auto pending = store.lookup(id);
    AI_SHIELD_CHECK(pending.ok());
    AI_SHIELD_CHECK(pending.value().disposition == ai_shield::provenance::FileDisposition::execution_pending);
    AI_SHIELD_CHECK(store.approve(id).ok());
    const auto allowed = store.lookup(id);
    AI_SHIELD_CHECK(allowed.ok());
    AI_SHIELD_CHECK(allowed.value().disposition == ai_shield::provenance::FileDisposition::allowed);
    id.content_hash = ai_shield::crypto::sha256("file-v2");
    const auto changed = store.lookup(id);
    AI_SHIELD_CHECK(changed.ok());
    AI_SHIELD_CHECK(changed.value().disposition == ai_shield::provenance::FileDisposition::execution_pending);
}

void test_bounded_ring() {
    ai_shield::BoundedRing<std::uint32_t, 2> ring;
    AI_SHIELD_CHECK(ring.push(10).ok());
    AI_SHIELD_CHECK(ring.push(20).ok());
    AI_SHIELD_CHECK(ring.push(30).status() == ai_shield::Status::out_of_budget);
    const auto first = ring.pop();
    const auto second = ring.pop();
    AI_SHIELD_CHECK(first.ok() && first.value() == 10);
    AI_SHIELD_CHECK(second.ok() && second.value() == 20);
    AI_SHIELD_CHECK(ring.pop().status() == ai_shield::Status::not_found);
}

void test_health_degradation() {
    const auto degraded = ai_shield::health::assess(ai_shield::health::SensorReport{
        .kind = ai_shield::health::SensorKind::etw,
        .state = ai_shield::health::SensorState::failed,
        .last_sequence = 5,
        .missing_sequences = 2,
        .last_monotonic_ns = 100});
    AI_SHIELD_CHECK(degraded.sensor_integrity_score == 100);
    AI_SHIELD_CHECK((degraded.reason_mask & ai_shield::abi::ReasonCode::sensor_integrity_gap) != 0U);
    AI_SHIELD_CHECK((degraded.reason_mask & ai_shield::abi::ReasonCode::degraded_mode) != 0U);
}

void test_service_registry_default_deny() {
    ai_shield::service_registry::Registry registry;
    const auto unknown = registry.admit(ai_shield::service_registry::Transport::udp, 0x3500U);
    AI_SHIELD_CHECK(unknown.action == ai_shield::abi::ShieldAction::drop_flow);
    AI_SHIELD_CHECK((unknown.reason_mask & ai_shield::abi::ReasonCode::unregistered_service) != 0U);

    AI_SHIELD_CHECK(registry.register_service(ai_shield::service_registry::ServicePolicy{
               .port_be = 0x5000U,
               .transport = ai_shield::service_registry::Transport::tcp,
               .protocol_id = 1,
               .externally_reachable = true,
               .critical_service = true,
               .fail_policy = ai_shield::service_registry::FailPolicy::fail_closed,
               .max_payload_bytes = 8192})
               .ok());
    const auto known = registry.admit(ai_shield::service_registry::Transport::tcp, 0x5000U);
    AI_SHIELD_CHECK(known.action == ai_shield::abi::ShieldAction::allow_monitored);
}

void test_dns_compression_loop_risk() {
    std::vector<std::byte> packet = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x0C}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01}};
    const auto parsed = ai_shield::protocols::dns::parse_message(packet);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::dns::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::proto_ambiguous) != 0U);
    AI_SHIELD_CHECK(evidence.hard_rule == 100);
}

void test_json_depth_budget() {
    const auto parsed = ai_shield::protocols::json::preflight("[[[{\"a\":1}]]]", 2);
    AI_SHIELD_CHECK(parsed.ok());
    AI_SHIELD_CHECK(parsed.value().depth_budget_exceeded);
    const auto evidence = ai_shield::protocols::json::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::proto_ambiguous) != 0U);
}

void test_sandbox_inconclusive_policy() {
    const auto evidence = ai_shield::sandbox::evidence_from(ai_shield::sandbox::ResultSummary{
        .tier = ai_shield::sandbox::Tier::appcontainer_fast,
        .outcome = ai_shield::sandbox::Outcome::timeout,
        .attempted_network = false,
        .attempted_host_profile = false,
        .created_executable = false,
        .event_count = 1});
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::sandbox_inconclusive) != 0U);
    const auto decision = ai_shield::policy::decide(
        ai_shield::policy::PolicyContext{.decision_id = 11, .flow_id = 12, .critical_service = true},
        evidence,
        ai_shield::crypto::sha256("sandbox-timeout"));
    AI_SHIELD_CHECK(decision.action == ai_shield::abi::ShieldAction::quarantine);
}

void test_process_guard_blocks_forbidden_child() {
    const auto evidence = ai_shield::process_guard::evaluate_create_process(ai_shield::process_guard::ProcessEvent{
        .parent_process_id = 100,
        .child_process_id = 101,
        .inherited_flow_id = 12,
        .parent_external_influenced = true,
        .child_signature = ai_shield::process_guard::SignatureState::trusted_signed,
        .image_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        .command_line = "powershell -EncodedCommand AAAA"});
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::command_execution) != 0U);
    const auto decision = ai_shield::policy::decide(
        ai_shield::policy::PolicyContext{.decision_id = 20, .flow_id = 12, .critical_service = true},
        evidence,
        ai_shield::crypto::sha256("process-child"));
    AI_SHIELD_CHECK(decision.action == ai_shield::abi::ShieldAction::quarantine);
}

void test_package_manifest_trust_gate() {
    const auto signature = ai_shield::crypto::sha256("trusted-policy-signer");
    const std::vector<ai_shield::package::FileEntry> files = {
        ai_shield::package::FileEntry{.path = "policy/rules.bin", .sha256 = ai_shield::crypto::sha256("rules-v2")},
        ai_shield::package::FileEntry{.path = "policy/metadata.bin", .sha256 = ai_shield::crypto::sha256("metadata-v2")}};
    ai_shield::package::Manifest manifest{.kind = ai_shield::package::PackageKind::policy,
                                          .manifest_version = 1,
                                          .min_abi_version = ai_shield::abi::kAbiVersion,
                                          .security_version = 2,
                                          .policy_version = 20,
                                          .model_version = 0,
                                          .files = files,
                                          .manifest_digest = {},
                                          .signature_fingerprint = signature};
    manifest.manifest_digest = ai_shield::package::compute_manifest_digest(manifest);
    const ai_shield::package::TrustAnchor trust{.kind = ai_shield::package::PackageKind::policy,
                                                .current_security_version = 1,
                                                .expected_signature_fingerprint = signature};
    const auto accepted = ai_shield::package::verify_manifest(manifest, trust);
    AI_SHIELD_CHECK(accepted.ok());
    AI_SHIELD_CHECK(accepted.value().accepted);

    auto downgrade = manifest;
    downgrade.security_version = 1;
    downgrade.manifest_digest = ai_shield::package::compute_manifest_digest(downgrade);
    AI_SHIELD_CHECK(ai_shield::package::verify_manifest(downgrade, trust).status() == ai_shield::Status::downgrade_attempt);

    auto tampered = manifest;
    tampered.policy_version = 21;
    AI_SHIELD_CHECK(ai_shield::package::verify_manifest(tampered, trust).status() == ai_shield::Status::integrity_failure);
}

void test_zip_preflight_path_escape_and_bomb() {
    std::vector<std::byte> zip(30U + 13U);
    const auto put16 = [&](std::size_t offset, std::uint16_t value) {
        zip[offset] = static_cast<std::byte>(value & 0xffU);
        zip[offset + 1U] = static_cast<std::byte>((value >> 8U) & 0xffU);
    };
    const auto put32 = [&](std::size_t offset, std::uint32_t value) {
        for (std::size_t i = 0; i < 4U; ++i) {
            zip[offset + i] = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
        }
    };
    put32(0, 0x04034b50U);
    put32(18, 1U);
    put32(22, 1000U);
    put16(26, 13U);
    const std::string name = "../evil.exe";
    for (std::size_t i = 0; i < name.size(); ++i) {
        zip[30U + i] = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
    zip.push_back(std::byte{0});
    const auto parsed = ai_shield::protocols::zip::preflight(zip);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::zip::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::archive_path_escape) != 0U);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::archive_bomb_risk) != 0U);
}

void test_pe_preflight_marks_executable_pending() {
    std::vector<std::byte> pe(0x400U);
    pe[0] = static_cast<std::byte>('M');
    pe[1] = static_cast<std::byte>('Z');
    pe[0x3C] = static_cast<std::byte>(0x80U);
    pe[0x80] = static_cast<std::byte>('P');
    pe[0x81] = static_cast<std::byte>('E');
    pe[0x84] = static_cast<std::byte>(0x64U);
    pe[0x85] = static_cast<std::byte>(0x86U);
    pe[0x86] = static_cast<std::byte>(0x01U);
    pe[0x94] = static_cast<std::byte>(0xF0U);
    pe[0x96] = static_cast<std::byte>(0x02U);
    pe[0x98] = static_cast<std::byte>(0x0BU);
    pe[0x99] = static_cast<std::byte>(0x02U);
    pe[0xD0] = static_cast<std::byte>(0x00U);
    pe[0xD1] = static_cast<std::byte>(0x20U);
    const auto section = 0x80U + 24U + 0xF0U;
    pe[section + 16U] = static_cast<std::byte>(0x20U);
    pe[section + 20U] = static_cast<std::byte>(0x00U);
    pe[section + 21U] = static_cast<std::byte>(0x02U);
    const auto parsed = ai_shield::protocols::pe::preflight(pe);
    AI_SHIELD_CHECK(parsed.ok());
    AI_SHIELD_CHECK(parsed.value().executable);
    const auto evidence = ai_shield::protocols::pe::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::external_exec_pending) != 0U);
}

void test_archive_provenance_propagation() {
    ai_shield::provenance::Store store;
    const ai_shield::provenance::FileIdentity archive{.volume_id = 7,
                                                      .file_id = 8,
                                                      .stream_id = 1,
                                                      .content_hash = ai_shield::crypto::sha256("archive"),
                                                      .provenance_id = 9};
    const ai_shield::provenance::FileIdentity child{.volume_id = 7,
                                                    .file_id = 10,
                                                    .stream_id = 1,
                                                    .content_hash = ai_shield::crypto::sha256("child"),
                                                    .provenance_id = 9};
    AI_SHIELD_CHECK(store.record_external(archive).ok());
    AI_SHIELD_CHECK(store.propagate_archive(archive, child).ok());
    const auto verdict = store.lookup(child);
    AI_SHIELD_CHECK(verdict.ok());
    AI_SHIELD_CHECK(verdict.value().disposition == ai_shield::provenance::FileDisposition::execution_pending);
}

void test_update_manager_rolls_back_failed_boot() {
    const auto signature = ai_shield::crypto::sha256("trusted-update-signer");
    const std::vector<ai_shield::package::FileEntry> files = {
        ai_shield::package::FileEntry{.path = "core/ai_shield_core.exe", .sha256 = ai_shield::crypto::sha256("core-v2")}};
    ai_shield::package::Manifest manifest{.kind = ai_shield::package::PackageKind::update,
                                          .manifest_version = 1,
                                          .min_abi_version = ai_shield::abi::kAbiVersion,
                                          .security_version = 2,
                                          .policy_version = 2,
                                          .model_version = 2,
                                          .files = files,
                                          .manifest_digest = {},
                                          .signature_fingerprint = signature};
    manifest.manifest_digest = ai_shield::package::compute_manifest_digest(manifest);
    const ai_shield::package::TrustAnchor trust{.kind = ai_shield::package::PackageKind::update,
                                                .current_security_version = 1,
                                                .expected_signature_fingerprint = signature};
    ai_shield::update::Manager manager;
    AI_SHIELD_CHECK(manager.stage(manifest, trust).ok());
    AI_SHIELD_CHECK(manager.staged_slot() == ai_shield::update::Slot::b);
    AI_SHIELD_CHECK(manager.activate_staged().ok());
    AI_SHIELD_CHECK(manager.active_slot() == ai_shield::update::Slot::b);
    AI_SHIELD_CHECK(manager.commit_boot(ai_shield::update::BootHealth{
               .drivers_loaded = true, .core_started = true, .audit_writable = false, .policy_loaded = true})
               .status() == ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(manager.active_slot() == ai_shield::update::Slot::a);
    AI_SHIELD_CHECK(manager.slot_info(ai_shield::update::Slot::b).state == ai_shield::update::SlotState::failed);
}

void test_tlsmeta_detects_downgrade() {
    std::vector<std::byte> hello(52U);
    hello[0] = std::byte{0x16};
    hello[1] = std::byte{0x03};
    hello[2] = std::byte{0x01};
    hello[4] = std::byte{0x2FU};
    hello[5] = std::byte{0x01};
    hello[8] = std::byte{0x2BU};
    hello[9] = std::byte{0x03};
    hello[10] = std::byte{0x01};
    hello[43] = std::byte{0x00};
    hello[45] = std::byte{0x02};
    hello[46] = std::byte{0x13};
    hello[47] = std::byte{0x01};
    hello[48] = std::byte{0x01};
    hello[50] = std::byte{0x00};
    hello[51] = std::byte{0x00};
    const auto parsed = ai_shield::protocols::tlsmeta::parse_client_hello(hello);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::tlsmeta::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::tls_downgrade) != 0U);
}

void test_xml_external_entity_risk() {
    const std::string xml = "<!DOCTYPE a [ <!ENTITY x SYSTEM \"file:///secret\"> ]><a>&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;</a>";
    const auto parsed = ai_shield::protocols::xml::preflight(xml);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::xml::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::xml_entity_expansion) != 0U);
    AI_SHIELD_CHECK(evidence.hard_rule == 100);
}

void test_pdf_active_content() {
    const std::string pdf = "%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript 3 0 R >> endobj\nxref\n%%EOF";
    std::vector<std::byte> bytes;
    for (const unsigned char ch : pdf) {
        bytes.push_back(static_cast<std::byte>(ch));
    }
    const auto parsed = ai_shield::protocols::pdf::preflight(bytes);
    AI_SHIELD_CHECK(parsed.ok());
    const auto evidence = ai_shield::protocols::pdf::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::document_active_content) != 0U);
}

void test_campaign_adaptive_correlation() {
    ai_shield::campaign::Tracker tracker;
    const auto hash = ai_shield::crypto::sha256("normalized");
    AI_SHIELD_CHECK(tracker.observe(ai_shield::campaign::Observation{.source_id = 1, .target_service_id = 9, .normalized_payload_hash = hash, .response_class = 200, .mutation_distance = 10}).reason_mask == 0U);
    AI_SHIELD_CHECK(tracker.observe(ai_shield::campaign::Observation{.source_id = 2, .target_service_id = 9, .normalized_payload_hash = hash, .response_class = 200, .mutation_distance = 20}).reason_mask == 0U);
    AI_SHIELD_CHECK(tracker.observe(ai_shield::campaign::Observation{.source_id = 3, .target_service_id = 9, .normalized_payload_hash = hash, .response_class = 200, .mutation_distance = 30}).reason_mask == 0U);
    const auto evidence = tracker.observe(ai_shield::campaign::Observation{
        .source_id = 4,
        .target_service_id = 9,
        .normalized_payload_hash = hash,
        .response_class = 200,
        .mutation_distance = 60,
        .follows_previous_response = true});
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::campaign_correlation) != 0U);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::adaptive_mutation) != 0U);
}

void test_flow_control_rate_and_redirect_limits() {
    ai_shield::flow_control::TokenBucket bucket(2, 1);
    AI_SHIELD_CHECK(bucket.consume(1'000'000'000ULL, 1).ok());
    AI_SHIELD_CHECK(bucket.consume(1'000'000'000ULL, 1).ok());
    AI_SHIELD_CHECK(bucket.consume(1'000'000'000ULL, 1).status() == ai_shield::Status::out_of_budget);
    AI_SHIELD_CHECK(bucket.consume(2'000'000'000ULL, 1).ok());

    ai_shield::flow_control::UdpSessionLimiter limiter(1, 10'000'000'000ULL);
    AI_SHIELD_CHECK(limiter.admit(ai_shield::flow_control::UdpFlowKey{.source_id = 1, .target_service_id = 2, .source_port_be = 10, .target_port_be = 53}, 1).action ==
           ai_shield::abi::ShieldAction::allow);
    const auto denied = limiter.admit(ai_shield::flow_control::UdpFlowKey{.source_id = 3, .target_service_id = 2, .source_port_be = 11, .target_port_be = 53}, 2);
    AI_SHIELD_CHECK(denied.action == ai_shield::abi::ShieldAction::rate_limit);
    AI_SHIELD_CHECK((denied.reason_mask & ai_shield::abi::ReasonCode::rate_limited) != 0U);

    ai_shield::flow_control::RedirectTracker tracker(2);
    AI_SHIELD_CHECK(tracker.record_redirect(42).action == ai_shield::abi::ShieldAction::allow);
    AI_SHIELD_CHECK(tracker.record_redirect(42).action == ai_shield::abi::ShieldAction::allow);
    const auto loop = tracker.record_redirect(42);
    AI_SHIELD_CHECK(loop.action == ai_shield::abi::ShieldAction::drop_flow);
    AI_SHIELD_CHECK((loop.reason_mask & ai_shield::abi::ReasonCode::proxy_loop) != 0U);
}

void test_worker_supervisor_crash_isolation() {
    ai_shield::worker::Supervisor supervisor(2, 1'000'000'000ULL);
    const auto first = supervisor.observe(ai_shield::worker::WorkerReport{
        .kind = ai_shield::worker::WorkerKind::json,
        .event = ai_shield::worker::WorkerEvent::crashed,
        .worker_id = 1,
        .monotonic_ns = 10});
    AI_SHIELD_CHECK((first.reason_mask & ai_shield::abi::ReasonCode::worker_crash) != 0U);
    AI_SHIELD_CHECK(!supervisor.circuit_open(ai_shield::worker::WorkerKind::json));
    const auto second = supervisor.observe(ai_shield::worker::WorkerReport{
        .kind = ai_shield::worker::WorkerKind::json,
        .event = ai_shield::worker::WorkerEvent::timed_out,
        .worker_id = 2,
        .monotonic_ns = 20});
    AI_SHIELD_CHECK((second.reason_mask & ai_shield::abi::ReasonCode::degraded_mode) != 0U);
    AI_SHIELD_CHECK(supervisor.circuit_open(ai_shield::worker::WorkerKind::json));
    const auto recovered = supervisor.observe(ai_shield::worker::WorkerReport{
        .kind = ai_shield::worker::WorkerKind::json,
        .event = ai_shield::worker::WorkerEvent::completed,
        .worker_id = 3,
        .monotonic_ns = 30});
    AI_SHIELD_CHECK(recovered.reason_mask == 0U);
    AI_SHIELD_CHECK(!supervisor.circuit_open(ai_shield::worker::WorkerKind::json));
}

void test_privacy_payload_sanitization() {
    const std::string payload = "secret-user-token-and-large-payload";
    std::vector<std::byte> bytes;
    for (const unsigned char ch : payload) {
        bytes.push_back(static_cast<std::byte>(ch));
    }
    const auto sanitized = ai_shield::privacy::sanitize_payload(
        bytes,
        ai_shield::privacy::ExportPolicy{
            .include_payload_excerpt = true,
            .max_excerpt_bytes = 6,
            .pseudonym_key = ai_shield::crypto::sha256("export-key")});
    AI_SHIELD_CHECK(sanitized.excerpt.size() == 6U);
    AI_SHIELD_CHECK((sanitized.reason_mask & ai_shield::abi::ReasonCode::privacy_redacted) != 0U);
    const auto p1 = ai_shield::privacy::stable_pseudonym(ai_shield::crypto::sha256("k"), "10.0.0.1");
    const auto p2 = ai_shield::privacy::stable_pseudonym(ai_shield::crypto::sha256("k"), "10.0.0.1");
    AI_SHIELD_CHECK(ai_shield::crypto::constant_time_equal(p1, p2));
}

void test_model_registry_blocks_online_learning() {
    const auto signature = ai_shield::crypto::sha256("trusted-model-signer");
    const std::vector<ai_shield::package::FileEntry> files = {
        ai_shield::package::FileEntry{.path = "model/model.bin", .sha256 = ai_shield::crypto::sha256("model-v3")}};
    ai_shield::package::Manifest manifest{.kind = ai_shield::package::PackageKind::model,
                                          .manifest_version = 1,
                                          .min_abi_version = ai_shield::abi::kAbiVersion,
                                          .security_version = 3,
                                          .policy_version = 0,
                                          .model_version = 30,
                                          .files = files,
                                          .manifest_digest = {},
                                          .signature_fingerprint = signature};
    manifest.manifest_digest = ai_shield::package::compute_manifest_digest(manifest);
    const ai_shield::package::TrustAnchor trust{.kind = ai_shield::package::PackageKind::model,
                                                .current_security_version = 2,
                                                .expected_signature_fingerprint = signature};
    ai_shield::model::Registry registry;
    AI_SHIELD_CHECK(registry.load_production_model(
                       manifest,
                       trust,
                       ai_shield::model::ModelMetadata{.model_version = 30,
                                                       .feature_schema_hash = ai_shield::crypto::sha256("schema"),
                                                       .training_data_fingerprint = ai_shield::crypto::sha256("training-set")})
               .ok());
    AI_SHIELD_CHECK(registry.has_active_model());
    AI_SHIELD_CHECK(registry.observe_live_sample().status() == ai_shield::Status::invalid_state_transition);
}

void test_policy_store_transaction_and_rollback() {
    const auto signature = ai_shield::crypto::sha256("trusted-policy-signer-2");
    const std::vector<ai_shield::package::FileEntry> files = {
        ai_shield::package::FileEntry{.path = "policy/rules-v3.bin", .sha256 = ai_shield::crypto::sha256("rules-v3")}};
    ai_shield::package::Manifest manifest{.kind = ai_shield::package::PackageKind::policy,
                                          .manifest_version = 1,
                                          .min_abi_version = ai_shield::abi::kAbiVersion,
                                          .security_version = 3,
                                          .policy_version = 3,
                                          .model_version = 0,
                                          .files = files,
                                          .manifest_digest = {},
                                          .signature_fingerprint = signature};
    manifest.manifest_digest = ai_shield::package::compute_manifest_digest(manifest);
    const ai_shield::package::TrustAnchor trust{.kind = ai_shield::package::PackageKind::policy,
                                                .current_security_version = 2,
                                                .expected_signature_fingerprint = signature};
    ai_shield::policy_store::Store store;
    AI_SHIELD_CHECK(store.stage(manifest, trust).ok());
    AI_SHIELD_CHECK(store.activate(1).ok());
    AI_SHIELD_CHECK(store.active().policy_version == 3);
    AI_SHIELD_CHECK(store.rollback().ok());
    AI_SHIELD_CHECK(store.active().policy_version == 1);
}

void test_incident_package_redacts_payload_and_hashes_timeline() {
    ai_shield::audit::AuditChain chain;
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{
               .sequence = 1,
               .monotonic_ns = 55,
               .reason_mask = ai_shield::abi::ReasonCode::document_active_content,
               .evidence_hash = ai_shield::crypto::sha256("doc-js")})
               .ok());
    const std::vector<ai_shield::sandbox::ResultSummary> sandbox_results = {
        ai_shield::sandbox::ResultSummary{.outcome = ai_shield::sandbox::Outcome::suspicious, .attempted_network = true}};
    const std::string payload = "private payload that must not be fully exported";
    std::vector<std::byte> payload_bytes;
    for (const unsigned char ch : payload) {
        payload_bytes.push_back(static_cast<std::byte>(ch));
    }
    const ai_shield::correlation::Context correlation{.flow_id = 7, .object_id = 8, .file_id = 9,
        .volume_id = 10, .provenance_id = 11, .process_id = 12, .parent_process_id = 13,
        .policy_version = 14, .model_version = 15};
    const auto package = ai_shield::incident::build_correlated(
        99,
        correlation,
        chain,
        sandbox_results,
        payload_bytes,
        ai_shield::privacy::ExportPolicy{.include_payload_excerpt = true,
                                         .max_excerpt_bytes = 8,
                                         .pseudonym_key = ai_shield::crypto::sha256("incident-key")});
    AI_SHIELD_CHECK(package.ok());
    AI_SHIELD_CHECK(package.value().events.size() == 1U);
    AI_SHIELD_CHECK(package.value().payload.excerpt.size() == 8U);
    AI_SHIELD_CHECK((package.value().aggregate_reason_mask & ai_shield::abi::ReasonCode::privacy_redacted) != 0U);
    AI_SHIELD_CHECK((package.value().aggregate_reason_mask & ai_shield::abi::ReasonCode::consequence_detected) != 0U);
    AI_SHIELD_CHECK(!ai_shield::crypto::constant_time_equal(package.value().timeline_hash, ai_shield::crypto::Sha256Digest{}));
    AI_SHIELD_CHECK(package.value().events[0].correlation.provenance_id == 11U);
    AI_SHIELD_CHECK(package.value().correlation.model_version == 15U);
}

void test_ipc_flow_event_validation() {
    const auto key = ai_shield::crypto::sha256("ipc-key");
    ai_shield::abi::FlowEvent event{};
    event.abi_version = ai_shield::abi::kAbiVersion;
    event.structure_size = sizeof(ai_shield::abi::FlowEvent);
    event.sequence = 10;
    event.flow_id = 100;
    event.monotonic_ns = 1'000;
    event.protocol = 6;
    event.payload_hash = ai_shield::crypto::sha256("payload");
    event.message_mac = ai_shield::ipc::compute_flow_event_mac(event, key);
    AI_SHIELD_CHECK(ai_shield::ipc::validate_flow_event(
               event,
               ai_shield::ipc::ValidationContext{.expected_next_sequence = 10,
                                                 .now_monotonic_ns = 1'000,
                                                 .max_clock_skew_ns = 100,
                                                 .mac_key = key})
               .ok());
    event.sequence = 11;
    AI_SHIELD_CHECK(ai_shield::ipc::validate_flow_event(
               event,
               ai_shield::ipc::ValidationContext{.expected_next_sequence = 10,
                                                 .now_monotonic_ns = 1'000,
                                                 .max_clock_skew_ns = 100,
                                                 .mac_key = key})
               .status() == ai_shield::Status::integrity_failure);
}

void test_pending_decision_timeout() {
    ai_shield::pending::Manager manager;
    AI_SHIELD_CHECK(manager.pend(42, 1'000, 100).ok());
    AI_SHIELD_CHECK(manager.pending_count() == 1U);
    const auto none = manager.expire(1'050);
    AI_SHIELD_CHECK(none.empty());
    const auto expired = manager.expire(1'100);
    AI_SHIELD_CHECK(expired.size() == 1U);
    AI_SHIELD_CHECK(expired[0].action == ai_shield::abi::ShieldAction::drop_flow);
    AI_SHIELD_CHECK((expired[0].reason_mask & ai_shield::abi::ReasonCode::decision_timeout) != 0U);
}

void test_platform_uri_normalization() {
    const auto uri = ai_shield::platform::normalize_path_uri("C:\\Users\\Alice\\Downloads\\File.EXE");
    AI_SHIELD_CHECK(uri.ok());
    AI_SHIELD_CHECK(uri.value() == "file:///c/users/alice/downloads/file.exe");
    AI_SHIELD_CHECK(ai_shield::platform::normalize_path_uri("C:\\Temp\\..\\secret.txt").status() == ai_shield::Status::ambiguous_input);
}

void test_retention_policy() {
    constexpr std::uint64_t day = 24ULL * 60ULL * 60ULL * 1'000'000'000ULL;
    AI_SHIELD_CHECK(ai_shield::retention::decide(ai_shield::retention::DataClass::flow_metadata, 29ULL * day, false, false).keep);
    AI_SHIELD_CHECK(!ai_shield::retention::decide(ai_shield::retention::DataClass::flow_metadata, 31ULL * day, false, false).keep);
    const auto payload = ai_shield::retention::decide(ai_shield::retention::DataClass::full_payload, 0, false, false);
    AI_SHIELD_CHECK(!payload.keep);
    AI_SHIELD_CHECK(payload.requires_explicit_admin_payload_opt_in);
    AI_SHIELD_CHECK(ai_shield::retention::decide(ai_shield::retention::DataClass::sandbox_report, 60ULL * day, true, false).keep);
}

void test_response_normalizer_does_not_leak_scores() {
    const auto response = ai_shield::response::external_response_for(ai_shield::abi::ShieldAction::quarantine);
    AI_SHIELD_CHECK(response == "request_not_processed");
    AI_SHIELD_CHECK(response.find("score") == std::string::npos);
    AI_SHIELD_CHECK(response.find("rule") == std::string::npos);
}

void test_risk_bands_and_policy_actions() {
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(24) == ai_shield::policy::DecisionBand::allow);
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(25) == ai_shield::policy::DecisionBand::allow_monitored);
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(50) == ai_shield::policy::DecisionBand::deep_inspection);
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(75) == ai_shield::policy::DecisionBand::redirect_sandbox);
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(100) == ai_shield::policy::DecisionBand::quarantine_or_drop);
    AI_SHIELD_CHECK(ai_shield::policy::band_for_score(150) == ai_shield::policy::DecisionBand::block_origin);

    const auto decision = ai_shield::policy::decide(
        ai_shield::policy::PolicyContext{.decision_id = 77, .flow_id = 88, .critical_service = false},
        ai_shield::detection::Evidence{.protocol = 60},
        ai_shield::crypto::sha256("risk"));
    AI_SHIELD_CHECK(decision.action == ai_shield::abi::ShieldAction::rate_limit);
}

void test_fail_policy_matrix() {
    const auto admin = ai_shield::fail_policy::decide(
        ai_shield::fail_policy::ServiceClass::admin_management, ai_shield::fail_policy::FailureKind::sandbox, 10);
    AI_SHIELD_CHECK(admin.action == ai_shield::abi::ShieldAction::quarantine);

    const auto web_low = ai_shield::fail_policy::decide(
        ai_shield::fail_policy::ServiceClass::web_api, ai_shield::fail_policy::FailureKind::sandbox, 20);
    AI_SHIELD_CHECK(web_low.action == ai_shield::abi::ShieldAction::allow_monitored);

    const auto web_high = ai_shield::fail_policy::decide(
        ai_shield::fail_policy::ServiceClass::web_api, ai_shield::fail_policy::FailureKind::sandbox, 80);
    AI_SHIELD_CHECK(web_high.action == ai_shield::abi::ShieldAction::drop_flow);

    const auto unregistered = ai_shield::fail_policy::decide(
        ai_shield::fail_policy::ServiceClass::unregistered, ai_shield::fail_policy::FailureKind::ai, 0);
    AI_SHIELD_CHECK(unregistered.action == ai_shield::abi::ShieldAction::block_origin);
}

void test_health_aggregation_and_diagnostics() {
    const std::vector<ai_shield::health::SensorReport> reports = {
        ai_shield::health::SensorReport{.kind = ai_shield::health::SensorKind::wfp,
                                        .state = ai_shield::health::SensorState::healthy},
        ai_shield::health::SensorReport{.kind = ai_shield::health::SensorKind::audit,
                                        .state = ai_shield::health::SensorState::degraded,
                                        .missing_sequences = 1}};
    const auto aggregate = ai_shield::health::aggregate(reports);
    AI_SHIELD_CHECK(aggregate.sensor_integrity_score == 70);
    AI_SHIELD_CHECK((aggregate.reason_mask & ai_shield::abi::ReasonCode::degraded_mode) != 0U);
    AI_SHIELD_CHECK(ai_shield::diagnostics::protection_degraded(ai_shield::diagnostics::Snapshot{
        .active_flows = 3, .pending_decisions = 1, .sandbox_capacity = 0, .worker_circuits_open = 0, .health = aggregate}));
}

void test_causal_chain_flow_file_process() {
    ai_shield::causal::Graph graph;
    AI_SHIELD_CHECK(graph.add_node(ai_shield::causal::Node{.id = 1,
                                                  .kind = ai_shield::causal::NodeKind::flow,
                                                  .identity_hash = ai_shield::crypto::sha256("flow")})
               .ok());
    AI_SHIELD_CHECK(graph.add_node(ai_shield::causal::Node{.id = 2,
                                                  .kind = ai_shield::causal::NodeKind::file,
                                                  .identity_hash = ai_shield::crypto::sha256("file")})
               .ok());
    AI_SHIELD_CHECK(graph.add_node(ai_shield::causal::Node{.id = 3,
                                                  .kind = ai_shield::causal::NodeKind::process,
                                                  .identity_hash = ai_shield::crypto::sha256("process")})
               .ok());
    AI_SHIELD_CHECK(graph.add_edge(1, 2).ok());
    AI_SHIELD_CHECK(graph.add_edge(2, 3).ok());
    const auto chain = graph.chain_to(3);
    AI_SHIELD_CHECK(chain.ok());
    AI_SHIELD_CHECK(chain.value().size() == 3U);
    AI_SHIELD_CHECK(chain.value()[0].kind == ai_shield::causal::NodeKind::flow);
    AI_SHIELD_CHECK(chain.value()[2].kind == ai_shield::causal::NodeKind::process);
}

void test_signature_detector_hash_and_substring() {
    ai_shield::signatures::Detector detector;
    const std::string payload = "GET /jndi:ldap://x HTTP/1.1\r\n\r\n";
    std::vector<std::byte> bytes;
    for (const unsigned char ch : payload) {
        bytes.push_back(static_cast<std::byte>(ch));
    }
    AI_SHIELD_CHECK(detector.add_rule(ai_shield::signatures::Rule{
        .rule_id = 1, .kind = ai_shield::signatures::RuleKind::substring, .severity = 80, .pattern = "jndi:ldap"}));
    AI_SHIELD_CHECK(detector.add_rule(ai_shield::signatures::Rule{
        .rule_id = 2, .kind = ai_shield::signatures::RuleKind::payload_hash, .severity = 100, .hash = ai_shield::crypto::sha256(bytes)}));
    const auto evidence = detector.inspect(bytes);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::signature_match) != 0U);
    AI_SHIELD_CHECK(evidence.hard_rule == 100);
}

void test_flow_baseline_scores_deviation() {
    ai_shield::baseline::FlowBaseline baseline;
    AI_SHIELD_CHECK(baseline.learn(ai_shield::baseline::FlowSample{.service_id = 4, .bytes_in = 100, .bytes_out = 100, .segment_count = 4}).ok());
    AI_SHIELD_CHECK(baseline.learn(ai_shield::baseline::FlowSample{.service_id = 4, .bytes_in = 110, .bytes_out = 90, .segment_count = 4}).ok());
    AI_SHIELD_CHECK(baseline.learn(ai_shield::baseline::FlowSample{.service_id = 4, .bytes_in = 100, .bytes_out = 120, .segment_count = 5}).ok());
    const auto evidence = baseline.score(ai_shield::baseline::FlowSample{.service_id = 4, .bytes_in = 5000, .bytes_out = 1000, .segment_count = 40});
    AI_SHIELD_CHECK(evidence.novelty >= 80);
}

void test_sequence_model_novelty() {
    ai_shield::sequence::NGramModel model(2);
    const std::vector<std::uint32_t> known = {1, 2, 3, 4};
    AI_SHIELD_CHECK(model.learn(known).ok());
    const std::vector<std::uint32_t> novel = {1, 9, 9, 4};
    const auto evidence = model.score(novel);
    AI_SHIELD_CHECK(evidence.novelty >= 50);
}

void test_feature_extraction_and_http_canonicalizer() {
    const std::string request_a = "GET /A HTTP/1.1\r\nHost: Example\r\nUser-Agent: X\r\n\r\n";
    const std::string request_b = "get /a http/1.1\r\nuser-agent: x\r\nhost: example\r\n\r\n";
    std::vector<std::byte> bytes;
    for (const unsigned char ch : request_a) {
        bytes.push_back(static_cast<std::byte>(ch));
    }
    const auto network = ai_shield::features::extract_network(bytes);
    AI_SHIELD_CHECK(network.payload_bytes == request_a.size());
    AI_SHIELD_CHECK(network.printable_ratio_percent > 80U);
    const auto parsed = ai_shield::protocols::http1::parse_request(request_a);
    AI_SHIELD_CHECK(parsed.ok());
    const auto protocol = ai_shield::features::extract_http(parsed.value());
    AI_SHIELD_CHECK(protocol.header_count == 2);
    const auto canon_a = ai_shield::protocols::http1::canonicalize_request(request_a);
    const auto canon_b = ai_shield::protocols::http1::canonicalize_request(request_b);
    AI_SHIELD_CHECK(canon_a.ok());
    AI_SHIELD_CHECK(canon_b.ok());
    AI_SHIELD_CHECK(canon_a.value() == canon_b.value());
}

void test_mutation_detector_simhash() {
    const std::string a = "GET /api/item?id=100 HTTP/1.1\r\n\r\n";
    const std::string b = "GET /api/item?id=101 HTTP/1.1\r\n\r\n";
    std::vector<std::byte> aa;
    std::vector<std::byte> bb;
    for (const unsigned char ch : a) {
        aa.push_back(static_cast<std::byte>(ch));
    }
    for (const unsigned char ch : b) {
        bb.push_back(static_cast<std::byte>(ch));
    }
    const auto evidence = ai_shield::mutation::compare_payloads(aa, bb);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::adaptive_mutation) != 0U || evidence.novelty > 0U);
}

void test_isolation_forest_scores_short_paths() {
    ai_shield::isolation_forest::Forest forest;
    AI_SHIELD_CHECK(forest.add_tree(ai_shield::isolation_forest::Tree{.nodes = {
                               ai_shield::isolation_forest::Node{.feature_index = 0, .threshold = 10.0F, .left = 1, .right = 2, .leaf = false},
                               ai_shield::isolation_forest::Node{.leaf = true},
                               ai_shield::isolation_forest::Node{.leaf = true}}})
               .ok());
    const std::vector<float> features = {100.0F};
    const auto evidence = forest.score(features);
    AI_SHIELD_CHECK(evidence.novelty >= 55);
}

void test_shadow_catalog_and_sandbox_budget() {
    ai_shield::shadow::Catalog catalog;
    AI_SHIELD_CHECK(catalog.add(ai_shield::shadow::Target{
                           .service_id = 5,
                           .kind = ai_shield::shadow::TargetKind::download,
                           .tier = ai_shield::sandbox::Tier::appcontainer_fast,
                           .p99_budget_ns = 250'000'000ULL})
               .ok());
    const auto selected = catalog.select(5, 95);
    AI_SHIELD_CHECK(selected.ok());
    AI_SHIELD_CHECK(selected.value().tier == ai_shield::sandbox::Tier::hyperv_isolated);
    const auto budget = ai_shield::sandbox_budget::budget_for(selected.value().tier, 95);
    AI_SHIELD_CHECK(budget.memory_bytes >= 1536ULL * 1024ULL * 1024ULL);
    AI_SHIELD_CHECK(ai_shield::sandbox_budget::exceeded(budget, budget.wall_time_ns + 1U, 1U, 1U));
}

void test_service_certificate_pinning() {
    ai_shield::service_identity::PinStore pins;
    const auto cert = ai_shield::crypto::sha256("spki");
    AI_SHIELD_CHECK(pins.add(ai_shield::service_identity::CertificatePin{.service_id = 7, .spki_sha256 = cert}).ok());
    AI_SHIELD_CHECK(pins.verify(7, cert));
    AI_SHIELD_CHECK(!pins.verify(7, ai_shield::crypto::sha256("other-spki")));
}

void test_service_discovery_requires_confirmation() {
    ai_shield::service_registry::Registry registry;
    const auto proposed = ai_shield::service_discovery::propose(ai_shield::service_discovery::ObservedListener{
        .port_be = 0x3905U,
        .transport = ai_shield::service_registry::Transport::tcp,
        .protocol_id = 443,
        .externally_reachable = true});
    AI_SHIELD_CHECK(proposed.ok());
    const auto before = registry.admit(ai_shield::service_registry::Transport::tcp, 0x3905U);
    AI_SHIELD_CHECK(before.action == ai_shield::abi::ShieldAction::drop_flow);
    AI_SHIELD_CHECK(ai_shield::service_discovery::confirm(registry, proposed.value()).ok());
    const auto after = registry.admit(ai_shield::service_registry::Transport::tcp, 0x3905U);
    AI_SHIELD_CHECK(after.action == ai_shield::abi::ShieldAction::allow_monitored);
}

void test_policy_authorization_admin_and_local_confirmation() {
    AI_SHIELD_CHECK(ai_shield::policy_authorization::authorize(ai_shield::policy_authorization::PolicyChange{
               .actor_id = 10, .admin = false, .high_risk = false, .local_confirmation = false})
               .status() == ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(ai_shield::policy_authorization::authorize(ai_shield::policy_authorization::PolicyChange{
               .actor_id = 10, .admin = true, .high_risk = true, .local_confirmation = false})
               .status() == ai_shield::Status::invalid_state_transition);
    AI_SHIELD_CHECK(ai_shield::policy_authorization::authorize(ai_shield::policy_authorization::PolicyChange{
               .actor_id = 10, .admin = true, .high_risk = true, .local_confirmation = true})
               .ok());
}

void test_provenance_quarantine_and_execute_gate() {
    ai_shield::provenance::Store store;
    ai_shield::provenance::FileIdentity id{.volume_id = 11,
                                           .file_id = 12,
                                           .stream_id = 1,
                                           .content_hash = ai_shield::crypto::sha256("download-v1"),
                                           .provenance_id = 13};
    AI_SHIELD_CHECK(store.record_external(id).ok());
    const auto pending = store.execution_allowed(id);
    AI_SHIELD_CHECK(pending.ok() && !pending.value());
    AI_SHIELD_CHECK(store.approve(id).ok());
    const auto allowed = store.execution_allowed(id);
    AI_SHIELD_CHECK(allowed.ok() && allowed.value());
    id.content_hash = ai_shield::crypto::sha256("download-v2");
    const auto changed = store.execution_allowed(id);
    AI_SHIELD_CHECK(changed.ok() && !changed.value());
    AI_SHIELD_CHECK(store.quarantine(id, ai_shield::abi::ReasonCode::external_exec_pending).ok());
    const auto blocked = store.execution_allowed(id);
    AI_SHIELD_CHECK(blocked.ok() && !blocked.value());
}

void test_system_preflight_and_maintenance_mode() {
    const auto good = ai_shield::system_preflight::evaluate(ai_shield::system_preflight::SystemFacts{
        .supported_edition = true,
        .secure_boot = true,
        .tpm2 = true,
        .virtualization = true,
        .hvci_compatible = true,
        .enough_disk = true,
        .conflicting_driver = false});
    AI_SHIELD_CHECK(good.install_allowed);
    AI_SHIELD_CHECK(good.failure_count == 0U);
    const auto blocked = ai_shield::system_preflight::evaluate(ai_shield::system_preflight::SystemFacts{
        .supported_edition = true,
        .secure_boot = true,
        .tpm2 = true,
        .virtualization = true,
        .hvci_compatible = false,
        .enough_disk = true,
        .conflicting_driver = true});
    AI_SHIELD_CHECK(!blocked.install_allowed);
    AI_SHIELD_CHECK(blocked.failure_count == 2U);
    AI_SHIELD_CHECK(!ai_shield::maintenance::can_uninstall(ai_shield::maintenance::MaintenanceGuard{
        .maintenance_mode = false, .local_admin = true, .audit_delete_confirmed = true}));
    AI_SHIELD_CHECK(ai_shield::maintenance::can_uninstall(ai_shield::maintenance::MaintenanceGuard{
        .maintenance_mode = true, .local_admin = true, .audit_delete_confirmed = false}));
    AI_SHIELD_CHECK(ai_shield::maintenance::can_delete_audit(ai_shield::maintenance::MaintenanceGuard{
        .maintenance_mode = true, .local_admin = true, .audit_delete_confirmed = true}));
}

void test_learning_mode_limits_and_hard_rules() {
    const auto monitored = ai_shield::learning::apply(ai_shield::learning::LearningWindow{
        .enabled = true,
        .mode = ai_shield::learning::LearningMode::observation_only,
        .started_monotonic_ns = 10,
        .now_monotonic_ns = 20},
                                                      ai_shield::abi::ReasonCode::proto_ambiguous,
                                                      40);
    AI_SHIELD_CHECK(monitored.action == ai_shield::abi::ShieldAction::allow_monitored);
    AI_SHIELD_CHECK(monitored.hard_rules_remain_active);
    AI_SHIELD_CHECK(!monitored.expired);
    const auto hard = ai_shield::learning::apply(ai_shield::learning::LearningWindow{
        .enabled = true,
        .mode = ai_shield::learning::LearningMode::observation_only,
        .started_monotonic_ns = 10,
        .now_monotonic_ns = 20},
                                                 ai_shield::abi::ReasonCode::command_execution,
                                                 100);
    AI_SHIELD_CHECK(hard.action == ai_shield::abi::ShieldAction::quarantine);
    const auto expired = ai_shield::learning::apply(ai_shield::learning::LearningWindow{
        .enabled = true,
        .mode = ai_shield::learning::LearningMode::shadow_candidate_generation,
        .started_monotonic_ns = 0,
        .now_monotonic_ns = ai_shield::learning::kMaxLearningDurationNs + 1U},
                                                    0,
                                                    0);
    AI_SHIELD_CHECK(expired.expired);
}

void test_cloud_optin_transfer_gate() {
#if AI_SHIELD_ENABLE_CLOUD
    AI_SHIELD_CHECK(ai_shield::cloud::authorize_transfer(ai_shield::cloud::TransferRequest{
               .admin_opt_in = false, .contains_payload = false, .payload_export_enabled = false, .max_bytes = 100, .requested_bytes = 10})
               .status() == ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(ai_shield::cloud::authorize_transfer(ai_shield::cloud::TransferRequest{
               .admin_opt_in = true, .contains_payload = true, .payload_export_enabled = false, .max_bytes = 100, .requested_bytes = 10})
               .status() == ai_shield::Status::invalid_state_transition);
    AI_SHIELD_CHECK(ai_shield::cloud::authorize_transfer(ai_shield::cloud::TransferRequest{
               .admin_opt_in = true, .contains_payload = false, .payload_export_enabled = false, .max_bytes = 100, .requested_bytes = 200})
               .status() == ai_shield::Status::out_of_budget);
    AI_SHIELD_CHECK(ai_shield::cloud::authorize_transfer(ai_shield::cloud::TransferRequest{
               .admin_opt_in = true, .contains_payload = true, .payload_export_enabled = true, .max_bytes = 100, .requested_bytes = 10})
               .ok());
#else
    static_assert(AI_SHIELD_ENABLE_CLOUD == 0);
#endif
}

void test_recovery_plan_and_release_gate() {
    const auto critical = ai_shield::recovery::plan_for(ai_shield::recovery::Severity::critical);
    AI_SHIELD_CHECK(critical.flow_action == ai_shield::abi::ShieldAction::block_origin);
    AI_SHIELD_CHECK(critical.reduce_network_access);
    AI_SHIELD_CHECK(critical.lock_updates);
    AI_SHIELD_CHECK(critical.local_alarm);

    const auto pass = ai_shield::release_gate::evaluate(ai_shield::release_gate::Metrics{
        .soak_days = 30,
        .hardware_profiles = 10,
        .bugcheck_free = true,
        .deadlock_free = true,
        .known_attack_corpus_blocked = true,
        .benign_false_block_ppm = 99,
        .mutation_campaign_detection_percent = 95,
        .consequence_guard_complete = true,
        .throughput_percent = 90,
        .p99_fastpath_us = 250,
        .recovery_drill_passed = true});
    AI_SHIELD_CHECK(pass.release_allowed);
    const auto fail = ai_shield::release_gate::evaluate(ai_shield::release_gate::Metrics{
        .soak_days = 29,
        .hardware_profiles = 9,
        .bugcheck_free = false,
        .deadlock_free = true,
        .known_attack_corpus_blocked = true,
        .benign_false_block_ppm = 100,
        .mutation_campaign_detection_percent = 94,
        .consequence_guard_complete = true,
        .throughput_percent = 89,
        .p99_fastpath_us = 251,
        .recovery_drill_passed = false});
    AI_SHIELD_CHECK(!fail.release_allowed);
    AI_SHIELD_CHECK(fail.failed_checks == 8U);
}

void test_support_package_manifest_hashes_and_redaction() {
    ai_shield::incident::Package incident{.incident_id = 77,
                                          .timeline_hash = ai_shield::crypto::sha256("timeline"),
                                          .audit_export_hash = ai_shield::crypto::sha256("audit"),
                                          .aggregate_reason_mask = ai_shield::abi::ReasonCode::command_execution,
                                          .payload = ai_shield::privacy::SanitizedPayload{
                                              .reason_mask = ai_shield::abi::ReasonCode::privacy_redacted}};
    const auto manifest = ai_shield::support::build_manifest(
        88,
        ai_shield::diagnostics::Snapshot{.active_flows = 1,
                                         .pending_decisions = 2,
                                         .sandbox_capacity = 3,
                                         .worker_circuits_open = 4,
                                         .health = ai_shield::health::Degradation{
                                             .sensor_integrity_score = 70,
                                             .reason_mask = ai_shield::abi::ReasonCode::degraded_mode}},
        incident);
    AI_SHIELD_CHECK(manifest.package_id == 88U);
    AI_SHIELD_CHECK(manifest.payload_redacted);
    AI_SHIELD_CHECK((manifest.reason_mask & ai_shield::abi::ReasonCode::command_execution) != 0U);
    AI_SHIELD_CHECK((manifest.reason_mask & ai_shield::abi::ReasonCode::degraded_mode) != 0U);
    AI_SHIELD_CHECK(!ai_shield::crypto::constant_time_equal(manifest.diagnostics_hash, ai_shield::crypto::Sha256Digest{}));
    AI_SHIELD_CHECK(!ai_shield::crypto::constant_time_equal(manifest.incident_hash, ai_shield::crypto::Sha256Digest{}));
}

void test_broker_runtime_and_backpressure() {
    const auto low = ai_shield::broker::plan_workers(ai_shield::broker::HostCapacity{.logical_cores = 1, .reserved_cores = 0});
    AI_SHIELD_CHECK(low.worker_count == 2U);
    AI_SHIELD_CHECK(low.iocp_model);
    const auto capped = ai_shield::broker::plan_workers(ai_shield::broker::HostCapacity{.logical_cores = 32, .reserved_cores = 2});
    AI_SHIELD_CHECK(capped.worker_count == 16U);

    const auto allow = ai_shield::backpressure::decide(
        ai_shield::backpressure::Limits{.per_flow_bytes = 100, .per_source_flows = 3, .per_service_flows = 10, .global_flows = 20},
        ai_shield::backpressure::Usage{.flow_bytes = 90, .source_flows = 3, .service_flows = 9, .total_flows = 20});
    AI_SHIELD_CHECK(allow.action == ai_shield::abi::ShieldAction::allow);
    const auto limited = ai_shield::backpressure::decide(
        ai_shield::backpressure::Limits{.per_flow_bytes = 100, .per_source_flows = 3, .per_service_flows = 10, .global_flows = 20},
        ai_shield::backpressure::Usage{.flow_bytes = 101, .source_flows = 3, .service_flows = 9, .total_flows = 20});
    AI_SHIELD_CHECK(limited.action == ai_shield::abi::ShieldAction::rate_limit);
    AI_SHIELD_CHECK((limited.reason_mask & ai_shield::abi::ReasonCode::queue_overflow) != 0U);
}

void test_tls_managed_endpoint_requires_admin_cert_and_pin() {
    ai_shield::service_identity::PinStore pins;
    const auto spki = ai_shield::crypto::sha256("managed-cert");
    AI_SHIELD_CHECK(pins.add(ai_shield::service_identity::CertificatePin{.service_id = 40, .spki_sha256 = spki}).ok());
    const ai_shield::service_registry::ServicePolicy policy{.port_be = 0xBB01U,
                                                            .transport = ai_shield::service_registry::Transport::tcp,
                                                            .protocol_id = 443,
                                                            .externally_reachable = true,
                                                            .critical_service = true,
                                                            .fail_policy = ai_shield::service_registry::FailPolicy::fail_closed,
                                                            .max_payload_bytes = 65536};
    AI_SHIELD_CHECK(ai_shield::tls_service::authorize_managed_endpoint(ai_shield::tls_service::ManagedEndpoint{
               .service_id = 40, .policy = policy, .spki_sha256 = spki, .administrator_provided_certificate = true},
                                                              pins)
               .ok());
    AI_SHIELD_CHECK(ai_shield::tls_service::authorize_managed_endpoint(ai_shield::tls_service::ManagedEndpoint{
               .service_id = 40,
               .policy = policy,
               .spki_sha256 = ai_shield::crypto::sha256("other"),
               .administrator_provided_certificate = true},
                                                              pins)
               .status() == ai_shield::Status::integrity_failure);
}

void test_dataset_and_canary_governance() {
    AI_SHIELD_CHECK(ai_shield::dataset::accept_dataset(ai_shield::dataset::DatasetVersion{
               .version = 1,
               .source_fingerprint = ai_shield::crypto::sha256("dataset"),
               .privacy_filter_applied = true,
               .human_reviewed_edge_cases = true})
               .ok());
    AI_SHIELD_CHECK(ai_shield::dataset::accept_dataset(ai_shield::dataset::DatasetVersion{
               .version = 1,
               .source_fingerprint = ai_shield::crypto::sha256("dataset"),
               .privacy_filter_applied = false,
               .human_reviewed_edge_cases = true})
               .status() == ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(ai_shield::dataset::approve_canary_promotion(ai_shield::dataset::CanaryEvaluation{
               .production_model_version = 3,
               .canary_model_version = 4,
               .monitor_mode_only = true,
               .attack_detection_percent = 100,
               .false_block_ppm = 99,
               .rollback_available = true})
               .ok());
    AI_SHIELD_CHECK(ai_shield::dataset::approve_canary_promotion(ai_shield::dataset::CanaryEvaluation{
               .production_model_version = 4,
               .canary_model_version = 4,
               .monitor_mode_only = true,
               .attack_detection_percent = 100,
               .false_block_ppm = 99,
               .rollback_available = true})
               .status() == ai_shield::Status::downgrade_attempt);
}

void test_build_attestation_requires_repro_inputs() {
    const std::vector<ai_shield::build::ArtifactHash> artifacts = {
        ai_shield::build::ArtifactHash{.artifact_id = 1, .sha256 = ai_shield::crypto::sha256("core.exe")},
        ai_shield::build::ArtifactHash{.artifact_id = 2, .sha256 = ai_shield::crypto::sha256("driver.sys")}};
    const auto attestation = ai_shield::build::attest(
        ai_shield::build::BuildManifest{.build_id = 55,
                                        .compiler_manifest_hash = ai_shield::crypto::sha256("compiler"),
                                        .sdk_manifest_hash = ai_shield::crypto::sha256("sdk"),
                                        .sbom_hash = ai_shield::crypto::sha256("sbom"),
                                        .pdbs_archived = true,
                                        .reproducible_flags_enabled = true},
        artifacts);
    AI_SHIELD_CHECK(attestation.ok());
    AI_SHIELD_CHECK(!ai_shield::crypto::constant_time_equal(attestation.value(), ai_shield::crypto::Sha256Digest{}));
    AI_SHIELD_CHECK(ai_shield::build::attest(ai_shield::build::BuildManifest{
                                        .build_id = 55,
                                        .compiler_manifest_hash = ai_shield::crypto::sha256("compiler"),
                                        .sdk_manifest_hash = ai_shield::crypto::sha256("sdk"),
                                        .sbom_hash = ai_shield::crypto::sha256("sbom"),
                                        .pdbs_archived = false,
                                        .reproducible_flags_enabled = true},
                                    artifacts)
               .status() == ai_shield::Status::invalid_argument);
}

void test_http2_preflight_header_and_stream_limits() {
    std::vector<std::byte> frame(9U + 5U);
    frame[2] = std::byte{0x05};
    frame[3] = std::byte{0x01};
    frame[8] = std::byte{0x03};
    const auto parsed = ai_shield::protocols::http2::preflight(frame, 4, 1);
    AI_SHIELD_CHECK(parsed.ok());
    AI_SHIELD_CHECK(parsed.value().frame_count == 1U);
    AI_SHIELD_CHECK(parsed.value().header_budget_exceeded);
    AI_SHIELD_CHECK(parsed.value().stream_state_anomaly);
    const auto evidence = ai_shield::protocols::http2::evidence_from(parsed.value());
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::proto_ambiguous) != 0U);

    const std::vector<std::byte> broken = {std::byte{0x00}, std::byte{0x00}, std::byte{0x02}};
    const auto malformed = ai_shield::protocols::http2::preflight(broken, 4, 1);
    AI_SHIELD_CHECK(malformed.ok());
    AI_SHIELD_CHECK(malformed.value().malformed);
}

void test_egress_gate_allowlist_and_external_block() {
    const std::vector<ai_shield::egress::Rule> rules = {
        ai_shield::egress::Rule{.service_id = 7, .destination_ipv4_be = 0x0a000001U, .destination_port_be = 0x01BBU}};
    const auto allowed = ai_shield::egress::decide(ai_shield::egress::Request{
                                                       .service_id = 7,
                                                       .destination_ipv4_be = 0x0a000001U,
                                                       .destination_port_be = 0x01BBU,
                                                       .externally_influenced = true},
                                                   rules);
    AI_SHIELD_CHECK(allowed.action == ai_shield::abi::ShieldAction::allow);
    const auto blocked = ai_shield::egress::decide(ai_shield::egress::Request{
                                                       .service_id = 7,
                                                       .destination_ipv4_be = 0x08080808U,
                                                       .destination_port_be = 0x0035U,
                                                       .externally_influenced = true},
                                                   rules);
    AI_SHIELD_CHECK(blocked.action == ai_shield::abi::ShieldAction::drop_flow);
    AI_SHIELD_CHECK((blocked.reason_mask & ai_shield::abi::ReasonCode::consequence_detected) != 0U);
}

void test_consequence_detector_runtime_signals() {
    const auto none = ai_shield::consequence::evaluate(ai_shield::consequence::RuntimeEvent{});
    AI_SHIELD_CHECK(none.reason_mask == 0U);
    const auto evidence = ai_shield::consequence::evaluate(ai_shield::consequence::RuntimeEvent{
        .child_process = true,
        .executable_file_created = false,
        .executable_memory = true,
        .sensitive_token_access = true,
        .registry_persistence = true,
        .unexpected_egress = true});
    AI_SHIELD_CHECK(evidence.hard_rule == 100);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::consequence_detected) != 0U);
    AI_SHIELD_CHECK((evidence.reason_mask & ai_shield::abi::ReasonCode::command_execution) != 0U);
}

void test_fuzz_plan_and_compatibility_lab_gates() {
    const auto ready = ai_shield::fuzz_plan::assess(ai_shield::fuzz_plan::CorpusStatus{
        .has_seed_corpus = true,
        .has_roundtrip_invariants = true,
        .has_length_offset_invariants = true,
        .has_unicode_cases = true,
        .aggregate_test_cases = 1'000'000'000ULL,
        .cpu_days = 1});
    AI_SHIELD_CHECK(ready.accepted);
    const auto missing = ai_shield::fuzz_plan::assess(ai_shield::fuzz_plan::CorpusStatus{
        .has_seed_corpus = true,
        .has_roundtrip_invariants = false,
        .has_length_offset_invariants = true,
        .has_unicode_cases = false,
        .aggregate_test_cases = 1,
        .cpu_days = 1});
    AI_SHIELD_CHECK(!missing.accepted);
    AI_SHIELD_CHECK(missing.missing_checks == 3U);

    const auto lab = ai_shield::compat::evaluate(ai_shield::compat::LabResult{
        .hvci_enabled = true,
        .secure_boot_enabled = true,
        .verifier_72h_passed = true,
        .hlk_passed = true,
        .vpn_clients_passed = true,
        .hyperv_passed = true,
        .defender_passed = true,
        .hardware_profiles = 10});
    AI_SHIELD_CHECK(lab.accepted);
    const auto failed = ai_shield::compat::evaluate(ai_shield::compat::LabResult{
        .hvci_enabled = false,
        .secure_boot_enabled = true,
        .verifier_72h_passed = false,
        .hlk_passed = true,
        .vpn_clients_passed = false,
        .hyperv_passed = true,
        .defender_passed = true,
        .hardware_profiles = 9});
    AI_SHIELD_CHECK(!failed.accepted);
    AI_SHIELD_CHECK(failed.failed_checks == 4U);
}

void test_abi_validation_negative_cases() {
    ai_shield::abi::FlowEvent event{};
    event.abi_version = ai_shield::abi::kAbiVersion;
    event.structure_size = sizeof(ai_shield::abi::FlowEvent);
    event.sequence = 5;
    event.flow_id = 77;
    event.monotonic_ns = 1'000;
    AI_SHIELD_CHECK(ai_shield::abi_validation::validate_flow_event(
               event,
               ai_shield::abi_validation::ValidationContext{.expected_next_sequence = 5,
                                                            .now_monotonic_ns = 1'000,
                                                            .max_clock_skew_ns = 100,
                                                            .known_flow_id = 77})
               .ok());
    event.abi_version = 0;
    AI_SHIELD_CHECK(ai_shield::abi_validation::validate_flow_event(
               event,
               ai_shield::abi_validation::ValidationContext{.expected_next_sequence = 5,
                                                            .now_monotonic_ns = 1'000,
                                                            .max_clock_skew_ns = 100,
                                                            .known_flow_id = 77})
               .status() == ai_shield::Status::incompatible_version);
    event.abi_version = ai_shield::abi::kAbiVersion;
    event.flags = 0x8000U;
    AI_SHIELD_CHECK(ai_shield::abi_validation::validate_flow_event(
               event,
               ai_shield::abi_validation::ValidationContext{.expected_next_sequence = 5,
                                                            .now_monotonic_ns = 1'000,
                                                            .max_clock_skew_ns = 100,
                                                            .known_flow_id = 77})
               .status() == ai_shield::Status::malformed_input);
}

void test_audit_checkpoint_external_anchor() {
    ai_shield::audit::AuditChain chain;
    AI_SHIELD_CHECK(chain.append(ai_shield::audit::AuditRecord{
               .sequence = 1,
               .monotonic_ns = 10,
               .reason_mask = ai_shield::abi::ReasonCode::proto_malformed,
               .evidence_hash = ai_shield::crypto::sha256("anchored")})
               .ok());
    const auto checkpoint = chain.checkpoint(ai_shield::crypto::sha256("checkpoint-signer"));
    AI_SHIELD_CHECK(checkpoint.ok());
    AI_SHIELD_CHECK(chain.verify_checkpoint(checkpoint.value()).ok());
    auto tampered = checkpoint.value();
    tampered.sequence = 2;
    AI_SHIELD_CHECK(chain.verify_checkpoint(tampered).status() == ai_shield::Status::integrity_failure);
}

void test_provenance_copy_and_rename_chains() {
    ai_shield::provenance::Store store;
    const ai_shield::provenance::FileIdentity downloaded{.volume_id = 1,
                                                         .file_id = 2,
                                                         .stream_id = 1,
                                                         .content_hash = ai_shield::crypto::sha256("download"),
                                                         .provenance_id = 100,
                                                         .creation_sequence = 1,
                                                         .parent_provenance_id = 0};
    const ai_shield::provenance::FileIdentity copied{.volume_id = 1,
                                                     .file_id = 3,
                                                     .stream_id = 1,
                                                     .content_hash = ai_shield::crypto::sha256("download"),
                                                     .provenance_id = 101,
                                                     .creation_sequence = 2,
                                                     .parent_provenance_id = 0};
    const ai_shield::provenance::FileIdentity renamed{.volume_id = 1,
                                                      .file_id = 4,
                                                      .stream_id = 1,
                                                      .content_hash = ai_shield::crypto::sha256("download"),
                                                      .provenance_id = 102,
                                                      .creation_sequence = 3,
                                                      .parent_provenance_id = 0};
    AI_SHIELD_CHECK(store.record_external(downloaded).ok());
    AI_SHIELD_CHECK(store.propagate_copy(downloaded, copied).ok());
    const auto copy_verdict = store.lookup(copied);
    AI_SHIELD_CHECK(copy_verdict.ok());
    AI_SHIELD_CHECK(copy_verdict.value().identity.parent_provenance_id == downloaded.provenance_id);
    AI_SHIELD_CHECK(store.propagate_rename(copied, renamed).ok());
    AI_SHIELD_CHECK(store.lookup(copied).status() == ai_shield::Status::not_found);
    const auto renamed_verdict = store.lookup(renamed);
    AI_SHIELD_CHECK(renamed_verdict.ok());
    AI_SHIELD_CHECK(renamed_verdict.value().disposition == ai_shield::provenance::FileDisposition::execution_pending);
}

void test_pending_decision_limits_and_late_completion() {
    ai_shield::pending::Manager manager(ai_shield::pending::Manager::Limits{
        .max_pending = 1, .max_budget_ns = 100, .max_service_budget_ns = 100, .max_reserved_bytes = 64});
    AI_SHIELD_CHECK(manager.pend_for_service(1, 7, 1'000, 50, 32).ok());
    AI_SHIELD_CHECK(manager.pend_for_service(2, 7, 1'000, 50, 32).status() == ai_shield::Status::out_of_budget);
    AI_SHIELD_CHECK(manager.complete_at(1, ai_shield::abi::ShieldAction::allow, 1'049).ok());
    AI_SHIELD_CHECK(manager.pend_for_service(3, 7, 1'000, 50, 32).ok());
    AI_SHIELD_CHECK(manager.complete_at(3, ai_shield::abi::ShieldAction::allow, 1'050).status() ==
           ai_shield::Status::invalid_state_transition);
}

void test_replay_path_is_deterministic_and_bounded() {
    const std::string request = "GET /../../secret HTTP/1.1\r\nHost: local\r\n\r\n";
    std::vector<std::byte> payload;
    for (const unsigned char ch : request) {
        payload.push_back(static_cast<std::byte>(ch));
    }
    const auto first = ai_shield::replay::execute(ai_shield::replay::Scenario{
        .flow_id = 44, .service_id = 9, .policy_version = 3, .critical_service = true, .payload = payload,
        .correlation = {.file_id = 55, .volume_id = 66, .provenance_id = 77, .process_id = 88,
                        .parent_process_id = 87, .model_version = 4}});
    const auto second = ai_shield::replay::execute(ai_shield::replay::Scenario{
        .flow_id = 44, .service_id = 9, .policy_version = 3, .critical_service = true, .payload = payload});
    AI_SHIELD_CHECK(first.ok());
    AI_SHIELD_CHECK(second.ok());
    AI_SHIELD_CHECK(first.value().decision.action == second.value().decision.action);
    AI_SHIELD_CHECK(first.value().decision.reason_mask == second.value().decision.reason_mask);
    AI_SHIELD_CHECK(ai_shield::crypto::constant_time_equal(first.value().audit_root, second.value().audit_root));
    AI_SHIELD_CHECK(first.value().audit_records == 1U);
    AI_SHIELD_CHECK(first.value().causal_nodes == 2U);
    AI_SHIELD_CHECK(first.value().causal_edges == 1U);
    AI_SHIELD_CHECK(first.value().policy_version == 3U);
    AI_SHIELD_CHECK(first.value().correlation.file_id == 55U);
    AI_SHIELD_CHECK(first.value().correlation.process_id == 88U);
    AI_SHIELD_CHECK(first.value().correlation.model_version == 4U);
}

void test_abi2_hmac_and_validation() {
    const auto key = ai_shield::crypto::sha256("abi2-channel-key");
    ai_shield::abi2::SensorEvent event{};
    event.header.sequence = 7;
    event.header.monotonic_ns = 1'000;
    event.header.flow_id = 11;
    event.header.object_id = 12;
    event.header.policy_version = 5;
    event.sensor = 1;
    event.kind = 3;
    event.process_id = 44;
    event.evidence_hash = ai_shield::crypto::sha256("abi2-evidence");
    ai_shield::abi2::seal(event, key);
    AI_SHIELD_CHECK(ai_shield::abi2::validate(event, ai_shield::abi2::ValidationContext{
        .expected_sequence = 7, .now_monotonic_ns = 1'000, .maximum_clock_skew_ns = 10, .channel_key = key}).ok());
    event.process_id++;
    AI_SHIELD_CHECK(ai_shield::abi2::validate(event, ai_shield::abi2::ValidationContext{
        .expected_sequence = 7, .now_monotonic_ns = 1'000, .maximum_clock_skew_ns = 10, .channel_key = key}).status() ==
                    ai_shield::Status::integrity_failure);
}

void append_u32_le(std::vector<std::byte>& bytes, std::uint32_t value) {
    for (std::size_t i = 0; i < 4U; ++i) {
        bytes.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xffU));
    }
}

void append_u64_le(std::vector<std::byte>& bytes, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        bytes.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xffU));
    }
}

void append_replay_event(std::vector<std::byte>& bytes,
                         ai_shield::replay::EventKind kind,
                         const std::vector<std::byte>& body) {
    append_u32_le(bytes, static_cast<std::uint32_t>(kind));
    append_u32_le(bytes, static_cast<std::uint32_t>(body.size()));
    bytes.insert(bytes.end(), body.begin(), body.end());
}

std::vector<std::byte> replay_body_u64(std::span<const std::uint64_t> values) {
    std::vector<std::byte> body;
    for (const auto value : values) {
        append_u64_le(body, value);
    }
    return body;
}

void test_replay_event_stream_covers_plan_events() {
    std::vector<std::byte> scenario;
    for (const char ch : std::string_view{"AISHRP02"}) {
        scenario.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    append_u64_le(scenario, 9);
    append_u64_le(scenario, 8);

    const std::uint64_t flow_open_values[] = {101, 77, 1, 1'000};
    append_replay_event(scenario, ai_shield::replay::EventKind::flow_open, replay_body_u64(flow_open_values));

    const std::uint64_t identity_values[] = {77, 1};
    append_replay_event(scenario, ai_shield::replay::EventKind::service_identity, replay_body_u64(identity_values));

    std::vector<std::byte> protocol;
    append_u32_le(protocol, static_cast<std::uint32_t>(ai_shield::replay::ProtocolHint::http1));
    append_replay_event(scenario, ai_shield::replay::EventKind::protocol_hint, protocol);

    const std::string request = "GET /safe HTTP/1.1\r\nHost: local\r\n\r\n";
    std::vector<std::byte> data;
    for (const unsigned char ch : request) {
        data.push_back(static_cast<std::byte>(ch));
    }
    append_replay_event(scenario, ai_shield::replay::EventKind::flow_data, data);

    const std::uint64_t process_a[] = {10, 11, 1};
    std::vector<std::byte> process_body = replay_body_u64(process_a);
    append_u32_le(process_body, static_cast<std::uint32_t>(ai_shield::process_consequence::SignatureState::trusted_signed));
    append_u32_le(process_body, 0);
    append_u64_le(process_body, 1);
    append_replay_event(scenario, ai_shield::replay::EventKind::process_evidence, process_body);

    const std::uint64_t file_values[] = {1};
    append_replay_event(scenario, ai_shield::replay::EventKind::file_evidence, replay_body_u64(file_values));

    const std::uint64_t correlation_values[] = {201, 202, 203, 204, 205, 206, 9, 3, 101};
    append_replay_event(scenario, ai_shield::replay::EventKind::correlation_context,
                        replay_body_u64(correlation_values));
    const std::uint64_t close_values[] = {2'000};
    append_replay_event(scenario, ai_shield::replay::EventKind::flow_close, replay_body_u64(close_values));

    const auto result = ai_shield::replay::parse_and_execute(scenario);
    AI_SHIELD_CHECK(result.ok());
    AI_SHIELD_CHECK(result.value().policy_version == 9U);
    AI_SHIELD_CHECK(result.value().audit_verifiable);
    AI_SHIELD_CHECK(result.value().causal_graph_complete);
    AI_SHIELD_CHECK(result.value().audit_records == 1U);
    AI_SHIELD_CHECK(result.value().causal_nodes == 2U);
    AI_SHIELD_CHECK(result.value().correlation.file_id == 202U);
    AI_SHIELD_CHECK(result.value().correlation.provenance_id == 204U);
    AI_SHIELD_CHECK(result.value().correlation.model_version == 3U);
    AI_SHIELD_CHECK((result.value().decision.reason_mask & ai_shield::abi::ReasonCode::command_execution) != 0U);
    AI_SHIELD_CHECK((result.value().decision.reason_mask & ai_shield::abi::ReasonCode::external_exec_pending) != 0U);
}

void test_ipv6_quic_and_siem_metadata() {
    std::array<std::byte, 52> packet{};
    packet[0] = std::byte{0x60};
    packet[5] = std::byte{12};
    packet[6] = std::byte{44};
    packet[40] = std::byte{58};
    packet[43] = std::byte{1};
    packet[47] = std::byte{7};
    packet[48] = std::byte{128};
    const auto ipv6 = ai_shield::ipv6_security::inspect_ipv6(packet);
    AI_SHIELD_CHECK(ipv6.ok());
    AI_SHIELD_CHECK(ipv6.value().terminal_protocol == 58U);
    AI_SHIELD_CHECK(ipv6.value().more_fragments);
    AI_SHIELD_CHECK(ipv6.value().icmpv6_type == 128U);

    const std::array<std::byte, 9> quic{std::byte{0xc0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{1}, std::byte{1}, std::byte{0xaa}, std::byte{0}, std::byte{0}};
    const auto metadata = ai_shield::ipv6_security::inspect_quic(quic);
    AI_SHIELD_CHECK(metadata.ok());
    AI_SHIELD_CHECK(metadata.value().version == 1U);
    AI_SHIELD_CHECK(metadata.value().destination_connection_id_length == 1U);

    const ai_shield::siem::Event event{.monotonic_ns = 5, .reason_mask = 7, .risk_score = 200,
        .action = "block", .correlation = {.flow_id = 9, .file_id = 10, .process_id = 11,
                                            .policy_version = 12, .model_version = 13}};
    AI_SHIELD_CHECK(ai_shield::siem::format(event, ai_shield::siem::Format::cef).starts_with("CEF:0|AI Shield"));
    AI_SHIELD_CHECK(ai_shield::siem::format(event, ai_shield::siem::Format::leef).starts_with("LEEF:2.0|"));
    AI_SHIELD_CHECK(ai_shield::siem::format(event, ai_shield::siem::Format::json_lines).find("\"flow_id\":9") !=
                    std::string::npos);
}

void test_ransomware_detector_requires_correlated_behavior() {
    ai_shield::ransomware::Detector detector{};
    ai_shield::ransomware::Verdict verdict{};
    for (std::uint64_t index = 1; index <= 96; ++index) {
        verdict = detector.observe({.process_id = 42, .parent_process_id = 7, .object_id = index,
            .monotonic_ns = index * 10'000'000ULL, .kind = ai_shield::ransomware::MutationKind::write});
    }
    AI_SHIELD_CHECK(verdict.severity == ai_shield::ransomware::Severity::suspicious);
    AI_SHIELD_CHECK(!verdict.contain_process_tree);
    AI_SHIELD_CHECK((verdict.reason_mask & ai_shield::ransomware::Reason::write_burst) != 0U);
    AI_SHIELD_CHECK((verdict.reason_mask & ai_shield::ransomware::Reason::broad_target_set) != 0U);
    for (std::uint64_t index = 97; index <= 120; ++index) {
        verdict = detector.observe({.process_id = 42, .parent_process_id = 7, .object_id = index,
            .monotonic_ns = index * 10'000'000ULL, .kind = ai_shield::ransomware::MutationKind::rename});
    }
    AI_SHIELD_CHECK(verdict.severity == ai_shield::ransomware::Severity::confirmed);
    AI_SHIELD_CHECK(verdict.contain_process_tree);
    AI_SHIELD_CHECK((verdict.reason_mask & ai_shield::ransomware::Reason::destructive_burst) != 0U);

    detector.reset(42);
    verdict = detector.observe({.process_id = 42, .object_id = 500, .monotonic_ns = 2'000'000'000ULL,
        .kind = ai_shield::ransomware::MutationKind::canary});
    AI_SHIELD_CHECK(verdict.score >= 90U);
    AI_SHIELD_CHECK(verdict.contain_process_tree);
}

void test_recovery_vault_builds_cutoff_restore_plan() {
    ai_shield::recovery_vault::Catalog catalog{1024};
    const auto first_hash = ai_shield::crypto::sha256("first");
    const auto second_hash = ai_shield::crypto::sha256("second");
    AI_SHIELD_CHECK(catalog.add({.snapshot_id = 1, .captured_ns = 100, .bytes = 100,
        .path = "C:/Users/test/Documents/a.txt", .content_hash = first_hash}).ok());
    AI_SHIELD_CHECK(catalog.add({.snapshot_id = 2, .captured_ns = 200, .bytes = 120,
        .path = "C:/Users/test/Documents/a.txt", .content_hash = second_hash}).ok());
    AI_SHIELD_CHECK(catalog.add({.snapshot_id = 2, .captured_ns = 200, .bytes = 80,
        .path = "C:/Users/test/Documents/b.txt", .content_hash = first_hash}).ok());
    const std::array<std::string, 3> paths{
        "C:/Users/test/Documents/a.txt", "C:/Users/test/Documents/b.txt", "C:/Users/test/Documents/missing.txt"};
    const auto plan = catalog.plan(paths, 150);
    AI_SHIELD_CHECK(plan.versions.size() == 1U);
    AI_SHIELD_CHECK(plan.versions[0].snapshot_id == 1U);
    AI_SHIELD_CHECK(plan.total_bytes == 100U);
    AI_SHIELD_CHECK(plan.missing_paths.size() == 2U);
    AI_SHIELD_CHECK(!catalog.add({.snapshot_id = 3, .captured_ns = 300, .bytes = 900,
        .path = "C:/Users/test/Documents/large.bin", .content_hash = second_hash}).ok());
}

}  // namespace

int main() {
    test_abi();
    test_checked();
    test_flow_state();
    test_http_policy();
    test_audit_chain();
    test_audit_export_roundtrip_and_tamper();
    test_provenance();
    test_bounded_ring();
    test_health_degradation();
    test_service_registry_default_deny();
    test_dns_compression_loop_risk();
    test_json_depth_budget();
    test_sandbox_inconclusive_policy();
    test_process_guard_blocks_forbidden_child();
    test_package_manifest_trust_gate();
    test_zip_preflight_path_escape_and_bomb();
    test_pe_preflight_marks_executable_pending();
    test_archive_provenance_propagation();
    test_update_manager_rolls_back_failed_boot();
    test_tlsmeta_detects_downgrade();
    test_xml_external_entity_risk();
    test_pdf_active_content();
    test_campaign_adaptive_correlation();
    test_flow_control_rate_and_redirect_limits();
    test_worker_supervisor_crash_isolation();
    test_privacy_payload_sanitization();
    test_model_registry_blocks_online_learning();
    test_policy_store_transaction_and_rollback();
    test_incident_package_redacts_payload_and_hashes_timeline();
    test_ipc_flow_event_validation();
    test_pending_decision_timeout();
    test_platform_uri_normalization();
    test_retention_policy();
    test_response_normalizer_does_not_leak_scores();
    test_risk_bands_and_policy_actions();
    test_fail_policy_matrix();
    test_health_aggregation_and_diagnostics();
    test_causal_chain_flow_file_process();
    test_signature_detector_hash_and_substring();
    test_flow_baseline_scores_deviation();
    test_sequence_model_novelty();
    test_feature_extraction_and_http_canonicalizer();
    test_mutation_detector_simhash();
    test_isolation_forest_scores_short_paths();
    test_shadow_catalog_and_sandbox_budget();
    test_service_certificate_pinning();
    test_service_discovery_requires_confirmation();
    test_policy_authorization_admin_and_local_confirmation();
    test_provenance_quarantine_and_execute_gate();
    test_system_preflight_and_maintenance_mode();
    test_learning_mode_limits_and_hard_rules();
    test_cloud_optin_transfer_gate();
    test_recovery_plan_and_release_gate();
    test_support_package_manifest_hashes_and_redaction();
    test_broker_runtime_and_backpressure();
    test_tls_managed_endpoint_requires_admin_cert_and_pin();
    test_dataset_and_canary_governance();
    test_build_attestation_requires_repro_inputs();
    test_http2_preflight_header_and_stream_limits();
    test_egress_gate_allowlist_and_external_block();
    test_consequence_detector_runtime_signals();
    test_fuzz_plan_and_compatibility_lab_gates();
    test_abi_validation_negative_cases();
    test_audit_checkpoint_external_anchor();
    test_abi2_hmac_and_validation();
    test_provenance_copy_and_rename_chains();
    test_pending_decision_limits_and_late_completion();
    test_replay_path_is_deterministic_and_bounded();
    test_replay_event_stream_covers_plan_events();
    test_ipv6_quic_and_siem_metadata();
    test_ransomware_detector_requires_correlated_behavior();
    test_recovery_vault_builds_cutoff_restore_plan();
    std::cout << "ai_shield_unit_tests passed\n";
    return 0;
}
