#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>

#include "ai_shield/enterprise_command.hpp"
#include "ai_shield/enterprise_policy.hpp"
#include "ai_shield/enterprise_rbac.hpp"
#include "ai_shield/enterprise_trust.hpp"
#include "ai_shield/fleet_telemetry.hpp"
#include "ai_shield/sha256.hpp"

namespace {

void check(bool condition, std::string_view expression, const char* file, int line) {
    if (!condition) {
        std::cerr << "check failed: " << expression << " at " << file << ":" << line << "\n";
        std::exit(1);
    }
}

#define AI_SHIELD_CHECK(expr) check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

void test_identity_enrollment_rotation_and_clone_detection() {
    using namespace ai_shield::enterprise::trust;
    const auto hardware = ai_shield::crypto::sha256("hardware-a");
    const auto key_a = ai_shield::crypto::sha256("key-a");
    const auto key_b = ai_shield::crypto::sha256("key-b");
    DeviceRegistry registry;
    DeviceIdentity identity{.organization_id = 10, .site_id = 20, .device_id = 30,
        .certificate_serial = 40, .certificate_not_before_ns = 100, .certificate_not_after_ns = 1'000,
        .enrollment_epoch = 1, .hardware_binding = hardware, .public_key_spki = key_a,
        .state = IdentityState::pending, .tpm_bound = true};
    const AttestationEvidence evidence{.hardware_binding = hardware, .public_key_spki = key_a,
        .secure_boot = true, .measured_boot = true, .key_attested = true};
    AI_SHIELD_CHECK(registry.enroll(identity, evidence, 200, true).ok());
    AI_SHIELD_CHECK(registry.authorize(30, 40, hardware, 300).ok());
    AI_SHIELD_CHECK(registry.rotate(30, 40, 41, key_b, 250, 2'000).ok());
    AI_SHIELD_CHECK(registry.authorize(30, 40, hardware, 300).status() ==
                    ai_shield::Status::integrity_failure);

    identity.hardware_binding = ai_shield::crypto::sha256("cloned-hardware");
    identity.certificate_serial = 42;
    identity.public_key_spki = ai_shield::crypto::sha256("key-c");
    const AttestationEvidence clone{.hardware_binding = identity.hardware_binding,
        .public_key_spki = identity.public_key_spki, .secure_boot = true,
        .measured_boot = true, .key_attested = true};
    AI_SHIELD_CHECK(registry.enroll(identity, clone, 300, true).status() ==
                    ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(registry.revoke(30).ok());
    AI_SHIELD_CHECK(registry.authorize(30, 41, hardware, 400).status() ==
                    ai_shield::Status::integrity_failure);
}

void test_policy_antirollback_rollout_and_break_glass() {
    using namespace ai_shield::enterprise;
    const auto signer = ai_shield::crypto::sha256("enterprise-policy-root");
    policy::Envelope envelope{.organization_id = 10, .site_id = 20, .policy_version = 8,
        .security_version = 5, .parent_policy_version = 7, .issued_at_ns = 100,
        .expires_at_ns = 1'000, .minimum_agent_version = 200, .scope = policy::Scope::site,
        .ring = policy::Ring::pilot, .rollout_percent = 25,
        .rules_hash = ai_shield::crypto::sha256("rules"),
        .parent_hash = ai_shield::crypto::sha256("parent"), .signer_fingerprint = signer};
    envelope.envelope_hash = policy::content_hash(envelope);
    const policy::VerificationContext context{.now_ns = 200, .agent_version = 201,
        .active_policy_version = 7, .active_security_version = 5, .trusted_signer = signer,
        .signature_valid = true};
    AI_SHIELD_CHECK(policy::validate(envelope, context, {}).ok());
    auto downgrade = context;
    downgrade.active_policy_version = 8;
    AI_SHIELD_CHECK(policy::validate(envelope, downgrade, {}).status() ==
                    ai_shield::Status::downgrade_attempt);
    AI_SHIELD_CHECK(!policy::selected_for_rollout(envelope, 0));

    envelope.break_glass = true;
    envelope.expires_at_ns = 500;
    envelope.envelope_hash = policy::content_hash(envelope);
    const std::array approvals{
        rbac::Approval{.actor_id = 1, .role = rbac::Role::policy_approver, .approved_at_ns = 150},
        rbac::Approval{.actor_id = 2, .role = rbac::Role::policy_approver, .approved_at_ns = 160}};
    AI_SHIELD_CHECK(policy::validate(envelope, context, approvals).ok());
    const std::array duplicate{
        approvals[0],
        rbac::Approval{.actor_id = 1, .role = rbac::Role::policy_approver, .approved_at_ns = 170}};
    AI_SHIELD_CHECK(policy::validate(envelope, context, duplicate).status() ==
                    ai_shield::Status::integrity_failure);
}

void test_commands_are_typed_bounded_and_replay_safe() {
    using namespace ai_shield::enterprise;
    const auto signer = ai_shield::crypto::sha256("response-root");
    command::Envelope envelope{.command_id = 1, .organization_id = 10, .device_id = 20,
        .actor_id = 30, .issued_at_ns = 100, .expires_at_ns = 500, .nonce = 999,
        .target_id = 20, .action = command::Action::isolate_network,
        .target_kind = command::TargetKind::device, .signer_fingerprint = signer};
    envelope.content_hash = command::hash(envelope);
    const command::VerificationContext context{
        .now_ns = 200, .trusted_signer = signer, .signature_valid = true};
    const rbac::Principal responder{.actor_id = 30, .role = rbac::Role::responder};
    AI_SHIELD_CHECK(command::validate(envelope, context, responder, {}).ok());

    envelope.action = command::Action::terminate_process;
    envelope.target_kind = command::TargetKind::process;
    envelope.target_id = 123;
    envelope.content_hash = command::hash(envelope);
    AI_SHIELD_CHECK(command::validate(envelope, context, responder, {}).status() ==
                    ai_shield::Status::integrity_failure);
    const std::array approvals{
        rbac::Approval{.actor_id = 40, .role = rbac::Role::policy_approver, .approved_at_ns = 150},
        rbac::Approval{.actor_id = 41, .role = rbac::Role::recovery_operator, .approved_at_ns = 160}};
    AI_SHIELD_CHECK(command::validate(envelope, context, responder, approvals).ok());

    command::ReplayGuard replay{2};
    AI_SHIELD_CHECK(replay.accept(1, 999).ok());
    AI_SHIELD_CHECK(replay.accept(1, 1'000).status() == ai_shield::Status::integrity_failure);
    AI_SHIELD_CHECK(replay.accept(2, 999).status() == ai_shield::Status::integrity_failure);
}

void test_fleet_batches_detect_gaps_tampering_and_preserve_critical_events() {
    using namespace ai_shield::enterprise::fleet;
    const auto signer = ai_shield::crypto::sha256("device-cert");
    Batch batch{.organization_id = 1, .device_id = 2, .boot_id = 3, .batch_sequence = 1,
        .first_event_sequence = 1, .last_event_sequence = 4, .policy_version = 5,
        .model_version = 6, .agent_version = 200, .created_at_ns = 100,
        .priority = Priority::security, .payload_hash = ai_shield::crypto::sha256("events"),
        .signer_fingerprint = signer};
    batch.batch_hash = hash(batch);
    const VerificationContext context{.expected_device_id = 2, .expected_boot_id = 3,
        .expected_batch_sequence = 1, .expected_event_sequence = 1, .trusted_signer = signer,
        .signature_valid = true};
    AI_SHIELD_CHECK(validate(batch, context).ok());
    auto tampered = batch;
    tampered.last_event_sequence = 5;
    AI_SHIELD_CHECK(validate(tampered, context).status() == ai_shield::Status::integrity_failure);

    StoreForwardQueue queue{2};
    AI_SHIELD_CHECK(queue.push(batch).ok());
    auto diagnostic = batch;
    diagnostic.batch_sequence = 2;
    diagnostic.priority = Priority::diagnostic;
    AI_SHIELD_CHECK(queue.push(diagnostic).ok());
    auto critical = batch;
    critical.batch_sequence = 3;
    critical.priority = Priority::critical;
    AI_SHIELD_CHECK(queue.push(critical).ok());
    AI_SHIELD_CHECK(queue.dropped() == 1U);
    AI_SHIELD_CHECK(queue.pending().size() == 2U);
    AI_SHIELD_CHECK(queue.acknowledge(1).ok());
}

}  // namespace

int main() {
    test_identity_enrollment_rotation_and_clone_detection();
    test_policy_antirollback_rollout_and_break_glass();
    test_commands_are_typed_bounded_and_replay_safe();
    test_fleet_batches_detect_gaps_tampering_and_preserve_critical_events();
    std::cout << "ai_shield_enterprise_tests passed\n";
    return 0;
}
