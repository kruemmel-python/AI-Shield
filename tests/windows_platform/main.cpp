#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

#include "ai_shield/abi.hpp"
#include "ai_shield/provenance.hpp"
#include "ai_shield/sandbox.hpp"
#include "ai_shield/sandbox_budget.hpp"
#include "ai_shield/service_registry.hpp"
#include "ai_shield/sha256.hpp"
#include "platform/windows/common/abi_translation.hpp"
#include "platform/windows/minifilter/provenance_adapter.hpp"
#include "platform/windows/sandbox/appcontainer_launcher.hpp"
#include "platform/windows/sandbox/parser_pool.hpp"
#include "platform/windows/security/tpm_trust_anchor.hpp"
#include "platform/windows/sensors/etw_amsi_adapter.hpp"
#include "platform/windows/service/driver_channel.hpp"
#include "platform/windows/security/secure_runtime_state.hpp"
#include "platform/windows/wfp/adapter/wfp_enforcement.hpp"
#include "platform/windows/wfp/adapter/wfp_telemetry.hpp"

namespace {

void check(bool condition, std::string_view expression, const char* file, int line) {
    if (!condition) {
        std::cerr << "check failed: " << expression << " at " << file << ":" << line << "\n";
        std::exit(1);
    }
}

#define AI_SHIELD_WIN_CHECK(expr) check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

void test_wfp_telemetry_translation() {
    ai_shield::platform::windows::WinFlowObservation observation{
        .sequence = 1,
        .flow_id = 10,
        .monotonic_ns = 100,
        .local_ipv4_be = 0x0a000002U,
        .remote_ipv4_be = 0x0a000001U,
        .local_port_be = 0x1f90U,
        .remote_port_be = 0xd204U,
        .transport = ai_shield::platform::windows::WinTransport::tcp,
        .flags = 0,
        .payload_hash = ai_shield::crypto::sha256("telemetry")};
    const auto inbound = ai_shield::platform::windows::wfp::translate_telemetry(
        ai_shield::platform::windows::wfp::TelemetryEvent{
            .layer = ai_shield::platform::windows::wfp::LayerEvent::ale_auth_recv_accept,
            .observation = observation,
            .inbound = true});
    AI_SHIELD_WIN_CHECK(inbound.ok());
    AI_SHIELD_WIN_CHECK(inbound.value().source_ipv4_be == 0x0a000001U);
    AI_SHIELD_WIN_CHECK(inbound.value().target_port_be == 0x1f90U);

    const auto outbound = ai_shield::platform::windows::wfp::translate_telemetry(
        ai_shield::platform::windows::wfp::TelemetryEvent{
            .layer = ai_shield::platform::windows::wfp::LayerEvent::ale_auth_connect,
            .observation = observation,
            .inbound = false});
    AI_SHIELD_WIN_CHECK(outbound.ok());
    AI_SHIELD_WIN_CHECK(outbound.value().source_ipv4_be == 0x0a000002U);
    AI_SHIELD_WIN_CHECK(outbound.value().target_ipv4_be == 0x0a000001U);
}

void test_driver_channel_sequence_validation() {
    ai_shield::platform::windows::service::DriverChannelState state{.next_sequence = 1, .now_monotonic_ns = 100};
    ai_shield::abi::FlowEvent event{};
    event.abi_version = ai_shield::abi::kAbiVersion;
    event.structure_size = sizeof(ai_shield::abi::FlowEvent);
    event.sequence = 1;
    event.flow_id = 50;
    event.monotonic_ns = 100;
    AI_SHIELD_WIN_CHECK(ai_shield::platform::windows::service::accept_flow_event(state, event).ok());
    AI_SHIELD_WIN_CHECK(state.next_sequence == 2U);
    AI_SHIELD_WIN_CHECK(ai_shield::platform::windows::service::accept_flow_event(state, event).status() ==
                        ai_shield::Status::integrity_failure);
}

void test_driver_event_to_abi2_translation() {
    ai_shield::platform::windows::DriverEventObservation source{
        .version = 0x00010002U, .size = 72U, .sensor = 3U, .kind = 9U, .sequence = 9U,
        .timestamp_100ns = 50U, .process_id = 42U, .subject_id = 88U};
    const auto key = ai_shield::crypto::sha256("windows-abi2-key");
    const auto translated = ai_shield::platform::windows::to_sensor_event_v2(source, 5, 3, key);
    AI_SHIELD_WIN_CHECK(translated.ok());
    AI_SHIELD_WIN_CHECK(translated.value().header.policy_version == 5U);
    AI_SHIELD_WIN_CHECK(translated.value().header.object_id == 88U);
    AI_SHIELD_WIN_CHECK(ai_shield::abi2::validate(translated.value(), ai_shield::abi2::ValidationContext{
        .expected_sequence = 9, .now_monotonic_ns = 5'000, .maximum_clock_skew_ns = 0, .channel_key = key}).ok());

    ai_shield::platform::windows::DriverEventObservation wfp{
        .version = 0x00010002U, .size = 72U, .sensor = 1U, .kind = 1U, .sequence = 10U,
        .timestamp_100ns = 51U, .process_id = 43U, .subject_id = 89U,
        .local_port = 53000U, .remote_port = 443U, .reserved = 17U};
    const auto flow = ai_shield::platform::windows::to_sensor_event_v2(wfp, 5, 3, key);
    AI_SHIELD_WIN_CHECK(flow.ok());
    AI_SHIELD_WIN_CHECK(flow.value().protocol == 17U);
    AI_SHIELD_WIN_CHECK(flow.value().header.flow_id != 0U);
    AI_SHIELD_WIN_CHECK(flow.value().remote_port == 443U);
}

void test_wfp_enforcement_fast_policy() {
    const auto unknown = ai_shield::platform::windows::wfp::decide_fast_path(
        ai_shield::platform::windows::wfp::FastPolicyInput{
            .admission = ai_shield::service_registry::Admission{
                .action = ai_shield::abi::ShieldAction::drop_flow,
                .reason_mask = ai_shield::abi::ReasonCode::unregistered_service},
            .broker_available = true,
            .known_blocked_source = false,
            .pending_capacity_available = true,
            .service_class = ai_shield::fail_policy::ServiceClass::unregistered});
    AI_SHIELD_WIN_CHECK(unknown.action == ai_shield::platform::windows::wfp::KernelAction::block);

    const auto pend = ai_shield::platform::windows::wfp::decide_fast_path(
        ai_shield::platform::windows::wfp::FastPolicyInput{
            .admission = ai_shield::service_registry::Admission{.action = ai_shield::abi::ShieldAction::allow_monitored},
            .broker_available = true,
            .known_blocked_source = false,
            .pending_capacity_available = true,
            .service_class = ai_shield::fail_policy::ServiceClass::web_api});
    AI_SHIELD_WIN_CHECK(pend.action == ai_shield::platform::windows::wfp::KernelAction::pend);
}

void test_appcontainer_launch_spec_validation() {
    const auto budget = ai_shield::sandbox_budget::budget_for(ai_shield::sandbox::Tier::appcontainer_fast, 50);
    const auto valid = ai_shield::platform::windows::sandbox::validate_launch_spec(
        ai_shield::platform::windows::sandbox::AppContainerLaunchSpec{
            .analysis_id = 1,
            .parser_id = 2,
            .budget = budget,
            .allow_network = false,
            .allow_child_processes = false,
            .executable_path = L"C:\\Windows\\System32\\notepad.exe",
            .work_directory = L"C:\\Windows\\Temp"});
    AI_SHIELD_WIN_CHECK(valid.ok());
    const auto invalid = ai_shield::platform::windows::sandbox::validate_launch_spec(
        ai_shield::platform::windows::sandbox::AppContainerLaunchSpec{
            .analysis_id = 1,
            .parser_id = 2,
            .budget = budget,
            .allow_network = true,
            .allow_child_processes = false,
            .executable_path = L"C:\\Windows\\System32\\notepad.exe",
            .work_directory = L"C:\\Windows\\Temp"});
    AI_SHIELD_WIN_CHECK(invalid.status() == ai_shield::Status::invalid_state_transition);
}

void test_minifilter_provenance_adapter() {
    ai_shield::provenance::Store store;
    const ai_shield::provenance::FileIdentity source{.volume_id = 1,
                                                     .file_id = 2,
                                                     .stream_id = 1,
                                                     .content_hash = ai_shield::crypto::sha256("downloaded"),
                                                     .provenance_id = 10};
    AI_SHIELD_WIN_CHECK(ai_shield::platform::windows::minifilter::apply_file_event(
                            store,
                            ai_shield::platform::windows::minifilter::FileEvent{
                                .operation = ai_shield::platform::windows::minifilter::FileOperation::external_create,
                                .target = source})
                            .ok());
    AI_SHIELD_WIN_CHECK(ai_shield::platform::windows::minifilter::apply_file_event(
                            store,
                            ai_shield::platform::windows::minifilter::FileEvent{
                                .operation = ai_shield::platform::windows::minifilter::FileOperation::image_load,
                                .target = source})
                            .status() == ai_shield::Status::invalid_state_transition);
    AI_SHIELD_WIN_CHECK(store.approve(source).ok());
    AI_SHIELD_WIN_CHECK(ai_shield::platform::windows::minifilter::apply_file_event(
                            store,
                            ai_shield::platform::windows::minifilter::FileEvent{
                                .operation = ai_shield::platform::windows::minifilter::FileOperation::image_load,
                                .target = source})
                            .ok());
}

void test_secure_runtime_state_rotation_and_recovery() {
    const auto directory = std::filesystem::temp_directory_path() /
                           (L"AIShieldRuntimeTest-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    ai_shield::platform::windows::security::SecureRuntimeStore store(directory);
    const auto initial = store.load_or_create();
    AI_SHIELD_WIN_CHECK(initial.ok());
    AI_SHIELD_WIN_CHECK(initial.value().generation == 1U);
    const auto versioned = store.update_versions(9U, 4U);
    AI_SHIELD_WIN_CHECK(versioned.ok());
    const auto rotated = store.rotate_key();
    AI_SHIELD_WIN_CHECK(rotated.ok());
    AI_SHIELD_WIN_CHECK(rotated.value().generation == 2U);
    AI_SHIELD_WIN_CHECK(rotated.value().previous_generation == 1U);
    AI_SHIELD_WIN_CHECK(rotated.value().channel_key != rotated.value().previous_channel_key);
    {
        std::ofstream corrupt(directory / L"runtime-state.dpapi", std::ios::binary | std::ios::trunc);
        corrupt << "invalid";
    }
    const auto recovered = store.load_or_create();
    AI_SHIELD_WIN_CHECK(recovered.ok());
    AI_SHIELD_WIN_CHECK(recovered.value().policy_version == 9U);
    AI_SHIELD_WIN_CHECK(recovered.value().model_version == 4U);
    AI_SHIELD_WIN_CHECK(store.update_versions(8U, 4U).status() == ai_shield::Status::integrity_failure);
    {
        std::ofstream primary(directory / L"runtime-state.dpapi", std::ios::binary | std::ios::trunc);
        primary << "invalid-primary";
        std::ofstream recovery(directory / L"runtime-state.recovery.dpapi", std::ios::binary | std::ios::trunc);
        recovery << "invalid-recovery";
    }
    AI_SHIELD_WIN_CHECK(store.load_or_create().status() == ai_shield::Status::integrity_failure);
    std::filesystem::remove_all(directory, error);
}

void test_etw_amsi_translation_and_parser_pool_limits() {
    const auto key = ai_shield::crypto::sha256("sensor-key");
    const auto etw = ai_shield::platform::windows::sensors::translate_etw({
        .sequence = 1, .monotonic_ns = 10, .event_id = 7,
        .correlation = {.flow_id = 2, .file_id = 3, .process_id = 4, .policy_version = 5, .model_version = 6},
        .evidence_hash = ai_shield::crypto::sha256("etw")}, key);
    AI_SHIELD_WIN_CHECK(etw.ok());
    AI_SHIELD_WIN_CHECK(etw.value().sensor == ai_shield::platform::windows::sensors::kEtwSensor);
    AI_SHIELD_WIN_CHECK(etw.value().file_id == 3U);
    const auto amsi = ai_shield::platform::windows::sensors::translate_amsi({
        .sequence = 2, .monotonic_ns = 11, .process_id = 4, .scan_result = 1,
        .policy_version = 5, .model_version = 6, .content_hash = ai_shield::crypto::sha256("amsi")}, key);
    AI_SHIELD_WIN_CHECK(amsi.ok());
    AI_SHIELD_WIN_CHECK(amsi.value().sensor == ai_shield::platform::windows::sensors::kAmsiSensor);
    ai_shield::platform::windows::sandbox::ParserPool pool(0U);
    AI_SHIELD_WIN_CHECK(pool.start({.analysis_id = 1, .parser_id = 1,
        .budget = {.wall_time_ns = 1, .memory_bytes = 1, .max_processes = 1},
        .executable_path = L"C:\\Windows\\System32\\notepad.exe", .work_directory = L"C:\\Windows\\Temp"})
        .status() == ai_shield::Status::out_of_budget);
    const auto tpm = ai_shield::platform::windows::security::tpm_status();
    AI_SHIELD_WIN_CHECK(!tpm.key_available || tpm.provider_available);
}

}  // namespace

int main() {
    test_wfp_telemetry_translation();
    test_driver_channel_sequence_validation();
    test_driver_event_to_abi2_translation();
    test_wfp_enforcement_fast_policy();
    test_appcontainer_launch_spec_validation();
    test_minifilter_provenance_adapter();
    test_secure_runtime_state_rotation_and_recovery();
    test_etw_amsi_translation_and_parser_pool_limits();
    std::cout << "ai_shield_windows_platform_tests passed\n";
    return 0;
}
