#include "platform/windows/sensors/etw_amsi_adapter.hpp"

#include <windows.h>
#include <amsi.h>

namespace ai_shield::platform::windows::sensors {

Result<abi2::SensorEvent> translate_etw(const EtwObservation& source,
                                        const crypto::Sha256Digest& channel_key) noexcept {
    if (source.sequence == 0U || source.monotonic_ns == 0U || source.event_id == 0U ||
        source.correlation.policy_version == 0U || source.correlation.model_version == 0U)
        return Status::invalid_argument;
    abi2::SensorEvent event{};
    event.header.sequence = source.sequence;
    event.header.monotonic_ns = source.monotonic_ns;
    event.header.flow_id = source.correlation.flow_id;
    event.header.object_id = source.correlation.object_id;
    event.header.policy_version = source.correlation.policy_version;
    event.header.model_version = source.correlation.model_version;
    event.sensor = kEtwSensor;
    event.kind = source.event_id;
    event.process_id = source.correlation.process_id;
    event.parent_process_id = source.correlation.parent_process_id;
    event.provenance_id = source.correlation.provenance_id;
    event.volume_id = source.correlation.volume_id;
    event.file_id = source.correlation.file_id;
    event.subject_id = (static_cast<std::uint64_t>(source.level) << 32U) |
                       (static_cast<std::uint64_t>(source.version) << 16U) | source.event_id;
    event.source_address = source.provider_id;
    event.evidence_hash = source.evidence_hash;
    abi2::seal(event, channel_key);
    return event;
}

Result<abi2::SensorEvent> translate_amsi(const AmsiObservation& source,
                                         const crypto::Sha256Digest& channel_key) noexcept {
    if (source.sequence == 0U || source.monotonic_ns == 0U || source.process_id == 0U ||
        source.policy_version == 0U || source.model_version == 0U) return Status::invalid_argument;
    abi2::SensorEvent event{};
    event.header.sequence = source.sequence;
    event.header.monotonic_ns = source.monotonic_ns;
    event.header.object_id = source.process_id;
    event.header.policy_version = source.policy_version;
    event.header.model_version = source.model_version;
    event.sensor = kAmsiSensor;
    event.kind = 1U;
    event.process_id = source.process_id;
    event.subject_id = source.scan_result;
    event.decision = source.scan_result;
    if (AmsiResultIsMalware(source.scan_result) ||
        (source.scan_result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START &&
         source.scan_result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)) event.event_flags |= 0x00000002U;
    event.evidence_hash = source.content_hash;
    abi2::seal(event, channel_key);
    return event;
}

Result<AmsiObservation> scan_with_amsi(std::span<const std::byte> content,
                                      std::uint64_t sequence,
                                      std::uint64_t monotonic_ns,
                                      std::uint64_t policy_version,
                                      std::uint64_t model_version) noexcept {
    if (content.empty() || content.size() > ULONG_MAX || sequence == 0U || monotonic_ns == 0U ||
        policy_version == 0U || model_version == 0U) return Status::invalid_argument;
    HAMSICONTEXT context = nullptr;
    if (FAILED(AmsiInitialize(L"AIShield", &context))) return Status::integrity_failure;
    AMSI_RESULT result = AMSI_RESULT_NOT_DETECTED;
    const HRESULT scanned = AmsiScanBuffer(context, const_cast<std::byte*>(content.data()),
                                           static_cast<ULONG>(content.size()),
                                           L"AIShieldSensorContent", nullptr, &result);
    AmsiUninitialize(context);
    if (FAILED(scanned)) return Status::integrity_failure;
    return AmsiObservation{.sequence = sequence, .monotonic_ns = monotonic_ns,
        .process_id = GetCurrentProcessId(), .scan_result = static_cast<std::uint32_t>(result),
        .policy_version = policy_version, .model_version = model_version,
        .content_hash = crypto::sha256(content)};
}

}  // namespace ai_shield::platform::windows::sensors
