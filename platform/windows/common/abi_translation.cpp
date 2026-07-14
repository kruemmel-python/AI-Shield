#include "platform/windows/common/abi_translation.hpp"

#include <span>

namespace ai_shield::platform::windows {

ai_shield::Result<ai_shield::abi::FlowEvent> to_flow_event(const WinFlowObservation& observation) noexcept {
    if (observation.sequence == 0U || observation.flow_id == 0U ||
        (observation.transport != WinTransport::tcp && observation.transport != WinTransport::udp)) {
        return ai_shield::Status::invalid_argument;
    }

    ai_shield::abi::FlowEvent event{};
    event.abi_version = ai_shield::abi::kAbiVersion;
    event.structure_size = sizeof(ai_shield::abi::FlowEvent);
    event.sequence = observation.sequence;
    event.flow_id = observation.flow_id;
    event.monotonic_ns = observation.monotonic_ns;
    event.source_ipv4_be = observation.remote_ipv4_be;
    event.target_ipv4_be = observation.local_ipv4_be;
    event.source_port_be = observation.remote_port_be;
    event.target_port_be = observation.local_port_be;
    event.protocol = static_cast<std::uint16_t>(observation.transport);
    event.flags = observation.flags;
    event.payload_hash = observation.payload_hash;
    return event;
}

ai_shield::Result<ai_shield::abi2::SensorEvent> to_sensor_event_v2(
    const DriverEventObservation& source,
    std::uint64_t policy_version,
    std::uint64_t model_version,
    const ai_shield::crypto::Sha256Digest& channel_key) noexcept {
    if (source.version != 0x00010002U || source.size != 72U || source.sequence == 0ULL ||
        source.sensor < 1U || source.sensor > 3U || source.kind < 1U || source.kind > 10U ||
        (source.flags & ~ai_shield::abi2::kKnownEventFlags) != 0U) {
        return ai_shield::Status::integrity_failure;
    }
    ai_shield::abi2::SensorEvent event{};
    event.header.sequence = source.sequence;
    event.header.monotonic_ns = source.timestamp_100ns <= UINT64_MAX / 100ULL
                                    ? source.timestamp_100ns * 100ULL : UINT64_MAX;
    event.header.object_id = source.subject_id;
    if (source.sensor == 1U)
        event.header.flow_id = (source.process_id << 32U) ^ source.subject_id ^
                               (static_cast<std::uint64_t>(source.local_port) << 16U) ^ source.remote_port;
    event.header.policy_version = policy_version;
    event.header.model_version = model_version;
    event.sensor = source.sensor;
    event.kind = source.kind;
    event.process_id = source.process_id;
    event.subject_id = source.subject_id;
    if (source.sensor == 2U && source.reserved != 0U) {
        event.file_id = source.subject_id;
        event.volume_id = source.reserved;
        event.provenance_id = (static_cast<std::uint64_t>(source.reserved) << 32U) ^ source.subject_id;
    } else if (source.sensor == 3U && source.kind == 5U) {
        event.parent_process_id = source.reserved;
    }
    event.local_port = source.local_port;
    event.remote_port = source.remote_port;
    event.address_family = static_cast<std::uint16_t>(source.address_family);
    event.protocol = source.sensor == 1U ? static_cast<std::uint16_t>(source.reserved) : 0U;
    event.decision = source.decision;
    event.event_flags = source.flags;
    event.evidence_hash = ai_shield::crypto::sha256(std::as_bytes(std::span(&source, 1U)));
    ai_shield::abi2::seal(event, channel_key);
    return event;
}

}  // namespace ai_shield::platform::windows
