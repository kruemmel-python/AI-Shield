#pragma once

#include <cstdint>
#include <type_traits>

#include "ai_shield/abi.hpp"
#include "ai_shield/abi2.hpp"
#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::platform::windows {

enum class WinTransport : std::uint16_t {
    tcp = 6,
    udp = 17
};

struct WinFlowObservation final {
    std::uint64_t sequence = 0;
    std::uint64_t flow_id = 0;
    std::uint64_t monotonic_ns = 0;
    std::uint32_t local_ipv4_be = 0;
    std::uint32_t remote_ipv4_be = 0;
    std::uint16_t local_port_be = 0;
    std::uint16_t remote_port_be = 0;
    WinTransport transport = WinTransport::tcp;
    std::uint16_t flags = 0;
    ai_shield::crypto::Sha256Digest payload_hash{};
};

struct DriverEventObservation final {
    std::uint32_t version = 0;
    std::uint32_t size = 0;
    std::uint32_t sensor = 0;
    std::uint32_t kind = 0;
    std::uint64_t sequence = 0;
    std::uint64_t timestamp_100ns = 0;
    std::uint64_t process_id = 0;
    std::uint64_t subject_id = 0;
    std::uint32_t address_family = 0;
    std::uint32_t local_port = 0;
    std::uint32_t remote_port = 0;
    std::uint32_t decision = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved = 0;
};

static_assert(sizeof(DriverEventObservation) == 72U);
static_assert(std::is_trivially_copyable_v<DriverEventObservation>);

[[nodiscard]] ai_shield::Result<ai_shield::abi::FlowEvent> to_flow_event(const WinFlowObservation& observation) noexcept;
[[nodiscard]] ai_shield::Result<ai_shield::abi2::SensorEvent> to_sensor_event_v2(
    const DriverEventObservation& event,
    std::uint64_t policy_version,
    std::uint64_t model_version,
    const ai_shield::crypto::Sha256Digest& channel_key) noexcept;

}  // namespace ai_shield::platform::windows
