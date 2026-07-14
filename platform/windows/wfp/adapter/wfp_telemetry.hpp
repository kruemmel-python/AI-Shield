#pragma once

#include <cstdint>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"
#include "platform/windows/common/abi_translation.hpp"

namespace ai_shield::platform::windows::wfp {

enum class LayerEvent : std::uint32_t {
    ale_auth_connect,
    ale_auth_recv_accept,
    ale_flow_established,
    ale_endpoint_closure
};

struct TelemetryEvent final {
    LayerEvent layer = LayerEvent::ale_auth_recv_accept;
    WinFlowObservation observation{};
    bool inbound = true;
};

[[nodiscard]] ai_shield::Result<ai_shield::abi::FlowEvent> translate_telemetry(const TelemetryEvent& event) noexcept;

}  // namespace ai_shield::platform::windows::wfp
