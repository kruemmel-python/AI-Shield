#include "platform/windows/wfp/adapter/wfp_telemetry.hpp"

namespace ai_shield::platform::windows::wfp {

ai_shield::Result<ai_shield::abi::FlowEvent> translate_telemetry(const TelemetryEvent& event) noexcept {
    auto observation = event.observation;
    if (!event.inbound) {
        const auto source_ip = observation.remote_ipv4_be;
        const auto source_port = observation.remote_port_be;
        observation.remote_ipv4_be = observation.local_ipv4_be;
        observation.remote_port_be = observation.local_port_be;
        observation.local_ipv4_be = source_ip;
        observation.local_port_be = source_port;
    }
    auto translated = to_flow_event(observation);
    if (!translated.ok()) {
        return translated.status();
    }
    switch (event.layer) {
    case LayerEvent::ale_auth_connect:
    case LayerEvent::ale_auth_recv_accept:
    case LayerEvent::ale_flow_established:
    case LayerEvent::ale_endpoint_closure:
        return translated;
    }
    return ai_shield::Status::invalid_argument;
}

}  // namespace ai_shield::platform::windows::wfp
