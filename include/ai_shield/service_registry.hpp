#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::service_registry {

enum class Transport : std::uint16_t {
    tcp = 6,
    udp = 17
};

enum class FailPolicy : std::uint32_t {
    fail_closed,
    allow_monitored_interactive
};

struct ServicePolicy final {
    std::uint16_t port_be = 0;
    Transport transport = Transport::tcp;
    std::uint16_t protocol_id = 0;
    bool externally_reachable = false;
    bool critical_service = true;
    FailPolicy fail_policy = FailPolicy::fail_closed;
    std::uint32_t max_payload_bytes = 64U * 1024U;
};

struct Admission final {
    abi::ShieldAction action = abi::ShieldAction::drop_flow;
    std::uint32_t reason_mask = 0;
    ServicePolicy policy{};
};

class Registry final {
public:
    [[nodiscard]] Result<void> register_service(ServicePolicy policy);
    [[nodiscard]] Admission admit(Transport transport, std::uint16_t port_be) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return policies_.size(); }

private:
    std::vector<ServicePolicy> policies_;
};

}  // namespace ai_shield::service_registry
