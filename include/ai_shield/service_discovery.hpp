#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"
#include "ai_shield/service_registry.hpp"

namespace ai_shield::service_discovery {

struct ObservedListener final {
    std::uint16_t port_be = 0;
    service_registry::Transport transport = service_registry::Transport::tcp;
    std::uint16_t protocol_id = 0;
    bool externally_reachable = false;
};

[[nodiscard]] Result<service_registry::ServicePolicy> propose(ObservedListener listener) noexcept;
[[nodiscard]] Result<void> confirm(service_registry::Registry& registry,
                                   service_registry::ServicePolicy policy) noexcept;

}  // namespace ai_shield::service_discovery
