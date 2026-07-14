#pragma once

#include <cstdint>
#include <string_view>

#include "ai_shield/result.hpp"

namespace ai_shield::platform::windows::siem {

enum class Transport : std::uint32_t { udp, tcp };

[[nodiscard]] Result<void> send_syslog(std::string_view host, std::uint16_t port,
                                       std::string_view message, Transport transport) noexcept;

}  // namespace ai_shield::platform::windows::siem
