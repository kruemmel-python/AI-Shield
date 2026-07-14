#include "platform/windows/siem/syslog_connector.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>

namespace ai_shield::platform::windows::siem {

Result<void> send_syslog(std::string_view host, std::uint16_t port,
                         std::string_view message, Transport transport) noexcept {
    if (host.empty() || port == 0U || message.empty() || message.size() > 64U * 1024U)
        return Status::invalid_argument;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return Status::integrity_failure;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = transport == Transport::tcp ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = transport == Transport::tcp ? IPPROTO_TCP : IPPROTO_UDP;
    addrinfo* addresses = nullptr;
    const std::string host_text(host);
    const std::string port_text = std::to_string(port);
    if (getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &addresses) != 0) {
        WSACleanup();
        return Status::not_found;
    }
    bool sent = false;
    for (auto* address = addresses; address != nullptr && !sent; address = address->ai_next) {
        SOCKET socket_handle = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (socket_handle == INVALID_SOCKET) continue;
        if (transport == Transport::udp || connect(socket_handle, address->ai_addr,
                                                    static_cast<int>(address->ai_addrlen)) == 0) {
            const int result = transport == Transport::tcp
                                   ? send(socket_handle, message.data(), static_cast<int>(message.size()), 0)
                                   : sendto(socket_handle, message.data(), static_cast<int>(message.size()), 0,
                                            address->ai_addr, static_cast<int>(address->ai_addrlen));
            sent = result == static_cast<int>(message.size());
        }
        closesocket(socket_handle);
    }
    freeaddrinfo(addresses);
    WSACleanup();
    return sent ? Result<void>{} : Result<void>{Status::integrity_failure};
}

}  // namespace ai_shield::platform::windows::siem
