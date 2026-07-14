#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "ai_shield/abi.hpp"
#include "ai_shield/replay.hpp"
#include "ai_shield/response_normalizer.hpp"

namespace {

constexpr std::uint64_t kPrototypeServiceId = 1;
constexpr std::uint64_t kPrototypePolicyVersion = 1;
constexpr int kBacklog = 16;
constexpr int kReceiveLimit = 1024 * 1024;

struct Endpoint final {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
};

struct Config final {
    Endpoint listen{.host = "127.0.0.1", .port = 18080};
    Endpoint backend{};
    bool demo_mode = true;
    bool once = false;
    bool self_test = false;
};

struct WsaSession final {
    bool started = false;
    WsaSession() {
        WSADATA data{};
        started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~WsaSession() {
        if (started) {
            WSACleanup();
        }
    }
};

struct Socket final {
    SOCKET value = INVALID_SOCKET;

    Socket() = default;
    explicit Socket(SOCKET socket) noexcept : value(socket) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            value = other.value;
            other.value = INVALID_SOCKET;
        }
        return *this;
    }
    ~Socket() { close(); }

    void close() noexcept {
        if (value != INVALID_SOCKET) {
            closesocket(value);
            value = INVALID_SOCKET;
        }
    }

    [[nodiscard]] bool valid() const noexcept { return value != INVALID_SOCKET; }
};

struct BindResult final {
    std::vector<Socket> listeners{};
    int error_code = 0;
};

bool parse_endpoint(std::string_view text, Endpoint& endpoint) {
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos || colon + 1U >= text.size()) {
        return false;
    }
    endpoint.host = std::string(text.substr(0, colon));
    if (endpoint.host.size() >= 2U && endpoint.host.front() == '[' && endpoint.host.back() == ']') {
        endpoint.host = endpoint.host.substr(1U, endpoint.host.size() - 2U);
    }
    const auto port_text = text.substr(colon + 1U);
    std::uint32_t port = 0;
    for (const char ch : port_text) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        port = port * 10U + static_cast<std::uint32_t>(ch - '0');
        if (port > 65535U) {
            return false;
        }
    }
    endpoint.port = static_cast<std::uint16_t>(port);
    return endpoint.port != 0U;
}

bool parse_args(int argc, char** argv, Config& config) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--self-test") {
            config.self_test = true;
        } else if (arg == "--once") {
            config.once = true;
        } else if (arg == "--demo") {
            config.demo_mode = true;
        } else if (arg == "--listen" && i + 1 < argc) {
            if (!parse_endpoint(argv[++i], config.listen)) {
                return false;
            }
        } else if (arg == "--backend" && i + 1 < argc) {
            if (!parse_endpoint(argv[++i], config.backend)) {
                return false;
            }
            config.demo_mode = false;
        } else {
            return false;
        }
    }
    return true;
}

void print_usage() {
    std::cerr << "usage: ai_shield_prototype [--listen 127.0.0.1:18080] [--demo | --backend 127.0.0.1:8080] [--once]\n";
    std::cerr << "       ai_shield_prototype --self-test\n";
}

Socket connect_socket(const Endpoint& endpoint) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* raw = nullptr;
    const std::string port = std::to_string(endpoint.port);
    if (getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &raw) != 0 || raw == nullptr) {
        return Socket{};
    }

    Socket socket{};
    for (addrinfo* current = raw; current != nullptr; current = current->ai_next) {
        Socket candidate(::socket(current->ai_family, current->ai_socktype, current->ai_protocol));
        if (candidate.valid() && connect(candidate.value, current->ai_addr, static_cast<int>(current->ai_addrlen)) == 0) {
            socket = std::move(candidate);
            break;
        }
    }
    freeaddrinfo(raw);
    return socket;
}

BindResult bind_listeners(const Endpoint& endpoint) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* raw = nullptr;
    const std::string port = std::to_string(endpoint.port);
    const int address_result = getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &raw);
    if (address_result != 0 || raw == nullptr) {
        return BindResult{.listeners = {}, .error_code = address_result};
    }

    std::vector<Socket> listeners;
    int error_code = 0;
    for (addrinfo* current = raw; current != nullptr; current = current->ai_next) {
        Socket listener(::socket(current->ai_family, current->ai_socktype, current->ai_protocol));
        if (!listener.valid()) {
            error_code = WSAGetLastError();
            continue;
        }
        if (current->ai_family == AF_INET6) {
            const DWORD ipv6_only = 1;
            setsockopt(listener.value, IPPROTO_IPV6, IPV6_V6ONLY,
                       static_cast<const char*>(static_cast<const void*>(&ipv6_only)), sizeof(ipv6_only));
        }
        if (bind(listener.value, current->ai_addr, static_cast<int>(current->ai_addrlen)) == 0 &&
            listen(listener.value, kBacklog) == 0) {
            listeners.push_back(std::move(listener));
        } else {
            error_code = WSAGetLastError();
        }
    }
    freeaddrinfo(raw);
    return BindResult{.listeners = std::move(listeners), .error_code = error_code};
}

bool send_all(SOCKET socket, std::string_view data) {
    std::size_t sent_total = 0;
    while (sent_total < data.size()) {
        const int chunk = send(socket,
                               data.data() + sent_total,
                               static_cast<int>(data.size() - sent_total),
                               0);
        if (chunk <= 0) {
            return false;
        }
        sent_total += static_cast<std::size_t>(chunk);
    }
    return true;
}

std::string bytes_to_string(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (const auto byte : bytes) {
        out.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return out;
}

std::vector<std::byte> receive_http_request(SOCKET socket) {
    std::vector<std::byte> data;
    data.reserve(4096);
    char buffer[4096]{};
    while (data.size() < kReceiveLimit) {
        const int received = recv(socket, buffer, static_cast<int>(sizeof(buffer)), 0);
        if (received <= 0) {
            break;
        }
        for (int i = 0; i < received; ++i) {
            data.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffer[i])));
        }
        const auto text = bytes_to_string(data);
        if (text.find("\r\n\r\n") != std::string_view::npos) {
            break;
        }
    }
    return data;
}

ai_shield::replay::ReplayResult analyze(std::span<const std::byte> request, std::uint64_t flow_id) {
    const auto result = ai_shield::replay::execute(ai_shield::replay::Scenario{
        .flow_id = flow_id,
        .service_id = kPrototypeServiceId,
        .policy_version = kPrototypePolicyVersion,
        .critical_service = true,
        .payload = request,
        .protocol_hint = ai_shield::replay::ProtocolHint::http1,
        .service_identity_verified = true,
        .file_external = false});
    if (result.ok()) {
        return result.value();
    }
    ai_shield::replay::ReplayResult fallback{};
    fallback.decision.action = ai_shield::abi::ShieldAction::drop_flow;
    fallback.decision.reason_mask = ai_shield::abi::ReasonCode::abi_violation;
    fallback.decision.risk_score = 100;
    fallback.policy_version = kPrototypePolicyVersion;
    return fallback;
}

bool action_allows(ai_shield::abi::ShieldAction action) noexcept {
    return action == ai_shield::abi::ShieldAction::allow || action == ai_shield::abi::ShieldAction::allow_monitored;
}

std::string blocked_response(ai_shield::abi::ShieldAction action) {
    const auto body = ai_shield::response::external_response_for(action);
    return "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}

std::string demo_response(const ai_shield::replay::ReplayResult& result) {
    const std::string body = "ai_shield_prototype ok\nrisk_score=" + std::to_string(result.decision.risk_score) +
                             "\nreason_mask=" + std::to_string(result.decision.reason_mask) + "\n";
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}

bool proxy_to_backend(SOCKET client, const Endpoint& backend, std::span<const std::byte> request) {
    Socket upstream = connect_socket(backend);
    if (!upstream.valid()) {
        const std::string body = "backend_unavailable";
        const std::string response =
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\n\r\n" + body;
        return send_all(client, response);
    }

    const auto request_text = bytes_to_string(request);
    if (!send_all(upstream.value, request_text)) {
        return false;
    }

    char buffer[4096]{};
    while (true) {
        const int received = recv(upstream.value, buffer, static_cast<int>(sizeof(buffer)), 0);
        if (received <= 0) {
            break;
        }
        if (!send_all(client, std::string_view(buffer, static_cast<std::size_t>(received)))) {
            return false;
        }
    }
    return true;
}

int run_self_test() {
    const std::string benign = "GET /safe HTTP/1.1\r\nHost: local\r\n\r\n";
    std::vector<std::byte> benign_bytes;
    for (const unsigned char ch : benign) {
        benign_bytes.push_back(static_cast<std::byte>(ch));
    }
    const auto benign_result = analyze(benign_bytes, 1);
    if (!action_allows(benign_result.decision.action)) {
        std::cerr << "self-test benign request was blocked\n";
        return 2;
    }

    const std::string malicious = "GET /../../secret HTTP/1.1\r\nHost: local\r\n\r\n";
    std::vector<std::byte> malicious_bytes;
    for (const unsigned char ch : malicious) {
        malicious_bytes.push_back(static_cast<std::byte>(ch));
    }
    const auto malicious_result = analyze(malicious_bytes, 2);
    if (action_allows(malicious_result.decision.action)) {
        std::cerr << "self-test malicious request was allowed\n";
        return 2;
    }
    std::cout << "ai_shield_prototype self-test passed\n";
    return 0;
}

int run_gateway(const Config& config) {
    auto bind_result = bind_listeners(config.listen);
    auto listeners = std::move(bind_result.listeners);
    if (listeners.empty()) {
        std::cerr << "could not bind listener " << config.listen.host << ":" << config.listen.port
                  << " wsa_error=" << bind_result.error_code << "\n";
        std::cerr << "check for an existing ai_shield_prototype process or choose another --listen port\n";
        return 2;
    }

    std::cout << "ai_shield_prototype listening on " << config.listen.host << ":" << config.listen.port;
    if (config.demo_mode) {
        std::cout << " in demo mode\n";
    } else {
        std::cout << " forwarding to " << config.backend.host << ":" << config.backend.port << "\n";
    }

    std::uint64_t flow_id = 1;
    do {
        fd_set read_set;
        FD_ZERO(&read_set);
        for (const auto& listener : listeners) FD_SET(listener.value, &read_set);
        if (select(0, &read_set, nullptr, nullptr, nullptr) == SOCKET_ERROR) continue;
        SOCKET accepted = INVALID_SOCKET;
        for (const auto& listener : listeners) {
            if (FD_ISSET(listener.value, &read_set)) {
                accepted = accept(listener.value, nullptr, nullptr);
                break;
            }
        }
        Socket client(accepted);
        if (!client.valid()) {
            continue;
        }

        const auto request = receive_http_request(client.value);
        const auto result = analyze(request, flow_id++);
        std::cout << "decision action=" << static_cast<unsigned int>(result.decision.action)
                  << " risk=" << result.decision.risk_score
                  << " reason=" << result.decision.reason_mask
                  << " audit=" << (result.audit_verifiable ? 1 : 0)
                  << " graph=" << (result.causal_graph_complete ? 1 : 0) << "\n";

        if (!action_allows(result.decision.action)) {
            const auto response = blocked_response(result.decision.action);
            send_all(client.value, response);
        } else if (config.demo_mode) {
            const auto response = demo_response(result);
            send_all(client.value, response);
        } else {
            proxy_to_backend(client.value, config.backend, request);
        }
    } while (!config.once);

    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Config config{};
    if (!parse_args(argc, argv, config)) {
        print_usage();
        return 2;
    }

    WsaSession wsa;
    if (!wsa.started) {
        std::cerr << "winsock initialization failed\n";
        return 2;
    }

    if (config.self_test) {
        return run_self_test();
    }
    return run_gateway(config);
}
