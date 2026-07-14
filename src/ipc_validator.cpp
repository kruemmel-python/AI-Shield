#include "ai_shield/ipc_validator.hpp"

#include <vector>

namespace ai_shield::ipc {
namespace {

template <typename T>
void append_le(std::vector<std::byte>& out, T value) {
    const auto u = static_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        out.push_back(static_cast<std::byte>((u >> (i * 8U)) & 0xffU));
    }
}

void append_digest(std::vector<std::byte>& out, const crypto::Sha256Digest& digest) {
    out.insert(out.end(), digest.begin(), digest.end());
}

}  // namespace

crypto::Sha256Digest compute_flow_event_mac(const abi::FlowEvent& event, const crypto::Sha256Digest& key) {
    std::vector<std::byte> bytes;
    bytes.reserve(160U);
    bytes.insert(bytes.end(), key.begin(), key.end());
    append_le(bytes, event.abi_version);
    append_le(bytes, event.structure_size);
    append_le(bytes, event.sequence);
    append_le(bytes, event.flow_id);
    append_le(bytes, event.monotonic_ns);
    append_le(bytes, event.source_ipv4_be);
    append_le(bytes, event.target_ipv4_be);
    append_le(bytes, event.source_port_be);
    append_le(bytes, event.target_port_be);
    append_le(bytes, event.protocol);
    append_le(bytes, event.flags);
    append_digest(bytes, event.payload_hash);
    return crypto::sha256(bytes);
}

Result<void> validate_flow_event(const abi::FlowEvent& event, const ValidationContext& context) noexcept {
    if (!abi::valid_header(event.abi_version, event.structure_size, sizeof(abi::FlowEvent))) {
        return Status::integrity_failure;
    }
    if (event.sequence != context.expected_next_sequence) {
        return Status::integrity_failure;
    }
    const auto lower_bound = context.now_monotonic_ns > context.max_clock_skew_ns
                                 ? context.now_monotonic_ns - context.max_clock_skew_ns
                                 : 0ULL;
    const auto upper_bound = context.now_monotonic_ns + context.max_clock_skew_ns;
    if (event.monotonic_ns < lower_bound || event.monotonic_ns > upper_bound) {
        return Status::integrity_failure;
    }
    const auto mac = compute_flow_event_mac(event, context.mac_key);
    if (!crypto::constant_time_equal(mac, event.message_mac)) {
        return Status::integrity_failure;
    }
    return {};
}

}  // namespace ai_shield::ipc
