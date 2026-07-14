#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace ai_shield::abi {

inline constexpr std::uint32_t kAbiMajor = 1;
inline constexpr std::uint32_t kAbiMinor = 0;
inline constexpr std::uint32_t kAbiVersion = (kAbiMajor << 16U) | kAbiMinor;

enum class ShieldAction : std::uint32_t {
    allow = 0,
    allow_monitored,
    rate_limit,
    redirect_sandbox,
    quarantine,
    drop_flow,
    block_origin,
    suspend_target
};

enum ReasonCode : std::uint32_t {
    proto_malformed = 0x0001U,
    proto_ambiguous = 0x0002U,
    signature_match = 0x0004U,
    path_traversal = 0x0008U,
    command_execution = 0x0010U,
    external_exec_pending = 0x0020U,
    sandbox_inconclusive = 0x0040U,
    sandbox_escape_signal = 0x0080U,
    sensor_integrity_gap = 0x0100U,
    abi_violation = 0x0200U,
    policy_signature_invalid = 0x0400U,
    model_signature_invalid = 0x0800U,
    campaign_correlation = 0x1000U,
    consequence_detected = 0x2000U,
    queue_overflow = 0x4000U,
    degraded_mode = 0x8000U,
    unregistered_service = 0x00010000U,
    archive_path_escape = 0x00020000U,
    archive_bomb_risk = 0x00040000U,
    executable_format_anomaly = 0x00080000U,
    update_rollback = 0x00100000U,
    tls_downgrade = 0x00200000U,
    xml_entity_expansion = 0x00400000U,
    document_active_content = 0x00800000U,
    adaptive_mutation = 0x01000000U,
    proxy_loop = 0x02000000U,
    rate_limited = 0x04000000U,
    worker_crash = 0x08000000U,
    privacy_redacted = 0x10000000U,
    online_learning_blocked = 0x20000000U,
    transaction_rollback = 0x40000000U,
    decision_timeout = 0x80000000U
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324)
#endif

struct alignas(64) ShieldDecision final {
    std::uint32_t abi_version;
    std::uint32_t structure_size;
    std::uint64_t decision_id;
    std::uint64_t flow_id;
    ShieldAction action;
    std::uint16_t risk_score;
    std::uint16_t confidence;
    std::uint32_t reason_mask;
    std::uint64_t valid_until_monotonic_ns;
    std::array<std::byte, 32> evidence_hash;
    std::array<std::byte, 32> message_mac;
};

struct alignas(64) FlowEvent final {
    std::uint32_t abi_version;
    std::uint32_t structure_size;
    std::uint64_t sequence;
    std::uint64_t flow_id;
    std::uint64_t monotonic_ns;
    std::uint32_t source_ipv4_be;
    std::uint32_t target_ipv4_be;
    std::uint16_t source_port_be;
    std::uint16_t target_port_be;
    std::uint16_t protocol;
    std::uint16_t flags;
    std::array<std::byte, 32> payload_hash;
    std::array<std::byte, 32> message_mac;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

static_assert(std::is_standard_layout_v<ShieldDecision>);
static_assert(std::is_trivially_copyable_v<ShieldDecision>);
static_assert(alignof(ShieldDecision) == 64);
static_assert(std::is_standard_layout_v<FlowEvent>);
static_assert(std::is_trivially_copyable_v<FlowEvent>);
static_assert(alignof(FlowEvent) == 64);

inline constexpr bool valid_header(std::uint32_t version, std::uint32_t size, std::uint32_t expected_size) noexcept {
    return version == kAbiVersion && size == expected_size;
}

}  // namespace ai_shield::abi
