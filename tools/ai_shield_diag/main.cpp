#include <cstddef>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "ai_shield/audit.hpp"
#include "ai_shield/http1.hpp"
#include "ai_shield/policy.hpp"
#include "ai_shield/sha256.hpp"

namespace {

const char* action_name(ai_shield::abi::ShieldAction action) noexcept {
    using ai_shield::abi::ShieldAction;
    switch (action) {
        case ShieldAction::allow:
            return "allow";
        case ShieldAction::allow_monitored:
            return "allow_monitored";
        case ShieldAction::rate_limit:
            return "rate_limit";
        case ShieldAction::redirect_sandbox:
            return "redirect_sandbox";
        case ShieldAction::quarantine:
            return "quarantine";
        case ShieldAction::drop_flow:
            return "drop_flow";
        case ShieldAction::block_origin:
            return "block_origin";
        case ShieldAction::suspend_target:
            return "suspend_target";
    }
    return "unknown";
}

std::string digest_hex(const ai_shield::crypto::Sha256Digest& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64U);
    for (const auto value : digest) {
        const auto byte = std::to_integer<unsigned int>(value);
        result.push_back(digits[(byte >> 4U) & 0xfU]);
        result.push_back(digits[byte & 0xfU]);
    }
    return result;
}

ai_shield::Result<ai_shield::audit::AuditChain> read_audit_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return ai_shield::Status::not_found;
    const std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> bytes(raw.size());
    for (std::size_t i = 0U; i < raw.size(); ++i)
        bytes[i] = static_cast<std::byte>(static_cast<unsigned char>(raw[i]));
    return ai_shield::audit::deserialize(bytes);
}

int verify_audit_file(const char* path) {
    const auto parsed = read_audit_file(path);
    if (!parsed.ok() && parsed.status() == ai_shield::Status::not_found) {
        std::cerr << "audit_status=open_failed\n";
        return 2;
    }
    if (!parsed.ok()) {
        std::cerr << "audit_status=invalid\n";
        std::cerr << "status_code=" << static_cast<std::uint32_t>(parsed.status()) << "\n";
        return 3;
    }
    std::cout << "audit_status=valid\n";
    std::cout << "segments=" << parsed.value().segments().size() << "\n";
    return 0;
}

int dump_audit_json(const char* path) {
    const auto parsed = read_audit_file(path);
    if (!parsed.ok()) return parsed.status() == ai_shield::Status::not_found ? 2 : 3;
    std::size_t record_count = 0U;
    for (const auto& segment : parsed.value().segments()) record_count += segment.records.size();
    std::cout << "{\"schema\":\"AIShieldAuditView/1\",\"integrity\":\"valid\",\"segments\":"
              << parsed.value().segments().size() << ",\"record_count\":" << record_count << ",\"records\":[";
    bool first = true;
    for (const auto& segment : parsed.value().segments()) {
        for (const auto& record : segment.records) {
            if (!first) std::cout << ',';
            first = false;
            const auto& c = record.correlation;
            std::cout << "{\"sequence\":" << record.sequence
                      << ",\"monotonic_ns\":" << record.monotonic_ns
                      << ",\"disposition\":\"" << (record.reason_mask == 0U ? "observed" : "blocked")
                      << "\",\"reason_mask\":" << record.reason_mask
                      << ",\"flow_id\":" << c.flow_id << ",\"object_id\":" << c.object_id
                      << ",\"file_id\":" << c.file_id << ",\"volume_id\":" << c.volume_id
                      << ",\"provenance_id\":" << c.provenance_id << ",\"process_id\":" << c.process_id
                      << ",\"parent_process_id\":" << c.parent_process_id
                      << ",\"policy_version\":" << c.policy_version << ",\"model_version\":" << c.model_version
                      << ",\"evidence_hash\":\"" << digest_hex(record.evidence_hash) << "\"}";
        }
    }
    std::cout << "]}\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "audit-verify") {
        return verify_audit_file(argv[2]);
    }
    if (argc == 3 && std::string(argv[1]) == "audit-dump-json") {
        return dump_audit_json(argv[2]);
    }

    std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    const auto parsed = ai_shield::protocols::http1::parse_request(input);
    ai_shield::detection::Evidence evidence{};
    if (parsed.ok()) {
        evidence = ai_shield::protocols::http1::evidence_from(parsed.value());
    } else {
        evidence.protocol = 100;
        evidence.reason_mask = ai_shield::abi::ReasonCode::proto_malformed;
    }
    const auto hash = ai_shield::crypto::sha256(input);
    const ai_shield::policy::PolicyContext context{.decision_id = 1,
                                                   .flow_id = 42,
                                                   .now_monotonic_ns = 1'000'000,
                                                   .critical_service = true,
                                                   .runtime_gate_active = true,
                                                   .mode = ai_shield::policy::ProtectionMode::balanced};
    const auto decision = ai_shield::policy::decide(context, evidence, hash);
    std::cout << "action=" << action_name(decision.action) << "\n";
    std::cout << "risk_score=" << decision.risk_score << "\n";
    std::cout << "reason_mask=0x" << std::hex << decision.reason_mask << std::dec << "\n";
    return 0;
}
