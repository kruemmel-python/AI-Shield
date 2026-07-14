#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

#include "ai_shield/replay.hpp"

namespace {

int status_code(ai_shield::Status status) {
    return static_cast<int>(status) == 0 ? 0 : 2;
}

void print_digest(const ai_shield::crypto::Sha256Digest& digest) {
    for (const auto byte : digest) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(std::to_integer<unsigned char>(byte));
    }
    std::cout << std::dec;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: ai_shield_replay <scenario.bin>\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "could not open scenario\n";
        return 2;
    }
    std::vector<std::byte> bytes;
    char ch = 0;
    while (input.get(ch)) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }

    const auto result = ai_shield::replay::parse_and_execute(bytes);
    if (!result.ok()) {
        std::cerr << "replay rejected status=" << static_cast<unsigned int>(result.status()) << "\n";
        return status_code(result.status());
    }

    std::cout << "flow_id=" << result.value().decision.flow_id << "\n";
    std::cout << "policy_version=" << result.value().policy_version << "\n";
    std::cout << "action=" << static_cast<unsigned int>(result.value().decision.action) << "\n";
    std::cout << "risk_score=" << result.value().decision.risk_score << "\n";
    std::cout << "reason_mask=" << result.value().decision.reason_mask << "\n";
    std::cout << "audit_records=" << result.value().audit_records << "\n";
    std::cout << "audit_verifiable=" << (result.value().audit_verifiable ? 1 : 0) << "\n";
    std::cout << "audit_root=";
    print_digest(result.value().audit_root);
    std::cout << "\n";
    std::cout << "causal_nodes=" << result.value().causal_nodes << "\n";
    std::cout << "causal_edges=" << result.value().causal_edges << "\n";
    std::cout << "causal_graph_complete=" << (result.value().causal_graph_complete ? 1 : 0) << "\n";
    return 0;
}
