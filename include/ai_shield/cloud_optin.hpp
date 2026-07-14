#pragma once

#include <cstdint>

#include "ai_shield/result.hpp"

namespace ai_shield::cloud {

struct TransferRequest final {
    bool admin_opt_in = false;
    bool contains_payload = false;
    bool payload_export_enabled = false;
    std::uint64_t max_bytes = 0;
    std::uint64_t requested_bytes = 0;
};

[[nodiscard]] Result<void> authorize_transfer(TransferRequest request) noexcept;

}  // namespace ai_shield::cloud
