#pragma once

#include <cstdint>

namespace ai_shield::retention {

enum class DataClass : std::uint32_t {
    flow_metadata,
    security_incident,
    sandbox_report,
    full_payload,
    health_performance
};

struct Decision final {
    bool keep = false;
    bool requires_explicit_admin_payload_opt_in = false;
};

[[nodiscard]] std::uint64_t default_retention_ns(DataClass data_class) noexcept;
[[nodiscard]] Decision decide(DataClass data_class,
                              std::uint64_t age_ns,
                              bool incident_context,
                              bool explicit_payload_opt_in) noexcept;

}  // namespace ai_shield::retention
