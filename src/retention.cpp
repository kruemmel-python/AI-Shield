#include "ai_shield/retention.hpp"

namespace ai_shield::retention {
namespace {

constexpr std::uint64_t kDayNs = 24ULL * 60ULL * 60ULL * 1'000'000'000ULL;

}  // namespace

std::uint64_t default_retention_ns(DataClass data_class) noexcept {
    switch (data_class) {
        case DataClass::flow_metadata:
            return 30ULL * kDayNs;
        case DataClass::security_incident:
            return 90ULL * kDayNs;
        case DataClass::sandbox_report:
            return 30ULL * kDayNs;
        case DataClass::full_payload:
            return 0ULL;
        case DataClass::health_performance:
            return 14ULL * kDayNs;
    }
    return 0ULL;
}

Decision decide(DataClass data_class, std::uint64_t age_ns, bool incident_context, bool explicit_payload_opt_in) noexcept {
    if (data_class == DataClass::full_payload) {
        return Decision{explicit_payload_opt_in, !explicit_payload_opt_in};
    }
    auto retention = default_retention_ns(data_class);
    if (data_class == DataClass::sandbox_report && incident_context) {
        retention = 90ULL * kDayNs;
    }
    return Decision{age_ns <= retention, false};
}

}  // namespace ai_shield::retention
