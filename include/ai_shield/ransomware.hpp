#pragma once

#include <cstdint>
#include <map>
#include <vector>

namespace ai_shield::ransomware {

enum class MutationKind : std::uint8_t { write, rename, remove, truncate, canary, recovery_tamper };
enum class Severity : std::uint8_t { normal, suspicious, confirmed };

namespace Reason {
constexpr std::uint32_t write_burst = 1U << 0U;
constexpr std::uint32_t destructive_burst = 1U << 1U;
constexpr std::uint32_t entropy_increase = 1U << 2U;
constexpr std::uint32_t broad_target_set = 1U << 3U;
constexpr std::uint32_t canary_modified = 1U << 4U;
constexpr std::uint32_t recovery_tamper = 1U << 5U;
}

struct Observation final {
    std::uint64_t process_id = 0;
    std::uint64_t parent_process_id = 0;
    std::uint64_t object_id = 0;
    std::uint64_t monotonic_ns = 0;
    MutationKind kind = MutationKind::write;
    std::uint32_t entropy_before_milli = 0;
    std::uint32_t entropy_after_milli = 0;
    bool trusted_process = false;
};

struct Policy final {
    std::uint64_t window_ns = 10'000'000'000ULL;
    std::uint32_t write_threshold = 96;
    std::uint32_t destructive_threshold = 24;
    std::uint32_t distinct_object_threshold = 64;
    std::uint32_t entropy_delta_milli = 1200;
    std::uint32_t suspicious_score = 50;
    std::uint32_t containment_score = 80;
};

struct Verdict final {
    Severity severity = Severity::normal;
    std::uint32_t score = 0;
    std::uint32_t reason_mask = 0;
    std::uint32_t writes = 0;
    std::uint32_t destructive_operations = 0;
    std::uint32_t distinct_objects = 0;
    bool create_incident = false;
    bool contain_process_tree = false;
};

class Detector final {
public:
    explicit Detector(Policy policy = {});
    [[nodiscard]] Verdict observe(const Observation& observation);
    void reset(std::uint64_t process_id);

private:
    struct ProcessWindow final { std::vector<Observation> observations; };
    Policy policy_;
    std::map<std::uint64_t, ProcessWindow> windows_;
};

}  // namespace ai_shield::ransomware

