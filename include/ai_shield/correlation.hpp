#pragma once

#include <cstdint>
#include <type_traits>

namespace ai_shield::correlation {

struct Context final {
    std::uint64_t flow_id = 0;
    std::uint64_t object_id = 0;
    std::uint64_t file_id = 0;
    std::uint64_t volume_id = 0;
    std::uint64_t provenance_id = 0;
    std::uint64_t process_id = 0;
    std::uint64_t parent_process_id = 0;
    std::uint64_t policy_version = 0;
    std::uint64_t model_version = 0;
};

[[nodiscard]] constexpr bool valid(const Context& context) noexcept {
    return context.flow_id != 0U && context.policy_version != 0U && context.model_version != 0U;
}

static_assert(sizeof(Context) == 72U);
static_assert(std::is_standard_layout_v<Context> && std::is_trivially_copyable_v<Context>);

}  // namespace ai_shield::correlation
