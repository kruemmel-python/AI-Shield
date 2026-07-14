#pragma once

#include <cstdint>
#include <string_view>

#include <windows.h>

#include "ai_shield/result.hpp"
#include "ai_shield/sandbox_budget.hpp"

namespace ai_shield::platform::windows::sandbox {

struct AppContainerLaunchSpec final {
    std::uint64_t analysis_id = 0;
    std::uint32_t parser_id = 0;
    ai_shield::sandbox_budget::Budget budget{};
    bool allow_network = false;
    bool allow_child_processes = false;
    std::wstring_view executable_path;
    std::wstring_view work_directory;
    std::wstring_view result_pipe_name;
};

struct LaunchedProcess final {
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    HANDLE job = nullptr;
    std::uint32_t process_id = 0;
};

[[nodiscard]] ai_shield::Result<void> validate_launch_spec(const AppContainerLaunchSpec& spec) noexcept;
[[nodiscard]] ai_shield::Result<LaunchedProcess> launch_shadow_parser(const AppContainerLaunchSpec& spec) noexcept;
[[nodiscard]] ai_shield::Result<void> resume_launched_process(LaunchedProcess& process) noexcept;
void close_launched_process(LaunchedProcess& process) noexcept;

}  // namespace ai_shield::platform::windows::sandbox
