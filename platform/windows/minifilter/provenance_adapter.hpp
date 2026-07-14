#pragma once

#include <cstdint>

#include "ai_shield/provenance.hpp"
#include "ai_shield/result.hpp"

namespace ai_shield::platform::windows::minifilter {

enum class FileOperation : std::uint32_t {
    external_create,
    copy,
    rename,
    image_load
};

struct FileEvent final {
    FileOperation operation = FileOperation::external_create;
    ai_shield::provenance::FileIdentity source{};
    ai_shield::provenance::FileIdentity target{};
};

[[nodiscard]] ai_shield::Result<void> apply_file_event(ai_shield::provenance::Store& store,
                                                       const FileEvent& event) noexcept;

}  // namespace ai_shield::platform::windows::minifilter
