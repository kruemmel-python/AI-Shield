#include "platform/windows/minifilter/provenance_adapter.hpp"

namespace ai_shield::platform::windows::minifilter {

ai_shield::Result<void> apply_file_event(ai_shield::provenance::Store& store, const FileEvent& event) noexcept {
    switch (event.operation) {
    case FileOperation::external_create:
        return store.record_external(event.target);
    case FileOperation::copy:
        return store.propagate_copy(event.source, event.target);
    case FileOperation::rename:
        return store.propagate_rename(event.source, event.target);
    case FileOperation::image_load:
        return store.execution_allowed(event.target).ok() && store.execution_allowed(event.target).value()
                   ? ai_shield::Result<void>{}
                   : ai_shield::Result<void>{ai_shield::Status::invalid_state_transition};
    }
    return ai_shield::Status::invalid_argument;
}

}  // namespace ai_shield::platform::windows::minifilter
