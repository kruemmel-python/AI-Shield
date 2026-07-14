#include "ai_shield/service_identity.hpp"

namespace ai_shield::service_identity {

Result<void> PinStore::add(CertificatePin pin) {
    if (pin.service_id == 0U) {
        return Status::invalid_argument;
    }
    pins_.push_back(pin);
    return {};
}

bool PinStore::verify(std::uint64_t service_id, const crypto::Sha256Digest& presented_spki) const noexcept {
    for (const auto& pin : pins_) {
        if (pin.service_id == service_id) {
            return crypto::constant_time_equal(pin.spki_sha256, presented_spki);
        }
    }
    return false;
}

}  // namespace ai_shield::service_identity
