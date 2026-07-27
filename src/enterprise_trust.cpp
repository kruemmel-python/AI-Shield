#include "ai_shield/enterprise_trust.hpp"

#include <algorithm>

namespace ai_shield::enterprise::trust {
namespace {

[[nodiscard]] bool zero(const crypto::Sha256Digest& value) noexcept {
    crypto::Sha256Digest empty{};
    return crypto::constant_time_equal(value, empty);
}

}  // namespace

Result<void> validate(const DeviceIdentity& identity, const AttestationEvidence& evidence,
                      std::uint64_t now_ns, bool require_tpm) noexcept {
    if (identity.organization_id == 0U || identity.site_id == 0U || identity.device_id == 0U ||
        identity.certificate_serial == 0U || identity.enrollment_epoch == 0U ||
        identity.certificate_not_before_ns > now_ns || identity.certificate_not_after_ns <= now_ns ||
        identity.certificate_not_before_ns >= identity.certificate_not_after_ns ||
        identity.state == IdentityState::revoked || zero(identity.hardware_binding) ||
        zero(identity.public_key_spki)) {
        return Status::invalid_argument;
    }
    if (!crypto::constant_time_equal(identity.hardware_binding, evidence.hardware_binding) ||
        !crypto::constant_time_equal(identity.public_key_spki, evidence.public_key_spki)) {
        return Status::integrity_failure;
    }
    if (require_tpm && (!identity.tpm_bound || !evidence.key_attested || !evidence.secure_boot ||
                        !evidence.measured_boot)) {
        return Status::integrity_failure;
    }
    return {};
}

Result<void> DeviceRegistry::enroll(DeviceIdentity identity, const AttestationEvidence& evidence,
                                    std::uint64_t now_ns, bool require_tpm) {
    const auto verified = validate(identity, evidence, now_ns, require_tpm);
    if (!verified.ok()) return verified.status();
    for (const auto& known : devices_) {
        if (known.device_id == identity.device_id) {
            if (!crypto::constant_time_equal(known.hardware_binding, identity.hardware_binding))
                return Status::integrity_failure;
            return Status::invalid_state_transition;
        }
        if (known.certificate_serial == identity.certificate_serial ||
            crypto::constant_time_equal(known.public_key_spki, identity.public_key_spki))
            return Status::integrity_failure;
    }
    identity.state = IdentityState::active;
    devices_.push_back(identity);
    return {};
}

Result<void> DeviceRegistry::rotate(std::uint64_t device_id, std::uint64_t expected_certificate_serial,
                                    std::uint64_t new_certificate_serial,
                                    crypto::Sha256Digest new_public_key_spki,
                                    std::uint64_t not_before_ns, std::uint64_t not_after_ns) {
    if (device_id == 0U || new_certificate_serial == 0U ||
        expected_certificate_serial == new_certificate_serial || zero(new_public_key_spki) ||
        not_before_ns >= not_after_ns)
        return Status::invalid_argument;
    auto found = std::find_if(devices_.begin(), devices_.end(),
                             [device_id](const DeviceIdentity& item) { return item.device_id == device_id; });
    if (found == devices_.end()) return Status::not_found;
    if (found->state != IdentityState::active || found->certificate_serial != expected_certificate_serial)
        return Status::integrity_failure;
    for (const auto& known : devices_) {
        if (known.device_id != device_id &&
            (known.certificate_serial == new_certificate_serial ||
             crypto::constant_time_equal(known.public_key_spki, new_public_key_spki)))
            return Status::integrity_failure;
    }
    found->certificate_serial = new_certificate_serial;
    found->public_key_spki = new_public_key_spki;
    found->certificate_not_before_ns = not_before_ns;
    found->certificate_not_after_ns = not_after_ns;
    ++found->enrollment_epoch;
    return {};
}

Result<void> DeviceRegistry::revoke(std::uint64_t device_id) noexcept {
    auto found = std::find_if(devices_.begin(), devices_.end(),
                             [device_id](const DeviceIdentity& item) { return item.device_id == device_id; });
    if (found == devices_.end()) return Status::not_found;
    found->state = IdentityState::revoked;
    return {};
}

Result<void> DeviceRegistry::authorize(std::uint64_t device_id, std::uint64_t certificate_serial,
                                       const crypto::Sha256Digest& hardware_binding,
                                       std::uint64_t now_ns) const noexcept {
    const auto found = std::find_if(devices_.begin(), devices_.end(),
                                   [device_id](const DeviceIdentity& item) { return item.device_id == device_id; });
    if (found == devices_.end()) return Status::not_found;
    if (found->state != IdentityState::active || found->certificate_serial != certificate_serial ||
        now_ns < found->certificate_not_before_ns || now_ns >= found->certificate_not_after_ns ||
        !crypto::constant_time_equal(found->hardware_binding, hardware_binding))
        return Status::integrity_failure;
    return {};
}

}  // namespace ai_shield::enterprise::trust
