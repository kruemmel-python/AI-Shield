#pragma once

#include <cstdint>
#include <vector>

#include "ai_shield/result.hpp"
#include "ai_shield/sha256.hpp"

namespace ai_shield::enterprise::trust {

enum class IdentityState : std::uint32_t { pending, active, revoked, recovery };

struct DeviceIdentity final {
    std::uint64_t organization_id = 0;
    std::uint64_t site_id = 0;
    std::uint64_t device_id = 0;
    std::uint64_t certificate_serial = 0;
    std::uint64_t certificate_not_before_ns = 0;
    std::uint64_t certificate_not_after_ns = 0;
    std::uint64_t enrollment_epoch = 0;
    crypto::Sha256Digest hardware_binding{};
    crypto::Sha256Digest public_key_spki{};
    IdentityState state = IdentityState::pending;
    bool tpm_bound = false;
};

struct AttestationEvidence final {
    crypto::Sha256Digest hardware_binding{};
    crypto::Sha256Digest public_key_spki{};
    bool secure_boot = false;
    bool measured_boot = false;
    bool key_attested = false;
};

[[nodiscard]] Result<void> validate(const DeviceIdentity& identity,
                                    const AttestationEvidence& evidence,
                                    std::uint64_t now_ns,
                                    bool require_tpm) noexcept;

class DeviceRegistry final {
public:
    [[nodiscard]] Result<void> enroll(DeviceIdentity identity, const AttestationEvidence& evidence,
                                      std::uint64_t now_ns, bool require_tpm);
    [[nodiscard]] Result<void> rotate(std::uint64_t device_id, std::uint64_t expected_certificate_serial,
                                      std::uint64_t new_certificate_serial,
                                      crypto::Sha256Digest new_public_key_spki,
                                      std::uint64_t not_before_ns, std::uint64_t not_after_ns);
    [[nodiscard]] Result<void> revoke(std::uint64_t device_id) noexcept;
    [[nodiscard]] Result<void> authorize(std::uint64_t device_id, std::uint64_t certificate_serial,
                                         const crypto::Sha256Digest& hardware_binding,
                                         std::uint64_t now_ns) const noexcept;
    [[nodiscard]] const std::vector<DeviceIdentity>& devices() const noexcept { return devices_; }

private:
    std::vector<DeviceIdentity> devices_;
};

}  // namespace ai_shield::enterprise::trust
