#include "platform/windows/security/tpm_trust_anchor.hpp"

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>

#include <array>
#include <bit>

namespace ai_shield::platform::windows::security {
namespace {

constexpr wchar_t kKeyName[] = L"AIShield.Runtime.Attestation.v2";

struct Provider final {
    NCRYPT_PROV_HANDLE handle = 0;
    ~Provider() { if (handle != 0) NCryptFreeObject(handle); }
};

struct Key final {
    NCRYPT_KEY_HANDLE handle = 0;
    ~Key() { if (handle != 0) NCryptFreeObject(handle); }
};

bool open_provider(Provider& provider) {
    return NCryptOpenStorageProvider(&provider.handle, MS_PLATFORM_CRYPTO_PROVIDER, 0U) == ERROR_SUCCESS;
}

bool open_key(Provider& provider, Key& key) {
    return NCryptOpenKey(provider.handle, &key.handle, kKeyName, 0U,
                         NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
}

}  // namespace

TpmStatus tpm_status() noexcept {
    Provider provider{};
    if (!open_provider(provider)) return {};
    DWORD implementation = 0;
    DWORD bytes = 0;
    const bool hardware = NCryptGetProperty(provider.handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                             std::bit_cast<PBYTE>(&implementation), sizeof(implementation),
                                             &bytes, 0U) == ERROR_SUCCESS &&
                          (implementation & NCRYPT_IMPL_HARDWARE_FLAG) != 0U;
    Key key{};
    return {.provider_available = true, .hardware_backed = hardware, .key_available = open_key(provider, key)};
}

Result<void> ensure_tpm_anchor() noexcept {
    Provider provider{};
    if (!open_provider(provider)) return Status::not_found;
    Key existing{};
    if (open_key(provider, existing)) return {};
    Key key{};
    if (NCryptCreatePersistedKey(provider.handle, &key.handle, NCRYPT_RSA_ALGORITHM, kKeyName, 0U,
                                 NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
        return Status::integrity_failure;
    DWORD length = 2048U;
    if (NCryptSetProperty(key.handle, NCRYPT_LENGTH_PROPERTY, std::bit_cast<PBYTE>(&length), sizeof(length), 0U) !=
            ERROR_SUCCESS ||
        NCryptFinalizeKey(key.handle, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) return Status::integrity_failure;
    return {};
}

Result<std::vector<std::byte>> sign_tpm_challenge(std::span<const std::byte> challenge_hash) noexcept {
    if (challenge_hash.size() != 32U) return Status::invalid_argument;
    Provider provider{};
    Key key{};
    if (!open_provider(provider) || !open_key(provider, key)) return Status::not_found;
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    DWORD size = 0;
    if (NCryptSignHash(key.handle, &padding, std::bit_cast<PBYTE>(challenge_hash.data()),
                       static_cast<DWORD>(challenge_hash.size()), nullptr, 0U, &size,
                       NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS || size == 0U)
        return Status::integrity_failure;
    std::vector<std::byte> signature(size);
    if (NCryptSignHash(key.handle, &padding, std::bit_cast<PBYTE>(challenge_hash.data()),
                       static_cast<DWORD>(challenge_hash.size()), std::bit_cast<PBYTE>(signature.data()), size,
                       &size, NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
        return Status::integrity_failure;
    signature.resize(size);
    return signature;
}

}  // namespace ai_shield::platform::windows::security
