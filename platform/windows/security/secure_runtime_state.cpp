#include "platform/windows/security/secure_runtime_state.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>

#include <array>
#include <cstring>
#include <fstream>
#include <span>
#include <vector>

namespace ai_shield::platform::windows::security {
namespace {

constexpr std::array<unsigned char, 8> kMagic{'A', 'I', 'S', 'H', 'R', 'T', '0', '2'};
constexpr std::size_t kPlainSize = 8U + 4U * sizeof(std::uint64_t) + 64U;

void append_u64(std::vector<unsigned char>& bytes, std::uint64_t value) {
    for (std::size_t index = 0; index < 8U; ++index)
        bytes.push_back(static_cast<unsigned char>((value >> (index * 8U)) & 0xffU));
}

Result<std::uint64_t> read_u64(std::span<const unsigned char> bytes, std::size_t& offset) {
    if (offset + 8U > bytes.size()) return Status::malformed_input;
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8U; ++index)
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8U);
    offset += 8U;
    return value;
}

std::vector<unsigned char> serialize(const RuntimeState& state) {
    std::vector<unsigned char> bytes(kMagic.begin(), kMagic.end());
    bytes.reserve(kPlainSize);
    append_u64(bytes, state.generation);
    append_u64(bytes, state.policy_version);
    append_u64(bytes, state.model_version);
    append_u64(bytes, state.previous_generation);
    for (const auto value : state.channel_key) bytes.push_back(std::to_integer<unsigned char>(value));
    for (const auto value : state.previous_channel_key) bytes.push_back(std::to_integer<unsigned char>(value));
    return bytes;
}

Result<RuntimeState> deserialize(std::span<const unsigned char> bytes) {
    if (bytes.size() != kPlainSize || !std::equal(kMagic.begin(), kMagic.end(), bytes.begin()))
        return Status::malformed_input;
    std::size_t offset = kMagic.size();
    const auto generation = read_u64(bytes, offset);
    const auto policy = read_u64(bytes, offset);
    const auto model = read_u64(bytes, offset);
    const auto previous = read_u64(bytes, offset);
    if (!generation.ok() || !policy.ok() || !model.ok() || !previous.ok() ||
        generation.value() == 0U || model.value() == 0U) return Status::integrity_failure;
    RuntimeState state{generation.value(), policy.value(), model.value(), previous.value()};
    for (auto& value : state.channel_key) value = static_cast<std::byte>(bytes[offset++]);
    for (auto& value : state.previous_channel_key) value = static_cast<std::byte>(bytes[offset++]);
    return state;
}

bool random_key(crypto::Sha256Digest& key) {
    std::array<unsigned char, 32> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    std::memcpy(key.data(), random.data(), key.size());
    SecureZeroMemory(random.data(), random.size());
    return true;
}

bool atomic_write(const std::filesystem::path& path, std::span<const unsigned char> bytes) {
    const auto temporary = path.wstring() + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE || bytes.size() > MAXDWORD) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                    written == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok) { DeleteFileW(temporary.c_str()); return false; }
    return MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

}  // namespace

SecureRuntimeStore::SecureRuntimeStore(std::filesystem::path directory) : directory_(std::move(directory)) {}

Result<RuntimeState> SecureRuntimeStore::load() const {
    const auto read_protected = [](const std::filesystem::path& path) -> Result<RuntimeState> {
        std::ifstream input(path, std::ios::binary);
        if (!input) return Status::not_found;
        std::vector<unsigned char> encrypted((std::istreambuf_iterator<char>(input)), {});
        if (encrypted.empty() || encrypted.size() > MAXDWORD) return Status::malformed_input;
        DATA_BLOB source{static_cast<DWORD>(encrypted.size()), encrypted.data()};
        DATA_BLOB plain{};
        if (!CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &plain))
            return Status::integrity_failure;
        const auto state = deserialize(std::span<const unsigned char>(plain.pbData, plain.cbData));
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
        return state;
    };
    auto state = read_protected(directory_ / L"runtime-state.dpapi");
    if (state.ok()) return state;
    state = read_protected(directory_ / L"runtime-state.recovery.dpapi");
    if (state.ok()) {
        std::error_code error;
        std::filesystem::remove(directory_ / L"runtime-state.dpapi", error);
        if (error) return Status::integrity_failure;
        const auto restored = save(state.value());
        if (!restored.ok()) return restored.status();
    }
    return state;
}

Result<void> SecureRuntimeStore::save(const RuntimeState& state) const {
    auto plain = serialize(state);
    DATA_BLOB source{static_cast<DWORD>(plain.size()), plain.data()};
    DATA_BLOB encrypted{};
    if (!CryptProtectData(&source, L"AI Shield Runtime State v2", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &encrypted)) return Status::integrity_failure;
    std::error_code error;
    std::filesystem::create_directories(directory_, error);
    const auto primary = directory_ / L"runtime-state.dpapi";
    const auto recovery = directory_ / L"runtime-state.recovery.dpapi";
    bool ok = true;
    if (std::filesystem::exists(primary, error)) {
        std::filesystem::copy_file(primary, recovery, std::filesystem::copy_options::overwrite_existing, error);
        ok = !error;
    }
    if (ok) ok = atomic_write(primary, std::span<const unsigned char>(encrypted.pbData, encrypted.cbData));
    SecureZeroMemory(encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    return ok ? Result<void>{} : Result<void>{Status::integrity_failure};
}

Result<RuntimeState> SecureRuntimeStore::load_or_create() const {
    auto loaded = load();
    if (loaded.ok()) return loaded;
    if (std::filesystem::exists(directory_ / L"runtime-state.dpapi") ||
        std::filesystem::exists(directory_ / L"runtime-state.recovery.dpapi"))
        return Status::integrity_failure;
    RuntimeState state{};
    const auto legacy = directory_ / L"channel.key";
    std::ifstream input(legacy, std::ios::binary);
    std::array<char, 32> legacy_bytes{};
    if (input.read(legacy_bytes.data(), legacy_bytes.size()) && input.peek() == EOF)
        std::memcpy(state.channel_key.data(), legacy_bytes.data(), state.channel_key.size());
    else if (!random_key(state.channel_key)) return Status::integrity_failure;
    SecureZeroMemory(legacy_bytes.data(), legacy_bytes.size());
    const auto saved = save(state);
    if (!saved.ok()) return saved.status();
    if (std::filesystem::exists(legacy)) {
        std::error_code error;
        std::filesystem::remove(legacy, error);
        if (error) return Status::integrity_failure;
    }
    return state;
}

Result<RuntimeState> SecureRuntimeStore::update_versions(std::uint64_t policy_version,
                                                         std::uint64_t model_version) const {
    if (policy_version == 0U || model_version == 0U) return Status::invalid_argument;
    auto state = load_or_create();
    if (!state.ok() || policy_version < state.value().policy_version || model_version < state.value().model_version)
        return Status::integrity_failure;
    state.value().policy_version = policy_version;
    state.value().model_version = model_version;
    const auto saved = save(state.value());
    return saved.ok() ? state : Result<RuntimeState>{saved.status()};
}

Result<RuntimeState> SecureRuntimeStore::rotate_key() const {
    auto state = load_or_create();
    if (!state.ok() || state.value().generation == UINT64_MAX) return Status::integrity_failure;
    state.value().previous_generation = state.value().generation;
    state.value().previous_channel_key = state.value().channel_key;
    ++state.value().generation;
    if (!random_key(state.value().channel_key)) return Status::integrity_failure;
    const auto saved = save(state.value());
    return saved.ok() ? state : Result<RuntimeState>{saved.status()};
}

}  // namespace ai_shield::platform::windows::security
