#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

namespace {

constexpr std::uint32_t kMaximumMessage = 64U * 1024U;
constexpr wchar_t kEventSource[] = L"AIShieldBrowser";

bool valid_message(std::string_view message) noexcept {
    if (message.size() < 2U || message.size() > kMaximumMessage || message.front() != '{' ||
        message.back() != '}') return false;
    for (const unsigned char value : message) {
        if (value < 0x20U || value == 0x7fU) return false;
    }
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, message.data(),
                               static_cast<int>(message.size()), nullptr, 0) > 0;
}

bool read_exact(std::span<char> output) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        std::cin.read(output.data() + offset, static_cast<std::streamsize>(output.size() - offset));
        const auto count = static_cast<std::size_t>(std::cin.gcount());
        if (count == 0U) return false;
        offset += count;
    }
    return true;
}

bool write_message(std::string_view message) {
    const auto length = static_cast<std::uint32_t>(message.size());
    const std::array<char,4> prefix{
        static_cast<char>(length & 0xffU), static_cast<char>((length >> 8U) & 0xffU),
        static_cast<char>((length >> 16U) & 0xffU), static_cast<char>((length >> 24U) & 0xffU)};
    std::cout.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
    std::cout.write(message.data(), static_cast<std::streamsize>(message.size()));
    std::cout.flush();
    return std::cout.good();
}

bool emit_event(std::string_view message) {
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, message.data(),
                                             static_cast<int>(message.size()), nullptr, 0);
    if (required <= 0) return false;
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, message.data(),
                            static_cast<int>(message.size()), wide.data(), required) != required) return false;
    HANDLE source = RegisterEventSourceW(nullptr, kEventSource);
    if (source == nullptr) return false;
    const wchar_t* strings[] = {wide.c_str()};
    const bool emitted = ReportEventW(source, EVENTLOG_INFORMATION_TYPE, 0U, 2001U, nullptr,
                                      1U, 0U, strings, nullptr) != FALSE;
    DeregisterEventSource(source);
    return emitted;
}

int run() {
    for (;;) {
        std::array<char, sizeof(std::uint32_t)> prefix{};
        if (!read_exact(prefix)) return std::cin.eof() ? 0 : 3;
        const auto length = static_cast<std::uint32_t>(static_cast<unsigned char>(prefix[0])) |
                            (static_cast<std::uint32_t>(static_cast<unsigned char>(prefix[1])) << 8U) |
                            (static_cast<std::uint32_t>(static_cast<unsigned char>(prefix[2])) << 16U) |
                            (static_cast<std::uint32_t>(static_cast<unsigned char>(prefix[3])) << 24U);
        if (length == 0U || length > kMaximumMessage) return 4;
        std::string message(length, '\0');
        if (!read_exact(message)) return 3;
        if (!valid_message(message)) {
            if (!write_message("{\"accepted\":false}")) return 3;
            continue;
        }
        const bool accepted = emit_event(message);
        if (!write_message(accepted ? "{\"accepted\":true}" : "{\"accepted\":false}")) return 3;
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"self-test") {
        return valid_message("{\"schema\":1}") && !valid_message("{}\n") &&
               !valid_message(std::string(kMaximumMessage + 1U, 'x')) ? 0 : 2;
    }
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    return run();
}
