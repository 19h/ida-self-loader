#include "self_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace {

template <typename T>
void put_le(std::vector<std::uint8_t>& data, std::size_t offset, T value) {
    using Unsigned = std::make_unsigned_t<T>;
    Unsigned current = static_cast<Unsigned>(value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        data[offset + i] = static_cast<std::uint8_t>(current & 0xFF);
        current >>= 8;
    }
}

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

std::vector<std::uint8_t> synthetic_self() {
    std::vector<std::uint8_t> data(512, 0);
    put_le<std::uint32_t>(data, 0, self::kSelfMagic);
    put_le<std::uint16_t>(data, 0x18, 2);

    put_le<std::uint64_t>(data, 0x20, 0x2804);
    put_le<std::uint64_t>(data, 0x28, 0x1000);
    put_le<std::uint64_t>(data, 0x30, 0x100);
    put_le<std::uint64_t>(data, 0x38, 0x100);
    put_le<std::uint64_t>(data, 0x40, 0x2804);
    put_le<std::uint64_t>(data, 0x48, 0x2000);
    put_le<std::uint64_t>(data, 0x50, 0x200);
    put_le<std::uint64_t>(data, 0x58, 0x1000);

    constexpr std::size_t elf = 0x60;
    data[elf] = 0x7F;
    data[elf + 1] = 'E';
    data[elf + 2] = 'L';
    data[elf + 3] = 'F';
    data[elf + 4] = 2;
    data[elf + 5] = 1;
    data[elf + 6] = 1;
    data[elf + 7] = 9;
    put_le<std::uint16_t>(data, elf + 16, 0xFE10);
    put_le<std::uint16_t>(data, elf + 18, 62);
    put_le<std::uint32_t>(data, elf + 20, 1);
    put_le<std::uint64_t>(data, elf + 24, 0x40);
    put_le<std::uint64_t>(data, elf + 32, 64);
    put_le<std::uint16_t>(data, elf + 52, 64);
    put_le<std::uint16_t>(data, elf + 54, 56);
    put_le<std::uint16_t>(data, elf + 56, 2);

    const std::size_t code = elf + 64;
    put_le<std::uint32_t>(data, code, 1);
    put_le<std::uint32_t>(data, code + 4, 5);
    put_le<std::uint64_t>(data, code + 8, 0x4000);
    put_le<std::uint64_t>(data, code + 16, 0);
    put_le<std::uint64_t>(data, code + 32, 0x100);
    put_le<std::uint64_t>(data, code + 40, 0x100);

    const std::size_t writable = code + 56;
    put_le<std::uint32_t>(data, writable, 1);
    put_le<std::uint32_t>(data, writable + 4, 6);
    put_le<std::uint64_t>(data, writable + 8, 0x5000);
    put_le<std::uint64_t>(data, writable + 16, 0x4000);
    put_le<std::uint64_t>(data, writable + 32, 0x200);
    put_le<std::uint64_t>(data, writable + 40, 0x1000);
    return data;
}

void run_synthetic_tests() {
    const std::vector<std::uint8_t> valid = synthetic_self();
    self::Image image;
    std::string error;
    require(self::parse_header(valid, 0x3000, image, error), "valid synthetic SELF rejected");
    require(image.entry == 0x40, "wrong synthetic entry point");
    require(image.segments.size() == 2, "wrong synthetic segment count");
    require(image.segments[0].file_offset == 0x1000
            && image.segments[0].virtual_address == 0
            && image.segments[0].executable(), "wrong synthetic text mapping");
    require(image.segments[1].file_offset == 0x2000
            && image.segments[1].memory_size == 0x1000
            && image.segments[1].writable(), "wrong synthetic data/BSS mapping");

    std::vector<std::uint8_t> malformed = valid;
    put_le<std::uint64_t>(malformed, 0x30, 0x101);
    require(!self::parse_header(malformed, 0x3000, image, error),
            "mismatched compressed payload was accepted");

    malformed = valid;
    put_le<std::uint64_t>(malformed, 0x28, 0x2F01);
    require(!self::parse_header(malformed, 0x3000, image, error),
            "out-of-file payload was accepted");

    malformed = valid;
    malformed[0x60 + 4] = 1;
    require(!self::parse_header(malformed, 0x3000, image, error),
            "ELF32 container was accepted");

    const std::vector<std::uint8_t> truncated(valid.begin(), valid.begin() + 100);
    require(!self::parse_header(truncated, 0x3000, image, error),
            "truncated SELF was accepted");
}

void verify_reference_file(const char* path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    require(input.good(), "could not open reference SELF");
    const std::streamoff stream_size = input.tellg();
    require(stream_size > 0, "reference SELF is empty");
    const auto file_size = static_cast<std::uint64_t>(stream_size);
    const std::size_t header_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(file_size, self::kMaxHeaderBytes));
    std::vector<std::uint8_t> data(header_size);
    input.seekg(0);
    input.read(reinterpret_cast<char*>(data.data()), data.size());
    require(input.good(), "could not read reference SELF headers");

    self::Image image;
    std::string error;
    require(self::parse_header(data, file_size, image, error), error.c_str());
    require(image.entry == 0x4366790, "reference entry point mismatch");
    require(image.segments.size() == 5, "reference PT_LOAD count mismatch");
    constexpr std::uint64_t offsets[] = {
        0x485D0, 0x8FB93B0, 0x9F18B90, 0xA43E4F0, 0xAC33C10,
    };
    constexpr std::uint64_t sizes[] = {
        0x8F692DC, 0xF5CEC0, 0x5219E0, 0x7EE4B6, 0xE48B58,
    };
    for (std::size_t i = 0; i < 5; ++i) {
        require(image.segments[i].file_offset == offsets[i],
                "reference SELF payload offset mismatch");
        require(image.segments[i].file_size == sizes[i],
                "reference SELF payload size mismatch");
    }
    require(image.segments[3].memory_size == 0x43D54E8,
            "reference BSS size mismatch");
}

} // namespace

int main(int argc, char** argv) {
    try {
        run_synthetic_tests();
        if (argc == 2)
            verify_reference_file(argv[1]);
        else if (argc > 2)
            throw std::runtime_error("usage: self_parser_tests [reference-SELF]");
        std::cout << "SELF parser tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "SELF parser test failed: " << exception.what() << '\n';
        return 1;
    }
}
