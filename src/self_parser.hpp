#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace self {

constexpr std::uint32_t kSelfMagic = 0x1D3D154F;
constexpr std::size_t kMaxSelfSegments = 64;
constexpr std::size_t kMaxProgramHeaders = 128;
constexpr std::size_t kMaxHeaderBytes =
        0x20 + kMaxSelfSegments * 32 + 64 + kMaxProgramHeaders * 56;

struct LoadSegment {
    std::size_t program_header_index = 0;
    std::size_t self_segment_index = 0;
    std::uint32_t flags = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;

    bool executable() const { return (flags & 1U) != 0; }
    bool writable() const { return (flags & 2U) != 0; }
    bool readable() const { return (flags & 4U) != 0; }
};

struct Image {
    std::uint64_t entry = 0;
    std::uint16_t elf_type = 0;
    std::vector<LoadSegment> segments;
};

// data holds only the beginning of the file, up to kMaxHeaderBytes.
// file_size is the complete input size used to validate all payload ranges.
bool parse_header(
        const std::vector<std::uint8_t>& data,
        std::uint64_t file_size,
        Image& image,
        std::string& error);

} // namespace self
