#include "self_parser.hpp"

#include <limits>
#include <type_traits>
#include <utility>

namespace self {
namespace {

constexpr std::uint16_t kElfTypeSceExec = 0xFE00;
constexpr std::uint16_t kElfTypeSceDynExec = 0xFE10;
constexpr std::uint16_t kElfMachineX86_64 = 62;
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint64_t kSelfPayloadFlag = 0x800;

struct SelfSegment {
    std::size_t index;
    std::uint64_t offset;
    std::uint64_t size;
};

template <typename T>
bool read_le(const std::vector<std::uint8_t>& data, std::size_t offset, T& value) {
    if (offset > data.size() || sizeof(T) > data.size() - offset)
        return false;

    using Unsigned = std::make_unsigned_t<T>;
    Unsigned result = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        result |= static_cast<Unsigned>(data[offset + i]) << (i * 8);
    value = static_cast<T>(result);
    return true;
}

bool contains(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

bool fail(std::string& error, const std::string& message) {
    error = message;
    return false;
}

bool parse_self_segment(
        const std::vector<std::uint8_t>& data,
        std::size_t offset,
        std::uint64_t& flags,
        SelfSegment& segment) {
    std::uint64_t uncompressed_size = 0;
    return read_le(data, offset, flags)
            && read_le(data, offset + 8, segment.offset)
            && read_le(data, offset + 16, segment.size)
            && read_le(data, offset + 24, uncompressed_size);
}

} // namespace

bool parse_header(
        const std::vector<std::uint8_t>& data,
        std::uint64_t file_size,
        Image& image,
        std::string& error) {
    error.clear();
    image = Image{};

    std::uint32_t magic = 0;
    if (!read_le(data, 0, magic))
        return fail(error, "Input is too small for a SELF header");
    if (magic != kSelfMagic)
        return fail(error, "Sony SELF magic was not found");

    std::uint16_t self_segment_count = 0;
    if (!read_le(data, 0x18, self_segment_count))
        return fail(error, "Truncated SELF header");
    if (self_segment_count == 0 || self_segment_count > kMaxSelfSegments)
        return fail(error, "Invalid SELF segment count");

    const std::size_t elf_offset = 0x20 + self_segment_count * 32;
    if (elf_offset > data.size() || 64 > data.size() - elf_offset)
        return fail(error, "Truncated embedded ELF header");

    if (data[elf_offset] != 0x7F || data[elf_offset + 1] != 'E'
            || data[elf_offset + 2] != 'L' || data[elf_offset + 3] != 'F')
        return fail(error, "Embedded ELF header was not found");
    if (data[elf_offset + 4] != 2 || data[elf_offset + 5] != 1)
        return fail(error, "Only little-endian ELF64 SELF files are supported");
    if (data[elf_offset + 6] != 1 || data[elf_offset + 7] != 9)
        return fail(error, "Embedded ELF is not a Sony System-V executable");

    std::uint16_t elf_type = 0;
    std::uint16_t machine = 0;
    std::uint32_t elf_version = 0;
    std::uint64_t entry = 0;
    std::uint64_t program_offset = 0;
    std::uint16_t elf_header_size = 0;
    std::uint16_t program_entry_size = 0;
    std::uint16_t program_count = 0;
    if (!read_le(data, elf_offset + 16, elf_type)
            || !read_le(data, elf_offset + 18, machine)
            || !read_le(data, elf_offset + 20, elf_version)
            || !read_le(data, elf_offset + 24, entry)
            || !read_le(data, elf_offset + 32, program_offset)
            || !read_le(data, elf_offset + 52, elf_header_size)
            || !read_le(data, elf_offset + 54, program_entry_size)
            || !read_le(data, elf_offset + 56, program_count))
        return fail(error, "Truncated ELF64 header fields");

    if (elf_type != kElfTypeSceExec && elf_type != kElfTypeSceDynExec)
        return fail(error, "Unsupported Sony ELF executable type");
    if (machine != kElfMachineX86_64 || elf_version != 1)
        return fail(error, "Embedded ELF is not an AMD64 executable");
    if (elf_header_size < 64 || program_entry_size != 56)
        return fail(error, "Unsupported ELF64 header layout");
    if (program_count == 0 || program_count > kMaxProgramHeaders)
        return fail(error, "Invalid ELF program-header count");

    const std::uint64_t program_bytes =
            static_cast<std::uint64_t>(program_entry_size) * program_count;
    if (!contains(program_offset, program_bytes, data.size() - elf_offset))
        return fail(error, "ELF program headers exceed the buffered header area");

    std::vector<SelfSegment> payloads;
    for (std::size_t i = 0; i < self_segment_count; ++i) {
        SelfSegment segment{i, 0, 0};
        std::uint64_t flags = 0;
        if (!parse_self_segment(data, 0x20 + i * 32, flags, segment))
            return fail(error, "Truncated SELF segment table");
        if ((flags & kSelfPayloadFlag) != 0)
            payloads.push_back(segment);
    }

    Image parsed;
    parsed.entry = entry;
    parsed.elf_type = elf_type;
    std::size_t payload_index = 0;
    const std::size_t program_table = elf_offset + program_offset;

    for (std::size_t i = 0; i < program_count; ++i) {
        const std::size_t current = program_table + i * program_entry_size;
        std::uint32_t type = 0;
        std::uint32_t flags = 0;
        std::uint64_t virtual_address = 0;
        std::uint64_t file_size_in_elf = 0;
        std::uint64_t memory_size = 0;
        std::uint64_t unused = 0;
        if (!read_le(data, current, type)
                || !read_le(data, current + 4, flags)
                || !read_le(data, current + 8, unused)
                || !read_le(data, current + 16, virtual_address)
                || !read_le(data, current + 32, file_size_in_elf)
                || !read_le(data, current + 40, memory_size))
            return fail(error, "Truncated ELF program header");
        if (type != kPtLoad)
            continue;
        if (memory_size < file_size_in_elf
                || !contains(virtual_address, memory_size,
                             std::numeric_limits<std::uint64_t>::max()))
            return fail(error, "Invalid PT_LOAD memory range");

        LoadSegment load;
        load.program_header_index = i;
        load.flags = flags;
        load.virtual_address = virtual_address;
        load.file_size = file_size_in_elf;
        load.memory_size = memory_size;

        if (file_size_in_elf != 0) {
            if (payload_index >= payloads.size())
                return fail(error, "Missing SELF payload for a PT_LOAD segment");
            const SelfSegment& payload = payloads[payload_index++];
            if (payload.size != file_size_in_elf)
                return fail(error,
                        "SELF/ELF payload sizes differ; compressed or encrypted "
                        "payloads must be unpacked before loading");
            if (!contains(payload.offset, payload.size, file_size))
                return fail(error, "SELF payload extends past end of file");
            load.self_segment_index = payload.index;
            load.file_offset = payload.offset;
        } else {
            load.self_segment_index = std::numeric_limits<std::size_t>::max();
        }
        parsed.segments.push_back(load);
    }

    if (parsed.segments.empty())
        return fail(error, "ELF contains no PT_LOAD segments");

    for (std::size_t i = 0; i < parsed.segments.size(); ++i) {
        const LoadSegment& a = parsed.segments[i];
        const std::uint64_t a_end = a.virtual_address + a.memory_size;
        for (std::size_t j = i + 1; j < parsed.segments.size(); ++j) {
            const LoadSegment& b = parsed.segments[j];
            const std::uint64_t b_end = b.virtual_address + b.memory_size;
            if (a.virtual_address < b_end && b.virtual_address < a_end)
                return fail(error, "PT_LOAD virtual-memory ranges overlap");
        }
    }

    if (entry != 0) {
        bool valid_entry = false;
        for (const LoadSegment& load : parsed.segments) {
            if (load.executable()
                    && entry >= load.virtual_address
                    && entry - load.virtual_address < load.memory_size) {
                valid_entry = true;
                break;
            }
        }
        if (!valid_entry)
            return fail(error, "ELF entry point is outside executable PT_LOAD segments");
    }

    // Any remaining payload records belong to non-PT_LOAD ELF metadata.
    image = std::move(parsed);
    return true;
}

} // namespace self
