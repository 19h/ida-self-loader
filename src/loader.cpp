#include <ida.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <segment.hpp>

#include "self_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace {

constexpr ea_t kImageBase = 0x400000;

bool read_image(linput_t* li, self::Image& image, std::string& error) {
    const qoff64_t input_size = qlsize(li);
    if (input_size <= 0) {
        error = "Empty input file";
        return false;
    }

    const std::uint64_t file_size = static_cast<std::uint64_t>(input_size);
    const std::size_t bytes_to_read = static_cast<std::size_t>(
            std::min<std::uint64_t>(file_size, self::kMaxHeaderBytes));
    std::vector<std::uint8_t> headers(bytes_to_read);
    if (qlseek(li, 0, SEEK_SET) != 0
            || qlread(li, headers.data(), headers.size())
                    != static_cast<ssize_t>(headers.size())) {
        error = "Could not read SELF headers";
        return false;
    }
    return self::parse_header(headers, file_size, image, error);
}

int idaapi accept_file(
        qstring* fileformatname,
        qstring* processor,
        linput_t* li,
        const char* /*filename*/) {
    if (li == nullptr)
        return 0;

    self::Image image;
    std::string error;
    try {
        if (!read_image(li, image, error))
            return 0;
    } catch (...) {
        return 0;
    }

    *fileformatname = "Sony SELF/fSELF executable (decrypted AMD64)";
    *processor = "metapc";
    return 1;
}

const char* segment_name(const self::LoadSegment& load, std::size_t index,
                         char (&buffer)[32]) {
    if (load.executable()) {
        qsnprintf(buffer, sizeof(buffer), ".text%zu", index);
        return buffer;
    }
    if (load.writable()) {
        qsnprintf(buffer, sizeof(buffer), ".data%zu", index);
        return buffer;
    }
    qsnprintf(buffer, sizeof(buffer), ".rdata%zu", index);
    return buffer;
}

void create_segment(const self::LoadSegment& load, std::size_t index) {
    const ea_t start = kImageBase + load.virtual_address;
    if (start < kImageBase || load.memory_size > BADADDR - start)
        loader_failure("PT_LOAD address range overflows IDA's address space");

    char name_buffer[32];
    const char* name = segment_name(load, index, name_buffer);
    const char* segment_class = load.executable()
            ? "CODE" : (load.writable() ? "DATA" : "CONST");

    segment_info_t info;
    info.start_ea = start;
    info.end_ea = start + load.memory_size;
    info.set_sel(allocate_selector(0));
    info.set_align(saRelByte);
    info.set_comb(scPub);
    info.set_bitness(2);
    info.set_type(load.executable() ? SEG_CODE : SEG_DATA);
    // Keep every mapped segment readable to help static analysis.
    uchar permissions = SEGPERM_READ;
    if (load.writable())
        permissions |= SEGPERM_WRITE;
    if (load.executable())
        permissions |= SEGPERM_EXEC;
    info.set_perm(permissions);
    info.set_name(name);
    info.set_sclass(segment_class);

    if (!add_segment_ex(&info, ADDSEG_NOSREG | ADDSEG_SPARSE))
        loader_failure("Could not create segment %s", name);
}

void idaapi load_file(
        linput_t* li,
        ushort neflags,
        const char* /*fileformatname*/) {
    self::Image image;
    std::string error;
    try {
        if (!read_image(li, image, error))
            loader_failure("%s", error.c_str());
    } catch (const std::exception& exception) {
        loader_failure("SELF loader: %s", exception.what());
    } catch (...) {
        loader_failure("SELF loader: unknown parsing error");
    }

    set_processor_type("metapc", SETPROC_LOADER);
    inf_set_app_bitness(64);
    inf_set_baseaddr(kImageBase);

    msg("SELF: loading %zu decrypted PT_LOAD segment(s) at image base %a\n",
        image.segments.size(), kImageBase);
    for (std::size_t i = 0; i < image.segments.size(); ++i) {
        const self::LoadSegment& load = image.segments[i];
        create_segment(load, i);
        const ea_t start = kImageBase + load.virtual_address;
        if ((neflags & NEF_MINI) == 0 && load.file_size != 0) {
            if (!file2base(li, load.file_offset, start, start + load.file_size,
                           FILEREG_PATCHABLE))
                loader_failure("Could not map SELF payload %zu", i);
        }
        msg("SELF: %a-%a <- file %llx (%llu file / %llu memory bytes)\n",
            start, start + load.memory_size,
            static_cast<unsigned long long>(load.file_offset),
            static_cast<unsigned long long>(load.file_size),
            static_cast<unsigned long long>(load.memory_size));
    }

    if (image.entry != 0) {
        const ea_t entry = kImageBase + image.entry;
        segment_t* entry_segment = getseg(entry);
        if (entry_segment == nullptr)
            loader_failure("Could not resolve the ELF entry-point segment");
        add_entry(entry, entry, "_start", true, AEF_IDBENC);
        inf_set_start_cs(entry_segment->sel);
        inf_set_start_ip(entry);
        inf_set_start_ea(entry);
    }

    create_filename_cmt();
    msg("SELF: entry point registered; relocations, NID imports and dynamic "
        "linking metadata are not applied by this loader.\n");
}

} // namespace

idaman loader_t ida_module_data LDSC;

loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    nullptr,
    nullptr,
    nullptr,
};
