# Sony SELF/fSELF IDA loader

A C++17 IDA 9.x loader for **decrypted, little-endian AMD64 SELF/fSELF executables**.
It uses the SDK's native `ida_add_loader()` CMake API.

## Behavior

- Recognizes Sony SELF magic `0x1D3D154F`.
- Parses the embedded SCE ELF64 header and program headers.
- Associates decrypted SELF payload records with ELF `PT_LOAD` segments.
- Creates 64-bit `metapc` segments at image base `0x400000`.
- Copies initialized payloads and preserves virtual sizes, including BSS tails.
- Registers the ELF entry point as `_start`.
- Validates counts, arithmetic, file bounds, virtual-address overlap, and entry-point placement.
- Rejects unsupported ELF classes/machines/types and payload-size mismatches.

This initial loader intentionally does **not** decrypt or decompress payloads, resolve NID imports, apply relocations, or process dynamic-linking metadata. Input must already be decrypted. Relative code references retain their original layout; absolute pointers still require relocation-aware analysis.

## Build and install

With `IDASDK` pointing to an IDA SDK checkout, use the Make wrapper:

```sh
cd self_loader
make build       # configure and compile
make test        # run parser tests
make install     # copy the loader to ~/.idapro/loaders/
make clean       # remove build/
make rebuild     # clean and rebuild
make uninstall   # remove the installed loader
```

To supply the SDK path through Make instead:

```sh
make build IDA_SDK_DIR=/path/to/ida-sdk
```

The equivalent direct CMake commands are:

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Or pass the SDK location directly:

```sh
cmake -B build -G Ninja \
  -DIDA_SDK_DIR=/path/to/ida-sdk \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The loader is written to:

```text
build/bin/loaders/self_loader.dylib   # macOS
build/bin/loaders/self_loader.so      # Linux
build/bin/loaders/self_loader.dll     # Windows
```

`IDABIN` can override the output root. `make install` copies the module to `~/.idapro/loaders/`; `INSTALL_DIR` and `BUILD_DIR` can override those paths. A manual installation can instead place the module in IDA's user `loaders/` directory. Restart IDA before opening a SELF file.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

The parser test also accepts a decrypted SELF path for reference-layout validation:

```sh
./build/self_parser_tests /path/to/eboot.bin
```

## Files

- `src/loader.cpp` — IDA callbacks, segment mapping, and entry-point registration.
- `src/self_parser.hpp` / `src/self_parser.cpp` — SDK-independent bounded parser.
- `tests/self_parser_tests.cpp` — synthetic malformed-input tests and reference-file checks.
