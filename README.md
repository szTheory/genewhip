# Genewhip

A portable Sega Genesis / Mega Drive emulator in C, designed as an embeddable core with a small desktop runner.

**Status: early audio-capable preview; general game compatibility is unproven.** The C17 core
exposes an installable C API 4 with a bounded 68000 subset, ROM/RAM bus, VDP subset, connected
Z80 sound path, PSG, discrete YM2612 FM/timers/status/DAC, and deterministic PCM. Original seams
and the raster toy exercise PSG, FM and DAC activity; an opt-in SDL3 runner captures audio through
the host path. The pinned Z80 PR slice contains 1,433 partially gated records; no whole-record
pass claim is made. The independent game smoke currently stops at unsupported VDP mirror address
`0xC00006`; it is not a compatibility result. No commercial-game audio, hardware-truth, PAL,
Model 2, analog-filter or performance claim is established. See [audio evidence and limits](docs/audio.md#phase-3-evidence-and-limits).

Two locally exercised macOS arm64 archives exist, neither signed, notarized or published:

- the [SDK/diagnostic archive](packaging/README.md): `bash scripts/package-sdk.sh`
- the [desktop archive](packaging/desktop/README.md): `bash scripts/package-desktop.sh`
  (set `GENEWHIP_SDL3_ARCHIVE` to a local SDL3 tarball if offline; its SHA-256 is still enforced)

Shortest adoption path from a clean checkout: `bash scripts/ci/required-gate.sh`, then either package
script, then the smoke named in each README. Desktop build from source:
`cmake -S . -B build/desktop -DGENEWHIP_BUILD_DESKTOP=ON && cmake --build build/desktop`.
The desktop archive bundles the versioned Phase 2 evidence report, which keeps unknown and
unsupported rows visible. No release is published (the repository has no remote).

The planned foundation is an original C17 core, CMake/CTest, deterministic emulated time, explicit video/audio/input interfaces and a separate SDL3 runner for macOS. Original project work uses the [MIT license](LICENSE). Dependencies and test fixtures retain their own notices and require review before inclusion.

The first milestone targets a narrow, documented playable preview. Broader regional and cartridge support, battery saves, snapshots/replay, Playstead/libretro integration and constrained-device investigation follow measured progress.

- [Project definition](.planning/PROJECT.md)
- [Requirements](.planning/REQUIREMENTS.md)
- [Roadmap](.planning/ROADMAP.md)
- [Research summary](.planning/research/SUMMARY.md) and [topic index](.planning/research/README.md)
- [Development agreement](.planning/context/OPERATING.md)
- [Fresh-session handoff](.planning/context/BOOTSTRAP.md)

Build and test offline, with CMake 3.27+ and a C17 compiler (C++11 for header smoke).
Core-only builds with tools/tests disabled retain CMake 3.24+ support:

```sh
cmake -S . -B build/phase1
cmake --build build/phase1
ctest --test-dir build/phase1 --output-on-failure
cmake --install build/phase1 --prefix build/sdk
cmake -S tests/consumer -B build/example -DCMAKE_PREFIX_PATH="$PWD/build/sdk" -DGW_ROM="$PWD/build/phase1/diagnostic.bin"
cmake --build build/example
ctest --test-dir build/example --output-on-failure
```

Consumers use `find_package(Genewhip 0.1.0 EXACT CONFIG REQUIRED)` and link
`Genewhip::core`. SDL and network access are not required. For a core-only build,
set `BUILD_TESTING=OFF`, `GENEWHIP_BUILD_TOOLS=OFF` and `GENEWHIP_TEST_HOOKS=OFF`; the private allocation test
symbol is then omitted. See the [public API](include/genewhip/genewhip.h),
[consumer example](tests/consumer/main.c), and [subset limits/state inventory](docs/core.md).

The automated SDK smoke installs to a temporary prefix, moves it, then builds and
runs a copied C/C++ consumer project against the relocated package. No published
release is claimed. Development uses OpenGSD and stops after every phase.

The [headless diagnostic and evidence tools](evidence/README.md) produce repeatable,
identity-bound reports through the public API. Qualification rejects dirty/stale,
missing, malformed or incomplete results. The [fixture manifest](fixtures/README.md)
admits the original diagnostic only; Pong remains rejected with unresolved
generated-byte rights/build/runtime gates and no playable replacement admitted.
