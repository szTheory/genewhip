# Genewhip

Genewhip is a portable C17 Sega Genesis / Mega Drive emulator core with a small SDL3 desktop runner. **v0.2.0 is a published prerelease** ([release](https://github.com/szTheory/genewhip/releases/tag/v0.2.0)), tested via exact downloaded bytes on macOS 26.6.2 arm64. It is unsigned and unnotarized; no older deployment target or other host has been runtime-qualified. Evidence covers one control plus bounded Tank Battle and RECURSION94 routes; whole-game and general hardware compatibility remain unproven. See [delivery status](docs/delivery.md) for source, CI, publisher, and external-adoption details. This current status postdates the release source and does not alter its immutable assets. The published [0.1.0 preview](https://github.com/szTheory/genewhip/releases/tag/v0.1.0) remains available.

Start with one of these task paths:

- [Play](packaging/desktop/README.md#v02-play) from an exact qualified desktop archive.
- [Build](packaging/README.md#v02-build-core) the SDL-free core offline or follow the optional desktop-tooling path.
- [Embed](docs/core.md#v02-embed) the installed SDK from an external C or C++ consumer.

## Tested scope

| Area | Current evidence |
|---|---|
| Console profile | Model 1 VA3, NTSC-U, pre-TMSS; deterministic Genewhip reset policy |
| Cartridges | Copied linear ROMs up to 4 MiB; no mapper, SRAM/save, TMSS, or firmware |
| Video | Bounded progressive VDP subset, 256/320 by 224 fields; unsupported modes stop explicitly; no interlace or mid-line effects |
| Input | Two configurable three-button ports; keyboard/gamepad and scripted replay in the desktop runner |
| Sound | Connected Z80 sound path, PSG, discrete YM2612 FM/timers/status/DAC, deterministic PCM; exact VA3 FM reset wiring and broad game audio remain unknown |
| Game evidence | v0.1 independent MIT game v2: 6 source-derived cases, 840 requested fields, plus a 720-field sustained case. v0.2.0 exact-download adoption: Tank Battle and RECURSION94 full routes plus an independent-game-v2 720-field sustained route, each checked with software and native SDL (six bounded objective routes); whole-game compatibility and completion remain unknown |
| Desktop host | Native SDL3 video/input/audio exercised on macOS 26.6.2 arm64; six bounded software/native SDL objective routes and three Cocoa/CoreAudio clients passed. Renderer readback, physical scanout, achieved vsync, acoustic quality, and latency remain unknown |
| Distribution | Published receipt-backed v0.1.0 preview and v0.2.0 prerelease desktop and SDL-free SDK archives; exact v0.2.0 downloads passed external adoption. Both releases are unsigned and unnotarized; v0.2.0 runtime evidence is macOS 26.6.2 arm64 only |

The independent fixture has two separate histories: v1 is retained as a historical bounded MAME admission, while corrected v2 is the currently admitted source/reference fixture. Neither admission alone demonstrates Genewhip compatibility. Genewhip's separate v2 gameplay result is limited to the scenarios and denominators above. The original raster toy is a deterministic PSG/FM/DAC diagnostic, not game-audio evidence. FM comparator differences, the approved reset exception, and the unresolved BUSREQ source conflict are recorded in [audio evidence](docs/audio.md). Optional subjective listening remains unknown by the settled Phase 3 disposition; it is not a release gate.

## v0.2 task paths

Use the published v0.2.0 archives and their adjacent qualification receipts. Before running any bundled verifier, executable, or build script, verify trusted source/workflow/run/attempt provenance and subject digests for the exact download. Those checks and the independent downloaded-byte adoption passed for v0.2.0. A checksum proves byte identity, not publisher identity.

## Build and embed from source

The core is SDL-free and builds offline. CMake 3.27+, Ninja, a C17 compiler, and a C++11 compiler are needed for the consumer smoke. This source path installs the core and exercises a relocated external C/C++ consumer:

<a id="source-build"></a>

```sh
cmake -S . -B "$BUILD_DIR" -G Ninja -DGENEWHIP_TEST_HOOKS=OFF
cmake --build "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" -R '^installed_consumer$' --output-on-failure --no-tests=error
```

For a clean checkout's full local gate, use `bash scripts/ci/required-gate.sh`. API 4 is a source/structure version; the package version is 0.2.0. This is a pre-1.0 project: recompile consumers for an API version change, and do not assume a stable cross-compiler binary ABI. Input logs have their own `genewhip-input-log 1` format version; changing that header is independent of either version number.

For no-emulator contract feedback and the SDL-free core build, see the [local testing guide](docs/local-testing.md).

The C API documents ownership, sizes, units, lifetimes, errors, serialization, and allocation behavior in [`include/genewhip/genewhip.h`](include/genewhip/genewhip.h) and [the core contract](docs/core.md). `Genewhip::core` is SDL-free. ROM bytes are copied on load. Instances are single-thread-at-a-time; independent instances may run concurrently. Create/load allocate; ordinary run/query/output calls are bounded and allocation-free. Only the pixel pointer returned by `gw_get_video_field` is borrowed, read-only, and valid until the next run/load/cold-init/console-reset/destroy on that machine. Other outputs are copied.

## Obtainable packages

The [v0.2.0 release page](https://github.com/szTheory/genewhip/releases/tag/v0.2.0) lists both archive names and their SHA-256 values; each asset also has a checksum sidecar, qualification receipt, and source-bound inventory. Follow the tested download, checksum, extraction and consumer steps in the [SDL-free SDK guide](packaging/README.md) and [desktop guide](packaging/desktop/README.md). Five documented play/build/embed/error commands passed against exact downloaded bytes; the local documentation contract is also exercised by `python3 tests/package/docs_commands.py --local-artifacts artifacts`. A checksum identifies bytes and does not authenticate the publisher. Game cases, field denominators, archive controls, diagnostic/audio checks, load/drop/reload behavior, and native host sessions are recorded in each exact package receipt. Evidence does not establish two-clean-build byte reproducibility, other operating systems/architectures, broader compatibility, whole-game completion, or physical audio/display quality.

## Fixtures, rights, and limits

The [fixture manifest guide](fixtures/README.md) identifies the original diagnostic and game sources, revisions, MIT notices, ROM identities, and bounded evidence. Pong remains rejected because generated-byte rights, reproducible build, and runtime/SRAM evidence are unresolved. Preserve the project MIT license and all SDL3, ymfm, and fixture notices in copied or redistributed packages.

See [core limits](docs/core.md), [video](docs/video.md), [input](docs/input.md), and [audio](docs/audio.md) for unsupported hardware, model-scoped assumptions, and remaining unknowns. The project does not claim cycle-accurate 68000 timing, complete VDP/VDP modes, save devices, general cartridge support, broad game compatibility, or universal host support.
