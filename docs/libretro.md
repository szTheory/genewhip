# Libretro core

Genewhip provides an optional, private Libretro API-version-1 shared core. It
uses the existing C17 machine API; it does not add Libretro symbols to the
public Genewhip SDK.

## Build and test

The shared core is off by default and has no package-manager or network build
dependency:

```sh
cmake -S . -B build/libretro \
  -DBUILD_TESTING=ON \
  -DGENEWHIP_BUILD_LIBRETRO=ON \
  -DGENEWHIP_BUILD_DESKTOP=OFF
cmake --build build/libretro --target genewhip_libretro libretro_host --parallel 2
ctest --test-dir build/libretro -R '^libretro_(host_smoke|host_contract|callbacks|pixels_stop|admission|fixture_route|route_contract)$' \
  --output-on-failure --no-tests=error
```

The Linux x86_64 CI lane loads the just-built shared object through
`dlopen`/`dlsym`, supplies the diagnostic ROM from memory, and runs the lifecycle
and callback contracts. The macOS build is useful for local development but
does not establish Linux support. The private ABI header and adapter are not
installed with the public core SDK.

`fixtures/independent-game-v2/build.sh --validate-only` checks the admitted
fixture and pinned toolchain lock without depending on an existing diagnostic
ROM build. CTest's production-consumer check receives the diagnostic ROM from
the active CMake build directory.

The admitted v2 fixture route runs through the built module, not through an
adapter-internal test. The host receives the source scenario's Start/Right
schedule and records the actual pitched video, stereo batch, and input
callbacks. It checks title-no-start and start-idle controls against the
40-field start-move marker checkpoint, then replays each route and compares
ordered video and PCM digests. Raw callback frames and audio are held only in
temporary scratch files and removed after the report is built. The report binds
the current admission-evidence digest to its manifest row, along with the ROM,
source, scenario, oracle, controls, workflow, module, run, and input identities.

CTest writes `build/libretro/libretro-route.json`. Validate it independently
with:

```sh
python3 -I scripts/evidence/libretro_route.py \
  --validate build/libretro/libretro-route.json \
  --library build/libretro/genewhip_libretro.so
```

On a local non-Linux build, the report records the route observations but has
`status: unknown` because it lacks a clean Linux x86_64 workflow run identity.
Only the hosted normal CI lane can produce a route pass. The evidence supports
the named source-defined checkpoint and controls; it does not establish
whole-game compatibility or physical display/audio quality.

## Content and lifecycle

The core requests memory-backed content (`need_fullpath = false`) and never
opens `retro_game_info.path`. A successful load copies bytes into a newly
created Genewhip machine before replacing the active machine. A failed load
returns false, destroys any candidate, unloads the current game, and clears
owned frame and audio state. Frontend callback registrations remain available
across unload and reinitialization. Load, unload, reset, init, and deinit are
synchronous and safe to repeat.

One Libretro core instance owns one Genewhip machine. Calls and callbacks are
synchronous on the frontend's calling thread. Callback reentrancy is not
supported. ROM and save paths are not opened, retained, or read from host
environment settings.

## Input, video, audio, and timing

Each loaded `retro_run` polls the frontend and schedules complete pad states at
the machine's current master tick. The supported digital mapping is:

| RetroPad | Genewhip pad |
| --- | --- |
| D-pad directions | Matching directions |
| B | B |
| Y | A |
| A | C |
| Start | Start |

Only the current three-button pad is supported on ports 0 and 1. Other device
types and unsupported controls are neutral; analog input is not interpreted.
The adapter polls once on every run, then queries only the eight supported
RetroPad IDs for selected joypad ports. A run that first encounters an
unsupported CPU operation has already sampled input; later sticky-stop runs
poll but do not sample controls or advance the machine.

Each successful run advances to one completed field using integer core ticks.
Video reports the actual 256- or 320-pixel width and 224-pixel height. With
XRGB8888 accepted, the callback receives the core's actual byte pitch. If the
frontend rejects that format or has no environment callback, the adapter
converts bounded rows to Libretro's default 0RGB1555 format and reports a
packed `width * 2` byte pitch. Pixel buffers passed to callbacks are borrowed
for the duration of the callback. The adapter copies each completed image into
owned storage before the core can mutate it.

An unsupported CPU stop does not complete a field. If it occurs partway
through a run, the adapter discards the partial field's queued PCM and keeps
its sample indices consistent; that audio is not replayed after reset. Each
later sticky-stop run repeats the last complete image (or a deterministic
320-by-224 blank image before the first field), with packed rows and no new
audio or emulated progress. A reset or successful game load clears the cached
image and allows execution to recover. Video callbacks remain synchronous and
must not reenter the core. Repeated-image pitch is `width * 4` for XRGB8888 or
`width * 2` for 0RGB1555.

The reported frame rate is `GW_MASTER_HZ / GW_FIELD_TICKS`; audio is configured
at 48,000 Hz. Stereo audio is drained in bounded frame batches through the
batch callback, with ordered left/right pairs. The sample counts follow the
core's integer ticks, independently of host callback delay. If the frontend
accepts only part of a batch, the unaccepted frames are discarded once; this
does not spin or change emulated time. If no batch callback is registered, the
per-sample callback receives the same ordered pairs. If neither audio callback
exists, the bounded queue is drained and discarded.

## Reported capabilities and limits

The current profile is VA3 NTSC-U only. `retro_get_region` reports NTSC. The
core does not support SRAM or other memory regions, serialization, special or
subsystem loads, cheats, filesystem/VFS content, no-game operation, hardware
rendering, analog/six-button input, other regions, or unsupported mappers. The
corresponding mandatory ABI entry points return null, zero, or false, or remain
inert as appropriate.

These statements describe the implemented adapter contract. They do not claim
whole-game compatibility, broad hardware correctness, physical video/audio
quality, latency, or support on platforms that have not been tested.

## ABI header provenance

`src/libretro/vendor/libretro.h` is based on the canonical header from
`libretro-common` commit
[`d9597c359a5ca8399a4e244f816e7e975a92a2aa`](https://github.com/libretro/libretro-common/blob/d9597c359a5ca8399a4e244f816e7e975a92a2aa/include/libretro.h).
One trailing space was removed to keep the vendored source whitespace-clean.
Its SHA-256 is
`70b56ff4550e6085f72027b45372bf5d87804cf495764a10c50d7c1b831491a1`.
The file retains its own MIT copyright and permission notice; that notice
applies to the ABI header.

To update the pin, review the canonical upstream ABI and its license at an
immutable revision, retain the header content and notice, record the vendored
SHA-256, inspect
the mandatory export roster, and run the actual-library and lifecycle tests.
Do not fetch the header during normal configuration or build.
