# Desktop runner

`genewhip-desktop` is an opt-in SDL3 runner. The core never depends on it: a default configure, build
and install stays offline and SDL-free. The current local playable preview is unsigned and
unnotarized and was exercised on macOS 26.6.2 arm64; no other OS/architecture or older deployment
target is qualified. It bundles the corrected independent-game-v2 and the original PSG/FM/DAC
raster diagnostic. The game result is bounded to six source-derived cases/840 fields plus a
720-field scenario; it does not establish broad game or game-audio compatibility. Physical scanout,
actual vsync, acoustic quality, and latency remain unknown. Package identities and checksums are in
[`packaging/desktop/README.md`](../packaging/desktop/README.md).

## Build

```sh
cmake -S . -B build/desktop -DGENEWHIP_BUILD_DESKTOP=ON
cmake --build build/desktop
SDL_VIDEODRIVER=dummy ctest --test-dir build/desktop -R 'runner_|session_contract'
GENEWHIP_LIVE_DISPLAY=1 ctest --test-dir build/desktop -L live-display  # opens a real window
GENEWHIP_LIVE_AUDIO=1 ctest --test-dir build/desktop -L live-audio      # opens a real audio device
build/desktop/tools/desktop/genewhip-desktop path/to/cartridge.bin
```

The option downloads `SDL3-3.4.18.tar.gz` from the SDL GitHub release and builds it static.
CMake rejects any archive whose SHA-256 is not
`9c75cf16330322c217dedd2e0609f1124f1b54b8633e763467b4684d0f4334a3`.
`-DGENEWHIP_SDL3_ARCHIVE=/path/to/SDL3-3.4.18.tar.gz` substitutes a local copy of the same tarball;
the digest is still enforced, so only the pinned bytes are accepted. There is no system-SDL path.
The pin and its identity evidence are recorded in `packaging/dependencies/sdl3.json`.

## Command line

```text
genewhip-desktop [--fields N] [--scale N] [--host-script FILE] [--record LOG | --replay LOG]
                 [--dump-audio FILE] [--print-field-hashes] [--stats FILE] [--stats-interval N]
                 [--port1 SRC] [--port2 SRC] ROM
```

`--fields N` exits after N emulated fields. `--scale N` sets the initial window scale (default 3).
`--host-script` replays host controls at pacing-frame numbers, one command per line:
`<frame> pause|resume|reset|quit|mute|unmute`, `<frame> press <port 1|2> <mask-hex>` (the full
logical button state of that port, OR-ed with real keyboard or gamepad state) and
`<frame> drop <path>`. It drives the same handlers as real events and exists so tests run without a
display.
The runner opens a separate 48 kHz, stereo, signed 16-bit SDL audio stream when available. After
each successful field step it pulls that field's PCM from `gw_session` and queues it, including each
catch-up field. Audio queue depth never gates stepping and never enters core state or field hashes.
`--dump-audio FILE` writes those unmodified core samples as interleaved little-endian signed 16-bit
stereo frames before runner drift correction, in bounded synchronous chunks. A failed open, write or
close reports `ERROR: could not write audio dump` or `ERROR: could not finish audio dump` and exits
nonzero. The capture is diagnostic output; it does not change playback or machine state.
On exit the runner prints `fields=N paused_fields=M resets=K` followed by audio counters. A pacing
frame is one field period: `fields` counts stepped fields, `paused_fields` counts frames spent paused.

SDL's stream ratio follows `ratio = 1 + clamp(k * (depth - target) / target, -0.005, +0.005)`,
where `depth` and `target` are queued source frames, `target` is 2403 frames (about three fields),
`k` is 0.1 (`GW_RATE_K_PPM=100000`), and the ratio is updated once after each field. SDL's device
sample-frame hint is 800 and the queue cap is 9612 frames (four times the target); above the cap,
the oldest frames are drained and counted as overruns and dropped frames. The controller is pure
integer C in `tools/session/rate_ctl.c`; only the runner converts its ppm output to SDL's float
ratio. This controls drift without host time entering the core.

The exit line includes legacy `queued_frames`, `underruns`, `overruns`, `dropped_frames`,
`produced_frames`, `consumed_frames`, `core_frames`, `core_lost` and `core_clipped`, plus the
versioned source-queue and loss counters described below. Host timing counters vary with the driver
and are checked through
`produced_frames = consumed_frames + queued_frames + dropped_frames` and the ratio bound, not
compared between runs. Core counters and field hashes are replay-stable. Queue accounting uses
SDL's queued input bytes, which are the exact data put into the stream in its input format; they are
not device-converted output bytes. In this runner the stream input is stereo signed 16-bit PCM, so
one source frame is four bytes. Each observation reconciles the expected source-frame depth with the
observed depth; after enqueue, the expectation includes the newly submitted source frames so
backend drain during that interval is counted. The desktop contract injects a drain between those
observations by calling `runner_audio_put_field` with a fake SDL stream, and a negative control
using the former post-enqueue snapshot behavior fails the counter assertion. See SDL's
[`SDL_GetAudioStreamQueued`](https://wiki.libsdl.org/SDL3/SDL_GetAudioStreamQueued) documentation.
Overrun removal and stream clearing serialize their queue observation and removal with
[`SDL_LockAudioStream`](https://wiki.libsdl.org/SDL3/SDL_LockAudioStream), so frames intentionally
discarded by those operations remain distinct from frames drained by the playback backend.
If SDL audio initialization or stream startup fails, the runner prints exactly one
`audio: disabled (<sanitized reason>)` stderr line, reports `audio=off` and continues video-only;
the core remains configured at 48 kHz, so machine results remain the same.

Audio statistics identify `queue_source_unit` as SDL input bytes and stereo source frames. The
current/min/max depth is reported as both `queue_source_bytes` and `queue_source_frames`; six bounded
histogram buckets cover zero, one, up to one target, up to two targets, up to the four-target cap,
and over-cap depth. `queue_samples` is the number of producer or serialized queue observations, and
`queue_exposure_ns` is the monotonic interval from the first to last observation. This describes
software queue depth over exposure, not device consumption, acoustic output, or latency.

`underruns` remains compatible and equals `producer_starvation_observations`: the producer observed
zero queued source frames after priming while neither paused nor intentionally priming. It is not a
physical playback-gap count. `core_lost_frames` and `core_clipped_frames` are the core-reported
cumulative totals. `host_cap_overruns` and `host_cap_dropped_frames` count oldest source frames
removed above the queue cap. `intentional_clear_frames` partitions into `pause_clear_frames` and
`reprime_clear_frames`; stream shutdown/failure discards are separately recorded as
`stream_failure_dropped_frames`. These drop categories sum to `dropped_frames`, the conservation
term. `pause_ramp_frames`, `reprime_silence_frames`, `audio_paused`, `audio_muted` and
`mute_transitions` expose host control behavior; silence and ramp frames are submitted source frames,
not core-produced audio. If audio is unavailable, `audio_available` is zero and `queue_samples` is
zero. A required audio qualification must reject that row; video-only fallback is not an audio pass.

`--stats FILE` writes one JSON object at exit. Schema version 2 adds host-only scheduler and
presentation observations to the audio counters. `scheduled_deadlines` and `lateness_samples` count
each due scheduler slot; lateness is `max(observed_monotonic_ns - scheduled_deadline_ns, 0)`, with
total, maximum and eight bounded buckets (exactly zero, then upper bounds of 100/250/500 us and 1/2/4
ms, then greater than 4 ms). `clock_exposure_ns` is monotonic wall-clock time from runner start to
stats capture. Counters saturate at `UINT64_MAX`; `stats_saturated` makes that visible.

`emulated_fields` counts successful core field steps. `catchup_fields` counts steps after the first
due slot in a scheduler pump. `discarded_wall_ns` is wall-clock debt discarded after the four-field
catch-up cap; it does not represent skipped machine time or monitor frames. `present_calls` counts
attempts for a non-empty core field, `present_successes` counts successful SDL texture/render/present
calls, and `present_errors` counts failed attempts. `last_presented_field_id` is the latest successful
core field sequence. `superseded_fields` counts an unpresented identity displaced by a newer core
field; `repeated_field_ids` counts consecutive attempts with the same identity. Pixel equality is
not used. `last_present_error` retains the most recent SDL failure detail and `presentation_error`
signals whether such a detail is present. These are software observations, not scanout or physical
display evidence.

`--stats-interval N` writes the same numeric `key=value` fields to stderr every N pacing frames;
stdout remains available for hashes and the exit summary. Reports contain counters and sanitized
SDL error text, never file paths or environment values. The title appends `A:{depth}ms`, where depth
is the current queued audio converted at 48 kHz.

## Controls

| Key | Action |
|---|---|
| M | Toggle runner-only mute with a 240-frame linear ramp |
| P or Space | Pause or resume; pause fades and clears queued audio, resume re-primes with silence and ramps in |
| R | Console reset, scheduled as `GW_EVENT_CONSOLE_RESET` at the current machine tick; audio re-primes |
| Esc, Cmd-Q, window close | Exit |

A reset after a sticky unsupported stop resets the machine directly, because a queued event cannot
clear that stop. Pausing stops calling the core and does not change machine state. Mute changes only
the samples submitted to SDL: the core continues running, PCM is still read, and input logs and field
hashes do not include mute state. A successful ROM drop also clears and re-primes the host stream.

## Input

The runner samples its sources once per emulated field and passes logical masks to
`gw_session_set_input`; the session stamps each change as a `GW_EVENT_PAD_STATE` at the next field
start tick (decision D-38). No host clock value ever reaches the machine, so presentation cadence,
pauses and catch-up cannot change machine results (`session_cadence` checks this).

| Host input | Genesis button |
|---|---|
| Arrow keys | D-pad |
| Z, X, C | A, B, C |
| Enter | Start |
| Gamepad D-pad | D-pad |
| Gamepad West, South, East | A, B, C |
| Gamepad Start | Start |

`--port1` and `--port2` take `keyboard`, `gamepad` or `none`. Defaults: port 1 reads the keyboard
and the first gamepad, port 2 reads the next gamepad. `none` attaches no controller to that port
(`GW_DEVICE_NONE`, reads pull-ups, presses are ignored). Gamepads are opened when connected; with
`gamepad` on both ports they are assigned in connection order.

Dropping a cartridge file on the window loads it through the same bounded reader as the command line
and `gw_session_replace_rom`: the new session starts at tick zero with the same port configuration.
A failed drop prints `REJECT: <reason> <name>` on stderr and keeps the current session. A successful
one prints `LOADED: <name>` and updates the title. An attached record log is cleared by a drop, so a
recorded log always describes one cartridge from tick zero.

### Record and replay

`--record LOG` writes the stamped pad changes and resets at exit; `--replay LOG` feeds them back
(host input and the reset key are ignored). The format (`genewhip-input-log 1`, then `<tick> pad
<port> <mask-hex>` or `<tick> reset`) holds only ticks, ports and masks. A `reset` line carries the target tick of the field step it precedes: the session
resets the machine immediately before that step, in recording and in replay, including after an unsupported stop. `--print-field-hashes` prints
one JSON line per field and a final `{fields, ram_fnv1a64}` line in the format of `gw_headless`:

```sh
build/desktop/tools/desktop/genewhip-desktop --record run.log --print-field-hashes game.bin > run.txt
build/desktop/tools/session/gw_headless game.bin --fields N --replay run.log   # same lines
```

`gw_headless ROM --fields N [--replay LOG] [--record LOG] [--port-device P1 P2]` (`pad3` or `none`)
runs the session without SDL. `runner_input_replay` compares a runner session with its headless
replay field by field. Logs are bounded to 65536 entries and are rejected with `header`, `syntax`,
`order`, `port`, `mask`, `capacity` or `io` before any event is scheduled. The runner and headless
client must use the same port devices as the recording.

Whether input feels immediate on a real display and a physical gamepad is a named human check:
automation establishes event chronology and reproducibility, not perceived responsiveness.

## Pacing, scaling and vsync

The runner owns the window, integer-scaled nearest-neighbour presentation and vsync. The session
module (`tools/session`) is SDL-free, reads no host clock and runs the core only to field-start
targets, `(n+1) * GW_FIELD_TICKS`, with `GW_RUN_CONTINUE_PAST_FIELD`. The runner paces from the
emulated field period, `GW_FIELD_TICKS / GW_MASTER_HZ` seconds (about 16.688 ms), using the host
monotonic clock. When the host falls behind it steps at most 4 fields per presented frame
(`GW_SESSION_CATCHUP_FIELDS`) and discards the remaining debt, so emulated time slows and is never
skipped. Host timing never changes machine results.

## Errors

A file that cannot be a cartridge is refused before any window opens: stderr gets
`REJECT: <reason> <name>` and the exit status is 1. Reasons: `missing`, `not-regular-file`,
`too-large` (over 4 MiB), `odd-size`, `read-error`, `invalid-rom` (rejected by the core, for example an
odd reset PC), and `host-script`. Only the final path component is printed, with every byte outside
printable ASCII replaced by `?`. The file is checked on the opened descriptor and read within the
size cap. A fatal SDL startup failure prints `ERROR:` and shows a modal message box. A guest
instruction or address the core does not support stops the machine; the title and stderr name the
opcode and address and the last field stays on screen.

## Dependency record and notice

`packaging/dependencies/sdl3.json` records SDL3 3.4.18: release URL and tag, archive size and SHA-256,
signature URL and SHA-256, the two signer fingerprints, `key_authenticity`, license (zlib), the SHA-256
of the archive's `LICENSE.txt`, build options and `fetch_evidence`. The verbatim zlib notice is
committed at `packaging/notices/SDL3-LICENSE.txt`. The signers' public keys are not committed (they
carry personal user IDs); the record keeps only their fingerprints and `signer_keys_sha256`, the digest
of the key block published on SDL's signing-keys page.

`bash scripts/deps/verify-sdl3.sh` re-downloads the tarball and signature and prints
`sdl3 verify: PASS` or `BLOCKED: <reason>`. It checks size and SHA-256 against the record, builds a
keyring only from the key block it fetches from that page into the ignored `build/deps/` cache
(or `SDL3_KEY_CACHE`), which must match `signer_keys_sha256` and the recorded fingerprints, requires `GOODSIG` plus `VALIDSIG` for a recorded fingerprint
(any expired, revoked, bad or missing-key status blocks), and compares the archive's `LICENSE.txt`
with the record and the committed notice. With no network and no matching cached key it prints
`BLOCKED:` and exits nonzero; it is not part of the offline required gate. It needs network access, `curl`, `gpg` and `gpgv`.

Key authenticity, as observed on 2026-10-19: both fingerprints match the key blocks on
`https://www.libsdl.org/signing-keys.php`, and the same tarball and signature bytes are served from
`libsdl.org/release/` and from GitHub. That page belongs to the SDL project, so this is a consistency
check, not an independent attestation; no web-of-trust path was evaluated.

Two tests run in the default build without SDL or network: `dependency_record` (record fields, the
CMake URL and `URL_HASH` equal the record, the notice digest equals `license_file_sha256`) and
`default_configure_offline` (a fresh default configure creates no `_deps`, no `FETCHCONTENT_BASE_DIR`
cache entry and no SDL source directory).

## Archive override

`-DGENEWHIP_SDL3_ARCHIVE=/path/to/SDL3-3.4.18.tar.gz` replaces only the download location. `URL_HASH`
still applies, so any other bytes are rejected. The override does not skip signature checking in
`verify-sdl3.sh`, which always fetches from the recorded URLs.

## CI lane

The `desktop` job in `.github/workflows/ci.yml` configures with `-DGENEWHIP_BUILD_DESKTOP=ON` from the
real URL and runs `ctest -R runner_` with the dummy video and audio drivers, plus the opt-in
`runner_live_display` case (`GENEWHIP_LIVE_DISPLAY=1`) and `runner_live_audio`
(`GENEWHIP_LIVE_AUDIO=1`). The display case opens a real Cocoa window, replays a
scripted two-port session with pause, resume and reset, and requires the same per-field hashes as the
dummy driver within a real-time pacing bound. Without the variable or a window server it reports
Skipped, not Passed. The job is not part of
`scripts/ci/required-gate.sh`, which stays SDL-free and offline. The repository has no remote yet, so
this job has never run on hosted CI; it is written and structure-checked locally only.

## Historical Phase 3 audio desktop archive

`bash scripts/package-desktop.sh` (from a clean checkout; the script rejects dirty sources) builds
`artifacts/genewhip-0.1.0-desktop-audio-preview-darwin-arm64-<rev12>.tar.gz` and a `.sha256` sidecar.
That historical archive contains `bin/genewhip-desktop`, `bin/gw_headless`, the original raster toy
and a recorded A/B/C input log, the Phase 3 evidence report, and MIT, SDL3 zlib, ymfm BSD-3-Clause
and fixture notices. It did not contain the independent game. It was unsigned and unnotarized and
was not a published release. The current archive identity and use instructions are in
[`packaging/desktop/README.md`](../packaging/desktop/README.md).

The script builds in fresh temporary directories, then runs `tests/package/desktop_smoke.py` on the
exact archive bytes before copying anything to `artifacts/`. The smoke checks the archive SHA-256,
full inventory, named tamper rejection and label, then relocates the extracted prefix and runs it
under SDL dummy drivers. It plays the toy for 60 fields, replays the bundled A/B/C schedule for 240
fields with audio on, checks `produced_frames = consumed_frames + queued_frames + dropped_frames`
and `core_lost=0`, and requires field hashes to match `gw_headless` replaying the same log. It also
checks a missing ROM and the host-control script. SDK and desktop archive listings and contents are
scanned for LGPL reference material. These checks exercise the delivered bytes, not a prior build
directory.

FM uses the attributed ymfm port. The Phase 3 report records 54,925 of 54,991 FM samples and 87 of
239 DAC samples differing from an alternate reference model, plus 22 FM and 34 DAC status-reading
differences. These are model comparisons and do not establish hardware truth. Reset assertion
follows the approved model amendment; exact VA3 reset wiring remains unknown. See `docs/audio.md`
and `03-FM-RESET-AMENDMENT.md` for the bounded evidence and assumptions.

Subjective listening of the toy's PSG/FM/DAC sound and audible pop/click quality remain optional
unknown observations under the settled Phase 3 UAT disposition. They are not mandatory phase or
release acceptance checks. Counters and captured PCM establish bounded automated behavior, not
listener preference or physical output quality.

## Limitations

- No file dialog. Audio uses the runner's 48 kHz SDL stream with host-only mute and observable stats.
  Both pads are three-button pads; keyboard, gamepad and drag-and-drop
  paths are covered by script tests. The display path is also checked on a real Cocoa window
  (`runner_live_display`, local macOS arm64), but no physical keyboard or gamepad is exercised.
- The pinned SDL3 source archive was downloaded and its digest/notices verified during the local
  build. No Genewhip release URL exists; the hosted CI desktop job has not run.
- A rejected file never opens a window, so the error appears only on stderr.
