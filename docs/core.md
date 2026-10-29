# Diagnostic core contract and limits

<a id="v02-embed"></a>

## Embed the exact v0.2.0 SDK

The SDK contains an external C17 consumer and C++11 header/link check. Extract the archive only after trusted provenance and the archive subject digest have been checked; the local development-only archive instead uses the trusted checkout's receipt verifier. Prerequisites are a trusted checkout, the exact SDK archive/receipt/sidecar, CMake 3.27 or newer, Ninja, and C17/C++11 compilers. This consumer needs no network or developer cache:

```sh
python3 -I "$CHECKOUT/tests/package/docs_commands.py" --verify-local \
  --local-artifacts "$ARTIFACT_DIR" --archive "$SDK_ARCHIVE" --role sdk --version 0.2.0
cd "$ARTIFACT_DIR"
shasum -a 256 -c "$ARTIFACT_DIR/$SDK_ARCHIVE.sha256"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARTIFACT_DIR/$SDK_ARCHIVE" -C "$EXTRACT_DIR"
SDK_DIR="$EXTRACT_DIR/${SDK_ARCHIVE%.tar.gz}"
cmake -S "$SDK_DIR/share/genewhip/consumer" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_PREFIX_PATH="$SDK_DIR" \
  -DGW_ROM="$SDK_DIR/share/genewhip/diagnostic.bin"
cmake --build "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error
```

The example checks the installed C API, compiles and links the public header from C++, and runs the diagnostic consumer. Package 0.2.0 is not an API version: this header still reports API 4. Input logs independently use `genewhip-input-log 1`.

The C17 API 4 core executes original diagnostic and independent-game guests through
an instance-owned 68000 subset, ROM/RAM bus, bounded VDP path, two controller ports,
connected Z80 sound path, PSG, discrete YM2612 FM/timers/status/DAC, and deterministic
PCM. See [video](video.md), [input](input.md), and [audio](audio.md) for component
contracts. A corrected independent MIT game v2 passes six source-derived Genewhip
public-client cases (840 requested fields) plus a separate 720-field scenario. This
is bounded evidence for that guest and profile; broad game compatibility remains
unproven.

The explicit profile is Model 1 VA3 NTSC-U, pre-TMSS. The nominal 53,693,175 Hz
master clock and CPU divider 7 are emulator conventions. Zeroed cold RAM and
registers are deterministic Genewhip policies, not power-on hardware claims.
No firmware, TMSS bypass, environment configuration or runtime dependency is used.

## Integrator contract (API 4)

`GW_API_VERSION` is 4 and is independent of the published 0.1.0 package and local
v0.2.0 development package. Input logs use the separate format string
`genewhip-input-log 1`; neither contract changed for package version 0.2.0.
Configuration/event/result structures must be
zero-initialized with `struct_size = sizeof(value)` and the current version; exact
size/version mismatches return `GW_ERROR_VERSION`. Unknown flags/invalid pointers,
overlapping caller buffers, invalid lengths and malformed events return
`GW_ERROR_ARGUMENT`; unsupported profile/reset/device choices return
`GW_ERROR_PROFILE` or `GW_ERROR_UNSUPPORTED`; malformed ROM reset vectors return
`GW_ERROR_ROM`; missing loaded content returns `GW_ERROR_NOT_LOADED`; time and
capacity bounds return `GW_ERROR_TIME` and `GW_ERROR_CAPACITY`; an absent video field
returns `GW_ERROR_EMPTY`. Check the returned `gw_status` and, for a successful run,
also inspect the `gw_run_result.stop_reason`: unsupported guest execution is a
reported stop, not a C API failure.

The caller owns the `gw_machine` after successful `gw_create` and must call
`gw_destroy` exactly once. `gw_load_rom` copies 514 bytes through 4 MiB of even-sized
ROM input and the caller may release its buffer after return. Failed replacement
leaves the existing machine unchanged. One host thread may use an instance at a
time; callers serialize access. Independent instances may run concurrently. The
core reads no host clock, environment, filesystem, network, or device service.
Create/load allocate; ordinary run/query/event/audio calls are bounded and
allocation-free.

All outputs are copied except the read-only pixel pointer from
`gw_get_video_field`. That pointer is core-owned and remains valid until the next
run, load, cold init, console reset, or destroy on that instance. Audio output is
copied interleaved native-endian `int16_t` stereo frames; master ticks use the
53,693,175 Hz model clock. `gw_audio_read` reports produced frames, first sample
index, lost oldest frames, and clipping through `gw_audio_read_result`. Buffers
must be suitably aligned, valid for the stated size, and non-overlapping with one
another or machine storage. Native structure layout is not a file format; no
cross-compiler binary ABI, snapshot, or replay compatibility is promised. Because
this is pre-1.0, rebuild consumers whenever the API version or header changes.

## CPU and video contracts

The executed 68000 subset, addressing modes and unsupported behaviour are specified
in [cpu.md](cpu.md). Video, VDP timing and the field contract are specified in
[video.md](video.md). Unsupported encodings, odd word/long accesses and unmapped
addresses stop with an unsupported-instruction or unsupported-address reason;
address-error and bus-error frames are not modeled.

Phase 4's corrected independent v2 successor completed all six frozen schedules
through the public headless client without an unsupported stop. This is a bounded
guest result, not a general game-compatibility claim; the separate v1 command-code
7 stop remains unsupported. Public VDP bus contracts also exercise a legal control
port mirror word write and split long write, plus explicit byte-lane and odd-word
stops (`gameplay_bus_contract`).

ROM maps at zero up to its copied length, at most 4 MiB. Work RAM is 64 KiB,
mirrored in the 0xe00000–0xffffff region. CPU addresses are masked to 24 bits.
There is no open-bus approximation or mapper fallback. Header strings and region
hints never override the caller's explicit profile. Loader validation initially
requires even size 514–4,194,304, an even reset PC in loaded ROM at/after 0x200,
and an even 32-bit reset A7 whose first six-byte exception-frame span after
predecrement maps contiguously to work RAM on the 24-bit bus. The 68000 address
register remains 32 bits; validation does not rewrite it to a 24-bit value. This
admits valid one-past-RAM reset pointers such as the admitted Tank vector
0xe1000000, whose first frame begins at bus address 0xfffffa, while retaining
rejection of zero, odd, unmapped, and boundary-crossing stack vectors. These are
supported-input policies, not a complete cartridge identification test.

For the ordinary linear-ROM/no-SRAM profile, one narrow cartridge-control
operation is modeled: a byte write of zero to 24-bit address `0x00a130f1`
completes without changing ROM. The address role follows Sega's 1993 register
description; Charles MacDonald's *Sega Genesis hardware notes* v0.8 §4.3 reports
the observed zero value and ROM overlay. This is medium-confidence evidence for
that byte operation, not proof for every board or SRAM configuration. The
existing four-CPU-clock bus-transfer cost is a bounded model inference; physical
byte-lane and exact timing behavior remain unverified. Reads, other widths,
nonzero values and neighboring addresses remain unsupported.

The address-register width and MC68000 24-bit bus distinction follow the
[NXP-hosted M68000 User's Manual](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf),
sections 2.1 and 2.3.2.
The two bytes at the reset PC must exist. A 512-byte header alone is therefore
not executable input. Unsupported profile/region returns `GW_ERROR_PROFILE`;
unsupported initialization policy returns `GW_ERROR_UNSUPPORTED`. No profile is
selected implicitly. A successful replacement copies bytes and cold-initializes;
a failed replacement retains ROM, RAM, CPU, time, counters and queued events.

## Time and state

Every actual ROM/RAM byte/word transfer advances four CPU clocks before sampling
or committing data. Long transfers use two high-word-first ordered accesses.
Each word independently masks its address to 24 bits and checks mapping/alignment.
A second-word fault retains the first word's time and any completed write;
the fault reports the second word's address. Public memory peeks remain
nonwrapping, all-or-nothing copies, independent of these CPU transactions.
Instruction extensions use the same bus. Internal delays are explicitly charged
for BRA/TRAP/RTE/RESET. This is an initial deterministic transaction model, **not
cycle-accurate 68000 timing**: prefetch, dummy accesses, physical exception-write
ordering and device stalls remain unqualified. STOP takes two explicit fetches.
There are no waiting devices yet; integrating one requires resumable pending bus
operations before claiming its timing. No device effects are batched to frame end.

Run calls finish at instruction boundaries and report overshoot. Do not re-use a
target less than the returned actual tick. Run-field rule (D-27, 02-01 option-d):
a call with `gw_run_result.flags == 0` also returns, with `GW_STOP_FIELD_COMPLETE`,
at the first instruction boundary at or after the next field end, so a host can
pull each field; `GW_RUN_CONTINUE_PAST_FIELD` runs to the target instead, keeps only
the latest field and increments `gw_video_field.dropped` for each superseded one.
Unknown flag bits return `GW_ERROR_ARGUMENT` before mutation. Machine results
never depend on the flag. Unsupported execution retains partial
effects and fetched PC, then remains stopped until reset/load. The dedicated
instruction address identifies the original faulting opcode even if PC advanced.
Future reset events are ordered by timestamp and insertion order and apply at the
first boundary at/after their timestamp, including the final boundary of a run
and a target equal to current time. A reset advances 112 ticks fetching vectors;
this can make more queued events due, which are also settled before return.
A supported STOP waits for a queued console reset or for an interrupt above the SR
mask (02-18): while stopped, emulated time and the VDP advance in steps of at most one
line (never past the next queued event, a scheduled VINT or the target), an accepted
interrupt resumes at the instruction after STOP through the normal interrupt entry,
and with no wake source the call returns `GW_STOP_CPU_STOPPED` at the requested target.
A field-stop request still returns `GW_STOP_FIELD_COMPLETE` at a field end while the
CPU is stopped. An unsupported stop needs a direct reset. Only console-reset
events exist, so equal-time insertion order has no distinguishable payload;
tests verify that all duplicates execute and consume their vector-fetch time.

`gw_run_result.overshoot_ticks` reports `max(actual_tick-requested_tick,0)`.
`GW_STOP_FIELD_COMPLETE` reports `actual_tick - end_tick` of the completed field.
The structure contract is exact-size at source API version 4 (API 4 adds audio
configuration and PCM output; API 3 introduced the video field query and version 2
added `overshoot_ticks`); recompile consumers against the current header. Targets/events above
`GW_MAX_TARGET_TICK` are rejected before mutation. Reserved integer headroom
(2^32 ticks since the Phase 2 review, was 4096) is an overflow guard, not a measured overshoot
promise; it exceeds the longest single VDP stall (a 65535-word VRAM DMA, about 2.8e7 ticks) by
more than two orders of magnitude. If execution enters that
headroom, cold init/load can restart time; further run/console reset may reject.
No arbitrary-tick observation or partial-instruction continuation is exposed.

Cold init/load zero RAM, all general registers and optional counters, discard
events, restart time, then fetch vectors. Console reset preserves RAM, counters,
events and elapsed time but resets CPU registers (zero except vector SSP/PC and
SR 0x2700); unspecified hardware register contents are modeled by policy.
Guest RESET preserves CPU/RAM/events and continues; the currently modeled PSG is
not reset by that instruction, and its enabled reset counter is observable.
`tests/api/{load,time,reset}_contract.c` exercises these distinctions, invalid
requests, exact limits and permitted run chunking. A bounded private test-build
bus record observes the first 16 writes over an instance lifetime, including
ticks and RAM before each side effect. It is not public diagnostics or machine
state, and is omitted entirely when `GENEWHIP_TEST_HOOKS=OFF`.

### Phase 6 bounded safety and chunk probes

The retained [Phase 6 safety report](../evidence/phase6-safety.json) is bound to
its candidate and records the same 12 named contracts passing in native,
ASan+UBSan, and test-hooks-off builds. The finite malformed-input run reports
4096/4096 malformed-load cases with a128-tick limit. The separate finite API
safety run records16 cases,128 total steps, a180,000-tick budget, a2,048-frame
output bound,416 returned frames and16 checked guards; its maximum observed
tick was179,032. Reported process memory high-water marks remain below the1 GiB
bound; see the report for each variant's measured value. These are the recorded
bounded probes, not a claim that all malformed inputs or allocations have been
exhausted.

The [Phase6 chunk report](../evidence/phase6-chunk.json) records independent
baseline and varied-chunk instances for both complete routes. RECURSION94
compared3,631 fields,20 ordered input events and28,127,873 instruction events;
Tank Battle compared4,196 fields,22 events and48,964,930 instruction events.
Every compared field has equal full RAM, CPU state, pixel rows and complete
PCM bytes. Bounded diagnostic windows retain every instruction event, including
repeated source markers, with zero dropped records. The terminal source boundary
also has equal RAM and CPU state, including REC's last source marker after its
last completed video field. Reset and both-port segmentation cases are exercised
separately by the short three-variant contracts.

REC used37,680,953 aggregate API calls in42.04 seconds; Tank used3,381,981 in39.74
seconds, within their respective100-million/600-second and10-million/300-second
child limits. The REC pair uses an instruction-step baseline; Tank uses bounded
4,096-tick baseline windows. Both compare against varied target requests. Full
PCM and the selected frame also retain FNV-1a64 equality with the earlier
canonical captures; those cross-capture fingerprints retain their collision
limitation. Byte equality between instances establishes bounded determinism;
independent source-media evidence supplies the separate hardware corroboration.

The REC route client requests one tick at a time while its CPU is running;
the separate chunk replay varies bounded target requests. The supported-STOP
observation horizon is separately bounded to at most 308 master ticks. With no
wake source, `GW_STOP_CPU_STOPPED` means the CPU remains stopped while emulated
time advances to the requested horizon; field-stop requests still return at a
field boundary. The 308-tick route limit is a client-side observation bound, not
a general CPU timing or maximum-overshoot guarantee. See
`evidence/phase6-safety.json` and `evidence/phase6-chunk.json` for the exact
candidate identities and retained results.

Future-affecting state inventory: selected profile/reset policy and audio rate,
copied ROM and length, 64 KiB RAM, D0–D7, A0–A7, PC/SR, current tick, last attempted
instruction address/opcode, terminal stop/fault, pending reset events in stable
order, and PSG period/attenuation/latch/counter/output state and next step tick.
Audio resampler continuation is instance-owned. PCM queue state is output-only and
is not part of the execution digest. Initial
vectors and optional saturating counters support observation. Allocation counter
exists only in test builds. There is no public snapshot serialization; native
structure layout must never be used as a file format.

## State inventory (Phase 3)

These additions inventory the connected Z80 sound path and YM2612. The table describes
the current deterministic implementation; reset behavior that lacks exact VA3 wiring
evidence remains unknown for physical hardware. Output buffers and diagnostic capture do
not affect later machine execution and are excluded from the execution digest.

| State | Cold init/load | Z80 reset line | Affects execution / digest |
|---|---|---|---|
| Z80 primary/alternate registers, IX/IY, SP/PC/WZ, I/R, IFFs, IM, Q, HALT and EI delay | cleared | reset-defined subset cleared; RAM retained | yes |
| Z80 prefix decode, micro-op, pending bus cycles and instruction stage | cleared | cleared when reset is applied | yes |
| Z80 reset/BUSREQ levels, pending transitions and next-cycle tick | cleared | reflects line and arbitration transitions | yes |
| Z80 bank shift/latch and 8 KiB Z80 RAM | cleared | kept | yes |
| PSG latch, tone periods, attenuation, counters, outputs and noise LFSR | cleared | retained under current model | yes |
| YM registers, operators, channels, timers, status, busy deadline, sample grid and engine clocks | initialized from pinned ymfm reset routine | reset on asserted edge under approved provisional model | yes |
| YM shared address latch, DAC 9-bit value/enable and pending output level | cleared at cold init | DAC latch/enable retained; writes suppressed while reset held | yes |
| Held-reset write suppression and reset edge state | released | held writes ignored; repeated asserted writes do not reset again | yes |
| Audio resampler integrator and delta ring | cleared | retained; continuation across restore is deferred | yes |
| PCM queue, lost/clipped counters, first-frame index and audio-write trace | cleared | retained as output/observation | no; excluded from execution digest |
| Test-only YM sample buffers, bus events and trace records | cleared | instrumentation only | no; absent from production build |

Exact VA3 reset wiring, pulse width, envelope/phase reset replay and continuation after a
future save/restore remain unknown. See [docs/audio.md](audio.md) for the FM field inventory
and evidence boundaries.

The existing Z80 serial bank register is reachable by a granted 68000 byte write
at exact `0xA06000`; both masters use the same nine-bit bank and partial-write
count. See [Z80 mapping and model limits](z80.md#z80-memory-and-device-map-plan-03-15)
for the primary sources, ownership/reset contract, unsupported reads/widths and
unverified physical timing/partial-write behavior. This integration adds no bank
storage, mapper mode or public API.

## API 3 additions (historical)

Source API version 3 added `gw_get_video_field`, which describes the newest completed
field (`gw_video_field`: pixel format, width, height, pitch, start/end tick, sequence,
dropped count) and returns the single borrowed pointer in the API: read-only XRGB8888
pixels owned by the core, valid until the next `gw_run_until`, `gw_load_rom`,
`gw_cold_init`, `gw_console_reset` or `gw_destroy` on that machine. Every other
output is a copy. `GW_ERROR_EMPTY` is returned before the first completed field. The
byte order of a pixel and the CRAM conversion are specified in [video.md](video.md).

A machine is still one fixed allocation, now larger because it embeds VRAM, two
field buffers, a fixed PCM queue, resampler delta ring and PSG state, plus the ROM
copy. Create/load allocate; all other calls stay allocation-free.
`GW_EVENT_CAPACITY` is 64; submit events just in time, before running across their timestamp.

## API 4 audio additions

`gw_config.audio_rate_hz` selects PCM output from 8,000 through 192,000 Hz; zero
disables PCM production while chip state still advances. `gw_audio_read` copies
interleaved native-endian `int16_t` stereo frames from a bounded 8,192-frame queue.
Frame production follows `floor(actual_tick * rate / GW_MASTER_HZ)` across run
splits; overflow drops the oldest frames and reports `lost` and `first_index`.
The current deterministic mix contains PSG, FM and DAC sources; YM writes can be
copied from a bounded optional trace. PSG/FM comparator deviations, fixed model
choices and exact VA3 reset-wiring uncertainty are documented in [audio.md](audio.md)
and `evidence/fm-deviation-ledger.json`. These implementation and fixture results
do not establish broad game audio compatibility or exact silicon reset behavior.
The resampler kernel and its hash check are described by
`tests/audio/resampler_kernel_hash.py`.

`gw_config.port_device[2]` and `GW_EVENT_PAD_STATE` drive the I/O device
(see [input.md](input.md) and the [GW-06-04 I/O amendment](video.md#observed-io-amendment-gw-06-04)): `GW_DEVICE_NONE` and `GW_DEVICE_PAD3` are accepted at
creation and any other value returns `GW_ERROR_UNSUPPORTED`. The VDP supports the
documented subset described in [video.md](video.md); unsupported modes stop with
`GW_STOP_UNSUPPORTED_STATE` (see also [cpu.md](cpu.md)). `tests/consumer/main.c` pulls a field
from the installed SDK. API 4 adds `audio_rate_hz`, `gw_audio_read_result`,
`gw_audio_read`, `gw_audio_write`, `gw_configure_audio_trace` and
`gw_get_audio_writes`; audio outputs are copied. The video-field pixel pointer is
the sole borrowed output.
Z80 fault encodings follow [z80.md](z80.md): bit 30 marks Z80 faults, unsupported
instructions use `0x40000000 | z80_pc` with `opcode = prefix<<8 | byte`, and
unsupported addresses use `0x40000000 | z80_address`. No broad game compatibility,
complete audio-chip coverage, cycle accuracy, physical host-quality claim, or
published release is claimed.

### Phase 1 contract amendments (API 3, historical)

Statements from the Phase 1 contract that API 3 changed, with the plan that changed each:

- `GW_MAX_TARGET_TICK` moved from `UINT64_MAX - 4096` to `UINT64_MAX - 2^32` (Phase 2 code
  review CR-03): VDP DMA and FIFO stalls advance time inside one bus access, so 4096 ticks no
  longer bounded the overshoot of an accepted target and a DMA near the old limit made
  `gw_run_until` loop on a wrapped line counter.

- Stop values are no longer an ordered scale; `GW_STOP_FIELD_COMPLETE` (5) is a
  run-result reason that is never a sticky CPU stop (02-01). The diagnostic client
  now classifies unsupported outcomes with an explicit `unsupported_stop` test
  instead of `>=` (02-04).
- The sole borrowed pointer exception is the `gw_get_video_field` pixel pointer (02-01).
- One larger fixed machine allocation, including VRAM and two field buffers (02-01).
- Event capacity 16 became 64 (02-01).
- A zero-initialised `gw_run_result` now stops at the next field end (D-27 option-d):
  the "Run calls finish at instruction boundaries and report overshoot" sentence
  above and the `gw_run_until` header comment were rewritten (02-01, 02-04).
- `tests/api/contract.h` `run()` issues the run-to-target request
  (`GW_RUN_CONTINUE_PAST_FIELD`) with `run_field()` as the field-stop helper, and the
  consumer `run()` helper does the same; Phase 1 expectations through them are
  unchanged because all their targets are below the first publish tick 766,080
  (02-01, 02-04).
- Unchanged, with reason: `tools/diagnostic/main.c` keeps zero flags because its single
  run targets tick 10,000, below the first publish tick, so no field stop can occur;
  `tests/api/bounded_fuzz.c` keeps its 128-tick budget; the `time_contract.c` error-path
  calls are unchanged because flag validation follows the target check, and its huge-target
  STOP cases still pass because idle whole fields are fast-forwarded in O(1);
  `tests/evidence/integration.py` is unchanged because it drives the diagnostic client (02-01, 02-04).
- At the time of Phase 2, `scripts/package_sdk.py` metadata recorded `api_version` 3; the
  current SDK and desktop metadata record API 4 and their package smokes reject other values.

STOP behavior (02-18; STOP wake per D-22 and research Open Question 5). Each entry names
file, assertion or sentence, old expectation, new expectation and reason:

- `docs/core.md` "Time and state": old "Supported STOP can wait for a queued reset; without one
  it returns early, without inventing idle time." New: a supported STOP also wakes on an
  interrupt above the SR mask and otherwise returns at the target; reason: STOP wake.
- `docs/core.md` Phase 1 sentence "remains stopped until reset/load" (unsupported
  execution): unchanged, it describes unsupported stops, which still need reset or load.
- `docs/cpu.md` instruction table, STOP row: old "only console reset resumes this subset";
  new "console reset, or an accepted interrupt above the SR mask, resumes"; reason: STOP wake.
- `docs/cpu.md` Interrupts: old "a stopped CPU stays stopped until console reset"; new
  STOP wake paragraph (02-10 had left this for 02-18).
- `tests/api/time_contract.c` "STOP no event does not manufacture elapsed time": old
  `run(a,1000).actual_tick==168`; new `actual_tick==1000` with `GW_STOP_CPU_STOPPED`
  (renamed "STOP with no wake source advances to the target"); reason: stopped time advances.
- `tests/api/time_contract.c` "early stop has zero overshoot": old zero overshoot at the
  early return; new zero overshoot at the target.
- `tests/api/time_contract.c` "below maximum target accepted" and "maximum target accepted":
  old `actual_tick` equal to the unchanged STOP tick; new exactly `UINT64_MAX-4097` and
  `UINT64_MAX-4096`; reason: stopped runs end at their targets (one O(1) jump, no wake
  source).
- `tests/api/time_contract.c` "STOP boundary", "STOP wake at target", "STOP again" and
  "large integer event timestamp exact": unchanged, they still hold.
- `tests/api/reset_contract.c` line 29 (`GW_STOP_CPU_STOPPED && d.d[1]==7` after `run(m,1500)`)
  and `tests/consumer/main.c` lines 48-49: unchanged, they assert the stop reason and
  registers, not the stopped tick.
- `tools/diagnostic/main.c` `bounded` observation string: the `ticks-` value was 1750 in the
  Phase 1 evidence and is now the run target 10000; the predicate
  `run.actual_tick<=10000` still holds, so no predicate changed. The historical
  `01-04-diagnostic-evidence.json` stays byte-unchanged as Phase 1 history.
- `tests/vectors/cpu_interrupt.c` (plan 02-10, not Phase 1) "STOP still awaits console
  reset":
  old STOP ignores a pending VINT; new a masked interrupt keeps STOP stopped and an
  unmasked one wakes it into the handler.
- `docs/cpu.md` "Instruction subset" (moved from Phase 1 `docs/core.md` by 02-02, rewritten by
  02-10). Old: "No interrupt recognition, prefetch pipeline, privilege exception or
  user-stack switching is implemented; interrupt acceptance arrives in plan 02-10. Do not
  infer general 68000 completeness from this table." New: "Autovectored level-4 (HINT) and
  level-6 (VINT) interrupt recognition is implemented (see Interrupts); no prefetch pipeline,
  privilege exception or user-stack switching is implemented. Do not infer general 68000
  completeness from this table." Reason: autovectored interrupts per D-22 (02-10).
- Field stop while stopped: a zero-flag request still returns `GW_STOP_FIELD_COMPLETE`
  at a field end during STOP (option-d, 02-01); the `time_contract.c` STOP cases use the
  run-to-target helper and are unaffected.

## Diagnostic and oracle

Optional local instruction records use a fixed 256-entry instance buffer.
`config.diagnostics=0` disables counters and recording; setting it to 1 uses the
maximum capacity. `gw_configure_diagnostics` selects any capacity 0–256 and clears
observations without changing CPU, RAM, time or queued events. A capacity of zero
disables both counters and records. No event is constructed in the disabled run
path, and the core has no formatting or transport calls.

Each attempted instruction produces a numeric record at its CPU boundary,
including unsupported attempts; repeated calls on a sticky stop produce no new
attempt. Records retain the earliest entries and drop newer entries on overflow,
with a saturating dropped count. Copy-out requires room for all retained entries
and never consumes records. No borrowed pointer or allocation is involved.
Cold init/load clears observations; console reset preserves them. The buffer is
observation-only state and does not affect future machine execution. Threading
and non-overlap rules in the public header also apply to these calls.

`tests/diagnostics/diagnostics_contract.c` compares all CPU registers, run results,
time and all 64 KiB RAM between enabled and disabled copies of the original
diagnostic with identical scheduled reset events. It tests exact/over capacity,
independent buffers, rejected reads/configuration and allocation-free observation.

`diagnostic.S` is original MIT-licensed data-directive assembly with annotated
68000 instruction encodings. The original bounded C emitter `build_rom.c` writes
the declared big-endian words/longwords and zero-fills gaps. It does not execute
instructions or generate expectations; no cross-assembler download is required.
The 1 KiB ROM is rebuilt from source during the native CMake test build.

The independent constants in `tests/consumer/main.c` specify reset PC 0x200,
SSP 0xffff00, byte lanes 0x1234, longword 0x89abcdef, handler marker 0xcafe,
post-RTE marker 0xbeef, saved SR 0x2704 and return PC 0x22a. The consumer also
inspects the real six-byte stack frame, interleaves a second ROM variant, and
checks private allocation counters. A negative control corrupts the expected
word and requires the specific RAM-lanes assertion to fail. These tests establish
this authored scenario, not physical-board truth or broad game compatibility.
Fixture manifest/versioned evidence admission follows in the later Phase 1 plan.

The separate [CPU vector lane](../tests/vectors/README.md) pins a small
SingleStepTests NOP/MOVEQ subset and its MAME-derived oracle. It compares supported
register semantics with explicit PC normalization/relocation; it does not qualify
prefetch, bus timing or independently measured hardware. Unsupported user/trace
records and broader unrun instruction families remain visible in its manifest.

Semantics were consulted in the manufacturer's
[M68000 programmer reference](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf)
(MOVE, MOVEQ, BRA, TRAP, RESET, RTE, STOP) and
[MC68000 user manual](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)
(reset and exception frames). No emulator implementation was copied.

## State inventory (Phase 2 plus PSG)

The paragraph above lists the CPU-side inventory. Phase 2 adds the VDP, I/O and video output
state below. "Affects execution" means a later run can differ if the item differs; there is
still no public snapshot, so native layouts must not be serialized.

| State | Cold init / load | Console reset | Affects execution |
|---|---|---|---|
| CPU registers, PC, SR, stop/fault | cleared, then vectors fetched | zeroed except vector SSP/PC, SR 0x2700 | yes |
| 64 KiB work RAM, optional counters | cleared | kept | yes |
| Event queue (reset and pad events) | discarded | kept | yes |
| Master tick, raster phase | restarts at 0 | kept (timeline continues, A1) | yes |
| VDP registers (24) incl. interrupt enables | cleared | cleared (A8) | yes |
| VRAM (64 KiB), CRAM (64 words), VSRAM (40 words) | cleared | kept | yes |
| Command latch, active code and address | cleared | cleared | yes |
| FIFO (4 entries) and its commit ticks | cleared | cleared | yes |
| DMA state (68000, fill, copy) | cleared | cleared | yes |
| VINT/HINT pending, HINT counter, scheduled VINT | cleared | cleared | yes |
| Sprite overflow/collision flags | cleared | kept (cleared by a status read) | yes (status) |
| VDP advance tick | cleared | kept | yes |
| I/O data and control latches (two pads plus unconnected EXT GPIO) | cleared | cleared | yes |
| CPU USP (explicit supervisor MOVE access only) | zero policy | zero policy | yes, tagged nonzero extension |
| Held buttons per port | cleared | kept | yes |
| Port device configuration, version register | from `gw_config`; 0xA0 | kept | yes |
| Field buffers (2 x 224 lines, XRGB8888), widths, has-field | cleared | kept (completed field survives) | no, output only |
| Field sequence and dropped counters | cleared | kept | no, output only |
| PSG tone periods, attenuation, latch, counters, outputs and next step | cleared | kept | yes |
| Audio rate, resampler integrator and delta ring | from `gw_config`; cleared | kept | yes |
| PCM queue, first index, loss and clip observations | cleared | kept | no, output only |
| Per-run scratch (`fields_this_run`, next line tick) | cleared | kept | no, derived each run |

Guest `RESET` resets neither the VDP, I/O devices nor PSG. Session state (input log,
held masks, field cadence) belongs to the host layer, not the core (`docs/desktop.md`).

GW-06-04 adds on-chip EXT data/control latches without a third public pad or
serial device. Nonzero EXT latches append a tagged little-endian extension to
the private digest; default zero preserves old control values. Digest hashes
are comparisons with collision risk, not a state serialization/proof of equality.
See the [current I/O amendment](video.md#observed-io-amendment-gw-06-04).

The private route tools support `--route-instruction-probe PC` (decimal),
retaining at most the first identified boundary pair and the last boundary pair,
each with at most64 spans of64bytes. No cumulative instruction dump is retained.
`--route-probe-only` requires that option and a GWRC descriptor; it stops at that
specific instruction and labels the result `diagnostic-prefix`. Evidence
validators reject such a prefix as route evidence. All original descriptors,
source clocks and host input handlers stay in use.

Headless `--route-probe-stack-before-a7` requires an instruction probe and a
GWRC descriptor. It adds four one-byte reads at the original A7 minus four
before and after that first probe; read errors remain explicit. It can accompany
a continuing capture or `--route-probe-only`. The observer itself does not
change termination: a full capture retains the later stop separately, while a
prefix remains diagnostic evidence and cannot satisfy capture acceptance.

Running CPUs use target=current+1. A STOP-only horizon up to308 master ticks
cannot cross a modeled44-clock interrupt entry and then retire an instruction:
GWRC has only pad events, no queued resets, and entry faults stop immediately.
STOP requests honor field stops so field callbacks, meta input and PCM draining
remain at the same boundary. `--route-stop-horizon 1` retains the reference path;
the default is308. Original IRQ/marker/stack-fault guests compare exact source,
input, field and PCM observations in both clients. The first243 real RECURSION
source samples match the measured unoptimized prefix exactly. This changes
tool call frequency, not the core scheduler or emulated clock.

## Consolidated limitations (Phase 2/4)

Each item links to the document that states the details and what is, and is not, independently
checked. Evidence counts, including every unknown, unsupported and skipped outcome, are in
the source-bound Phase 4 reports described in `evidence/README.md`.

- CPU ([docs/cpu.md](cpu.md)): a subset of the 68000 instruction set; unsupported forms stop
  fail-closed. In the full pinned vector corpus 41097 of 210000 records pass and 168903 are
  reported unsupported. Timing is a deterministic transaction model, not cycle accuracy.
- Video ([docs/video.md](video.md)): FIFO/DMA slot rates, VINT offset, HV counter and sprite
  limits are model-scoped; shadow/highlight is a Genewhip convention; several status bits and
  edge cases are class unknown in the seams; no left-column blanking, interlace or mid-line
  effects.
- Input ([docs/input.md](input.md)): only the three-button pad; no six-button protocol or other
  peripherals; no controller settling delay; TH does not raise an interrupt.
- Desktop ([docs/desktop.md](desktop.md)): PSG playback is automated through the SDL stream; keyboard and gamepad paths are covered by
  scripts, not physical devices; the display path also passes an opt-in real-window lane locally;
  the hosted desktop job has not run. Actual vsync, renderer readback, physical scanout,
  acoustic quality and latency remain unknown.
- Game compatibility: the corrected independent-game-v2 has a separate six-case,
  840-requested-field Genewhip gameplay result and a 720-field sustained case through
  headless and desktop clients. That exact guest/profile/scenario result does not imply
  broad compatibility; CPU/VDP subsets, other games, hardware timing and other hosts
  remain unproven. See the current report in `evidence/phase4-gameplay.json` and its
  identity-qualified package copy.
- Evidence environment: the independent-game admission and consumer checks (CTest label `mame`)
  were run against a source-built signed MAME 0.289 for the corrected v2 fixture. The
  exact v1 executable is no longer available for a fresh historical probe: its current
  probe reports 2 skipped and 77 unknown, which is not a pass. The unresolved BUSREQ
  status-polarity conflict between two Sega primary manuals also remains visible in
  [z80.md](z80.md); current seam outcomes are model-conformance evidence, not hardware truth.

## Development and portability

Use C17, fixed-width unsigned arithmetic, explicit sign extension and byte decode.
Avoid signed-overflow arithmetic, unaligned casts, packed structs, hidden mutable
globals, VLAs and compiler extensions. Core allocations belong only in the private
helpers in `src/core.c`; no steady run/reset/inspection/event allocation is allowed.
Public ownership, size/version, threading and lifetime rules live in the installed
header. Static library packaging requires recompilation for incompatible 0.x
API changes; no binary ABI across compilers is promised.

Native tests exercise the current host toolchain only. Core-only CMake 3.24 is the
declared build floor, not evidence it was run. Evidence tools/tests require CMake
3.27+ and single-config Unix Makefiles or Ninja to bind generated target settings.
Cross-compilation with `BUILD_TESTING=OFF` and `GENEWHIP_BUILD_TOOLS=OFF` does not
require a host fixture generator or C++ compiler.

## Bounded source-step route tracer

The headless and SDL clients accept `--route-plan FILE --route-report FILE` for
the tool-private GWRP v1 tracer. The plan has a 12-byte header, at most 4096
operations, and a file-size limit of 1 MiB. Each operation observes 1–64
nonwrapping memory spans of 1–64 bytes at completed instruction boundaries,
with an instruction budget no greater than 100000. Addresses are 24-bit bus
addresses checked against the public read range. Dispatch masks are full
three-button pad states; explicit ticks must be nondecreasing, within the
public target-tick limit, and no earlier than the current session tick. A
`UINT64_MAX` tick selects the observed boundary. The parser rejects malformed,
truncated, oversized, or unknown operation data before opening or mutating a
session. GWRP is not a public API or evidence interchange format.

Reports from the route compiler keep load, boot, interaction, sustained, and
completion outcomes separate. Each stage can be pass, fail, unsupported,
skipped, unknown, or infrastructure-error and records whether it was reached.
An unreached stage remains visible; sustained play never implies completion.
`scripts/evidence/phase6_routes.py --validate REPORT` checks the frozen case
denominator, D-118/admission identities, source definitions, clocks, host
receipts, and stage evidence. `--self-test` exercises corrupt report mutants
without loading a game ROM. `--compile DIRECTORY` validates and lowers all twelve
admitted cases into executable `.gwrc` files, provenance sidecars and `roster.json`.
Pass receipts bind the compiled digest and a digest-checked native sample report;
the validator recomputes oracle facts from signal rows. A claimed predicate or
completion flag alone cannot establish a pass. Absence claims require the entire
declared observation window. Tank has no independently defined completion predicate.

GWRC v1 is the shared native frozen-controller format, accepted by both clients
through the same flags. Its 128-byte header and records contain little-endian
u32 words. Header words are: magic `GWRC`, version1, clock kind (1 field state
count, 2 completed source steps, 3 field schedule), total fields, active limit,
boot bound, eight section counts, state/attempt/tick/phase signal indices,
ticks per attempt, active/terminal state values, launch field/release interval/
port/button, render kind/field/attempt/tick/state, boundary-call limit, zero
reserved word. The eight sections have these record layouts:

| Section | u32 fields per record |
|---|---|
| Signals | source effective address, low24 bus address, byte width1/2, endian0 big/1 little |
| Markers | completed instruction PC, opcode (CLR.W absolute long, 0x4279) |
| Actions | first condition, condition count, first step, step count, physical-field timeout |
| Steps | first target, target count |
| Targets | port, single button bit, first condition, condition count |
| Conditions | signal index (0xFFFFFFFF means active ticks), comparison0 EQ/1 GE/2 LT, value |
| Events | attempt, source tick (physical field for kind3), state, port, button, asserted0/1 |
| Predicates | signal index, equals, inclusive lower/upper active-clock bounds |

At most4096 total records and1MiB are accepted. At most128 signal aliases are
read through at most64 nonwrapping spans, each at most64 bytes. Effective source
addresses remain in the descriptor and sidecar; tool reads explicitly use the
documented low24 CPU bus mapping. `gw_peek_memory` remains strict and rejects
addresses above0xFFFFFF. All structure/index/clock/capacity checks precede session
creation; source marker bytes are also checked against the loaded ROM before
execution. Unknown versions, kinds, reserved words, truncated/trailing records,
malformed buttons and nonmonotonic event clocks are rejected as `route-plan`.

Tank snapshots guest state once per published field, increments active ticks
only in state1, and releases each parallel target independently. Completed steps
advance on the next field. RECURSION recognizes the four source-proven completed
phase clears from the pinned ROM, ignores reset/duplicate publications, requires
contiguous attempt/tick progression, and dispatches ordered events at or beyond
their declared tick before the next guest instruction. Field callbacks dispatch
only C while the source UI/reset is paused; they never supply world predicates
or source ticks. Its B target remains the frozen D118 value695. Supported STOP
waits continue under the bounds; they are not unsupported instructions.

Native reports retain raw signal samples, desired/effective input masks, clock
counts, render requests, boundary-call/queue measurements and exact first
unsupported-stop tick separately from final tick. These are observations, not
automatic gameplay or stage passes. The bounded runner retains per-field PCM
draining and SDL presentation. Source observation uses one safe instruction
boundary at a time, including STOP waits; no device timing is guessed. Maximum
physical/active counts are7200/3600 (Tank uses4500/3600), and at most64 pad events
can be pending. The Python subprocess harness enforces600s,1MiB stdout/stderr,
8MiB reports and process-group termination. No real-game success beyond existing
load/CPU stops is established by the authored controller contracts.

### RECURSION94 Plan49 public-core tracer

The first bounded current-source RECURSION94 run used the unchanged B01 ROM,
source archive, input program and oracle. It reached all four declared
predicates and consumed7200 fields, but the final guest became terminal at
attempt4/tick719 after3599 observed completed source steps; the frozen
acceptance remains3600. The terminal transition is included: the four pinned
markers include the `.program_stable` phase clear, and the controller counts
each retired listed marker. The current evidence therefore does not indicate a
missing terminal marker or a CPU/bus stop, and does not justify changing the
observer, input timing, ROM or oracle. The route's declared24-step final B
interaction starting at observed tick696 predicts completion at tick720, while
this run completed at tick719; the one-step acceptance gap remains unresolved.

The retained causal public-core guest separately verifies poll, guest latch,
completed marker, host event dispatch and next poll: the sampled port word was
`0x7f`, `0x77`, `0x7f` for release/press/release, with marker words1/2/3 and
effective masks8/0/0. This establishes the small input seam only. It does not
qualify the route, its withheld-input cases, rendered frame or PCM evidence.
See `evidence/phase6-recursion49.json` and its checked companion for the
source-bound partial result; the six-run qualification and media/whole-phase
obligations remain pending.

### RECURSION94 Plan50 mapped delivery receipt

Plan50 adds `fixtures/phase6/recursion94-consumed-map-v1.json`: nineteen
source-ordered events with a separate source target, public-client dispatch,
consumed poll, expected mask and per-row provenance. The source is the pinned
Phase5-B input program at revision `459bf06`, bound by its SHA-256 in each row.
Sparse MAME observations remain marked unknown except for the retained final B
hold. Cleanup release is a separate controller action, not a twentieth map
event. The source-derived client schedule dispatches final B after tick696 so
the guest consumes it at tick697 through720; MAME's retained effective start
is tick697. This is a client delivery distinction, not a new CPU timing claim.
Paused C/meta requests use the source attempt/tick/state at eligible completed
field or source-marker boundaries. The frozen reference's field numbers stay
in `reference_request`; they are not native absolute-field predictions. The
consumer checks terminal publication, paused completed-step counts, C release,
and the next attempt's first completed step against the retained raw report.

The mapped public-core REC receipt passes 3600 completed source steps and the
four pinned predicates. It records 3631 observed fields (within the 7200-field
cap), 32,044,795 boundary calls, and queue high-water2. The final B poll is
observed at tick697 and the hold continues through tick720. This is one
developmental route receipt, not repeated title qualification or a phase
compatibility claim. `evidence/phase6-tracer-reviewed.json` revalidates the exact
retained raw execution under the corrected C/meta metadata and stricter
consumer, with its own immutable candidate snapshot. Its execution origin
links the unchanged original `evidence/phase6-tracer.json`; it is not another
game run or a corrected SDL game result.

The early SDL software diagnostic used a virtual hat without an explicit SDL
gamepad mapping. Its complete child reports show the core process completed,
but directional masks were not effective through `SDL_Gamepad`, so the mapped
guest route failed. The diagnostic still retained 3631 presentations and
center-pixel readback samples, 2,908,428 submitted PCM frames, and disk-audio
device activity; these observations do not make the input route pass. The
later no-ROM virtual-input contract adds explicit SDL GUID bindings and checks
all nineteen requested masks through the actual SDL event handler and
`sample_port`; it passes, but it does not repeat the guest, renderer or audio
route. The prior diagnostic and post-child wrapper exception remain preserved
in `evidence/phase6-sdl-diagnostic.json` and
`evidence/phase6-sdl-diagnostic-reconciled.json`. Those early diagnostic results
remain failed. Current full core/media and software/native SDL qualification
is recorded separately in the Plan51–53 reports and independent phase review.


### Retained Tank instruction observation (Plan 47, rejected checkpoint)

A single current headless run retained the PEA at `0x00ec32` (`0x4879`):
A7 decreased from `0xe0fffdf4` to `0xe0fffdf0`, the observed stack bytes became
`0006923c`, and the instruction consumed 140 master ticks. The later stop was
`GW_STOP_UNSUPPORTED_ADDRESS` at PC `0x02006c`, opcode `0x13fc`, for address
`0x00a130f1`, at master tick 8,724,688. This is an observed unsupported address;
it does not establish a hardware bus-error exception or route success.

The checkpoint was rejected: it selected at most 128 native boundary calls,
but the serialized route retained a 1,000,000,000-call ceiling and the run
reported 163,937 calls. The limit was checked after execution instead of being
enforced by the launched descriptor. This launch-contract defect remains open;
source and workload slots are frozen, and the two conditional control runs did
not start. The PEA prefix itself required 163,874 retired instructions, so
simply enforcing 128 calls would prevent reaching the observation. A future
useful checkpoint needs a deliberately selected suitable bound and matching
runtime enforcement; this result does not authorize another run.

See `evidence/phase6-tank-checkpoint47.json` and its rejected checked companion
for raw identities, observations, and limits. The corrected no-process contract
passed 71 checks, and native and sanitizer preparation each passed seven named
core contracts. Those checks and this retained prefix do not complete PLAY-02,
HOST-04, SAFE-02, the two-title/control/PCM denominator, actual-host evidence,
or full safety and chunk-determinism duties.

Phase6 canonical reports keep the immutable execution candidate separate from
current offline reader and media-expectation identities. A reader correction
revalidates retained raw plans, owned process receipts, complete stdout field
streams and captures without launching the emulator again. Changed native
runtime or controller bytes invalidate affected execution proof.

The Tank field120 media observation corroborates all70 arena wall cells visible
in the independently pinned reference PNG, the source/SGDK-selected red wall
palette, and source-guaranteed empty corridors. The procedural arena draw is
still in progress at that field; no visible tank or exact whole-frame agreement
is asserted. Source tile indices and actual palettes take precedence over color
comments. Native and host exact pixel equality is a separate obligation. The
short Tank shot gate corroborates source packets and PCM onset/mute; stable
pitch remains unknown when the gate is shorter than10ms.

CMake inputs in a Phase6 execution manifest retain their exact frozen provenance
snapshots. Freshness checks use the current runtime sources, executable bytes,
cache and runtime configuration. Test-registration metadata can change without
rerunning an identical native executable; runtime changes require affected proof
to be refreshed. Current host evidence also binds each selected run to its exact
completed process receipt, limits and confirmed group cleanup.
