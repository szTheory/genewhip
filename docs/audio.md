# Audio contract (API 4)

This page describes the deterministic core PCM interface and the audio behavior
implemented across the Phase 3 sound slice and the bounded Phase 4 game/desktop
qualification. The core owns no host audio device and uses no host clock.

## Phase 3 evidence and limits

Build the consolidated report with `python3 -I scripts/evidence/phase3_report.py
--build build/phase3 --out build/phase3/phase3-evidence.json`; validate an existing report
with `--validate FILE`. The versioned `genewhip-phase3-evidence` report pins the source
revision, build configuration, fixture digests, complete case roster, outcomes and reasons.
It includes all six D-44 rows, the PR and scheduled Z80 vector class denominators, runner
capability skips, and FM comparison classes. A registered check is executed before it is
reported as passing. Unknown, unsupported and skipped cases remain visible.

The FM ledger is [`evidence/fm-deviation-ledger.json`](../evidence/fm-deviation-ledger.json).
It records the exact Genewhip-port versus pinned ymfm comparison separately from the
independent Nuked-OPN2 model comparison. Current ledger counts are FM: 62 writes, 54,991
samples, 66 exact and 54,925 deviating, with 22 status mismatches; DAC: 257 writes, 239
samples, 152 DAC discontinuities and 87 deviating, with 34 status mismatches. This is
implementation/model comparison evidence, not hardware truth. Envelope/phase internals and
guest reset replay remain unknown. The variant identity is YM2612 discrete, VA3 Model 1;
exact VA3 reset wiring remains under the approved bounded exception in the Phase 3 record.

The original raster toy has measured temporal AC ranges of PSG 5,301, FM 13,430 and DAC
7,703. Idle YM DC alone is not activity. The Phase 3 independent-game smoke stopped at
VDP mirror address `0xC00006`; that historical result remains unsupported. The corrected
Phase 4 v2 guest separately passes six bounded Genewhip cases/840 requested fields,
including action-triggered sound and matched no-trigger silence, through the headless
and desktop clients. This is not general game-audio compatibility. Pong remains rejected
because rights/build/runtime gates are unresolved.
No analog output filter, YM3438 variant, Model 2 or PAL profile is claimed. Source/model
assumptions A1–A12 remain open for hardware confirmation; their source-derived relationships
do not establish hardware truth and remain visible in the Phase 3 evidence report. The user
explicitly made subjective listening optional; those observations remain unknown in the Phase 3
UAT and are not a current release gate. Automated PCM and host-session evidence does not establish
listener preference or physical output quality.

## PCM output and rate

Set `gw_config.audio_rate_hz` when creating a machine. Zero disables PCM
synthesis while chip state and timestamped writes continue to advance. Otherwise
the rate must be from 8,000 through 192,000 Hz. The rate is fixed for the
instance; create a new machine to change it.

`gw_audio_read` copies up to `capacity_frames` interleaved stereo frames into a
caller-owned buffer. Each frame is two native-endian `int16_t` samples. The core
does not return a borrowed buffer and does not allocate while running or reading.
For cross-platform evidence hashes, serialize each sample in little-endian byte
order before hashing.

The queue holds `GW_AUDIO_QUEUE_FRAMES` (8,192) frames. At a run boundary the
core finalizes samples through `actual_tick`; the cumulative frame count is

```text
N(T) = floor(T * rate / GW_MASTER_HZ)
     = (T / GW_MASTER_HZ) * rate
       + ((T % GW_MASTER_HZ) * rate) / GW_MASTER_HZ
```

The quotient/remainder form avoids overflowing the intermediate product for
accepted ticks and rates. There is no per-run rounding or remainder. At 48 kHz,
`N(896040) = 801`; the per-run increase can be 801 or 802 frames as the global
fractional position accumulates. A run that overshoots its request counts through
its returned `actual_tick`.

`gw_audio_read_result.first_index` is the absolute index of the first copied
frame. `produced` is the number copied. `lost` is the cumulative number of
oldest queued frames discarded after the queue filled; new frames never change
the run result or throttle execution. Drain at field boundaries to avoid loss.
`clipped` counts frames where either stereo channel saturated to int16 range.
The result also reports `GW_AUDIO_MIX_V1`, `GW_AUDIO_FILTER_BLEP_V1`, the
disabled flag, and zeroed reserved fields.

NULL arguments, zero capacity, and a byte-size overflow return
`GW_ERROR_ARGUMENT`; a wrong result size or API version returns
`GW_ERROR_VERSION`; an unloaded machine returns `GW_ERROR_NOT_LOADED`. These
failures leave both the output buffer and result unchanged. Load and cold init
clear the queue, loss and frame indices. Console reset preserves them.

## Current mix and filter identity

`GW_MIX_V1` contains the three PSG tone channels, PSG noise channel, and YM2612
output. PSG channels use a peak magnitude of 2,048 and the integer 2 dB
attenuation table; the sum is saturated to int16. FM gain and panning follow
the attributed YM2612 port.

`GW_AUDIO_FILTER_BLEP_V1` identifies the in-tree integer band-limited-step
resampler. Its checked-in kernel is generated with:

```sh
python3 -I tools/audio/gen_kernel.py
```

The kernel hash test verifies that the generated bytes match the committed
table. Runtime core code uses integer arithmetic only. No analog console/output
filter is modeled.

## Timestamped chip-write trace

Tracing is disabled by default. Call `gw_configure_audio_trace(machine,
capacity)` with a capacity from zero through `GW_AUDIO_TRACE_CAPACITY` (4,096)
to enable it. Configuration clears retained records and the dropped count. A
guest write arriving while tracing is full is dropped newest-first; the dropped
counter saturates at `UINT64_MAX`.

`gw_get_audio_writes` copies all retained records without consuming them. A
capacity smaller than the retained count returns `GW_ERROR_CAPACITY` before
writing either the buffer or output counters. Passing a NULL writes pointer is
valid only with capacity zero. Records contain the master tick at which the
write took effect, chip, register, raw value, and source. PSG register indices
are 0..7 and identify the affected latched register. Capacity zero records no
writes. Cold init and load clear records and loss while keeping the configured
capacity; console reset preserves them. Enabling the trace does not alter
execution or PCM.

### Original YM2612 seam scripts

`genewhip-seam-fm-script-v1` is an original 68000/Z80 fixture. Its Z80 IM1
handler writes one source-authored tuple per VBlank and polls busy before each
register/data write. The ordered trace covers key on/off; high-then-low,
low-then-high, high-only and low-only frequency latches; channel 3 special
mode/operator frequencies; LFO enable/rate; SSG-EG; timer A/B load and enable;
CSM; DAC enable/data; and a final keyed channel-four note before the reset
probe. The expectation derives each record and field window from the guest
source schedule and fails if records are missing, extra, reordered, dropped, or
outside their assigned window. Timer flags are checked; polling counts remain
unknown observations.

The opening 21 writes configure a bounded audible channel-0 patch from the Sega
Genesis Software Manual's YM2612 register map (archival scan/transcription,
pp. 10–16); eight repeated LFO-off writes hold that interval before the original
32 register-behavior cases. The fixture repair followed a failed audio-activity
check that found the previous bank-one patch and key-on addressed different
channels. The final channel-four key-on still feeds the unknown reset probe.

`genewhip-seam-dac-v1` defines a 256-byte triangle table in Z80 source, enables
the YM2612 DAC, and streams the bytes to register `$2A`. Each steady iteration
uses 39 Z80 T-states (6 for `INC HL`, 13 for `DJNZ`, 7 for `LD A,(HL)`, and 13
for the YM data write), or 585 master ticks at 15 ticks per Z80 T-state. The
seam checks the exact table, 256 writes at that spacing, and non-silent PCM;
sample quality is evaluated by the Plan 03-20 comparator. Replayable register
traces are written to `build/phase3/tests/devices/fm_script.trace.jsonl` and
`dac.trace.jsonl`.

Both fixtures run through the six chunk modes (one-tick, line, field, seeded
random, one-instruction and field-stop). The split tests compare PCM hashes,
write traces and machine-state digests. The FM run covers all 64 fields and
checks the guest's post-reset marker and all 62 source-script writes in every
mode. The DAC run checks all 257 writes (enable plus 256 samples) and nonempty
PCM. In the instruction mode, a bounded tick-step assertion is used because
the fixture's external 68000 reset clears diagnostic instruction counters.

The audio output stream and machine state are separate evidence domains. A
machine-state digest covers emulated device/scheduler state and excludes the
PCM presentation queue, queue loss and trace. An audio-output digest identifies
the declared rate, mix, filter, format and serialized stream beginning at frame
zero. Mark that output digest incomplete whenever `lost > 0`, and retain
`first_index` and `lost` with the evidence. This page specifies the evidence
split; this API slice does not expose a digest function.

## Timing constants

| Constant | Value | Source or class |
|---|---:|---|
| `GW_Z80_DIVIDER` | 15 master ticks per Z80 clock | Derived clock mapping: `GW_MASTER_HZ / 15 = 3,579,545 Hz`; D-39 model profile |
| `GW_PSG_STEP_TICKS` | 240 master ticks | 16 Z80 clocks per SN76489 update, from [SMS Power SN76489 notes](https://www.smspower.org/Development/SN76489); used by `src/psg.h` |
| `GW_FM_SAMPLE_TICKS` | 1,008 master ticks | Discrete YM2612 native sample interval: 144 input clocks at master/7; timer A count is 1008 ticks, timer B count is 16,128 ticks |

## PSG registers and sound model

The 68000-visible PSG data port is byte-write-only at `0xC00011`. Reads,
word accesses, and writes to `0xC00013`, `0xC00015`, or `0xC00017` stop with
`GW_STOP_UNSUPPORTED_ADDRESS`. Z80 writes to `0x7F11` reach the same PSG
model at the Z80 cycle timestamp and record Z80 source attribution in the trace.

A latch byte (bit 7 set) selects one of three tone channels or the noise
channel, then selects period/noise control or attenuation. A tone latch writes
the period's low four bits; a following data byte writes its upper six bits.
An attenuation latch writes a four-bit level, where each step reduces the
modeled amplitude by 2 dB and level 15 is silent. Tone periods 0 and 1 hold the
output high in this model. For periods above 1, the tone output toggles every
period count, giving `f = Zclk / (32 * N)`. SMS Power's [SN76489 notes](https://www.smspower.org/Development/SN76489)
and transcription of the [Game Gear official sound documentation](https://www.smspower.org/Development/GGOfficialDocs)
both describe the 32-times period relationship. This resolves assumption A1
for the documented clock/divider relation; the seam's measured PCM frequency is
still model evidence, not physical-console evidence.

The PSG updates once per 16 Z80 clocks (`GW_PSG_STEP_TICKS`, 240 master ticks).
The noise control byte selects white or periodic feedback and one of four
clocks: fixed reloads of `0x10`, `0x20`, and `0x40` PSG updates, or tone channel
2 output transitions. White feedback is the parity of LFSR bits 0 and 3;
periodic feedback uses bit 0. The 16-bit register shifts right and inserts
feedback at bit 15. Every noise-register write resets it to `0x8000`. These
details follow the cited [SN76489 reference](https://www.smspower.org/Development/SN76489)
and [plutiedev PSG notes](https://plutiedev.com/psg). The `genewhip-seam-psg-v1`
fixture checks three tone frequencies, the silent window, audible fixed and
tone-2-clocked noise, ordered writes, independently computed LFSR sequences,
chunk equivalence, and repeatability.

Console reset currently retains PSG registers, counters, output phase and LFSR.
This is the selected model policy; physical-console reset behavior is not
claimed. These references and tests inform the model but do not establish
measured compatibility for a physical Genesis.

## Current limitations

- The implemented sound path includes PSG, YM2612 FM/timers/status/busy/DAC,
  Z80 arbitration and banking. It remains a bounded implementation model; no
  broad cartridge-compatibility or physical-console matching claim is made.
- No analog filter or host device drift correction is modeled. Device playback
  and display pacing remain host responsibilities.
- Timer and reset contracts are automated implementation evidence. Exact VA3
  reset wiring, pulse width and complete silicon reset effects remain unknown.

## Primary-source records and remaining reset gap

### Variant source (D-48)

Source class: board photograph
Title: Genesis Model 1 VA3 board, IC BD M5 USA VA3 837-7071
URL: https://i.imgur.com/wrmj9Pa.jpg
Retrieval date: 2026-10-20
Retrieved file: build/refs/d48-va3-imgur-board.jpg
SHA-256: 61f923b534fe0d46e23a4e124e093ced09252ee4fcfa1911d8957bbee375ddb5
Figure: single 3264 by 2448 photograph; board identity near lower center, sound IC to the left of the VDP below the RF shield
IC designator: IC11
Quoted package marking: YAMAHA JAPAN; YM2612
Primary source confirms a discrete YM2612 on the VA3 Model 1.

The board silkscreen and fitted package were inspected in the same photograph.
The photograph establishes chip identity for this specimen; it does not trace
the reset wiring or establish analog fidelity. The downloaded photograph stays
in ignored local reference storage and is not redistributed. The image was
located through the [manufacture-date registry](https://www.sega-16forums.com/forum/console-talk/genesis-does/22695-sega-genesis-mega-drive-manufacture-date-registry/page5);
that forum's prose is not the source of the chip-identity finding.

### Reset search record (D-42; approved bounded exception, exact net unknown)

No qualifying VA3 Model 1 service manual or schematic tracing the YM2612 reset
pin net was retrieved. The [Console5 VA3 A/V schematic lead](https://console5.com/techwiki/images/8/8b/Mega_Drive_1_-_VA3_-_Audio%2C_Video_%28Sheet_2%29.png)
returned HTTP 403 through both web retrieval and curl. Its contents and reset
nets were not inspected. The [technical-documentation index](https://consolemods.org/wiki/Genesis:Technical_Documentation)
provides a PAL Model 1 VA4 manual and Model 2 manuals, which cannot prove the
exact VA3 Model 1 wiring. No `build/refs/d42-*` file or reset-net Finding exists.

The Sega *Genesis Sound Software Manual* (1992-02-21), printed page 2 / PDF
page 6, says that Z80 reset also clears the FM sound source. Its
[retrieved PDF](https://gendev.spritesmind.net/files/md/tech/Genesis%20Sound%20Software%20Manual%20%5B1992-02-21%5D.pdf)
is stored as `build/refs/genesis-sound-software-manual-1992-02-21.pdf`, SHA-256
`7a99b1bca39306323580581f56517bbcb7a17499e4bef41890f483489de0a75f`.
This is primary programmer documentation for the stated software-visible
behavior, but it neither identifies VA3 wiring nor specifies every chip state
cleared. The exact-VA3 reset net, minimum pulse width, and complete silicon
reset-state effects remain unknown. Under the user-approved 2026-10-20 amendment
in `03-FM-RESET-AMENDMENT.md`, this programmer-manual instruction is accepted as
bounded evidence for software-visible coupling. This is a documented programmer-
manual statement, not a schematic Finding; the exact VA3 reset net is unknown.
It does not satisfy the original service-manual/schematic gate. The approved
decision and remaining limits are recorded in
`.planning/phases/GW-03-sounded-cartridge-loop/03-FM-RESET-AMENDMENT.md`.

Approved reset evidence retrieval (source retained in ignored local storage):

```sh
curl -fL --max-time 30 'https://gendev.spritesmind.net/files/md/tech/Genesis%20Sound%20Software%20Manual%20%5B1992-02-21%5D.pdf' -o build/refs/genesis-sound-software-manual-1992-02-21.pdf
shasum -a 256 build/refs/genesis-sound-software-manual-1992-02-21.pdf
```

The expected output digest is
`7a99b1bca39306323580581f56517bbcb7a17499e4bef41890f483489de0a75f`. The
amendment authorizes provisional implementation behavior that resets YM2612 on
a Z80-reset edge, holds output silent and ignores writes while reset is held,
then resumes on the existing native-sample grid after release. The reset field
inventory follows the pinned ymfm reset routine. These implementation
contracts are classed unknown for exact VA3 hardware fidelity and are not
hardware passes.

The first search found no qualifying schematic source. The focused follow-up
resolved D-48 with the photograph above, while the D-42 schematic lead remained
inaccessible. The user approved the bounded programmer-manual exception on
2026-10-20. This preserves the historical failed schematic gate and classifies
the provisional implementation details as unknown for exact VA3 hardware
fidelity.

The `fm_script` seam keys a channel-four note, records a pre-reset status byte,
asserts Z80 reset from the 68000, then acquires the bus before reading YM
status again. The probe recorded bytes `ff 00` (pre-reset and post-reset,
respectively). This is classed **unknown** for exact VA3 hardware behavior
because the approved amendment does not provide a matching wiring Finding. It
is reported as observed provisional implementation behavior, not as a model
default or a hardware pass.

### FM engine and mix (Plan 03-17)

The discrete YM2612 engine is a BSD-3-Clause C17 port of ymfm revision
`81aec25ccbb98f4873a255f7551ac4dadac59b4a`. The six pinned source hashes,
verbatim notice, function mapping and specialization ledger are in
`packaging/notices/THIRD-PARTY-ymfm.txt`, also installed with the core.
Only that revision's `ymfm.h`, `ymfm_fm.h`, `ymfm_fm.ipp`, `ymfm_opn.h`,
`ymfm_opn.cpp` and `LICENSE` were read for the implementation. No prohibited
comparator implementation was read. This is a port, not original synthesis code.

The instance owns all registers, operators, channels and scheduling state.
The native rate is master/7/144, one sample each `GW_FM_SAMPLE_TICKS` (1008)
master ticks on a grid starting at tick 1008. Timer A period is
`(1024 - TA) * 1008` master ticks and timer B period is
`(256 - TB) * 16 * 1008`; enabled overflow sets status bits 0/1 and the
corresponding reset bits in register `$27` clear them. Timer and busy state
advance with PCM disabled. Data-write busy lasts 32 prescaled FM clocks
(`32 * prescale * 7` master ticks). Both CPU routes synchronize before writes: granted
68000 bytes at `$A04000..$A04003`, Z80 bytes at `$4000..$4003`. Address writes
set the upstream shared banked latch; matching-bank data writes generate the
chip/register/value/source trace. Ungranted 68000 writes are ignored. Status
is exposed at offset 0. Other read offsets return pinned ymfm's zero value,
which is unqualified for exact discrete-silicon read behavior; the profile
does not enable read-on-any-port. Timer expiries precede coincident samples.

The port retains all eight algorithms, feedback, panning, frequency-pair
latches, phase/detune/multipliers, envelope/key scaling, LFO AM/PM, SSG-EG,
channel 3 frequencies, timer-driven CSM, DAC enable/data and its low test bit.
Each channel's clipped 9-bit output `[-257,256]` becomes `[-260,260]` with
the discrete ladder discontinuity. Six channels scaled by `128*64/(6*65)`
therefore have full scale 32768. The approved FM share 24576 gives
`GW_MIX_V1_FM_NUM=3`, `GW_MIX_V1_FM_DEN=4`; the mapped full-scale peak is
24576. PSG and FM changes merge in timestamp order before PCM finalization.
The upstream idle DC offset and zero-crossing step are retained; analog
filtering is not modeled. Held-reset output is explicitly silent.

The original `fm_tone.S` cartridge requests/polls the Z80 bus, releases reset,
writes a single-carrier algorithm-7 patch, keys on, then returns the bus to a
HALTed Z80. `fm_tracer` pulls four fields through the public API, checks exact
frame counts and traced writes, and measures sign-crossing intervals. The
frequency relation is `FNUM * 2^block * (master/7) / (144 * 2^21)` for MUL=1.
FNUM/block and latch ordering follow the [Plutiedev register reference](https://www.plutiedev.com/ym2612-registers);
the accumulator normalization supplies the `2^21` denominator. FNUM 644 and
block 4 select approximately 261.72 Hz. This is a bounded implementation
pitch check, not a claim of complete hardware or game compatibility.

### Provisional reset implementation inventory (hardware fidelity unknown)

The user-approved amendment applies pinned `ym2612::reset`, which calls
`fm_engine_base::reset`; it does **not** reconstruct the chip. The following
inventory is asserted by `fm_reset_inventory` before downstream reset seams
rely on it. It describes an implementation contract, classed unknown for
exact VA3 hardware fidelity.

| State | On asserted edge | Upstream mapping |
|---|---|---|
| Register bytes, including internal frequency high latches | Zero, except `$B4..$B6`/`$1B4..$1B6` default to `$C0`; mode `$27` written through side-effect path | `opn_registers_base::reset`, `engine_mode_write` |
| Operator phase, attenuation, state, inversion, current/live keys | Phase 0; attenuation `$3FF`; release state; inversion/keys 0 | `fm_operator::reset` |
| Operator offsets and caches | Retained; mode write marks all channels modified so caches refresh before next clock | Operator constructor, `fm_engine_base::write/clock` |
| Channel feedback history and feedback input | Zero | `fm_channel::reset` |
| Channel offsets and operator mapping | Retained | Channel constructor, `assign_operators` |
| LFO counter and current AM value | Retained until later clocking; disabled LFO then resets counter | Register constructor/reset/clock |
| Envelope counter, total sample clocks, prescale, IRQ mask | Retained | Engine constructor/reset |
| Active channels and prepare counter | Retained; modified mask becomes all six | Engine reset/mode write |
| Timer running flags/deadlines | Both stopped/canceled by mode write | `engine_update_timer` |
| Status and derived IRQ state | Cleared | `set_reset_status`/`engine_check_interrupts` |
| Shared address latch, DAC 9-bit data and enable | Retained | `ym2612::reset` only resets FM engine |
| Busy deadline | Retained; expires with master time | Upstream interface busy state |
| Immutable waveform | Retained | Register constructor |
| Master time, sample grid, existing PCM and frame indices | Retained | Approved wrapper; held reset advances the existing grid |
| Mix last level | Timestamped step to zero; BLEP deltas continue | Approved wrapper; retained enabled DAC data can resume its DC contribution after release |

Writes on either CPU route are ignored while held, repeated asserted-level
writes do not reset again, and held time advances the existing sample grid
without clocking the engine. Release resumes at its next existing boundary;
it does not restore a prior FM key. Because upstream retains DAC data/enable,
a retained enabled DAC can resume its constant level after release. No new
minimum pulse width is asserted. Console reset asserts this same provisional
chip reset as a separately documented model choice. The extended public-route
and split-run reset contract belongs to Plan 03-18; hardware reset truth,
analog behavior and model comparison remain unqualified here.
