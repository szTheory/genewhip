# Video contract (API 4)

This page is the contract for the field query, VDP timing, write FIFO, DMA,
unsupported-mode stops, background planes A and B, the window plane, scrolling, priority,
sprites and shadow/highlight. Consolidated Phase 2 limitations are at the end of this page.

## Observed I/O amendment (GW-06-04)

The existing [input contract](input.md) will be consolidated in06-07. The current
shared bus now permits aligned word reads of the implemented version, pad and
EXT GPIO registers; long reads perform two independent ordered word reads.
Existing canonical byte accesses remain. Odd word accesses, unsupported serial
registers and public pad port2 remain rejected. Word writes and even-byte
accesses are still unsupported; no broader I/O completeness is implied.

Sega's Genesis Software Manual, Rev02/20/92, printedp74, permits byte/word
I/O access and specifies only the meaningful lower byte. The retrieved primary
scan is [Sega/Ozisoft's1992 manual](https://drive.google.com/uc?export=download&id=1wcpCpxszzCYjdhlHMcmoiA3XU9FLeKwV),
SHA256 `b70081d47ab877024a6f06c1d2024cbfc94aebdc21f51972e51d038026bc146a`,
PDFp84. It is research material, not redistributed as a project fixture.
[Charles MacDonald's hardware notes v0.8, section3](https://www.neperos.com/article/picov96e5792f069)
independently report even/odd read aliases and cold control00/data7F.
Duplicating a register byte into the unused upper word lane is an explicit
coherent model inference from those aliases, not a manufacturer word-lane claim.

The unconnected EXT pair at0xA10007/0xA1000D has separate instance-owned data
and direction latches. Input pins read high; output pins read the data latch,
with bit7 latch-backed as in the existing model. Load/cold/reset clear the
latches as deterministic policy; this does not establish physical VA3 reset
wiring. No EXT peripheral, third host pad or serial behavior is implemented.
The private digest distinguishes every nonzero latch bit using a tagged
zero-default-compatible extension. Original guests check independent pad
latches, read lanes, reset, state discrimination and rejected third-pad events.

## Field contract

`gw_get_video_field(machine, &field, &pixels)` describes the newest completed field and
borrows its pixels from core-owned storage.

| Descriptor field | Meaning |
|---|---|
| `pixel_format` | `GW_PIXEL_XRGB8888` (1) |
| `width` | 256 (H32) or 320 (H40); no width is fixed in the header |
| `height` | 224 |
| `pitch_bytes` | Distance between rows; at least `width * 4`. Only `width * 4` bytes of each row are defined |
| `start_tick` | Start tick of line 0 of the field |
| `end_tick` | Start tick of line 224 of the same field, i.e. the publish tick `field_index * GW_FIELD_TICKS + 224 * GW_LINE_TICKS` |
| `sequence` | Field index from zero since cold init |
| `dropped` | Fields superseded inside one run call (see below) |
| `flags`, `reserved` | Zero |

Pixel layout is defined byte-wise (a Genewhip convention, D-28): each pixel is one
`uint32_t` holding `0x00RRGGBB` in host byte order. In memory the bytes are B, G, R,
0x00 on little-endian hosts and 0x00, R, G, B on big-endian hosts. Rows are
`pitch_bytes` apart.

The call returns `GW_ERROR_EMPTY` before the first completed field after load or cold
init, `GW_ERROR_ARGUMENT` for NULL arguments and `GW_ERROR_VERSION` for a wrong
`struct_size`/`version`; outputs stay unchanged on any failure. The pixel pointer is
valid until the next `gw_run_until`, `gw_load_rom`, `gw_cold_init`, `gw_console_reset`
or `gw_destroy` on that machine.

### Run requests and `dropped` (D-27)

- Field-stop request (`gw_run_result.flags == 0`, the default): the call returns
  `GW_STOP_FIELD_COMPLETE` at the first safe boundary at or after `end_tick`.
  `overshoot_ticks` is then `actual_tick - end_tick`. If the target precedes the field
  end, the stop reason is `GW_STOP_TARGET`.
- Run-to-target request (`GW_RUN_CONTINUE_PAST_FIELD`): the call runs to the target
  and keeps only the newest field. `dropped` grows by the number of fields completed
  in that call minus one.
- `dropped` is a host observation. Machine state (CPU, RAM, ticks, published pixels
  for a given sequence) never depends on the request type or on how a run is split.
- Unknown flag bits return `GW_ERROR_ARGUMENT` before any mutation.

## Timing model

- Stopped CPU (plan 02-18): while the CPU is in STOP, time advances to the next of the
  next line boundary, a scheduled VINT, the next queued event and the run target, so fields
  keep publishing and a VINT or HINT above the mask wakes the CPU. When no VDP interrupt can
  wake it and the request is run-to-target, the whole span is one advance (idle fields are
  fast-forwarded).
- Lines are 3420 master ticks; a field has 262 lines (NTSC) = 896,040 ticks; lines 0
  to 223 are active and the field publishes at the start of line 224.
- Each line renders from VDP state sampled at its line-start tick (D-19). The VDP is
  advanced to bus time before every port access and at every CPU boundary, so results
  do not depend on how a run is split.
- Tick 0 is line 0 of field 0 after cold init. Console reset keeps the tick timeline
  and the raster phase (assumption A1). Line 0 at tick 0 renders from power-on
  registers, so field 0 reports width 256 unless a register write precedes it.
- Width is latched at line 0 of each field; a change takes effect on the next field.
- Data-port writes queue in a 4-entry FIFO (D-20) capturing code and address at
  enqueue; each lands at a modeled external-access slot tick. A write to a full FIFO
  holds the CPU until the oldest entry lands.
- Console reset (assumption A8) clears VDP registers, command latch, FIFO and DMA state
  and keeps VRAM, CRAM, VSRAM and the completed field.

### Write FIFO and DMA (plan GW-02-08, D-20, D-21)

One slot table paces everything the VDP does on behalf of the guest. It is the evenly
spaced external-access slot table above; slot `k` of `n` on a line is at
`line_start + k * 3420 / n`. No rate is taken from, or checked against, a reference
emulator, and Genewhip's table is authored independently.

- **FIFO.** A data-port write queues an entry holding its code, address and data at
  enqueue; each lands at the next access slot after the previous entry. A write to a
  full FIFO holds the CPU, through bus time, until the oldest entry lands, so occupancy
  never exceeds four. The status register shows FIFO empty (`0x200`) and full (`0x100`).
  Blanking has far more slots per line than active display, so the same burst that fills
  the FIFO in active display does not in blanking.
- **DMA command.** A control-port command with CD5 set and register 1 M1 set starts a
  DMA kind chosen by register 23 bits 7-6: `0x` 68000-to-VDP transfer (VRAM code `0x21`,
  CRAM `0x23`, VSRAM `0x25`), `10` VRAM fill (code `0x21`), `11` VRAM copy (code `0x30`).
  Length is registers 19/20; a 68000 source is registers 21/22/23 (bit 6 of register 23 is
  source word-address bit 22). A mismatch between register 23 and the command code, a DMA
  command with M1 clear, and DMA with a read code stop with `GW_STOP_UNSUPPORTED_ADDRESS`
  and the control-port address as `fault_address`.
- **68000-to-VDP transfer.** The CPU is halted for the whole transfer: words are delivered
  at consecutive access slots (two per VRAM word, one per CRAM or VSRAM word), every line
  elapsing during the halt still renders from the VRAM contents at its start tick, and
  bus time ends at the last delivery. Source words are fetched through the bus mapping
  checks (`gw_bus_span`) without adding bus ticks: only ROM within its loaded size and
  work RAM are mapped, and any other source stops with `GW_STOP_UNSUPPORTED_ADDRESS` and
  the source byte address as `fault_address`, never reading out of bounds. The 23-bit word
  source increments in its low 16 bits only, so it wraps inside its 128 KiB block. A VRAM
  destination at an odd address stays fail-closed like a data-port write.
- **Fill.** The command only arms the fill. The data-port write that follows lands as an
  ordinary VRAM word through the FIFO; the high byte of that word then fills `length`
  bytes from the next address, stepping by register 15, one byte per slot. The CPU keeps
  running and the status DMA bit (`0x02`) is set until the last byte lands. Any other
  command disarms an unstarted fill.
- **Copy.** The command itself starts a copy of `length` VRAM bytes from the byte address in
  registers 21/22 to the command address, destination stepping by register 15, two slots
  per byte. The CPU keeps running and the DMA bit is set while it runs.
- **Contention (model-scoped).** While a fill or copy is running, a data-port write or read
  and a new DMA command hold the CPU until it finishes. Hardware behaviour here is not
  independently sourced and the seam reports it `unknown`. Length 0 transfers nothing in
  Genewhip; the hardware meaning is likewise `unknown` (assumption A10).

### Timing constants

| Constant | Value | Source or class |
|---|---|---|
| Line length | 3420 master ticks | gendev t=519 hardware video measurements |
| Lines per field | 262 (224 active) | Sega documentation, NTSC raster |
| Access slots per line, H32 | 16 active / 166 blank | gendev t=851 Nemesis VRAM-access measurements; model-scoped |
| Access slots per line, H40 | 18 active / 204 blank | gendev t=851 Nemesis VRAM-access measurements; model-scoped |
| Slot spacing within a line | even | model-scoped approximation, not a measured schedule |
| 68000-to-VDP transfer rate, bytes per line | H32 16 active / 166 blank, H40 18 / 204 (`GW_VDP_DMA_RATE_*`) | gendev t=851 Nemesis VRAM-access hardware measurements, including the thread's follow-up correction of the blank figures to 166/204; model-scoped |
| 68000-to-VDP slot cost per word | VRAM 2 slots (two byte accesses); CRAM and VSRAM 1 slot (`GW_VDP_DMA_COST_*`) | VRAM word = two byte accesses per the same measurements; CRAM/VSRAM one slot per word is Genewhip-authored, model-scoped |
| VRAM fill rate | 1 slot per byte, i.e. equal to the 68000-to-VDP byte rate | Genewhip-authored, model-scoped; absolute value `unknown` in the seam (see "Fill and copy citation gap") |
| VRAM copy rate | 2 slots per byte, i.e. half the byte rate | Genewhip-authored, model-scoped, following the gendev forum report that copy runs at about half the transfer rate; absolute value `unknown` in the seam (see "Fill and copy citation gap") |
| FIFO depth | 4 | Sega documentation |
| VINT assertion offset, `GW_VDP_VINT_OFFSET_TICKS` | 0 ticks into line 224, H32 and H40 | model-scoped; the documented fact is only "once per field at the start of vertical blanking" (plutiedev vdp-registers IE0; Sega documentation). The true sub-line offset is `unknown`: no independent primary or hardware-observation figure was found, and no reference-emulator figure is attributed |
| HINT counter | decrement on lines 0..224, fire at 0 and reload from register 10, reload on lines 225..261 | assumption A3, community hardware observation (SpritesMind forum posts, Sega Retro VDP article); the sources disagree on the exact line range, so absolute counts are `REF-derived` in the seam |
| Interrupt entry | 44 clocks = 308 ticks, fixed | MC68000UM exception timing "Interrupt 44(5/3)" with a 4-clock acknowledge cycle; acknowledge variability is not modeled (A11) |
| HBLANK window | last `(total - active) / total` of the line, H32 342/256 and H40 420/320 pixels | pixel counts per Charles MacDonald, genvdp.txt (recalled, not re-read); linear map onto ticks is model-scoped |
| HV counter V | `0x00..0xEA` then `0xE5..0xFF` over the 262 NTSC lines | MacDonald, genvdp.txt (recalled); sequence only, no tick offset claimed |
| HV counter H | H32 `0x00..0x93,0xE9..0xFF`, H40 `0x00..0xB6,0xE4..0xFF`, linear in line ticks | model-scoped; the real value at a tick is unknown, so the seam reports it as `unknown` |
| CRAM channel table | 15 levels; normal `2 * v`, shadow `v`, highlight `v + 7` | Genewhip convention (assumption A5), not a measured curve |

No constant is attributed to a reference emulator; Genesis Plus GX is a behavioural
reference only.

### CRAM to XRGB8888

A CRAM word is `0000 BBB0 GGG0 RRR0`: R from bits 3-1, G from 7-5, B from 11-9. Each
3-bit value `v` maps to level `{0,27,49,71,87,103,119,130,146,157,174,190,206,228,255}[2 * v]`.
The backdrop is CRAM entry `register 7 & 0x3F`.

### Shadow and highlight (plan GW-02-19, D-28)

Setting register 12 bit 3 (S/TE) turns shadow/highlight on. The core resolves it to final
XRGB8888 itself; the host never sees an intensity. **The table is a Genewhip convention
(assumption A5), not measured hardware DAC output.** The same 15-level table is indexed by
intensity: normal `level[2v]`, shadow `level[v]`, highlight `level[v + 7]` (so highlight of
channel value 7 is 255, and black stays black when shadowed). Strictly, shadow < normal for
`v >= 1` and normal < highlight for `v <= 6`; at the endpoints the levels coincide.

With S/TE set, per pixel:

| Winning layer | Intensity |
|---|---|
| high-priority plane or sprite pixel | normal |
| low-priority plane or sprite pixel, and the backdrop | shadow |
| sprite pixel of palette 3 colour 14 (highlight operator) | not drawn; moves the pixel below up one step: shadow becomes normal, normal becomes highlight |
| sprite pixel of palette 3 colour 15 (shadow operator) | not drawn; the pixel below becomes shadow |

Operator sprites follow the usual sprite rules (link order, limits, first drawn wins, the
collision flag) and take effect on whatever lies below them. With S/TE clear, palette 3 colours
14 and 15 are ordinary colours. The operator colours and the priority rule follow the community
description in plutiedev; per-priority sprite shadowing and operator interaction with sprites
below are conventions chosen here and not independently verified.

`cram_expansion` (a Genewhip convention test, not hardware evidence) renders in-memory ROMs
through the public video output and checks exact black (`0x0000`) and white (`0x0EEE`), the
table ordering for every channel value, and each row of the table above. The raster toy turns
S/TE on at handler run 80; `raster_toy_planes` samples field 81 in full and requires pixels of
both shadow and normal intensity.

## Unsupported modes (D-23)

At each line render point (lines 0 to 223) the core stops with
`GW_STOP_UNSUPPORTED_STATE` instead of approximating when the guest has programmed:
V30 (register 1 bit 3), interlace (register 12 bits 2-1), mismatched RS0/RS1
(register 12 bits 7 and 0), or a display-enabled non-Mode-5 setting (register 1 bit 6
set, bit 2 clear). The stop is sticky until reset/load and
`fault_address = 0x80000000 | (register << 8) | value` (bit 31 is never a 24-bit bus
address). Transient writes between render points do not stop.

## Ports (plan GW-02-03)

- Data port (`0xC00000`, mirror `0xC00002`): word and long accesses (a long is two word
  transfers). Reads need a read code (VRAM, CRAM or VSRAM); the CPU first waits, in
  emulated ticks, until the FIFO has drained. Each access applies the register-15
  auto-increment with 16-bit wrap. CRAM and VSRAM ignore address bit 0; VSRAM entries
  40 and above read 0 (a defined Genewhip value, class `unknown` in the seam).
- Control port (`0xC00004`, mirror `0xC00006`): writes as before. Reads return the
  status word: FIFO empty `0x200`, FIFO full `0x100`, VINT `0x80` (set from the VINT
  assertion until acknowledgement, see Interrupts), sprite overflow `0x40` and collision `0x20` (cleared by the read),
  VBLANK `0x08` (line 224 and later, or display disabled), HBLANK `0x04` (model-scoped
  window, see the constants table), DMA `0x02` (set while a fill or copy runs), PAL `0x01`
  (0 on the NTSC profile). Bits 15-10 read 0.
- HV counter (`0xC00008..0xC0000F`): word reads only; see the constants table.
- Any data, status or HV read clears a pending first command word. Whether hardware
  does this is not stated in the cited documentation; the behavior follows the reference
  emulator and the seam labels it `REF-derived`.

## Unmodeled VDP accesses

Byte accesses, malformed or M1-less DMA commands, data reads under a write code, data
writes under a read code, odd-address VRAM word accesses and writes to the HV range stop with
`GW_STOP_UNSUPPORTED_ADDRESS` and the bus address as `fault_address`. A long access at
`0xC00006` also touches `0xC00008`, so it behaves as the hardware address map implies.

## Seam diagnostics

Seam ROMs live in `tests/devices/roms/`, are assembled by the pinned GNU Binutils 2.47
`m68k-elf-as` (`scripts/fixtures/build-original-roms.sh`), and are admitted as
`original-rom` rows in `fixtures/manifest.json`. `gw_seam_runner` runs a ROM to a tick
through the public API and prints a work-RAM window; `seam_check.py` judges it against
`NAME.expect.json`, which is authored from the cited documentation and never from
Genewhip output. Outcomes are `pass`, `fail`, `unknown`, `unsupported` and
`infrastructure-error` over a fixed denominator; oracle classes are `documented`,
`REF-derived` and `unknown`. A `REF-derived` pass is reported under its own class and is
not documented hardware evidence. `vdp_ports_seam_negative_control` flips one expected
byte of the first documented case and requires exactly that case to fail with `mismatch`.
Any unsupported stop marks every case `unsupported`.

The `ports` seam (13 cases):

| Case | Class | Basis |
|---|---|---|
| `vram-write-readback` | documented | plutiedev vdp-commands; Sega manual data-port read |
| `cram-write-readback` | documented | plutiedev vdp-commands; CRAM word format |
| `vsram-write-readback` | documented | plutiedev vdp-commands |
| `autoincrement-4` | documented | plutiedev vdp-registers, register 15 |
| `port-mirrors-c00002-c00006` | documented | plutiedev vdp-setup, vdp-commands |
| `status-fifo-empty-dma-pal` | documented | Sega manual status layout (mask `0x0203`) |
| `status-via-c00006` | documented | control-port mirror (mask `0x0203`) |
| `status-vblank-display-disabled` | REF-derived | reference emulator; manual defines VB only for vertical blanking |
| `latch-cleared-by-status-read` | REF-derived | reference emulator; plutiedev is silent |
| `status-upper-bits-and-hblank` | unknown | undocumented bits and Genewhip instruction timing |
| `hv-counter-word` | unknown | depends on Genewhip instruction timing |
| `vsram-entry-40-read` | unknown | undocumented past 40 entries |
| `completion-marker` | documented | ROM control flow reached the final store |

The FIFO-full status bit, which no `ports` case asserts, is covered by the `fifo` seam below.

The `fifo` seam (`genewhip-seam-fifo-v1`, 7 cases; tests `vdp_fifo_seam` and its negative
control). Its authored expectations assert orderings and relationships, never absolute
slot positions or instruction counts:

| Case | Class | Basis |
|---|---|---|
| `fifo-burst-order` | documented | plutiedev vdp-commands; Sega documentation: queued writes keep order |
| `fifo-full-flag-in-burst` | documented | Sega status bit 8; gendev t=851 slot rates: a sustained burst outruns the slots (mask `0x0100`) |
| `fifo-empty-flag-after-wait` | documented | Sega status bits 9 and 8 after polling (mask `0x0300`) |
| `fifo-no-full-in-blanking` | documented | gendev t=851: 166 blank slots per line versus 16 active (mask `0x0100`) |
| `fifo-address-change-pending` | documented | Sega documentation: each entry carries its own address and data |
| `fifo-status-per-write` | unknown | instruction count before the full flag first reads set is not independently known |
| `completion-marker` | documented | control flow reached the final store |

The `dma` seam (`genewhip-seam-dma-v1`, 25 cases; tests `vdp_dma_seam` and its negative
control). Documented rows come from the plutiedev dma-transfer, vdp-registers and
vdp-commands pages and the Sega status layout; the table words are fixed by the ROM's
construction (`dma.s`):

| Case | Class | Basis |
|---|---|---|
| `dma68k-vram-first`, `-middle`, `-last`, `-past-end-untouched` | documented | plutiedev dma-transfer: word units, VRAM DMA command, length bound |
| `dma68k-cpu-halt-hv-counter` | unknown | HV counter before and after depends on the unmeasured slot schedule; the halt itself is a model check in `vdp_timing_contract` |
| `dma68k-cram-first`, `-last` | documented | plutiedev dma-transfer: CRAM DMA command `0xC0000080` |
| `dma68k-vsram-first`, `-last` | documented | plutiedev dma-transfer: VSRAM DMA command `0x40000090` |
| `dma68k-source-128k-wrap` | REF-derived | plutiedev documents only that a source must not cross a 128 KiB boundary; the data read by a crossing transfer is commonly reported behaviour not re-read here, so it is not counted as documented evidence |
| `fill-interior-words`, `fill-bounded-by-length` | documented | plutiedev vdp-registers: DMD `10` = fill, length registers; edges excluded |
| `fill-busy-flag-set`, `fill-busy-flag-clear-after-poll` | documented | Sega status bit 1 (mask `0x0002`) |
| `fill-edge-first-word`, `fill-edge-last-word` | unknown | trigger-word and length-edge conventions are not independently sourced |
| `copy-busy-flag-set`, `copy-busy-flag-clear-after-poll` | documented | Sega status bit 1 (mask `0x0002`) |
| `copy-first-word`, `copy-middle-word`, `copy-last-word` | documented | plutiedev vdp-registers: DMD `11` = copy, source registers 21/22 |
| `dma-length-zero` | unknown | meaning of length 0 not independently sourced (assumption A10) |
| `fill-trigger-byte-replication` | unknown | byte lane and replication with a distinct-byte trigger word not sourced |
| `fill-data-port-write-during-fill` | unknown | CPU data-port access during a fill not sourced |
| `completion-marker` | documented | control flow reached the final store |

`vdp_timing_contract` (hooks builds only) is labelled Genewhip model conformance, not
hardware evidence: it restates the authored slot table and FIFO in the test and requires
exact tick equality for the FIFO stall in active display and its absence in blanking, the
halt duration of a 68000 transfer, fill and copy not halting the CPU, the wait of a later
data-port write, fail-closed unmapped sources and the 128 KiB wrap. The bounded fuzz mode
`gw_bounded_fuzz vdp-stream` (4096 random register, command, data and DMA streams, one
field each, run in the extended gate under ASan/UBSan) permits only target, field-complete
and unsupported address or state stops.

## Interrupts (plan GW-02-10, D-22)

HINT and VINT have separate pending, enable and acknowledge state. The CPU side is in
[cpu.md](cpu.md) (Interrupts).

- **VINT.** Raised once per field at the start tick of line 224 plus
  `GW_VDP_VINT_OFFSET_TICKS` (0, model-scoped, true offset `unknown`). It pends whether or
  not register 1 bit 5 (IE0) is set; the request level is 6 only while IE0 is set. The
  status VINT bit (`0x80`) reads set from the assertion until the interrupt is
  acknowledged, so a masked or disabled pending VINT stays visible. A status read does not
  clear it. Whether hardware clears the flag on a status read is not independently
  established and is reported `unknown` in the seam.
- **HINT.** Assumption A3. A counter is evaluated at the start of every line: on lines 0 to
  224 a counter at 0 raises HINT and reloads from register 10, otherwise it decrements; on
  lines 225 to 261 it reloads. Register 10 writes therefore take effect at the next reload.
  HINT pends regardless of register 0 bit 4 (IE1); the request level is 4 only while IE1 is
  set. With register 10 = N and a fresh counter that is one HINT every N + 1 lines,
  `floor(225 / (N + 1))` per field. Skipped idle fields (fast-forward) keep the same
  pending effects and run only when the counter equals register 10 at the field start.
- **Priority and acknowledgement.** `gw_vdp_irq_level` returns 6 for an enabled pending
  VINT, else 4 for an enabled pending HINT, else 0. Acceptance acknowledges only the taken
  source; the other is re-evaluated by the next level query, so VINT is taken before HINT and
  the pending HINT follows after the handler's RTE restores the mask.
- **Enable and mask timing.** Enabling IE0 or IE1 on an already-pending source and lowering
  the SR mask (MOVE to SR, ANDI to SR, RTE) both let the interrupt in at the next
  instruction boundary. Hardware measurements (gendev forum t=2202) report an instruction
  latency for the enable case that is not independently re-read, so Genewhip's immediate
  boundary rule is model-scoped and the seam reports the immediate counts `unknown`.
- **Console reset (A8)** clears both pending flags, the HINT counter and, with the
  registers, both enable bits.

### Interrupt seam (`genewhip-seam-irq-v1`, `vdp_irq_seam`)

One 2 KiB original ROM with level-4 and level-6 handlers that count entries, record the
HINT count and HV counter word at each VINT entry and append markers. Authored expectations
in `tests/devices/roms/irq.expect.json`; 22 cases are 15 documented, 4 REF-derived
(counted separately, never as hardware evidence) and 3 unknown.

| Case | Class | Basis |
|---|---|---|
| `vint-count-3`, `vint-at-vblank-start` | documented | plutiedev IE0; Sega documentation; MacDonald V counter `0xE0` on line 224 (V byte only) |
| `vint-handler-sr`, `hint-handler-sr` | documented | MC68000UM: S set, mask raised to the level (upper SR byte `0x26`, `0x24`) |
| `hint-count-reg10-0`, `-7`, `-223`, `hint-count-next-window` | REF-derived | assumption A3 (225, 28, 1 entries between consecutive VINT entries); community sources disagree on the line range |
| `hint-count-order-and-range`, `hint-count-range-flags` | documented | plutiedev register 10 (one HINT per register-10 + 1 lines); guest-computed tolerance of one line on 224/(N+1) |
| `vint-priority-over-hint` | documented | MC68000UM highest level first; VINT level 6, HINT level 4 |
| `mask-6-blocks-vint-status-set`, `mask-6-blocks-vint-count` | documented | Sega status bit 7; MC68000UM equal level postponed |
| `mask-6-status-after-delay` | unknown | whether the flag survives a status read is not independently established |
| `mask-lowered-takes-vint` | documented | MC68000UM: taken once the level exceeds the mask (settle of about 500 clocks) |
| `mask-lowered-latency-instructions`, `enable-pending-latency-instructions` | unknown | gendev t=2202 instruction latency not re-read; Genewhip uses the next boundary |
| `disabled-vint-not-taken`, `enable-pending-vint-taken` | documented | plutiedev IE0 gating |
| `marker-order-across-rte`, `rte-restores-mask` | documented | MC68000UM RTE restores SR and PC; the interrupted program continues |
| `completion-marker` | documented | control flow reached the final store |

The authored `cpu_interrupt` test (hooks builds) checks frame layout, SR bits, autovector
addresses `0x70` and `0x78`, the 308-tick entry, postponement at equal or lower level and
the status-bit rule. The ROM was built with the pinned assembler through
`scripts/fixtures/build-original-roms.sh`.

## Planes, window, scroll and priority (plan GW-02-11, D-19)

Each line renders from the registers, VRAM, CRAM and VSRAM sampled at its start tick. With
display disabled (register 1 bit 6 clear) the line is the backdrop only.

- **Name tables.** Plane A base `(reg2 & 0x38) << 10`, plane B base `(reg4 & 0x07) << 13`.
  Plane size from register 16: width bits 1-0 and height bits 5-4, code 0 = 32, 1 = 64,
  3 = 128 cells. Code 2 is prohibited; Genewhip reads it as 32 (class unknown). Entries
  are big-endian words: priority bit 15, palette 14-13, V-flip 12, H-flip 11, tile 10-0.
  Both planes share one size. Every derived VRAM address is masked to 16 bits.
- **Tiles.** 32 bytes, 8 rows of 4 bytes, 4 bits per pixel, leftmost pixel in the high
  nibble. Colour 0 of any palette line is transparent. The colour index is
  `palette * 16 + pixel` into CRAM, then the conversion above.
- **Horizontal scroll.** Table at `(reg13 & 0x3f) << 10`, plane A word then plane B word
  per entry, 4 bytes per line. Register 11 bits 1-0: 0 one entry for the screen, 2 one per
  8-line cell, 3 one per line, 1 prohibited (read as 0, class unknown). Cell mode keeps the
  per-line layout and reads the entry of the first line of the cell, line `y & ~7`, at byte
  offset `(y >> 3) * 32` (YaVDP: "every 8th line, two words in the horizontal scroll table
  affect the scrolling of the corresponding cell"). plutiedev's VDP register page describes
  register 11 mode 01 as "scroll eight lines, then repeat" (a repeating 8-entry pattern);
  Genewhip still reads mode 01 as full screen (class unknown) and is not changed by that
  description. Value 10 bits; positive moves
  the plane right, so screen x shows plane x `(x - scroll) mod width`.
- **Vertical scroll.** VSRAM 10-bit values; register 11 bit 2 clear: entry 0 (A) and 1 (B)
  for the screen; set: entries `2k` and `2k + 1` for each 16-pixel column `k`. Positive
  moves the plane up: line y shows plane y `(y + scroll) mod height`.
- **Window.** Replaces plane A where it covers. Region (registers 17, 18): horizontally x is
  covered left of (RIGHT = 0) or from (RIGHT = 1) `16 * (reg17 & 0x1f)` pixels, vertically
  likewise with `8 * (reg18 & 0x1f)` lines; a pixel is covered when either holds. The name
  table is 64 cells wide in H40 and 32 in H32, base `(reg3 & 0x3c) << 10` in H40 (bit 1
  ignored) and `(reg3 & 0x3e) << 10` in H32. It does not scroll.
- **Priority.** Front to back: plane A high, plane B high, plane A low, plane B low,
  backdrop (CRAM entry `reg7 & 0x3f`); a transparent pixel falls through. Sprites join the
  order as sprite high above everything and sprite low between plane B high and plane A low
  (see Sprites). Shadow and highlight (register 12 bit 3) are resolved in the core; see Shadow and highlight.

**Assumption A4** (name-table, tile and priority layouts): the formats above are exercised
only through the raster toy (`fixtures/raster-toy`), whose expectations come from
`scenario.json` and these formats, never from Genewhip output (oracle
`guest-source-derived-arithmetic`). The toy does not establish hardware behaviour for
register-11 mode 1, plane-size code 2, a horizontal window region, `RIGHT`/`DOWN` edges with
non-zero positions, or the union rule; those rows are class unknown and untested.

**Raster toy evidence.** `raster_toy_planes` compares field 3 pixel for pixel and requires
that the compared frame exercises backdrop, window, A over B, high B over low A, high A over
high B, H and V flips and all four palette lines. `raster_toy_scroll` compares full frames at
fields 3, 10 (full-screen scroll, VINT-driven), 20 (cell scroll), 37 (line scroll with 2-cell
vertical scroll), 50 (32x32 planes) and 66 (128x32 planes), plus a sparse grid on fields 1 to
69, and requires fields 1 to 16 to differ from their successors. `raster_toy_negative_control`
alters one expected palette word and requires the comparison to fail. The handler run count
equals the field sequence because the toy finishes start-up inside field 0, a property of
Genewhip's model-scoped timing. `raster_toy_sprites` replays the scenario's recorded port-1
input log through `gw_headless --replay` and requires, on fields 1 to 40, that the sprite
(colour 15 of palette 0, used by no other layer) covers exactly the 8x8 pixels at the position
`start + 2 * sum(held directions)` computed from `scenario.json`, or no pixel while nothing has
been pressed; the handler of run `c` observes entries with field `<= c - 1` and the sprite is
first drawn in field `c`. `raster_toy_sprites_negative_control` shifts the expectation by one
pixel and requires failure.

## Sprites (plan GW-02-12, D-24, D-30)

**Model.** The sprite table is at `(reg5 & 0x7f) << 9` (register 5 bit 0 is ignored in H40).
An entry is 8 bytes: Y (word, 10 bits, screen line + 128), size (byte: width in cells minus 1
in bits 3-2, height minus 1 in bits 1-0), link (byte, 7 bits), pattern word (priority bit 15,
palette 14-13, V-flip 12, H-flip 11, first tile 10-0) and X (word, 9 bits, screen column +
128). A sprite's tiles run column-major (tile + column * height + row); a flip mirrors the
whole sprite. Colour 0 of a palette line is transparent. Format and limits follow the
plutiedev sprites page; every address read from the table is masked to 16 bits and every x
is clipped to the active width before it indexes a line buffer.

**Traversal.** Each line walks the list from entry 0 following links until a link of 0 or
the per-frame bound: at most 80 entries in H40 and 64 in H32 are visited. Because the bound
counts visits, a cyclic list (for example 0 -> 1 -> 2 -> 1) ends at the bound, the field still
publishes, and the repeated entries are simply drawn again. Entries past the bound are never
drawn.

**Per-line limits.** A line draws at most 20 (H40) or 16 (H32) sprites, in traversal order;
the next sprite that touches the line sets the overflow flag (`sprite_overflow`, status bit
`0x40`) and ends the walk for that line. A line spends at most 320 (H40) or 256 (H32) sprite
pixel columns, counted per sprite width including clipped columns; a sprite that does not
fit draws only its leftmost columns that still do, and sets the overflow flag. The first
sprite drawn owns a pixel; an opaque pixel of a later sprite on an already owned position
sets the collision flag (`sprite_collision`, status bit `0x20`). Both flags are set while the
field renders and cleared by a status read.

**Priority.** A sprite pixel layers by its pattern priority bit: high above plane A high,
low between plane B high and plane A low (see Planes). Shadow and highlight operator sprites are
described under Shadow and highlight.

**Sprite seam (`genewhip-seam-sprites-v1`, `vdp_sprites_seam`).** `sprites.s` runs twelve
phases of one field each; at each field's end it reads the status register twice into work
RAM, and the checker also samples pixels of the field published at the end of each phase
(`gw_seam_runner --dump-field`, expectation key `field_samples`; the expected pixel is the
conversion of a stated CRAM word). 46 cases: 36 pass, 10 report `unknown`.
`vdp_sprites_seam_negative_control` flips one expected byte of the first documented case
and requires only that case to fail.

| Phase / case | Class | Basis |
|---|---|---|
| 1 link order 0 -> 2 -> 1: entry 2 wins the overlap, unlinked entry 3 is not drawn | documented | plutiedev sprites: link byte gives the next sprite, drawn in order |
| 2, 3 H40 20 sprites per line all drawn, the 21st is not | documented | plutiedev sprites: 20 per line |
| 4, 5 H32 16 sprites per line drawn, the 17th is not | documented | plutiedev sprites: 16 per line |
| 6 H40 chain of 100: entries 0..79 drawn, 80 and 99 not | documented | plutiedev sprites: 80 per frame |
| 7 H32 chain of 70: entry 63 drawn, 64 and 69 not | documented | plutiedev sprites: 64 per frame |
| 8 H40 ten 32-pixel sprites drawn, the eleventh is not | documented | plutiedev sprites: 320 sprite pixels per line |
| 9 H32 eight 32-pixel sprites drawn, the ninth is not | documented | plutiedev sprites: 256 sprite pixels per line |
| 12 cyclic list 0 -> 1 -> 2 -> 1 terminates, all three drawn, ROM finishes | documented | plutiedev sprites: at most 80 sprites per frame |
| status: collision (phase 1), overflow at 21 and 17 sprites, no flag at exactly 20 and 16, flags cleared by the read | REF-derived | reference-emulator behaviour recorded in 02-RESEARCH.md; plutiedev is silent on the status bits; no reference trace was captured in this plan |
| status flags after the frame bound, pixel limit, partial sprite, X = 0 and cyclic phases | unknown | no independent expectation; observed values reported |
| partial sprite at the pixel limit (leftmost columns drawn) | unknown | undocumented; Genewhip-defined |
| sprite after an X = 0 entry | unknown | masking is not modeled; observed value reported |

**Port-2 toy sprite (plan GW-02-19, INP-01).** The toy keeps two linked 8x8 sprites at VRAM
`0xF000` and `0xF008`: sprite 0 (palette 0, 2 pixels per pressed run) follows port 1, sprite 1
(palette 2, 3 pixels per pressed run) follows port 2, each read from its own data register
with TH high. `raster_toy_sprites` replays one recorded input log with entries for both ports
and, for every field 1-40, requires the exact 8x8 pixel set of each sprite at the position
computed from `scenario.json` alone (start + step x pressed runs, with the one-field stamping
latency stated in the toy source), and that each sprite moved on fields where the other port was
released. Its negative control shifts every expected start by one pixel and must fail.

**Sprite-table fuzz.** `gw_bounded_fuzz sprite-table` runs 4096 random ROMs (fixed seed
`53505254`): each DMAs random tiles and a random 128-entry sprite table (Y mostly on screen,
any size including the maximal 4x4, arbitrary links with self and two-entry cycles, H32 or H40,
S/TE on or off) and renders two fields. A field must complete with a documented stop reason,
publish the latched width, and every 64th ROM must reproduce the same pixel checksum. The
extended gate runs it under ASan/UBSan; the summary reports `fail: 0`.

The cyclic case follows the hardware link rule that a link of 0 ends the list, so a cycle
needs two entries other than 0 that link to each other.

## Limitations at this commit

- Mid-line register changes appear on the next line; width changes on the next field.
- Planes, window, scroll and priority are implemented (see above); mid-line register changes
  appear on the next line, so per-line effects need a line boundary; window edge cases beyond
  the toy are untested; the H40 window base rule is as stated above, not independently verified.
- Not implemented: left-column blanking; HV latch (register 0 bit 1) and register 6/8/9/14
  semantics. Shadow/highlight is a Genewhip convention (see above); its S/TE effect applies per
  line from the register value at that line.
- Sprites: the sprite attribute cache and its stale-entry behaviour, sprite evaluation one
  line ahead, dot-overflow edge cases (the flag source for the pixel limit, how a crossing
  sprite is cut), X = 0 masking, interlaced sprites, mid-line effects, sprite-table reads
  during DMA and the exact sources of SOVR/SCOL are unmodeled or unknown. The raster toy
  (sprite 0 follows port 1, sprite 1 follows port 2) and the seam ROM cover only the cases
  tabulated above.
- Interrupts: the VINT sub-line offset and the HINT line range are model-scoped or
  community-observed (see Interrupts); the Z80 interrupt line, external (level 2) interrupts
  and acknowledge-cycle variability are not modeled; a pending flag is one bit per source, so
  a second assertion before acknowledgement merges with the first.
- The H component of the HV counter and the HBLANK window are model-scoped maps.
- Byte accesses to VDP ports and PSG/Z80 mirrors stay fail-closed.
- Guest `RESET` does not reset the VDP.
- Access slots are an evenly spaced approximation, not a measured schedule.
- Absolute slot positions, FIFO commit ticks and DMA cycle counts are model-scoped; the seams
  assert only orderings and relationships. Slot rates are one shared evenly spaced table.
- DMA edge cases during active display (sprite and tile fetch interleaving, mid-line effects)
  are not modeled; a 68000 transfer holds the CPU for its whole duration and adds no other bus
  contention (no Z80 or refresh interaction).
- Length 0 transfers nothing (hardware meaning unknown), odd-address VRAM word destinations of
  a 68000 transfer stop fail-closed, a fill or copy that targets CRAM or VSRAM is unmodeled
  (the command stops), and fill byte-lane, odd-address replication and the last-byte edge
  are unknown.
- CPU data-port access, and a new DMA command, while a fill or copy is running hold the CPU
  until it ends; the hardware behaviour is unknown.
- **Fill and copy citation gap (D-21).** No independent primary source for the absolute VRAM
  fill and VRAM copy rates was found. The fill rate equal to the 68000-to-VDP byte rate and the
  copy rate at half of it are Genewhip-authored model-scoped values, following the gendev
  forum report that copy runs at about half the transfer rate; the seam classes their absolute
  values `unknown`. The gap closes only when a direct citation, such as the Sega Genesis
  Software Manual DMA bandwidth table, is recorded; its figures would then replace these.
