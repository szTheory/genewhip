# CPU contract

This page owns the Motorola 68000 instruction subset the core executes. Timing,
the bus and the public API are in [core.md](core.md); video is in [video.md](video.md).

## Instruction subset

| Instruction | Implemented forms |
|---|---|
| MOVE | Byte/word/long; all twelve source modes and every data-alterable destination (see the table below) |
| MOVEQ | All data registers and signed 8-bit immediates |
| BRA | 8-bit and 16-bit displacement; original 68000 interpretation (see Bcc/BSR below) |
| NOP, RESET | Supervisor execution; RESET continues and records external reset when counters enabled |
| TRAP | Vectors 32–47, six-byte SR/PC supervisor stack frame |
| RTE | Six-byte frame, supervisor non-trace return only |
| STOP | Supervisor non-trace state; console reset or an accepted interrupt above the SR mask resumes (see STOP wake) |
| PEA | Long effective address to the active stack; 68000 control addressing modes |

Other encodings, including legal instructions outside the tables on this page, return
`GW_STOP_UNSUPPORTED_INSTRUCTION` with the opcode and instruction address.
They do not become guest illegal-instruction exceptions. Unsupported user/trace
state has its own stop. Odd word/long accesses and unmapped addresses stop as
unsupported addresses; address-error/bus-error exception frames are not modeled.
Autovectored level-4 (HINT) and level-6 (VINT) interrupt recognition is implemented (see Interrupts); no prefetch pipeline, privilege exception or user-stack switching is implemented. Do not infer
general 68000 completeness from this table.

## Families added in GW-02-02

All of the following share one effective-address helper (`ea_address`, `ea_read`,
`ea_write` in `src/cpu68000.c`) covering all twelve 68000 addressing modes: Dn, An,
(An), (An)+, -(An), d16(An), d8(An,Xn) with word or long index, absolute word,
absolute long, d16(PC), d8(PC,Xn) and immediate. Increments, decrements and
extension words are applied in instruction-stream order, so
`MOVE.w (A5)+,(A5)` writes through the updated register. A byte access through A7
steps by two. Legality is checked before any operand side effect; an illegal mode
returns `GW_STOP_UNSUPPORTED_INSTRUCTION`.

| Instruction | Sizes | Source / destination modes | Flags |
|---|---|---|---|
| MOVE | b/w/l | any source (An for w/l only); data-alterable destination | N,Z set; V,C clear; X kept |
| MOVEA | w/l | any source; An destination; word sources sign-extend | none |
| LEA | l | control modes only: (An), d16(An), d8(An,Xn), abs.w, abs.l, d16(PC), d8(PC,Xn) | none |
| CLR | b/w/l | data-alterable destination | N=0, Z=1, V=0, C=0; X kept |
| TST | b/w/l | data-alterable operand | N,Z set; V,C clear; X kept |
| ADD, SUB | b/w/l | `<ea>,Dn` (An source for w/l) and `Dn,<ea>` (memory-alterable) | X,N,Z,V,C |
| ADDX | b/w/l | `Dy,Dx` only; old X is an additional carry input; byte/word preserve upper destination bits | X,N,V,C; Z stays set only while every result is zero |
| ADDA, SUBA | w/l | any source; word sources sign-extend; full address register | none |
| ADDI, SUBI | b/w/l | immediate to data-alterable destination | X,N,Z,V,C |
| ADDQ, SUBQ | b/w/l | data 0 encodes 8; data-alterable or An (w/l, full register, no flags) | X,N,Z,V,C (none for An) |
| CMP, CMPI | b/w/l | `<ea>,Dn`; immediate to data-alterable operand | N,Z,V,C; X kept |
| CMPA | w/l | any source; compares the full 32-bit register | N,Z,V,C; X kept |

Memory ADDX, SUBX, CMPM, MOVEP and every other
encoding still stop as unsupported instructions with the opcode and address. The
`ADD` and `SUB` encodings with modes 0-1 on the `Dn,<ea>` side belong to ADDX/SUBX
and retain that distinction; memory ADDX and all SUBX forms are unsupported.

Register ADDX follows [M68000PRM pp4-13–4-14](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf):
both operands and X are sampled before writing, so a self-alias such as
`ADDX.B D3,D3` doubles the old low byte and adds old X. X follows carry;
N/V/C describe the result, and a zero result preserves old Z. Its original
MC68000 register totals are four clocks byte/word and eight long, including
opcode fetch ([MC68000UM §8.10, table8-11](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)).
Memory predecrement ADDX remains unsupported. Size11 in the neighboring encoding
belongs to ADDA.L and retains its existing behavior.

## Families added in GW-02-06

Control flow, bit, logic, shift/rotate and status-register families, on the same
effective-address helper. Cycle timing for these is approximate (idle ticks follow
the BRA precedent; shifts add `2n` ticks) and unchecked.

| Instruction | Sizes | Forms | Flags |
|---|---|---|---|
| Bcc, BRA | 8-bit and 16-bit displacement | all sixteen condition codes (`condition_true`); BRA is condition 0 | none |
| BSR | 8-bit and 16-bit displacement | pushes the return address (`push32`) | none |
| DBcc | word | counter decrement in the low word of Dn; branch while the condition is false and the counter is not -1 | none |
| Scc | byte | Dn only; all sixteen conditions write `0xff` or `0x00` to the low byte, preserving its upper24 bits | none |
| JMP, JSR | none | control modes: (An), d16(An), d8(An,Xn), abs.w, abs.l, d16(PC), d8(PC,Xn) | none |
| RTS | none | pops the return address (`pop32`) | none |
| LINK, UNLK | LINK word displacement; long frame save/restore | A0–A6; active supervisor stack | none |
| BTST, BSET, BCLR, BCHG | byte (memory, bit mod 8), long (Dn, bit mod 32) | bit number in Dn or an immediate word; BTST also allows PC-relative and immediate (register form) sources | Z = tested bit clear; others kept |
| AND, OR | b/w/l | `<ea>,Dn` (data modes) and `Dn,<ea>` (memory-alterable) | N,Z set; V,C clear; X kept |
| EOR | b/w/l | `Dn,<ea>` (data-alterable) | N,Z set; V,C clear; X kept |
| ANDI, ORI, EORI | b/w/l | immediate to data-alterable destination | N,Z set; V,C clear; X kept |
| NOT | b/w/l | data-alterable operand | N,Z set; V,C clear; X kept |
| NEG | b/w/l | data-alterable operand | X,N,Z,V,C |
| EXT | w, l | data register | N,Z set; V,C clear; X kept |
| SWAP | w | data register | N,Z set on the 32-bit result; V,C clear; X kept |
| ASL, ASR, LSL, LSR, ROL, ROR | b/w/l register; word memory (count 1) | count 1-8 immediate or Dn modulo 64 (bounded loop of at most 63 steps) | X follows C for shifts (kept for rotates and count 0); N,Z; V only for ASL (set when the sign changes); C is the last bit out, 0 for count 0 |
| MOVE from SR | w | data-alterable destination (supervisor; the read-before-write cycle is not modeled) | none |
| MOVE to SR | w | data source; writes the implemented bits `0xA71F` | all |
| MOVE to CCR | w | data source; low five bits | X,N,Z,V,C |
| ANDI, ORI, EORI to SR | w | immediate; result masked to `0xA71F` | all |
| ANDI, ORI, EORI to CCR | b | immediate (carried in a word); low five bits | X,N,Z,V,C |

## PEA

PEA resolves a control effective address and pushes that 32-bit address in
big-endian order. It does not read the operand stored at that address, and it
does not change condition codes. Supported modes are `(An)`, `d16(An)`,
`d8(An,Xn)`, absolute word and long, `d16(PC)`, and `d8(PC,Xn)`. Address-register,
postincrement, predecrement, and immediate forms stop as unsupported
instructions before consuming extension words or changing the stack.
The data-register encodings `0x4840`–`0x4847` execute the existing SWAP
instruction; the PEA dispatch excludes them.

The instruction contract follows NXP's [M68000 Family Programmer's Reference
Manual, PEA, p. 4-159](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf):
`SP - 4 -> SP`, `<ea> -> (SP)`, long size, unchanged condition codes, and the
control-mode restriction. The successful clock totals follow [MC68000 User's
Manual, §8.9, Table 8-10, p. 8-8](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf):
12 clocks for `(An)`, 16 for displacement/absolute-word/PC-displacement forms,
and 20 for indexed/absolute-long forms. Section 8 describes the MC68000's
16-bit bus; section 7's 8-bit-bus totals do not apply. Tests compare these totals in
the current integer-tick model. The model fills internal clocks but does not
claim the manual's physical bus-cycle sequence.

Stack writes use the current 24-bit bus mapping while A7 retains its full
32-bit value. A failed stack write leaves the decremented A7 visible and stops
with the current unsupported-address result. This partial fault state is the
core's explicit model behavior; address-error/bus-error frames and physical
68000 exception ordering remain unimplemented. The original guest and public
headless-client regressions cover effective-address calculation, stack byte
order, flags, illegal modes, high A7 bits, bus wrapping, and stack faults.

Notes: a branch, jump, JSR or RTS to an odd target stops with
`GW_STOP_UNSUPPORTED_ADDRESS` (the address-error frame is not modeled). `sr_write`
masks to the implemented SR bits and then applies the same check as exception
return: a write that clears S (user mode) or sets T (trace) stops with
`GW_STOP_UNSUPPORTED_STATE` and leaves SR unchanged, so a guest never silently
switches stacks. All of this is supervisor-only, as is the rest of the subset.

Scc Dn follows [M68000PRM pp4-172–4-173](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf)
and [MC68000UM section8, table8-6](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf):
four clocks for false, six for true, including opcode fetch. Its flags are
unchanged. Memory Scc forms remain unsupported; their read-before-write bus
cycle is not approximated by a write-only operation. The adjacent mode001
encodings remain DBcc. The authored regression covers the entire register
condition truth table, byte preservation, timing, reset and split execution.

LINK.W saves the old full32 An at SP−4, copies that stack address into An,
then adds the sign-extended16 displacement to SP. UNLK copies An to SP,
reads the saved longword, advances SP by four, and restores An. Both preserve
all condition codes. The supported registers are A0–A6; A7 alias forms stop
as unsupported before consuming a displacement or changing registers because
their alias ordering has no independently established oracle here. LINK.L,
introduced after the original68000, remains unsupported. The contract follows
[M68000PRM LINK4-111 and UNLK4-194](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf);
successful totals are16/12 CPU clocks respectively, including opcode fetch
([MC68000UM section8, table8-12](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)).
The existing bus transfers supply those totals without extra idle clocks.

Frame addresses retain full32 arithmetic while bus accesses mask to24 bits.
In this diagnostic model, a LINK stack fault leaves SP decremented but An
unchanged; an UNLK read fault leaves SP equal to the frame address and An
unchanged. A completed first word transfer remains visible if the second
fails. These are explicit partial-state policies, not physical68000 exception
ordering claims; exception frames and prefetch remain unmodeled. The original
regression covers signed displacement boundaries, saved bytes, flags, timing,
unsupported aliases/encodings, fault states, reset and split execution.

Still unsupported, stopping with `GW_STOP_UNSUPPORTED_INSTRUCTION`: ROXL/ROXR, MULS.L,
DIVS, ABCD/SBCD/NBCD, NEGX, CHK, TAS, memory Scc, EXG, LINK/UNLK A7, LINK.L, RTR, RTE
variants beyond the six-byte frame, and the bitfield-style shift encodings. The AND/OR
encodings with modes 0-1 on the `Dn,<ea>` side belong to ABCD/SBCD/EXG and stay
unsupported.

## MOVEM (GW-06-03)

Word and long transfers implement six register-to-memory modes: `(An)`,
`-(An)`, `d16(An)`, brief `d8(An,Xn)`, absolute word and absolute long.
Memory-to-register implements eight: `(An)`, `(An)+`, `d16(An)`, brief
`d8(An,Xn)`, absolute word/long and the two PC-relative control modes.
The denominator is **28 direction/size/EA forms**, exercised by
`tests/api/movem_contract.c`. Register-direct encodings retain EXT where
applicable; illegal MOVEM directions/modes reject before fetching the mask or
applying an EA side effect. Later-CPU full extensions and byte MOVEM are not
advertised.

The independent semantics authority is [NXP M68000PRM](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf),
PDF pages231–233 (4-128–130). Normal masks transfer D0 through A7; predecrement
reverses both the mask correspondence and register order. An included base
register stores its **original MC68000 value**. Word loads sign-extend both
register types; a postincrement base in the list retains the final EA. Empty
lists transfer nothing and leave the base unchanged. Flags remain unchanged.
PC-relative extensions use the PC after the register mask.

Successful instruction totals follow [NXP MC68000UM](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf),
section8.9/table8-10: stores `8+4n` word or `8+8n` long clocks, loads
`12+4n` or `12+8n`, plus EA additions0 for indirect/update,4 for displacement
or absolute word,6 for brief index,8 for absolute long. One CPU clock is seven
master ticks. Fetches and successful bus words charge four clocks each; loads
add four idle clocks and indexed forms another two before transfers.

The tested **current model** performs ascending high-word/low-word bus accesses
within each long, including predecrement MOVEM. Register transfer order and total
clocks have manufacturer authority; these word-access timestamps and partial
fault effects are explicit model contracts, **not independently established
physical MC68000 micro-order or bus-error exception state**. Prefetch/dummy reads,
wait states and exception frames remain unmodeled. Completed words and registers
survive a sticky address fault; a failing predecrement remains visible, while
postincrement advances only after a whole operand completes. A failed long load
leaves that destination register unchanged. Tests inspect these boundaries via
public load/run/peek and existing private state/write observations; no new API.

The bounded production GWRC probe passes RECURSION's original0x1822/0x48e7
stop and records its next unsupported instruction0xc0fc at0x2528,
tick12993862, after14 completed video fields and0 active route ticks.
This is an instruction-repair result; interaction, sustained play, PCM and
performance remain unqualified. The pre-repair observer directly recorded
tick8529990 and9 completed fields; the older Phase5 receipt remains unchanged
and originally established only its final tick. See `evidence/phase6-repairs.json`.

## Observed instruction repairs (GW-06-04)

Supervisor `MOVE An,USP` and `MOVE USP,An` transfer all32 bits, preserving CCR
and unrelated registers. All eight address registers work in both directions;
explicit A7 still denotes the supervisor stack. Total execution is four CPU
clocks. The independent authority is [NXP M68000PRM](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf),
PDF p474 (6-21), and [MC68000UM](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf),
table8-12. User/trace state and privilege exception frames remain unsupported.
No user-mode stack bank switching is implied.

USP is instance-owned future-affecting CPU state. Load, cold initialization and
console reset set it to zero under the deterministic emulator policy; this does
not claim physical reset initializes USP. Guest RESET leaves it unchanged.
The private state digest appends the tagged little-endian `USP,version1,value`
extension only for nonzero USP. Zero retains the previous digest domain and
frozen control values; nonzero USP must discriminate future read behavior.
Original guests test zero and every individual bit with normalized visible
registers. No fixture oracle or historical digest was changed.

`MULU.W <ea>,Dn` accepts all11 data source addressing forms, multiplies the
unsigned low16 bits of each operand and replaces the complete destination with
the32-bit product. X remains unchanged; N/Z reflect that product; V/C clear.
NXP M68000PRM PDF pp241-242 (4-138–139) defines the semantics;
MC68000UM section8.3/table8-4 specifies `38+2*popcount(source)` CPU clocks
plus word EA time. Bus transfers already charge their clocks; predecrement
and indexed EA forms add two idle clocks. Illegal modes reject before extensions;
operand address faults preserve destination and flags. Full prefetch and
physical fault micro-order remain outside the model.

`MULS.W <ea>,Dn` accepts the same11 data source forms and multiplies signed
low16 operands to replace the full32 destination. X is preserved; N/Z describe
the product; V/C clear. An-direct sources and later-CPU long multiply encodings
remain unsupported. Signed semantics and allowed modes follow
[M68000PRM4-135–136](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf).
The original68000 timing is38+2n CPU clocks plus word EA time, where n counts
adjacent01/10 patterns in the17-bit source formed by appending a zero LSB
([MC68000UM8.3/table8-4](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)).
This differs from unsigned multiply's source popcount. Original regressions
cover signed boundaries, alternating source bits, upper-word exclusion, every
destination register, source/destination aliasing, both X states, data EAs,
unsupported encodings, operand faults, instance isolation, reset and split runs.
Operand-read failure retains the existing EA side effects and fetched-word time
without changing the result register or flags; physical exception sequencing
remains unmodeled.

`tests/api/phase6_repairs_contract.c` exercises these forms through original
public load/run guests, supplemented by private state observations. Truncated
USP and truncated-product mutants fail the named value assertions; removing
each dispatch restores its original unsupported symptom. Exact production
receipts in `evidence/phase6-repairs.json` show Tank passing0x0204/0x4e67 to
the I/O address stop0x021a/0x4ab9 at tick616, and RECURSION passing
0x2528/0xc0fc to0x7f3c/0x80fc at tick20824748 after23 completed fields.
Both routes remain blocked; these are bounded instruction results.

`DIVU.W <ea>,Dn` now supports the observed nonzero-divisor word operation
through the same11 data-source EA forms. It divides the full unsigned32-bit
dividend by the unsigned16-bit source, packs remainder in the upper word and
quotient in the lower word. X is kept; N/Z describe the16-bit quotient; V/C
clear. A quotient larger than65535 sets V and clears C without changing the
destination; undefined N/Z are preserved as model policy. Division by zero
stops with `GW_STOP_UNSUPPORTED_STATE`; the hardware's divide-zero exception
frame is not implemented. The authority is NXP M68000PRM PDF pp199-200
(4-96–97); its p200 signed-overflow note conflicts with the unsigned operation
description, so the unsigned16-bit range is used and boundary-tested.

DIVU timing is explicitly **approximate**: MC68000UM section8.3/table8-4
gives140 as a maximum basic clock count with operand-dependent variation.
The model charges that maximum plus word EA time; it does not claim an exact
operand-dependent microalgorithm. No primary source for that microalgorithm
was established. The opcode/value correction does not establish cycle accuracy.
Swapped quotient/remainder, truncated dividend and removed-dispatch controls
fail independent assertions. Source-route progress uses completed source writes,
not elapsed-cycle estimates.

The current bounded closeout leaves Tank at unsupported PEA0x4879/PC0xEC32,
tick8718556 after9 completed fields. RECURSION reaches all four source
predicates but becomes terminal after3599 completed steps, short of3600,
and reaches the frozen7200-field cap. The old native status0 report remains
historical rejected evidence; the tool now fails an incomplete field cap.
The [binding halt disposition](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-04-HALT-DISPOSITION.md)
records the reference-host delivery dependency and required replanning. No
input retiming, synthesized step or PEA correction was applied after that halt.

## Interrupts

Added in plan GW-02-10 (D-22). The run loop advances the VDP, then, before each
instruction fetch, asks `gw_vdp_irq_level` for the request level. Acceptance happens only at
an instruction boundary and only when the level exceeds the SR interrupt mask
(`(SR >> 8) & 7`); a level equal to or below the mask is postponed and the CPU steps
normally (MC68000UM: pending interrupts are detected between instruction executions).
Lowering the mask by MOVE to SR, ANDI to SR or RTE, or enabling a pending source, therefore
lets it in at the next boundary. Level 7 is not produced.

`gw_cpu_accept_interrupt(m, level)` (levels 4 and 6 only) mirrors `trap()` ordering:

1. push the PC (the address of the next instruction, long) and then the SR (word) on the
   supervisor stack through `gw_bus_write` (SR at A7, PC at A7 + 2); a failing write stops
   with the usual sticky unsupported-address stop and nothing is half-applied to A7;
2. read the autovector `(24 + level) * 4` through `gw_bus_read`: `0x70` for level 4 (vector
   28) and `0x78` for level 6 (vector 30), per MC68000UM;
3. set S, clear T, raise the mask to the level, keep the CCR, jump to the vector contents
   (an odd target stops as an unsupported address);
4. acknowledge the taken source with `gw_vdp_irq_ack`;
5. charge `GW_INTERRUPT_TICKS` = 44 clocks * 7 = 308 ticks in total, bus ticks included
   (MC68000UM "Interrupt 44(5/3)" with a 4-clock acknowledge cycle). It counts as one
   exception, not an instruction.

Limitation (A11): acknowledge-cycle variability is not modeled; the 44-clock total is fixed.
The saved SR keeps only the implemented bits.

STOP wake (plan 02-18, MC68000UM STOP): `stop #imm` loads SR and stops. While stopped, the
run loop advances time and the VDP in steps of at most one line (never past the next queued
event, a scheduled VINT or the target). An interrupt above the SR mask is accepted through
`gw_cpu_accept_interrupt` and the stacked PC is the instruction after STOP, so RTE continues
there. With no wake source the run returns `GW_STOP_CPU_STOPPED` at the target. Console
reset also wakes it. Evidence: irq seam case `stop-wake-vint` and `cpu_interrupt`.
Evidence: `cpu_interrupt` (authored from MC68000UM text, hooks builds) and the
`vdp_irq_seam` ROM described in [video.md](video.md).

## Evidence

Each family is checked against pinned SingleStepTests vectors through a private
sparse-memory overlay (see `tests/vectors/README.md`). Sub-form denominators:

| Source file | Sub-form: records |
|---|---|
| `v1/NOP.json.bin` | NOP: 2500 |
| `v1/MOVE.q.json.bin` | MOVEQ: 2500 |
| `v1/MOVE.w.json.bin` | MOVE: 2500 |
| `v1/MOVE.b.json.bin` | MOVE: 2500 |
| `v1/MOVE.l.json.bin` | MOVE: 2500 |
| `v1/MOVEA.w.json.bin` | MOVEA: 2500 |
| `v1/MOVEA.l.json.bin` | MOVEA: 2500 |
| `v1/LEA.json.bin` | LEA: 2500 |
| `v1/CLR.b.json.bin` | CLR: 2500 |
| `v1/CLR.w.json.bin` | CLR: 2500 |
| `v1/CLR.l.json.bin` | CLR: 2500 |
| `v1/TST.b.json.bin` | TST: 2500 |
| `v1/TST.w.json.bin` | TST: 2500 |
| `v1/TST.l.json.bin` | TST: 2500 |
| `v1/ADD.b.json.bin` | ADD: 1561, ADDI: 116, ADDQ: 823 |
| `v1/ADD.w.json.bin` | ADD: 1538, ADDI: 91, ADDQ: 871 |
| `v1/ADD.l.json.bin` | ADD: 1538, ADDI: 90, ADDQ: 872 |
| `v1/ADDA.w.json.bin` | ADDA: 2500 |
| `v1/ADDA.l.json.bin` | ADDA: 2500 |
| `v1/SUB.b.json.bin` | SUB: 1567, SUBI: 122, SUBQ: 811 |
| `v1/SUB.w.json.bin` | SUB: 1514, SUBI: 100, SUBQ: 886 |
| `v1/SUB.l.json.bin` | SUB: 1527, SUBI: 115, SUBQ: 858 |
| `v1/SUBA.w.json.bin` | SUBA: 2500 |
| `v1/SUBA.l.json.bin` | SUBA: 2500 |
| `v1/CMP.b.json.bin` | CMP: 1991, CMPI: 233, CMPM: 276 |
| `v1/CMP.w.json.bin` | CMP: 2032, CMPI: 207, CMPM: 261 |
| `v1/CMP.l.json.bin` | CMP: 2063, CMPI: 190, CMPM: 247 |
| `v1/CMPA.w.json.bin` | CMPA: 2500 |
| `v1/CMPA.l.json.bin` | CMPA: 2500 |
| `v1/Bcc.json.bin` | Bcc: 2334, BRA: 166 |
| `v1/DBcc.json.bin` | DBcc: 2500 |
| `v1/BSR.json.bin` | BSR: 2500 |
| `v1/JSR.json.bin` | JSR: 2500 |
| `v1/JMP.json.bin` | JMP: 2500 |
| `v1/RTS.json.bin` | RTS: 2500 |
| `v1/BTST.json.bin` | BTST.reg: 2240, BTST.imm: 260 |
| `v1/BSET.json.bin` | BSET.reg: 2219, BSET.imm: 281 |
| `v1/BCLR.json.bin` | BCLR.reg: 2204, BCLR.imm: 296 |
| `v1/BCHG.json.bin` | BCHG.reg: 2225, BCHG.imm: 275 |
| `v1/AND.b.json.bin` | AND: 2324, ANDI: 176 |
| `v1/AND.w.json.bin` | AND: 2342, ANDI: 158 |
| `v1/AND.l.json.bin` | AND: 2371, ANDI: 129 |
| `v1/OR.b.json.bin` | OR: 2339, ORI: 161 |
| `v1/OR.w.json.bin` | OR: 2351, ORI: 149 |
| `v1/OR.l.json.bin` | OR: 2340, ORI: 160 |
| `v1/EOR.b.json.bin` | EOR: 2233, EORI: 267 |
| `v1/EOR.w.json.bin` | EOR: 2237, EORI: 263 |
| `v1/EOR.l.json.bin` | EOR: 2238, EORI: 262 |
| `v1/NOT.b.json.bin` | NOT: 2500 |
| `v1/NOT.w.json.bin` | NOT: 2500 |
| `v1/NOT.l.json.bin` | NOT: 2500 |
| `v1/NEG.b.json.bin` | NEG: 2500 |
| `v1/NEG.w.json.bin` | NEG: 2500 |
| `v1/NEG.l.json.bin` | NEG: 2500 |
| `v1/EXT.w.json.bin` | EXT: 2500 |
| `v1/EXT.l.json.bin` | EXT: 2500 |
| `v1/SWAP.json.bin` | SWAP: 2500 |
| `v1/ASL.b.json.bin` | ASL: 2500 |
| `v1/ASL.w.json.bin` | ASL: 1890, ASL.mem: 610 |
| `v1/ASL.l.json.bin` | ASL: 2500 |
| `v1/ASR.b.json.bin` | ASR: 2500 |
| `v1/ASR.w.json.bin` | ASR: 1903, ASR.mem: 597 |
| `v1/ASR.l.json.bin` | ASR: 2500 |
| `v1/LSL.b.json.bin` | LSL: 2500 |
| `v1/LSL.w.json.bin` | LSL: 1888, LSL.mem: 612 |
| `v1/LSL.l.json.bin` | LSL: 2500 |
| `v1/LSR.b.json.bin` | LSR: 2500 |
| `v1/LSR.w.json.bin` | LSR: 1875, LSR.mem: 625 |
| `v1/LSR.l.json.bin` | LSR: 2500 |
| `v1/ROL.b.json.bin` | ROL: 2500 |
| `v1/ROL.w.json.bin` | ROL: 1902, ROL.mem: 598 |
| `v1/ROL.l.json.bin` | ROL: 2500 |
| `v1/ROR.b.json.bin` | ROR: 2500 |
| `v1/ROR.w.json.bin` | ROR: 1866, ROR.mem: 634 |
| `v1/ROR.l.json.bin` | ROR: 2500 |
| `v1/MOVEtoSR.json.bin` | MOVEtoSR: 2500 |
| `v1/MOVEfromSR.json.bin` | MOVEfromSR: 2500 |
| `v1/MOVEtoCCR.json.bin` | MOVEtoCCR: 2500 |
| `v1/ANDItoSR.json.bin` | ANDItoSR: 2500 |
| `v1/ORItoSR.json.bin` | ORItoSR: 2500 |
| `v1/EORItoSR.json.bin` | EORItoSR: 2500 |
| `v1/ANDItoCCR.json.bin` | ANDItoCCR: 2500 |
| `v1/ORItoCCR.json.bin` | ORItoCCR: 2500 |
| `v1/EORItoCCR.json.bin` | EORItoCCR: 2500 |

The `CMP.*` files also hold 784 CMPM records (184 apply); CMPM is not
implemented and is counted as an unsupported instruction form. Per-sub-form
pass/unsupported counts are in `tests/vectors/README.md`.
Only supervisor, non-trace vectors apply; user/trace states and address-error
vectors are counted as unsupported with their reason and never as passes.
Cycle timing, the prefetch queue and bus-cycle order are unchecked: CLR does
not model the 68000's read-before-write cycle, long writes to `-(An)` store the
high word first, and an odd word or long access stops with
`GW_STOP_UNSUPPORTED_ADDRESS` instead of raising the address-error frame.
