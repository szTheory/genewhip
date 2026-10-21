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
| ADDA, SUBA | w/l | any source; word sources sign-extend; full address register | none |
| ADDI, SUBI | b/w/l | immediate to data-alterable destination | X,N,Z,V,C |
| ADDQ, SUBQ | b/w/l | data 0 encodes 8; data-alterable or An (w/l, full register, no flags) | X,N,Z,V,C (none for An) |
| CMP, CMPI | b/w/l | `<ea>,Dn`; immediate to data-alterable operand | N,Z,V,C; X kept |
| CMPA | w/l | any source; compares the full 32-bit register | N,Z,V,C; X kept |

ADDX/SUBX, CMPM, MOVE from USP/to USP, MOVEM, MOVEP, MULU/DIVU and every other
encoding still stop as unsupported instructions with the opcode and address. The
`ADD` and `SUB` encodings with modes 0-1 on the `Dn,<ea>` side belong to ADDX/SUBX
and are therefore unsupported.

## Families added in GW-02-06

Control flow, bit, logic, shift/rotate and status-register families, on the same
effective-address helper. Cycle timing for these is approximate (idle ticks follow
the BRA precedent; shifts add `2n` ticks) and unchecked.

| Instruction | Sizes | Forms | Flags |
|---|---|---|---|
| Bcc, BRA | 8-bit and 16-bit displacement | all sixteen condition codes (`condition_true`); BRA is condition 0 | none |
| BSR | 8-bit and 16-bit displacement | pushes the return address (`push32`) | none |
| DBcc | word | counter decrement in the low word of Dn; branch while the condition is false and the counter is not -1 | none |
| JMP, JSR | none | control modes: (An), d16(An), d8(An,Xn), abs.w, abs.l, d16(PC), d8(PC,Xn) | none |
| RTS | none | pops the return address (`pop32`) | none |
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

Notes: a branch, jump, JSR or RTS to an odd target stops with
`GW_STOP_UNSUPPORTED_ADDRESS` (the address-error frame is not modeled). `sr_write`
masks to the implemented SR bits and then applies the same check as exception
return: a write that clears S (user mode) or sets T (trace) stops with
`GW_STOP_UNSUPPORTED_STATE` and leaves SR unchanged, so a guest never silently
switches stacks. All of this is supervisor-only, as is the rest of the subset.

Still unsupported, stopping with `GW_STOP_UNSUPPORTED_INSTRUCTION`: ROXL/ROXR, MULU/MULS,
DIVU/DIVS, MOVEM, ABCD/SBCD/NBCD, NEGX, CHK, TAS, Scc, EXG, LINK/UNLK, PEA, RTR, RTE
variants beyond the six-byte frame, and the bitfield-style shift encodings. The AND/OR
encodings with modes 0-1 on the `Dn,<ea>` side belong to ABCD/SBCD/EXG and stay
unsupported.

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
