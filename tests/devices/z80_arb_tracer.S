/* SPDX-License-Identifier: MIT */
/* Guest-visible D-42 model-conformance tracer. Sources: Technical Overview
 * 1.00 p.76 (D8 clear when accessible; poll status), contrary 1992 sound
 * manual p.2 retained in 03-BUSREQ-SOURCE-RECONCILIATION.md. */
.org 0x0000
.long 0x00ffff00
.long 0x00000200
.org 0x0200
/* 33fc 0100 00a11100: MOVE.W #$0100,$A11100 (request bus). */
.word 0x33fc
.word 0x0100
.long 0x00a11100
/* 207c 00ff0100: MOVEA.L #$FF0100,A0; 7400: MOVEQ #0,D2. */
.word 0x207c
.long 0x00ff0100
.word 0x7400
/* Poll and append even-byte bit 0: 1039 ...; 10c0; 5442; 33c2 ... */
.word 0x1039
.long 0x00a11100
.word 0x10c0
.word 0x5242
.word 0x33c2
.long 0x00ff0002
/* 0800 0000: BTST #0,D0; 66ea: BNE.S back to poll while request pending. */
.word 0x0800
.word 0x0000
.word 0x66ea
/* Hand-encoded Z80 program, with each opcode and mnemonic documented:
 * 3e 5a = LD A,$5A; 32 00 10 = LD ($1000),A; 18 fe = JR $ (loop).
 * Each encoding is covered by the Plan 03-08 Z80 functional vectors. */
.word 0x13fc
.word 0x003e
.long 0x00a00000
.word 0x13fc
.word 0x005a
.long 0x00a00001
.word 0x13fc
.word 0x0032
.long 0x00a00002
.word 0x13fc
.word 0x0000
.long 0x00a00003
.word 0x13fc
.word 0x0010
.long 0x00a00004
.word 0x13fc
.word 0x0018
.long 0x00a00005
.word 0x13fc
.word 0x00fe
.long 0x00a00006
/* 33fc 0000 A11200: reset assert; 33fc 0100 A11200: release at Z80 edge. */
.word 0x33fc
.word 0x0000
.long 0x00a11200
.word 0x33fc
.word 0x0100
.long 0x00a11200
/* 33fc 0000 A11100: release bus after the Z80 has been reset and restarted. */
.word 0x33fc
.word 0x0000
.long 0x00a11100
/* Fixed guest delay (NOP = 4 68000 cycles each) lets the Z80 finish. */
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
.word 0x4e71
/* Request again and repeat the status poll, appending to the same log. */
.word 0x33fc
.word 0x0100
.long 0x00a11100
.word 0x1039
.long 0x00a11100
.word 0x10c0
.word 0x5242
.word 0x33c2
.long 0x00ff0002
.word 0x0800
.word 0x0000
.word 0x66ea
/* Read Z80 result and publish it at FF0000. */
.word 0x1039
.long 0x00a01000
.word 0x13c0
.long 0x00ff0000
.word 0x33fc
.word 0x0000
.long 0x00a11100
.word 0x60fe
.org 0x03fe
.word 0x0000
