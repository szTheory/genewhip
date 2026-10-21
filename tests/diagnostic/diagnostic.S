/* SPDX-License-Identifier: MIT
 * Original Genewhip diagnostic, directive-only 68000 assembly.
 * All words are authored machine encodings, not output from Genewhip.
 * build_rom.c accepts .org/.word/.long with one numeric operand per line.
 * Comments give the equivalent mnemonics; source also uses GAS data syntax.
 * No assets, runtime, third-party code or cross-assembler are required.
 */
.org 0x0000
.long 0x00ffff00 /* initial supervisor stack */
.long 0x00000200 /* reset PC */
.org 0x0080
.long 0x00000300 /* TRAP #0 vector (32) */
.org 0x0200
.word 0x13fc /* move.b #0x12,0x00ff0000.l */
.word 0x0012
.long 0x00ff0000
.word 0x13fc /* move.b #0x34,0x00ff0001.l */
.word 0x0034
.long 0x00ff0001
.word 0x3039 /* move.w 0x00ff0000.l,d0: expected 0x1234 */
.long 0x00ff0000
.word 0x23fc /* move.l #0x89abcdef,0x00ff0002.l */
.long 0x89abcdef
.long 0x00ff0002
.word 0x2239 /* move.l 0x00ff0002.l,d1 */
.long 0x00ff0002
.word 0x7400 /* moveq #0,d2: set Z before exception */
.word 0x4e40 /* trap #0; return PC = 0x22a */
.word 0x33fc /* move.w #0xbeef,0x00ff0008.l: only after RTE */
.word 0xbeef
.long 0x00ff0008
.word 0x4e72 /* stop #0x2700 */
.word 0x2700
.org 0x0300
.word 0x3617 /* move.w (a7),d3: saved SR = 0x2704 */
.word 0x282f /* move.l 2(a7),d4: saved return PC = 0x22a */
.word 0x0002
.word 0x33fc /* move.w #0xcafe,0x00ff0006.l: exception marker */
.word 0xcafe
.long 0x00ff0006
.word 0x4e73 /* rte: restores SR, PC and stack */
.org 0x03fe
.word 0x0000 /* fixed 1024-byte ROM */
