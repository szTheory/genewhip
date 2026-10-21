/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP backdrop test ROM, directive-only 68000 assembly.
 * All words are authored machine encodings, not output from Genewhip.
 * Sets H40 V28 Mode 5, display on, auto-increment 2, backdrop = CRAM index 1,
 * writes CRAM[1] = 0x0E2A through the control and data ports, then loops.
 * Expected backdrop: R=5->174, G=1->49, B=7->255 (Genewhip 15-level table).
 */
.org 0x0000
.long 0x00ffff00 /* initial supervisor stack */
.long 0x00000200 /* reset PC */
.org 0x0200
.word 0x33fc /* move.w #0x8144,0x00c00004.l: reg1 = 0x44: display on, Mode 5, V28 */
.word 0x8144
.long 0x00c00004
.word 0x33fc /* move.w #0x8c81,0x00c00004.l: reg12 = 0x81: H40, RS0 = RS1 */
.word 0x8c81
.long 0x00c00004
.word 0x33fc /* move.w #0x8f02,0x00c00004.l: reg15 = 2: auto-increment 2 */
.word 0x8f02
.long 0x00c00004
.word 0x33fc /* move.w #0x8701,0x00c00004.l: reg7 = 1: backdrop palette 0 index 1 */
.word 0x8701
.long 0x00c00004
.word 0x23fc /* move.l #0xc0020000,0x00c00004.l: CRAM write, address 2 (index 1) */
.long 0xc0020000
.long 0x00c00004
.word 0x33fc /* move.w #0x0e2a,0x00c00000.l: CRAM[1] = 0x0e2a */
.word 0x0e2a
.long 0x00c00000
.word 0x60fe /* bra self */
.org 0x03fe
.word 0x0000 /* fixed 1024-byte ROM */
