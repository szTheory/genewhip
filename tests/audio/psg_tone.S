/* SPDX-License-Identifier: MIT
 * Original directive-only 68000 ROM: channel 0, SN76489 tone period N=0x0FE,
 * attenuation 0. Expected frequency follows the documented Zclk/(32*N) rule.
 */
.org 0x0000
.long 0x00ffff00 /* initial supervisor stack */
.long 0x00000200 /* reset PC */
.org 0x0200
.word 0x13fc /* move.b #0x8e,0x00c00011.l: channel 0 tone latch, period low 0x0e */
.word 0x008e
.long 0x00c00011
.word 0x13fc /* move.b #0x0f,0x00c00011.l: period high bits, N=0x0fe */
.word 0x000f
.long 0x00c00011
.word 0x13fc /* move.b #0x90,0x00c00011.l: channel 0 attenuation 0 */
.word 0x0090
.long 0x00c00011
.word 0x60fe /* bra.s self */
.org 0x03fe
.word 0x0000 /* fixed 1024-byte ROM */
