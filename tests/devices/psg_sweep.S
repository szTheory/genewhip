/* SPDX-License-Identifier: MIT
 * Original directive-only 68000 sound sweep ROM. D0 increments indefinitely;
 * each iteration updates a work-RAM byte and writes a changing channel-0 PSG
 * period. The fixed NOP delay keeps the optional write trace inside its bound
 * over the four-field equivalence window. */
.org 0x0000
.long 0x00ffff00 /* initial supervisor stack */
.long 0x00000200 /* reset PC */
.org 0x0200
.word 0x7000 /* moveq #0,d0 */
.word 0x13fc /* move.b #0,0x00ff0000.l */
.word 0x0000
.long 0x00ff0000
.word 0x33fc /* move.w #0x8144,0x00c00004.l: enable the display and Mode 5 */
.word 0x8144
.long 0x00c00004
.word 0x13fc /* move.b #0x90,0x00c00011.l: channel 0 attenuation 0 */
.word 0x0090
.long 0x00c00011
.word 0x5280 /* addq.l #1,d0 */
.word 0x13c0 /* move.b d0,0x00ff0000.l: record the changing counter */
.long 0x00ff0000
.word 0x13fc /* move.b #0x8e,0x00c00011.l: latch channel 0 period low bits */
.word 0x008e
.long 0x00c00011
.word 0x13c0 /* move.b d0,0x00c00011.l: update channel 0 period high bits */
.long 0x00c00011
.word 0x4e71 /* nop: fixed delay, 1 of 52 */
.word 0x4e71 /* nop: fixed delay, 2 of 52 */
.word 0x4e71 /* nop: fixed delay, 3 of 52 */
.word 0x4e71 /* nop: fixed delay, 4 of 52 */
.word 0x4e71 /* nop: fixed delay, 5 of 52 */
.word 0x4e71 /* nop: fixed delay, 6 of 52 */
.word 0x4e71 /* nop: fixed delay, 7 of 52 */
.word 0x4e71 /* nop: fixed delay, 8 of 52 */
.word 0x4e71 /* nop: fixed delay, 9 of 52 */
.word 0x4e71 /* nop: fixed delay, 10 of 52 */
.word 0x4e71 /* nop: fixed delay, 11 of 52 */
.word 0x4e71 /* nop: fixed delay, 12 of 52 */
.word 0x4e71 /* nop: fixed delay, 13 of 52 */
.word 0x4e71 /* nop: fixed delay, 14 of 52 */
.word 0x4e71 /* nop: fixed delay, 15 of 52 */
.word 0x4e71 /* nop: fixed delay, 16 of 52 */
.word 0x4e71 /* nop: fixed delay, 17 of 52 */
.word 0x4e71 /* nop: fixed delay, 18 of 52 */
.word 0x4e71 /* nop: fixed delay, 19 of 52 */
.word 0x4e71 /* nop: fixed delay, 20 of 52 */
.word 0x4e71 /* nop: fixed delay, 21 of 52 */
.word 0x4e71 /* nop: fixed delay, 22 of 52 */
.word 0x4e71 /* nop: fixed delay, 23 of 52 */
.word 0x4e71 /* nop: fixed delay, 24 of 52 */
.word 0x4e71 /* nop: fixed delay, 25 of 52 */
.word 0x4e71 /* nop: fixed delay, 26 of 52 */
.word 0x4e71 /* nop: fixed delay, 27 of 52 */
.word 0x4e71 /* nop: fixed delay, 28 of 52 */
.word 0x4e71 /* nop: fixed delay, 29 of 52 */
.word 0x4e71 /* nop: fixed delay, 30 of 52 */
.word 0x4e71 /* nop: fixed delay, 31 of 52 */
.word 0x4e71 /* nop: fixed delay, 32 of 52 */
.word 0x4e71 /* nop: fixed delay, 33 of 52 */
.word 0x4e71 /* nop: fixed delay, 34 of 52 */
.word 0x4e71 /* nop: fixed delay, 35 of 52 */
.word 0x4e71 /* nop: fixed delay, 36 of 52 */
.word 0x4e71 /* nop: fixed delay, 37 of 52 */
.word 0x4e71 /* nop: fixed delay, 38 of 52 */
.word 0x4e71 /* nop: fixed delay, 39 of 52 */
.word 0x4e71 /* nop: fixed delay, 40 of 52 */
.word 0x4e71 /* nop: fixed delay, 41 of 52 */
.word 0x4e71 /* nop: fixed delay, 42 of 52 */
.word 0x4e71 /* nop: fixed delay, 43 of 52 */
.word 0x4e71 /* nop: fixed delay, 44 of 52 */
.word 0x4e71 /* nop: fixed delay, 45 of 52 */
.word 0x4e71 /* nop: fixed delay, 46 of 52 */
.word 0x4e71 /* nop: fixed delay, 47 of 52 */
.word 0x4e71 /* nop: fixed delay, 48 of 52 */
.word 0x4e71 /* nop: fixed delay, 49 of 52 */
.word 0x4e71 /* nop: fixed delay, 50 of 52 */
.word 0x4e71 /* nop: fixed delay, 51 of 52 */
.word 0x4e71 /* nop: fixed delay, 52 of 52 */
.word 0x6080 /* bra.s back to the period update (signed displacement -128) */
.org 0x03fe
.word 0x0000 /* fixed 1024-byte ROM */
