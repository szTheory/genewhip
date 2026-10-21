/* SPDX-License-Identifier: MIT
 * Original Z80 driver: select ROM bank one, copy the marker, drive PSG tone. */
.text
.org 0
ld a,1
ld (0x6000),a
.rept 8
ld a,0
ld (0x6000),a
.endr
ld hl,0x8000
ld de,0x1000
ld bc,16
ldir
ld a,0x80
ld (0x7f11),a
ld a,0x08
ld (0x7f11),a
ld a,0x90
ld (0x7f11),a
/* 60 * 60 iterations. DEC C is 4 T-states and the taken JR NZ is 12
 * T-states; at the selected 15 master ticks/T, this provides over 850,000
 * master ticks of audible tone, enough for many 873.9 Hz cycles. These are
 * whole-instruction timings, not a claim about external bus wait totals. */
ld b,60
delay_outer:
ld c,60
delay_inner:
dec c
jr nz,delay_inner
djnz delay_outer
ld a,0x9f
ld (0x7f11),a
loop:
jr loop
