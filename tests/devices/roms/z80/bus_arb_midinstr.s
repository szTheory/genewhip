/* SPDX-License-Identifier: MIT
 * Original loop used by the PUSH micro-cycle grant fixture. */
.text
.org 0
ld sp,0x17ff
ld bc,0x1234
ld a,0x80
ld (0x7f11),a
ld a,0x08
ld (0x7f11),a
ld a,0x90
ld (0x7f11),a
loop:
push bc
jr loop
.org 40
