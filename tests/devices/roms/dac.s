/* SPDX-License-Identifier: MIT
 * Original 68000 loader for the nested Z80 DAC streaming guest. */
.cpu 68000
.text
.org 0
.long 0x00ffff00,0x00000200
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP DACSEAM"
.org 0x01f0
.ascii "JUE"
.org 0x0200
move.w #0x0100,0x00a11100
move.w #0x0000,0x00a11200
jsr 0x1000
move.w #0x0100,0x00a11200
move.w #0x0000,0x00a11100
stop_loop:
bra.s stop_loop
.org 0x1000
.set upload_index,0
.rept 512
move.b 0x00003000+upload_index,0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
rts
.org 0x3000
z80_payload:
.include "tests/devices/roms/z80/dac.inc"
z80_payload_end:
.if z80_payload_end-z80_payload != 512
.error "DAC Z80 payload must be 512 bytes"
.endif
