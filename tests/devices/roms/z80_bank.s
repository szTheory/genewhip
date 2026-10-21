/* SPDX-License-Identifier: MIT
 * Original 68000 harness for the banked Z80 ROM and PSG seam. */
.cpu 68000
.text
.org 0
.long 0x00ffff00,0x00000200
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP Z80BANK"
.org 0x01f0
.ascii "JUE"
.org 0x0200
.word 0x33fc,0x0100
.long 0x00a11100
.word 0x33fc,0x0000
.long 0x00a11200
.rept 48
.word 0x4e71
.endr
.word 0x33fc,0x0100
.long 0x00a11200
.set upload_index,0
.rept 87
.word 0x13f9
.long 0x3000+upload_index
.long 0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
.word 0x33fc,0x0000
.long 0x00a11100
.rept 4
.word 0x303c,4000
.word 0x5340,0x66fc
.endr
.word 0x33fc,0x0100
.long 0x00a11100
.rept 16
.word 0x13f9
.long 0x00a01000+upload_index-87
.long 0x00ff0000+upload_index-87
.set upload_index,upload_index+1
.endr
.word 0x60fe
.org 0x3000
z80_start:
.include "tests/devices/roms/z80/z80_bank.inc"
z80_end:
.if z80_end-z80_start != 87
.error "update Z80 upload length"
.endif
.org 0x8000
.ascii "Genewhip bank 01"
