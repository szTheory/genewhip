/* SPDX-License-Identifier: MIT
 * Original 68000 guest observes both bytes of a Z80 PUSH across grants. */
.cpu 68000
.text
.org 0
.long 0x00ffff00,0x00000200
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP MIDINS"
.org 0x01f0
.ascii "JUE"
.org 0x0200
.word 0x33fc,0x0100
.long 0x00a11100
.word 0x33fc,0x0000
.long 0x00a11200
.word 0x13fc,0x00aa
.long 0x00a017fe
.word 0x13fc,0x00bb
.long 0x00a017fd
.set upload_index,0
.rept 40
.word 0x13f9
.long 0x0700+upload_index
.long 0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
.word 0x33fc,0x0100
.long 0x00a11200
.word 0x33fc,0x0000
.long 0x00a11100
/* Source arithmetic: LD SP,nn (10T), LD BC,nn (10T), the three PSG writes
 * (60T), PUSH fetch (4T), and its internal delay (1T) place the high-byte
 * write at the following Z80 boundary. 42 68000 NOPs plus the modeled control
 * write place BUSREQ inside that 3T high-byte machine cycle. The grant is
 * observed at its end, before the separate low-byte machine cycle. */
.rept 42
.word 0x4e71
.endr
.word 0x33fc,0x0100
.long 0x00a11100
.word 0x1039
.long 0x00a017fe
.word 0x13c0
.long 0x00ff0000
.word 0x1039
.long 0x00a017fd
.word 0x13c0
.long 0x00ff0001
.word 0x33fc,0x0000
.long 0x00a11100
.rept 16
.word 0x4e71
.endr
.word 0x33fc,0x0100
.long 0x00a11100
.word 0x1039
.long 0x00a017fe
.word 0x13c0
.long 0x00ff0002
.word 0x1039
.long 0x00a017fd
.word 0x13c0
.long 0x00ff0003
.word 0x60fe
.org 0x0700
z80_start:
.include "tests/devices/roms/z80/bus_arb_midinstr.inc"
z80_end:
.if z80_end-z80_start != 40
.error "update Z80 upload length"
.endif
.org 0x07fe
.word 0
