/* SPDX-License-Identifier: MIT
 * Original 68000 harness for the independent Z80 interrupt guest.
 * The 32-T-state INT width is a documented model assumption (A7). */
.cpu 68000
.text
.org 0
.long 0x00ffff00,0x00000200
.org 0x0078
.long 0x00000e00
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP Z80INT "
.org 0x01f0
.ascii "JUE"
.org 0x0200
/* Hold reset and request the bus before uploading the original guest. */
move.w #0x0100,0x00a11100
move.w #0x0000,0x00a11200
.set upload_index,0
.rept 256
move.b 0x00002000+upload_index,0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
move.w #0x0100,0x00a11200
move.w #0x0000,0x00a11100
/* Give the first boot time to execute EI and HALT, then reset it. */
.rept 256
nop
.endr
move.w #0x0100,0x00a11100
move.w #0x0000,0x00a11200
/* Fixed launch arithmetic: reset vectors 112; request/reset 280;
 * 256 uploads * 168 (assembler-selected absolute-word ROM reads); release/reset 280 = first release at 43680.
 * 256 NOPs * 28; request/reset 280; counter clear 140; VDP enable 140;
 * SR write 56; reset/bus release 280 => second release at 51744.
 * The next strict global Z80 edge is 51750. No polling phase uncertainty. */
move.w #0,0x00ff0000
move.w #0x8164,0x00c00004
move.w #0x2000,%sr
move.w #0x0100,0x00a11200
move.w #0x0000,0x00a11100
/* Count ten VBlank intervals through the documented 68000 VINT path. */
wait_ten_vblanks:
move.w 0x00ff0000,%d0
cmpi.w #10,%d0
bne.s wait_ten_vblanks
/* Freeze Z80 and copy its guest-authored RAM observations to work RAM. */
.rept 128
nop
.endr
move.w #0x0100,0x00a11100
wait_result_grant:
move.b 0x00a11100,%d0
btst #0,%d0
bne.s wait_result_grant
.set result_index,0
.rept 7
move.b 0x00a01000+result_index,0x00ff0100+result_index
.set result_index,result_index+1
.endr
stop_loop:
bra.s stop_loop
.org 0x0e00
vint_handler:
addq.w #1,0x00ff0000
rte
.org 0x2000
z80_payload:
.include "tests/devices/roms/z80/z80_guest.inc"
z80_payload_end:
.if z80_payload_end-z80_payload != 256
.error "Z80 guest payload must remain 256 bytes"
.endif
