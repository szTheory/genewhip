/* SPDX-License-Identifier: MIT
 * Original 68000 harness for the D-50 FM register-script Z80 guest. */
.cpu 68000
.text
.org 0
.long 0x00ffff00,0x00000200
.org 0x0078
.long 0x00000e00
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP FMSCRPT"
.org 0x01f0
.ascii "JUE"
.org 0x0200
/* Halt Z80, request its bus, upload the nested Z80 ELF payload, and release. */
move.w #0x0100,0x00a11100
move.w #0x0000,0x00a11200
jsr 0x1000
move.w #0x0100,0x00a11200
move.w #0x0000,0x00a11100
move.w #0,0x00ff0000
move.w #0x8164,0x00c00004
move.w #0x2000,%sr
/* Each source Z80 tuple advances at one IM1 VBlank. After the 64th VBlank,
 * keep the guest's final key-on note active, sample status, then assert Z80
 * reset through the approved provisional coupling. */
wait_script:
move.w 0x00ff0000,%d0
cmpi.w #64,%d0
bne.s wait_script
move.b 0x00a04000,0x00ff0010
move.w #0x0000,0x00a11200
/* Copy guest observations after stopping the Z80. */
move.w #0x0100,0x00a11100
wait_result_grant:
move.b 0x00a11100,%d0
btst #0,%d0
bne.s wait_result_grant
move.b 0x00a04000,0x00ff0011
move.b 0x00a01010,0x00ff0020
move.b 0x00a01012,0x00ff0022
move.b 0x00a01013,0x00ff0023
move.b 0x00ff0010,0x00ff0024
move.b 0x00ff0011,0x00ff0025
stop_loop:
bra.s stop_loop
.org 0x0e00
vint_handler:
addq.w #1,0x00ff0000
rte
.org 0x1000
.set upload_index,0
.rept 1024
move.b 0x00004000+upload_index,0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
rts
.org 0x4000
z80_payload:
.include "tests/devices/roms/z80/fm_script.inc"
z80_payload_end:
.if z80_payload_end-z80_payload != 1024
.error "FM Z80 payload must be 1024 bytes"
.endif
