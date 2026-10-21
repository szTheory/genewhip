/* SPDX-License-Identifier: MIT
 * Original Z80 guest oracle: UM0080-defined EI, HALT, IM1, RETI and reset.
 * All timing below is source arithmetic for Genewhip's A7 model. */
.text
.org 0
jp 0x0080 /* boot; absolute addresses checked by stacked-PC oracle */
.org 0x38
im1_handler:
ld a,(0x1002)
or a
jr nz,count_entry
/* Capture the first stacked return PC, independent of the vector hooks.
 * Correct EI;HALT acceptance pushes after_halt (0x00b1). Premature EI
 * acceptance pushes halt_loop (0x00b0), so the named oracle fails. */
ld hl,0
add hl,sp
ld a,(hl)
ld (0x1005),a
inc hl
ld a,(hl)
ld (0x1006),a
count_entry:
ld a,(0x1002)
inc a
ld (0x1002),a
ei
reti
.org 0x80
boot:
ld a,(0x1004)
or a
jr nz,second_boot
inc a
ld (0x1004),a
ei
first_boot_halt:
halt
jr first_boot_halt
second_boot:
ld a,i
jp po,0x0097 /* iff2_clear */
ld a,0
jr iff2_store
iff2_clear:
ld a,1
iff2_store:
ld (0x1003),a
ld sp,0x1ff0
im 1
ld a,0x5a
ld (0x1000),a
/* Second boot starts at master tick 51750. JP boot (10T), startup
 * through marker (106T), LD BC (10T), delay (26*1827-5 T), one NOP
 * (4T), EI (4T): 47631T. EI retires at 766215, inside A7's
 * [766080,766560) pulse. HALT retires at 766275 before acceptance.
 * The next PC is source address 0x00b1. No observed output supplies it. */
ld bc,1827
delay:
dec bc
ld a,b
or c
jr nz,delay
nop
ei
halt_loop:
halt
after_halt:
ld a,(0x1001)
inc a
ld (0x1001),a
jr halt_loop
.org 0xff
.byte 0
