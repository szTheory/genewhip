/* SPDX-License-Identifier: MIT
 * Original FM-script Z80 guest. One source-defined (bank, register, value)
 * tuple is emitted from the IM1 handler for each VBlank. The handler waits
 * for YM2612 busy to clear before selecting and writing the register. */
.text
.org 0
jp 0x80
.org 0x38
 jp 0x200
.org 0x80
boot:
di
ld sp,0x1ff0
im 1
ld hl,0x300
ld (0x1000),hl
xor a
ld (0x1005),a
ei
main_loop:
halt
/* Timer observations and polling counts are reported, but remain unknown
 * because the guest's polling cadence is not an independent hardware oracle. */
ld a,(0x4000)
and 3
ld b,a
ld a,(0x1010)
or b
ld (0x1010),a
ld hl,(0x1012)
inc hl
ld (0x1012),hl
jr main_loop
.org 0x200
im1_handler:
push af
push bc
push hl
ld hl,(0x1000)
ld de,0x3ba /* 0x300 + 62 three-byte source records */
or a
sbc hl,de
jr z,script_finished
ld hl,(0x1000)
ld a,(hl)
inc hl
ld (0x1000),hl
ld (0x1002),a
ld a,(hl)
inc hl
ld (0x1000),hl
ld (0x1003),a
ld a,(hl)
inc hl
ld (0x1000),hl
ld (0x1004),a
ld a,(0x1002)
or a
jr nz,bank_one
busy_zero:
ld a,(0x4000)
bit 7,a
jr nz,busy_zero
ld a,(0x1003)
ld (0x4000),a
busy_data_zero:
ld a,(0x4000)
bit 7,a
jr nz,busy_data_zero
ld a,(0x1004)
ld (0x4001),a
jr write_done
bank_one:
busy_one:
ld a,(0x4000)
bit 7,a
jr nz,busy_one
ld a,(0x1003)
ld (0x4002),a
busy_data_one:
ld a,(0x4000)
bit 7,a
jr nz,busy_data_one
ld a,(0x1004)
ld (0x4003),a
write_done:
jr handler_exit
script_finished:
ld a,1
ld (0x1005),a
handler_exit:
pop hl
pop bc
pop af
ei
reti
.org 0x300
script:
/* bank, register, value; every write is authored here, never emulator output. */
.byte 0,0x30,0x01, 0,0x34,0x01, 0,0x38,0x01, 0,0x3c,0x01 /* channel 0: MUL=1 */
.byte 0,0x40,0x00, 0,0x44,0x7f, 0,0x48,0x7f, 0,0x4c,0x7f /* one carrier */
.byte 0,0x50,0x1f, 0,0x54,0x00, 0,0x58,0x00, 0,0x5c,0x00 /* attack */
.byte 0,0x80,0x0f, 0,0x84,0x0f, 0,0x88,0x0f, 0,0x8c,0x0f /* sustain/release */
.byte 0,0xb0,0x07, 0,0xb4,0xc0, 0,0xa4,0x22, 0,0xa0,0x84
.byte 0,0x28,0x10 /* key on channel 0 with operator 1 as carrier */
/* Hold the audible interval before the register-behavior experiments. */
.byte 0,0x22,0x00, 0,0x22,0x00, 0,0x22,0x00, 0,0x22,0x00
.byte 0,0x22,0x00, 0,0x22,0x00, 0,0x22,0x00, 0,0x22,0x00
.byte 0,0x40,0x7f, 0,0x44,0x00, 0,0x48,0x7f, 0,0x4c,0x00, 0,0xb0,0x07, 0,0xb4,0xc0
.byte 0,0xa4,0x22, 0,0xa0,0x69                  /* channel 0 high then low */
.byte 0,0xa1,0x24, 0,0xa5,0x12                  /* channel 1 low then high */
.byte 0,0xa6,0x25                                /* channel 2 high only */
.byte 0,0xa2,0x70                                /* channel 2 low only */
.byte 0,0x28,0xf0, 0,0x28,0x00                  /* key on/off channel 0 */
.byte 0,0x27,0x40                                /* channel 3 special mode */
.byte 0,0xa2,0x20, 0,0xa6,0x18, 0,0xaa,0x24, 0,0xae,0x14
.byte 0,0x22,0x0f, 0,0x22,0x0b                  /* LFO on, two rates */
.byte 0,0x90,0x0f, 0,0x92,0x0b                  /* SSG-EG modes */
.byte 0,0x24,0xff, 0,0x25,0x03, 0,0x26,0xff
.byte 0,0x27,0x0f                                /* load and enable A/B */
.byte 0,0x27,0x1f, 0,0x27,0x2f                  /* acknowledge A, then B */
.byte 0,0x27,0x8f                                /* CSM with timers running */
.byte 0,0x28,0xf2, 0,0x28,0x02                  /* key on/off channel 2 */
.byte 0,0x28,0xf5                                /* key-on channel 4 before the 68000 reset probe */
script_end:
.org 0x3ff
.byte 0
