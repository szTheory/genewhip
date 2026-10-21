/* SPDX-License-Identifier: MIT
 * Original Z80 DAC guest. The PCM bytes are a source-defined triangle ramp.
 * In the streaming loop each write is separated by 39 T-states: INC HL (6),
 * DJNZ taken (13), LD A,(HL) (7), LD (nn),A through the data write (13).
 * The final iteration is shorter after its last write and is not judged.
 * At the console's 15 master ticks per Z80 T-state the steady spacing is 585. */
.text
.org 0
di
ld sp,0x1ff0
/* YM busy before setup; after select, each PCM write is 39T apart, exceeding
 * the implementation's documented 32*prescale*7-tick busy interval. */
busy_setup:
ld a,(0x4000)
bit 7,a
jr nz,busy_setup
ld a,0x80
ld (0x4000),a
busy_enable:
ld a,(0x4000)
bit 7,a
jr nz,busy_enable
ld a,0x2b
ld (0x4000),a
ld a,0x80
ld (0x4001),a
busy_address:
ld a,(0x4000)
bit 7,a
jr nz,busy_address
ld a,0x2a
ld (0x4000),a
ld hl,0x100
ld b,0
stream:
ld a,(hl)
ld (0x4001),a
inc hl
djnz stream
done:
jr done
.org 0x100
pcm_table:
.set sample_index,0
.rept 256
.if sample_index < 128
.byte sample_index*2
.else
.byte (255-sample_index)*2
.endif
.set sample_index,sample_index+1
.endr
