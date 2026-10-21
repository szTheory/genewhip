/* SPDX-License-Identifier: MIT
 * Original Genewhip raster-toy sound guest. IM1 consumes the 68000 mailbox.
 * FM operator values follow the independently authored audible one-carrier
 * patch recorded in tests/devices/roms/z80/fm_script.s. */
.equ SND_PSG_BLIP, 1
.equ SND_FM_NOTE, 2
.equ SND_DAC_SAMPLE, 4
.equ MAILBOX, 0x1010
.equ PSG_TONE_PERIOD, 0x180
.equ PSG_ATTENUATION, 0x00
.equ PSG_DECAY_FIELDS, 24
.equ YM_FNUM_HIGH, 0x22
.equ YM_FNUM_LOW, 0x84
.equ YM_FNUM_HIGH_REG, 0xa4
.equ YM_FNUM_LOW_REG, 0xa0
.equ YM_KEY_REG, 0x28
.equ YM_CHANNEL, 0
.equ YM_KEY_ON, 0x10
.equ YM_DAC_REG, 0x2a
.equ YM_DAC_ENABLE_REG, 0x2b
.equ DAC_TABLE_LENGTH, 64
.equ DAC_CYCLE_DELAY, 12

.text
.org 0
    jp 0x80
.org 0x38
    jp 0x100
.org 0x80
guest_init:
    di
    ld sp,0x1ff0
    im 1
    xor a
    ld (MAILBOX),a
    ld (0x300),a
    ld (0x301),a
    ei
guest_idle:
    halt
    jr guest_idle

.org 0x100
im1_handler:
    push af
    push bc
    push de
    push hl
    ld a,(MAILBOX)
    ld d,a
    xor a
    ld (MAILBOX),a
    ld a,d
    cp SND_PSG_BLIP
    call z,0x130
    ld a,d
    cp SND_FM_NOTE
    call z,0x180
    ld a,d
    cp SND_DAC_SAMPLE
    call z,0x200
    call 0x150
    call 0x1b0
    pop hl
    pop de
    pop bc
    pop af
    ei
    reti

.org 0x130
play_psg:
    ld a,0x80 | (PSG_TONE_PERIOD & 0x0f)
    ld (0x7f11),a
    ld a,(PSG_TONE_PERIOD >> 4) & 0x3f
    ld (0x7f11),a
    ld a,0x90 | PSG_ATTENUATION
    ld (0x7f11),a
    ld a,PSG_DECAY_FIELDS
    ld (0x300),a
    ret

.org 0x150
psg_envelope:
    ld a,(0x300)
    or a
    ret z
    dec a
    ld (0x300),a
    and 0x0f
    add a,0x90
    ld (0x7f11),a
    ret

.org 0x180
play_fm:
    ; One-carrier audible patch from the Genewhip FM source, bank 0.
    ld hl,0x400
    ld b,21
fm_patch_loop:
    ld a,(hl)
    inc hl
    ld (0x4000),a
    ld a,(hl)
    inc hl
    ld (0x4001),a
    djnz fm_patch_loop
    ld a,30
    ld (0x301),a
    ret

.org 0x1b0
fm_envelope:
    ld a,(0x301)
    or a
    ret z
    dec a
    ld (0x301),a
    ret nz
    ld a,YM_KEY_REG
    ld (0x4000),a
    xor a
    ld (0x4001),a
    ret

.org 0x200
play_dac:
    ld a,YM_DAC_ENABLE_REG
    ld (0x4000),a
    ld a,0x80
    ld (0x4001),a
    ld hl,0x500
    ld b,DAC_TABLE_LENGTH
dac_loop:
    ld a,YM_DAC_REG
    ld (0x4000),a
    ld a,(hl)
    inc hl
    ld (0x4001),a
    ld c,DAC_CYCLE_DELAY
dac_delay:
    dec c
    jr nz,dac_delay
    djnz dac_loop
    ld a,YM_DAC_ENABLE_REG
    ld (0x4000),a
    xor a
    ld (0x4001),a
    ret

.org 0x300
    .byte 0
    .byte 0

.org 0x400
fm_patch:
    .byte 0x30,0x01, 0x34,0x01, 0x38,0x01, 0x3c,0x01
    .byte 0x40,0x00, 0x44,0x7f, 0x48,0x7f, 0x4c,0x7f
    .byte 0x50,0x1f, 0x54,0x00, 0x58,0x00, 0x5c,0x00
    .byte 0x80,0x0f, 0x84,0x0f, 0x88,0x0f, 0x8c,0x0f
    .byte 0xb0,0x07, 0xb4,0xc0, YM_FNUM_HIGH_REG,YM_FNUM_HIGH, YM_FNUM_LOW_REG,YM_FNUM_LOW
    .byte YM_KEY_REG,YM_KEY_ON
fm_patch_end:

.org 0x500
dac_samples:
.set dac_i,0
.rept DAC_TABLE_LENGTH
    .if dac_i < (DAC_TABLE_LENGTH / 2)
    .byte 0x80 + (dac_i * 4)
    .else
    .byte 0x80 + ((DAC_TABLE_LENGTH - 1 - dac_i) * 4)
    .endif
.set dac_i,dac_i+1
.endr
dac_samples_end:
.if dac_samples_end-dac_samples != DAC_TABLE_LENGTH
.error "DAC table length must match its source constant"
.endif
