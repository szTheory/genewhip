/* SPDX-License-Identifier: MIT
 * Authored 68000 machine words for device tests. Every emitted word is an
 * encoding written by hand (mnemonic in the comment at each call), not output
 * from Genewhip. Test ROMs are 1024 bytes with reset vectors SSP 0xffff00 / PC 0x200.
 */
#ifndef GW_TEST_DEVROM_H
#define GW_TEST_DEVROM_H
#include "contract.h"

#define VDP_DATA 0x00c00000u
#define VDP_CTRL 0x00c00004u

typedef struct rom_emit { uint8_t *rom; size_t pos; } rom_emit;

static inline void emit16(rom_emit *e, uint32_t v) { e->rom[e->pos++] = (uint8_t)(v >> 8); e->rom[e->pos++] = (uint8_t)v; }
static inline void emit32(rom_emit *e, uint32_t v) { emit16(e, v >> 16); emit16(e, v & 0xffffu); }
static inline void rom_begin(rom_emit *e, uint8_t *rom)
{
    rom_init(rom, 1024);
    rom[512] = 0; rom[513] = 0;
    e->rom = rom; e->pos = 512;
}
/* move.w #imm,(address).l */
static inline void emit_move_w(rom_emit *e, uint32_t imm, uint32_t address) { emit16(e, 0x33fc); emit16(e, imm); emit32(e, address); }
/* move.l #imm,(address).l */
static inline void emit_move_l(rom_emit *e, uint32_t imm, uint32_t address) { emit16(e, 0x23fc); emit32(e, imm); emit32(e, address); }
static inline void emit_reg(rom_emit *e, unsigned reg, unsigned value) { emit_move_w(e, 0x8000u | reg << 8 | value, VDP_CTRL); }
static inline void emit_bra_self(rom_emit *e) { emit16(e, 0x60fe); }
/* Reg 1, reg 12, auto-increment 2, backdrop index 1, CRAM[1] = 0x0E2A, then BRA self. */
static inline void build_setup_rom(uint8_t *rom, unsigned reg1, unsigned reg12)
{
    rom_emit e;
    rom_begin(&e, rom);
    emit_reg(&e, 1, reg1);
    emit_reg(&e, 12, reg12);
    emit_reg(&e, 15, 2);
    emit_reg(&e, 7, 1);
    emit_move_l(&e, 0xc0020000u, VDP_CTRL);   /* CRAM write, address 2 */
    emit_move_w(&e, 0x0e2au, VDP_DATA);
    emit_bra_self(&e);
}
#endif
