/* SPDX-License-Identifier: MIT */
#include "contract.h"

static gw_run_result run_guest(const uint8_t *program, size_t length)
{
    uint8_t rom[1024];
    gw_machine *m = machine();
    rom_init(rom, sizeof(rom));
    memcpy(rom + 0x200, program, length);
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load public bus guest");
    gw_run_result r = run(m, 3000);
    gw_destroy(m);
    return r;
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static gw_run_result move_word(uint32_t address, uint16_t value)
{
    uint8_t code[12];
    put16(code, 0x33fc); put16(code + 2, value); put32(code + 4, address);
    put16(code + 8, 0x60fe);
    return run_guest(code, 10);
}

int main(void)
{
    /* A register write through the second control-port mirror is legal. */
    gw_run_result mirror = move_word(0x00c00006, 0x8f02);
    CHECK(mirror.stop_reason == GW_STOP_TARGET, "control mirror accepts a word write");

    /* A long write is two ordered word writes; both control words are legal
       register-15 writes. This also exercises the mirror at the second word. */
    uint8_t split[14];
    put16(split, 0x23fc); put32(split + 2, 0x8f028f02); put32(split + 6, 0x00c00004);
    put16(split + 10, 0x60fe);
    gw_run_result long_write = run_guest(split, 12);
    CHECK(long_write.stop_reason == GW_STOP_TARGET, "split long control write completes");

    /* VDP ports reject byte lanes and odd word alignment with an explicit
       unsupported-address result instead of silently aliasing the access. */
    uint8_t byte_write[10];
    put16(byte_write, 0x13fc); put16(byte_write + 2, 0x01); put32(byte_write + 4, 0x00c00004);
    gw_run_result byte_lane = run_guest(byte_write, 8);
    CHECK(byte_lane.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS, "VDP byte lane remains unsupported");
    CHECK(byte_lane.fault_address == 0x00c00004, "byte lane reports exact VDP address");

    gw_run_result odd_word = move_word(0x00c00005, 0x8f02);
    CHECK(odd_word.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS, "odd VDP word remains unsupported");
    CHECK(odd_word.fault_address == 0x00c00005, "odd word reports exact VDP address");

    puts("gameplay_bus_contract: PASS (legal mirror/split-long; byte and odd-word stops)");
    return 0;
}
