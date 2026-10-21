/* SPDX-License-Identifier: MIT */
#include "contract.h"

static void boundary(uint32_t address, int write, uint32_t reason,
                     uint32_t fault, uint64_t tick)
{
    uint8_t rom[1024], bytes[4] = {0x55,0x55,0x55,0x55};
    gw_machine *m = machine();
    gw_diagnostic_event events[2]; size_t count; uint64_t dropped;
    rom_init(rom, sizeof(rom));
    rom[512] = write ? 0x23 : 0x20; rom[513] = write ? 0xfc : 0x39;
    if (write) { put32(rom+514, 0x12345678); put32(rom+518, address); }
    else put32(rom+514, address);
    CHECK(gw_configure_diagnostics(m, 2) == GW_OK, "enable boundary trace");
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "boundary load");
    gw_run_result r = run(m, 113);
    CHECK(r.stop_reason == reason, "boundary stop reason");
    CHECK(r.actual_tick == tick, "completed word transfer timing");
    gw_diagnostic_record d = snapshot(m);
    CHECK(r.fault_address == fault, "second word fault address");
    if (!write && reason == GW_STOP_TARGET)
        CHECK(d.d[0] == 0xff, "24-bit wrapped longword reads RAM then ROM");
    if (write && address == 0xfffffe) {
        CHECK(gw_peek_memory(m, address, bytes, 2) == GW_OK &&
              bytes[0] == 0x12 && bytes[1] == 0x34, "first write survives ROM second-word fault");
    }
    memset(bytes, 0x55, sizeof(bytes));
    CHECK(gw_peek_memory(m, address, bytes, 4) != GW_OK, "peek remains nonwrapping all-or-nothing");
    CHECK(bytes[0] == 0x55 && bytes[3] == 0x55, "failed peek preserves output");
    CHECK(gw_get_diagnostic_events(m, events, 2, &count, &dropped) == GW_OK &&
          count == 1 && dropped == 0, "one attempted instruction trace");
    CHECK(events[0].tick == tick && events[0].fault_address == fault &&
          events[0].stop_reason == reason && events[0].instruction_address == 0x200,
          "trace observes completed transfers before fault");
    gw_destroy(m);
}

int main(void)
{
    boundary(0xfffffe, 0, GW_STOP_TARGET, 0, 252);
    boundary(0x3fe, 0, GW_STOP_UNSUPPORTED_ADDRESS, 0x400, 224);
    boundary(0xfffffe, 1, GW_STOP_UNSUPPORTED_ADDRESS, 0, 280);
    boundary(0xffffff, 0, GW_STOP_UNSUPPORTED_ADDRESS, 0xffffff, 196);
    boundary(0xffffff, 1, GW_STOP_UNSUPPORTED_ADDRESS, 0xffffff, 252);
    puts("bus_boundary_contract: PASS"); return 0;
}
