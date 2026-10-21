/* SPDX-License-Identifier: MIT
 * D-23: unsupported display modes stop explicitly at the next line render
 * point; supported modes run. Expected fault encodings are authored constants.
 */
#include "devrom.h"

static void expect_stop(unsigned reg1, unsigned reg12, unsigned reg, unsigned value, const char *name)
{
    uint8_t rom[1024];
    gw_machine *m = machine();
    gw_run_result r;
    build_setup_rom(rom, reg1, reg12);
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, name);
    r = run(m, 20 * GW_LINE_TICKS);
    CHECK(r.stop_reason == GW_STOP_UNSUPPORTED_STATE, name);
    CHECK(r.fault_address == (0x80000000u | reg << 8 | value), name);
    CHECK(r.actual_tick >= GW_LINE_TICKS && r.actual_tick < 2 * GW_LINE_TICKS, "stops at the next line render point");
    CHECK(run(m, 30 * GW_LINE_TICKS).actual_tick == r.actual_tick, "stop is sticky");
    CHECK(gw_console_reset(m) == GW_OK, "reset clears the stop");
    /* The ROM restarts and reprograms the mode; stay short of the next render point. */
    CHECK(run(m, r.actual_tick + 500).stop_reason == GW_STOP_TARGET, "reset clears the sticky stop");
    gw_destroy(m);
}

static unsigned field_width(unsigned reg12)
{
    uint8_t rom[1024];
    gw_machine *m = machine();
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    unsigned fields;
    build_setup_rom(rom, 0x44, reg12);
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load negative control");
    for (fields = 0; fields < 2; ++fields)
        CHECK(run_field(m, 3 * (uint64_t)GW_FIELD_TICKS).stop_reason == GW_STOP_FIELD_COMPLETE, "field");
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK && f.sequence == 1, "second field");
    CHECK(f.pitch_bytes >= f.width * 4 && f.height == 224, "geometry");
    gw_destroy(m);
    return f.width;
}

int main(void)
{
    expect_stop(0x4c, 0x81, 1, 0x4c, "V30 (register 1 M2)");
    expect_stop(0x44, 0x83, 12, 0x83, "interlace LSM0");
    expect_stop(0x44, 0x85, 12, 0x85, "interlace LSM1");
    expect_stop(0x44, 0x01, 12, 0x01, "RS0 without RS1");
    expect_stop(0x44, 0x80, 12, 0x80, "RS1 without RS0");
    expect_stop(0x40, 0x81, 1, 0x40, "display enabled outside Mode 5");
    /* Negative controls: supported H40 V28 and H32 V28 run to target. */
    CHECK(field_width(0x81) == 320, "H40 field reports width 320");
    CHECK(field_width(0x00) == 256, "H32 field reports width 256");
    puts("vdp_modes_contract: PASS");
    return 0;
}
