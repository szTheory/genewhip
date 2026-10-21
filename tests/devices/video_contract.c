/* SPDX-License-Identifier: MIT
 * Field descriptor, run-stop, dropped and FIFO-timing contracts (D-20, D-25..D-28).
 * Expected values are authored constants or documented rules; hashes of Genewhip
 * output are used only to compare runs against each other.
 */
#include "devrom.h"

#define T_THREE_FIELDS UINT64_C(2600000) /* spans publish ticks 766080, 1662120, 2558160 */

static gw_machine *loaded(unsigned reg1, unsigned reg12)
{
    uint8_t rom[1024];
    gw_machine *m = machine();
    build_setup_rom(rom, reg1, reg12);
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load");
    return m;
}
static gw_video_field descriptor(void)
{
    gw_video_field f = {0};
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    return f;
}
static gw_video_field pull(gw_machine *m, const uint32_t **pixels)
{
    gw_video_field f = descriptor();
    CHECK(gw_get_video_field(m, &f, pixels) == GW_OK, "pull field");
    return f;
}

static void argument_checks(void)
{
    gw_machine *m = loaded(0x44, 0x81);
    gw_video_field f = descriptor(), sentinel;
    const uint32_t *pixels = (const uint32_t *)&f, *pixels_before = pixels;
    gw_run_result r = {0}, r_before;
    gw_diagnostic_record before;
    memset(&f.pixel_format, 0x5a, offsetof(gw_video_field, flags) - offsetof(gw_video_field, pixel_format));
    sentinel = f;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_EMPTY, "EMPTY after load");
    CHECK(memcmp(&f, &sentinel, sizeof(f)) == 0 && pixels == pixels_before, "EMPTY leaves outputs");
    CHECK(gw_get_video_field(NULL, &f, &pixels) == GW_ERROR_ARGUMENT, "NULL machine");
    CHECK(gw_get_video_field(m, NULL, &pixels) == GW_ERROR_ARGUMENT, "NULL descriptor");
    CHECK(gw_get_video_field(m, &f, NULL) == GW_ERROR_ARGUMENT, "NULL pixels");
    f.version++;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_VERSION, "wrong version");
    f.version--; f.struct_size--;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_VERSION, "wrong size");
    f.struct_size++;
    CHECK(memcmp(&f, &sentinel, sizeof(f)) == 0 && pixels == pixels_before, "errors leave outputs");
    r.struct_size = sizeof(r); r.version = GW_API_VERSION; r.flags = 2;
    r_before = r; before = snapshot(m);
    CHECK(gw_run_until(m, 1000, &r) == GW_ERROR_ARGUMENT, "unknown run flag bit rejected");
    r.flags = GW_RUN_CONTINUE_PAST_FIELD | 4;
    r_before.flags = r.flags;
    CHECK(gw_run_until(m, 1000, &r) == GW_ERROR_ARGUMENT, "unknown bit beside known bit rejected");
    CHECK(memcmp(&r, &r_before, sizeof(r)) == 0, "rejected run leaves result");
    { gw_diagnostic_record after = snapshot(m); CHECK(memcmp(&before, &after, sizeof(before)) == 0, "rejected run leaves machine"); }
    /* EMPTY again after cold init following real fields. */
    CHECK(run_field(m, T_THREE_FIELDS).stop_reason == GW_STOP_FIELD_COMPLETE, "first field");
    f = pull(m, &pixels);
    CHECK(gw_cold_init(m) == GW_OK, "cold init");
    f = descriptor();
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_EMPTY, "EMPTY after cold init");
    gw_destroy(m);
}

static void field_stop_checks(void)
{
    gw_machine *m = loaded(0x44, 0x81), *early = loaded(0x44, 0x81);
    gw_video_field f;
    const uint32_t *pixels;
    gw_run_result r;
    const uint64_t end = 224u * GW_LINE_TICKS; /* Publish tick of field 0. */
    r = run_field(early, end - 1000);
    CHECK(r.stop_reason == GW_STOP_TARGET && r.actual_tick < end, "target before field end stops at target");
    r = run_field(m, T_THREE_FIELDS);
    CHECK(r.stop_reason == GW_STOP_FIELD_COMPLETE, "zero-flag call stops at the field end");
    CHECK(r.actual_tick >= end && r.actual_tick < end + 1000, "first safe boundary at or after end_tick");
    CHECK(r.overshoot_ticks == r.actual_tick - end, "overshoot past end_tick");
    f = pull(m, &pixels);
    CHECK(f.sequence == 0 && f.start_tick == 0 && f.end_tick == end, "field 0 descriptor");
    CHECK(f.dropped == 0, "field stops drop nothing");
    gw_destroy(m); gw_destroy(early);
}

static void same_field(gw_machine *a, gw_machine *b)
{
    const uint32_t *pa, *pb;
    gw_video_field fa = pull(a, &pa), fb = pull(b, &pb);
    unsigned y;
    CHECK(fa.sequence == fb.sequence && fa.width == fb.width && fa.height == fb.height, "same field identity");
    CHECK(fa.start_tick == fb.start_tick && fa.end_tick == fb.end_tick, "same field ticks");
    for (y = 0; y < fa.height; ++y)
        CHECK(memcmp((const unsigned char *)pa + (size_t)y * fa.pitch_bytes,
                     (const unsigned char *)pb + (size_t)y * fb.pitch_bytes, fa.width * 4u) == 0, "same published pixels");
}

static void batching_checks(void)
{
    gw_machine *a = loaded(0x44, 0x81), *b = loaded(0x44, 0x81), *c = loaded(0x44, 0x81), *d = loaded(0x44, 0x81);
    gw_video_field f;
    const uint32_t *pixels;
    uint64_t t;
    gw_run_result r = run(d, T_THREE_FIELDS);
    CHECK(r.stop_reason == GW_STOP_TARGET, "run-to-target spans three field ends");
    f = pull(d, &pixels);
    CHECK(f.sequence == 2 && f.dropped == 2, "latest field, dropped increased by two");
    CHECK(f.end_tick == 2u * GW_FIELD_TICKS + 224u * GW_LINE_TICKS, "end_tick of third field");
    /* Same tick target: per-field stepping, one long run and prime-sized steps. */
    while (snapshot(a).tick < T_THREE_FIELDS) (void)run_field(a, T_THREE_FIELDS);
    (void)run(b, T_THREE_FIELDS);
    for (t = 7919; t < T_THREE_FIELDS; t += 7919) (void)run(c, t);
    (void)run(c, T_THREE_FIELDS);
    same(a, b); same(a, c); same(a, d);
    same_field(a, b); same_field(a, c); same_field(a, d);
    f = pull(a, &pixels);
    CHECK(f.dropped == 0, "stepping hosts observe no drops");
    gw_destroy(a); gw_destroy(b); gw_destroy(c); gw_destroy(d);
}

/* D-20: data-port writes queue in a 4-entry FIFO and land only at modeled slots.
 * A burst of 48 CRAM words during active display cannot finish at CPU speed
 * (24 move.l take about 4000 ticks at most); at one slot per 3420/18 ticks the
 * burst needs well over 6000. A marker store after the burst shows completion. */
static void fifo_checks(void)
{
    uint8_t rom[1024], marker[2];
    rom_emit e;
    gw_machine *m = machine();
    const uint32_t *pixels;
    gw_video_field f;
    unsigned i, y;
    rom_begin(&e, rom);
    emit_reg(&e, 1, 0x44); emit_reg(&e, 12, 0x81); emit_reg(&e, 15, 2); emit_reg(&e, 7, 1);
    emit_move_l(&e, 0xc0000000u, VDP_CTRL); /* CRAM write at address 0 */
    for (i = 0; i < 24; ++i) emit_move_l(&e, i == 0 ? 0x00000e2au : 0u, VDP_DATA); /* word 1 = 0x0e2a */
    emit_move_w(&e, 0x00a5, 0x00ff0000u);
    emit_bra_self(&e);
    CHECK(e.pos < 0x3fe, "ROM fits");
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load FIFO ROM");
    (void)run(m, 6000);
    CHECK(gw_peek_memory(m, 0xff0000, marker, 2) == GW_OK && marker[1] == 0, "burst is held by the FIFO slots");
    (void)run(m, 60000);
    CHECK(gw_peek_memory(m, 0xff0000, marker, 2) == GW_OK && marker[1] == 0xa5, "burst completes");
    (void)run_field(m, 3 * (uint64_t)GW_FIELD_TICKS);
    (void)run_field(m, 3 * (uint64_t)GW_FIELD_TICKS);
    f = pull(m, &pixels);
    CHECK(f.sequence == 1, "second field");
    for (y = 0; y < f.height; ++y)
        CHECK(((const uint32_t *)((const unsigned char *)pixels + (size_t)y * f.pitch_bytes))[0] == 0x00ae31ffu,
              "queued CRAM word reached the backdrop");
    gw_destroy(m);
}

int main(void)
{
    argument_checks();
    field_stop_checks();
    batching_checks();
    fifo_checks();
    puts("video_contract: PASS");
    return 0;
}
