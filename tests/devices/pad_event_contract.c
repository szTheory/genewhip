/* SPDX-License-Identifier: MIT
 * Pad event contract (D-33, D-34). Runs the original pad_echo ROM, whose RAM and
 * backdrop colour mirror the two controller ports. Expected bytes are computed
 * here from the documented active-low three-button protocol (plutiedev
 * controllers); pixels use the documented Genewhip CRAM table. Hashes of
 * Genewhip output compare runs with each other and are never an oracle.
 */
#include "devrom.h"

#define FRAME (3 * (uint64_t)GW_FIELD_TICKS)

/* Documented Genewhip convention (docs/video.md): channel v -> level[2 * v]. */
static const unsigned level[15] = {0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255};

static uint8_t rom_image[4096];
static size_t rom_size;

static void load_image(const char *path)
{
    FILE *f = fopen(path, "rb");
    CHECK(f != NULL, "ROM open");
    rom_size = fread(rom_image, 1, sizeof(rom_image), f);
    CHECK(rom_size >= GW_MIN_ROM_SIZE && fclose(f) == 0, "ROM read");
}

static gw_machine *pad_machine(unsigned dev0, unsigned dev1)
{
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1, {dev0, dev1}};
    CHECK(gw_create(&c, &m) == GW_OK, "create");
    CHECK(gw_load_rom(m, rom_image, rom_size) == GW_OK, "load pad_echo");
    return m;
}
static gw_machine *both_pads(void) { return pad_machine(GW_DEVICE_PAD3, GW_DEVICE_PAD3); }

static gw_event pad_event(uint64_t tick, uint32_t port, uint32_t mask)
{
    gw_event e = {sizeof(e), GW_API_VERSION, tick, GW_EVENT_PAD_STATE, port, mask, 0};
    return e;
}
static void schedule(gw_machine *m, uint64_t tick, uint32_t port, uint32_t mask)
{
    gw_event e = pad_event(tick, port, mask);
    CHECK(gw_schedule_event(m, &e) == GW_OK, "schedule pad");
}

/* Documented byte with TH driven high: bit 7 latch (0), bit 6 TH, active-low buttons. */
static uint32_t th_high_byte(uint32_t mask)
{
    uint32_t b = 0x40u;
    if (!(mask & GW_BUTTON_C)) b |= 0x20u;
    if (!(mask & GW_BUTTON_B)) b |= 0x10u;
    if (!(mask & GW_BUTTON_RIGHT)) b |= 0x08u;
    if (!(mask & GW_BUTTON_LEFT)) b |= 0x04u;
    if (!(mask & GW_BUTTON_DOWN)) b |= 0x02u;
    if (!(mask & GW_BUTTON_UP)) b |= 0x01u;
    return b;
}

static uint32_t expected_pixel(uint32_t word)
{
    return (level[2 * ((word >> 1) & 7)] << 16) | (level[2 * ((word >> 5) & 7)] << 8) |
           level[2 * ((word >> 9) & 7)];
}

static uint8_t ram_byte(gw_machine *m, uint32_t offset)
{
    uint8_t b;
    CHECK(gw_peek_memory(m, 0xff0000u + offset, &b, 1) == GW_OK, "peek RAM");
    return b;
}

static uint32_t top_left(gw_machine *m, uint64_t *sequence)
{
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK, "pull field");
    if (sequence) *sequence = f.sequence;
    return pixels[0];
}

static void run_two_fields(gw_machine *m)
{
    CHECK(run_field(m, FRAME).stop_reason == GW_STOP_FIELD_COMPLETE, "first field");
    CHECK(run_field(m, FRAME).stop_reason == GW_STOP_FIELD_COMPLETE, "second field");
}

/* Tracer: one scheduled button change reaches guest RAM and the published field. */
static void tracer(void)
{
    const uint32_t mask = GW_BUTTON_C | GW_BUTTON_UP;
    gw_machine *with = both_pads(), *without = both_pads();
    uint64_t sequence = 0;
    uint32_t pixel, word;
    schedule(with, 1000, 0, mask);
    run_two_fields(with);
    run_two_fields(without);
    CHECK(ram_byte(with, 0) == th_high_byte(mask), "port 0 byte follows the documented protocol");
    CHECK(ram_byte(with, 1) == th_high_byte(0), "port 1 unaffected");
    CHECK(ram_byte(without, 0) == th_high_byte(0), "no event: nothing pressed");
    word = ((uint32_t)th_high_byte(0) << 8) | th_high_byte(mask);
    pixel = top_left(with, &sequence);
    CHECK(sequence == 1, "second field");
    CHECK(pixel == expected_pixel(word), "backdrop shows the pressed state");
    CHECK(pixel != top_left(without, NULL), "backdrop differs from the run without the event");
    gw_destroy(with); gw_destroy(without);
}


static uint64_t fnv_field(gw_machine *m)
{
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    uint64_t h = UINT64_C(1469598103934665603);
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK, "pull field for hash");
    for (uint32_t y = 0; y < f.height; ++y) {
        const uint32_t *row = (const uint32_t *)((const unsigned char *)pixels + (size_t)y * f.pitch_bytes);
        for (uint32_t x = 0; x < f.width; ++x) { h ^= row[x]; h *= UINT64_C(1099511628211); }
    }
    return h ^ f.sequence;
}

static gw_status try_event(gw_machine *m, uint32_t struct_size, uint32_t version, uint64_t tick,
                           uint32_t type, uint32_t port, uint32_t mask, uint32_t reserved)
{
    gw_event e = {struct_size, version, tick, type, port, mask, reserved};
    return gw_schedule_event(m, &e);
}

static void validation(void)
{
    gw_machine *m = pad_machine(GW_DEVICE_PAD3, GW_DEVICE_NONE), *unloaded = NULL;
    gw_diagnostic_record before = snapshot(m), after;
    const gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, 0}};
    const uint32_t S = sizeof(gw_event), V = GW_API_VERSION, P = GW_EVENT_PAD_STATE;
    CHECK(gw_create(&c, &unloaded) == GW_OK, "create unloaded");
    CHECK(try_event(unloaded, S, V, 200, P, 0, 1, 0) == GW_ERROR_NOT_LOADED, "unloaded machine");
    gw_destroy(unloaded);
    CHECK(gw_schedule_event(m, NULL) == GW_ERROR_ARGUMENT, "NULL event");
    CHECK(try_event(m, S - 1, V, 200, P, 0, 1, 0) == GW_ERROR_VERSION, "wrong struct_size");
    CHECK(try_event(m, S, V + 1, 200, P, 0, 1, 0) == GW_ERROR_VERSION, "wrong version");
    CHECK(try_event(m, S, V, 200, P, 2, 1, 0) == GW_ERROR_ARGUMENT, "port 2");
    CHECK(try_event(m, S, V, 200, P, 0xffffffffu, 1, 0) == GW_ERROR_ARGUMENT, "huge port");
    CHECK(try_event(m, S, V, 200, P, 0, 0x100, 0) == GW_ERROR_ARGUMENT, "mask bit 8");
    CHECK(try_event(m, S, V, 200, P, 0, 0x80000000u, 0) == GW_ERROR_ARGUMENT, "mask bit 31");
    CHECK(try_event(m, S, V, 200, P, 0, 1, 1) == GW_ERROR_ARGUMENT, "reserved set");
    CHECK(try_event(m, S, V, 200, GW_EVENT_CONSOLE_RESET, 0, 1, 0) == GW_ERROR_ARGUMENT, "reset with mask");
    CHECK(try_event(m, S, V, 200, GW_EVENT_CONSOLE_RESET, 1, 0, 0) == GW_ERROR_ARGUMENT, "reset with port");
    CHECK(try_event(m, S, V, 200, 99, 0, 0, 0) == GW_ERROR_UNSUPPORTED, "unknown event type");
    CHECK(try_event(m, S, V, 200, P, 1, 1, 0) == GW_ERROR_UNSUPPORTED, "port configured NONE");
    CHECK(try_event(m, S, V, GW_MAX_TARGET_TICK + 1, P, 0, 1, 0) == GW_ERROR_TIME, "tick beyond the target limit");
    after = snapshot(m);
    CHECK(memcmp(&before, &after, sizeof(before)) == 0, "rejections leave the machine unchanged");
    /* Late events. The boundary tick itself is accepted. */
    run(m, 5000);
    before = snapshot(m);
    CHECK(try_event(m, S, V, before.tick - 1, P, 0, 1, 0) == GW_ERROR_TIME, "tick below current");
    CHECK(try_event(m, S, V, before.tick, P, 0, 1, 0) == GW_OK, "tick equal to current");
    after = snapshot(m);
    CHECK(memcmp(&before, &after, sizeof(before)) == 0, "scheduling does not run the machine");
    gw_destroy(m);
}

static void capacity(void)
{
    gw_machine *m = both_pads();
    const uint32_t S = sizeof(gw_event), V = GW_API_VERSION, P = GW_EVENT_PAD_STATE;
    gw_diagnostic_record before = snapshot(m), after;
    uint32_t last0 = 0, last1 = 0;
    /* Rejected submissions must not consume queue slots: all 64 still fit. */
    CHECK(try_event(m, S, V, 200, P, 2, 1, 0) == GW_ERROR_ARGUMENT, "reject one");
    CHECK(try_event(m, S, V, 200, P, 0, 0x100, 0) == GW_ERROR_ARGUMENT, "reject two");
    CHECK(try_event(m, S, V, 0, P, 0, 1, 0) == GW_ERROR_TIME, "reject three");
    for (uint32_t i = 0; i < GW_EVENT_CAPACITY; ++i) {
        uint32_t port = i & 1u, mask = (i * 37u + 5u) & 0xffu;
        schedule(m, 20000 + 100u * i, port, mask);
        if (port) last1 = mask; else last0 = mask;
    }
    CHECK(try_event(m, S, V, 99999, P, 0, 1, 0) == GW_ERROR_CAPACITY, "65th event");
    CHECK(try_event(m, S, V, 200, P, 0, 1, 0) == GW_ERROR_CAPACITY, "65th event, earlier tick");
    after = snapshot(m);
    CHECK(memcmp(&before, &after, sizeof(before)) == 0, "capacity rejection leaves the machine");
    run(m, 20000 + 100u * GW_EVENT_CAPACITY + 20000);
    CHECK(ram_byte(m, 0) == th_high_byte(last0) && ram_byte(m, 1) == th_high_byte(last1),
          "only the 64 accepted events applied, in tick order");
    schedule(m, snapshot(m).tick, 0, 0); /* Applied events freed their slots. */
    gw_destroy(m);
}

static void ordering_and_horizon(void)
{
    gw_machine *m = both_pads();
    const uint64_t target = 3 * (uint64_t)GW_FIELD_TICKS + 100000;
    /* Equal ticks keep insertion order: the later submission wins. */
    schedule(m, 4000, 0, GW_BUTTON_A);
    schedule(m, 4000, 0, GW_BUTTON_START);
    schedule(m, 3000, 0, GW_BUTTON_C); /* Earlier tick submitted last still sorts first. */
    run(m, 6000);
    /* TH is high in the echo loop, so only C/B/R/L/D/U show; neither A nor Start does. */
    CHECK(ram_byte(m, 0) == th_high_byte(0), "last equal-tick mask replaced the earlier C");
    gw_destroy(m);
    m = both_pads();
    schedule(m, 4000, 0, GW_BUTTON_START);
    schedule(m, 4000, 0, GW_BUTTON_B);
    schedule(m, 3000, 0, GW_BUTTON_C);
    run(m, 6000);
    CHECK(ram_byte(m, 0) == th_high_byte(GW_BUTTON_B), "insertion order picks B");
    gw_destroy(m);
    /* An event a field before the target is seen; one a field after is not. */
    m = both_pads();
    schedule(m, target - GW_FIELD_TICKS, 0, GW_BUTTON_C);
    schedule(m, target + GW_FIELD_TICKS, 1, GW_BUTTON_B);
    run(m, target);
    CHECK(ram_byte(m, 0) == th_high_byte(GW_BUTTON_C), "event before the target observed");
    CHECK(ram_byte(m, 1) == th_high_byte(0), "event after the target not observed");
    run(m, target + 2 * (uint64_t)GW_FIELD_TICKS);
    CHECK(ram_byte(m, 1) == th_high_byte(GW_BUTTON_B), "later event observed once the run crosses it");
    gw_destroy(m);
}

/* Hand-assembled probe: reads control then data of port 0 before and after
 * configuring them, so latch state at (re)start is visible in work RAM. */
static void latch_probe_rom(uint8_t *rom)
{
    rom_emit e;
    rom_begin(&e, rom);
    emit16(&e, 0x13f9); emit32(&e, 0x00a10009); emit32(&e, 0x00ff0010); /* move.b ctrl0,0xFF0010 */
    emit16(&e, 0x13fc); emit16(&e, 0x0040); emit32(&e, 0x00a10009);     /* move.b #0x40,ctrl0 */
    emit16(&e, 0x13f9); emit32(&e, 0x00a10003); emit32(&e, 0x00ff0011); /* move.b data0,0xFF0011 */
    emit16(&e, 0x13fc); emit16(&e, 0x0040); emit32(&e, 0x00a10003);     /* move.b #0x40,data0 */
    emit_bra_self(&e);
}

static void reset_policy(void)
{
    uint8_t probe[1024];
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, 0}};
    /* Latches clear on console reset while held buttons stay. */
    latch_probe_rom(probe);
    CHECK(gw_create(&c, &m) == GW_OK, "create probe");
    CHECK(gw_load_rom(m, probe, sizeof(probe)) == GW_OK, "load probe");
    schedule(m, 112, 0, GW_BUTTON_DOWN | GW_BUTTON_A);
    run(m, 4000);
    CHECK(ram_byte(m, 0x10) == 0x00, "control latch starts clear");
    /* TH is an output driven low (data latch clear): Start,A,0,0,Down,Up row with A and Down pressed = 0b100001. */
    CHECK(ram_byte(m, 0x11) == 0x21, "cold start: data latch clear, TH low row (Start high, A low, 0, 0, Down low, Up high)");
    {
        uint8_t again[2];
        run(m, 8000);
        /* Overwrite the observations by restarting the probe; latches are now 0x40. */
        CHECK(gw_console_reset(m) == GW_OK, "console reset");
        run(m, snapshot(m).tick + 4000);
        CHECK(gw_peek_memory(m, 0xff0010, again, 2) == GW_OK, "peek probe");
        CHECK(again[0] == 0x00, "console reset cleared the control latch");
        CHECK(again[1] == 0x21, "console reset cleared the data latch and kept the held buttons");
    }
    gw_destroy(m);

    /* Queued events survive a console reset. */
    m = both_pads();
    schedule(m, 1000, 0, GW_BUTTON_C);
    schedule(m, 3 * (uint64_t)GW_FIELD_TICKS, 0, GW_BUTTON_B);
    run(m, 2 * (uint64_t)GW_FIELD_TICKS);
    CHECK(ram_byte(m, 0) == th_high_byte(GW_BUTTON_C), "C held before reset");
    CHECK(gw_console_reset(m) == GW_OK, "console reset");
    run(m, snapshot(m).tick + 20000);
    CHECK(ram_byte(m, 0) == th_high_byte(GW_BUTTON_C), "held C survives console reset");
    run(m, 4 * (uint64_t)GW_FIELD_TICKS);
    CHECK(ram_byte(m, 0) == th_high_byte(GW_BUTTON_B), "queued B survives console reset and applies");
    /* Cold init clears held buttons and the queue. */
    schedule(m, snapshot(m).tick + 100000, 1, GW_BUTTON_C);
    CHECK(gw_cold_init(m) == GW_OK, "cold init");
    run(m, 3 * (uint64_t)GW_FIELD_TICKS);
    CHECK(ram_byte(m, 0) == th_high_byte(0) && ram_byte(m, 1) == th_high_byte(0),
          "cold init cleared held buttons and queued events");
    gw_destroy(m);
}

static const struct { uint64_t tick; uint32_t port, mask; } sched_a[] = {
    {1000, 0, GW_BUTTON_C | GW_BUTTON_UP}, {40000, 1, GW_BUTTON_B}, {900000, 0, GW_BUTTON_LEFT},
    {1300000, 1, GW_BUTTON_DOWN | GW_BUTTON_RIGHT}, {2000000, 0, 0}};
static const struct { uint64_t tick; uint32_t port, mask; } sched_b[] = {
    {2000, 1, GW_BUTTON_C}, {50000, 0, GW_BUTTON_B | GW_BUTTON_LEFT}, {950000, 1, GW_BUTTON_UP},
    {1400000, 0, GW_BUTTON_RIGHT}, {2100000, 1, 0}};
#define N_SCHED (sizeof(sched_a) / sizeof(sched_a[0]))
#define TARGET_END (3 * (uint64_t)GW_FIELD_TICKS)

static gw_machine *scheduled(int which, int duplicate)
{
    gw_machine *m = both_pads();
    for (size_t i = 0; i < N_SCHED; ++i) {
        uint64_t t = which ? sched_b[i].tick : sched_a[i].tick;
        uint32_t port = which ? sched_b[i].port : sched_a[i].port;
        uint32_t mask = which ? sched_b[i].mask : sched_a[i].mask;
        schedule(m, t, port, mask);
        if (duplicate && i % 2 == 0) schedule(m, t, port, mask);
    }
    return m;
}

static void idempotent_and_concurrent(void)
{
    gw_machine *solo_a = scheduled(0, 0), *solo_b = scheduled(1, 0), *dup = scheduled(0, 1);
    gw_machine *replay = scheduled(0, 0), *ia = scheduled(0, 0), *ib = scheduled(1, 0);
    uint64_t t;
    run(solo_a, TARGET_END); run(solo_b, TARGET_END); run(dup, TARGET_END); run(replay, TARGET_END);
    same(solo_a, replay);
    CHECK(fnv_field(solo_a) == fnv_field(replay), "replaying the same schedule reproduces the field");
    same(solo_a, dup);
    CHECK(fnv_field(solo_a) == fnv_field(dup), "duplicate identical events equal a single event");
    CHECK(fnv_field(solo_a) != fnv_field(solo_b), "different schedules differ");
    /* Interleave two live instances call by call, in prime-sized steps. */
    for (t = 0; t < TARGET_END;) {
        t = t + 7919 > TARGET_END ? TARGET_END : t + 7919;
        if (t > snapshot(ia).tick) run(ia, t);
        if (t > snapshot(ib).tick) run(ib, t);
    }
    CHECK(snapshot(ia).tick == snapshot(solo_a).tick, "interleaved a lands on the same tick");
    same(ia, solo_a);
    CHECK(fnv_field(ia) == fnv_field(solo_a), "interleaved a matches its solo field");
    same(ib, solo_b);
    CHECK(fnv_field(ib) == fnv_field(solo_b), "interleaved b matches its solo field");
    gw_destroy(solo_a); gw_destroy(solo_b); gw_destroy(dup); gw_destroy(replay);
    gw_destroy(ia); gw_destroy(ib);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2, "usage: pad_event_contract pad_echo.bin");
    load_image(argv[1]);
    tracer();
    validation();
    capacity();
    ordering_and_horizon();
    reset_policy();
    idempotent_and_concurrent();
    puts("pad_event_contract: PASS");
    return 0;
}
