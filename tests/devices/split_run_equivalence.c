/* SPDX-License-Identifier: MIT
 * Batch-independence property (HOST-02 core level, D-33): the same timestamped
 * pad schedule yields identical RAM, CPU snapshot and published field pixels at
 * every shared checkpoint however the host splits its run calls. The input ROM
 * is the original pad_echo image, whose backdrop mirrors both controller ports.
 *
 * Variants: one run-to-target call; per-field field-stop calls (the reference);
 * prime-sized (7919 tick) run-to-target chunks; single-instruction steps for the
 * first two fields. Checkpoints are the instruction-boundary ticks at which the
 * reference stops after each field. FNV-1a hashes only compare runs with each
 * other; the one authored oracle is the final port-0 byte, computed here from the
 * documented active-low protocol.
 */
#include "contract.h"
#ifdef GW_TEST_HOOKS
#include "state_digest.h"
#endif

#define FIELDS 20u
#define EVENTS 30u

typedef struct { uint64_t tick; uint32_t port, mask; } sched_event;
typedef struct {
    gw_diagnostic_record cpu;
    uint64_t ram_hash, pixel_hash;
#ifdef GW_TEST_HOOKS
    uint64_t state_digest;
#endif
} checkpoint;

static uint8_t rom_image[4096];
static size_t rom_size;
static sched_event schedule_[EVENTS];

static uint32_t lcg_state = 12345u;
static uint32_t lcg(void) { lcg_state = lcg_state * 1664525u + 1013904223u; return lcg_state >> 8; }

static void build_schedule(void)
{
    uint64_t tick = 5000;
    for (unsigned i = 0; i < EVENTS; ++i) {
        schedule_[i].tick = tick;
        schedule_[i].port = lcg() & 1u;
        schedule_[i].mask = lcg() & GW_BUTTON_MASK_PAD3;
        /* Every fifth event repeats the previous tick, exercising insertion order. */
        tick += (i % 5 == 4) ? 0 : 300000 + lcg() % 250000;
    }
}

static gw_machine *fresh(void)
{
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1,
                   {GW_DEVICE_PAD3, GW_DEVICE_PAD3}};
    CHECK(gw_create(&c, &m) == GW_OK, "create");
    CHECK(gw_load_rom(m, rom_image, rom_size) == GW_OK, "load pad_echo");
    return m;
}

/* Submit every event due before `horizon`; test schedules fit the bounded queue. */
static void feed(gw_machine *m, size_t *next, uint64_t horizon)
{
    while (*next < EVENTS && schedule_[*next].tick < horizon) {
        gw_event e = {sizeof(e), GW_API_VERSION, schedule_[*next].tick, GW_EVENT_PAD_STATE,
                      schedule_[*next].port, schedule_[*next].mask, 0};
        CHECK(gw_schedule_event(m, &e) == GW_OK, "just-in-time schedule");
        ++*next;
    }
}

static uint64_t fnv(uint64_t h, uint64_t v)
{
    h ^= v;
    return h * UINT64_C(1099511628211);
}

static checkpoint capture(gw_machine *m)
{
    checkpoint c;
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    uint8_t ram[GW_RAM_SIZE];
    uint64_t h = UINT64_C(1469598103934665603);
    c.cpu = snapshot(m);
#ifdef GW_TEST_HOOKS
    c.state_digest = gw_test_state_digest(m);
#endif
    CHECK(gw_peek_memory(m, 0xff0000, ram, sizeof(ram)) == GW_OK, "peek RAM");
    for (size_t i = 0; i < sizeof(ram); ++i) h = fnv(h, ram[i]);
    c.ram_hash = h;
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK, "pull field");
    h = UINT64_C(1469598103934665603);
    for (uint32_t y = 0; y < f.height; ++y) {
        const uint32_t *row = (const uint32_t *)((const unsigned char *)pixels + (size_t)y * f.pitch_bytes);
        for (uint32_t x = 0; x < f.width; ++x) h = fnv(h, row[x]);
    }
    c.pixel_hash = fnv(fnv(fnv(h, f.sequence), f.start_tick), f.width);
    return c;
}

static void expect_equal(const checkpoint *a, const checkpoint *b, const char *what)
{
    CHECK(memcmp(&a->cpu, &b->cpu, sizeof(a->cpu)) == 0, what);
    CHECK(a->ram_hash == b->ram_hash, what);
    CHECK(a->pixel_hash == b->pixel_hash, what);
#ifdef GW_TEST_HOOKS
    CHECK(a->state_digest == b->state_digest, "machine-state digest matches across split runs");
#endif
}

/* Advance `m` to exactly checkpoint tick `target` using calls of at most `chunk`
 * ticks (chunk == 1 steps one instruction at a time). */
static void advance_to(gw_machine *m, size_t *next, uint64_t target, uint64_t chunk)
{
    /* The full event schedule is queued identically for every run variant. */
    feed(m, next, UINT64_MAX);
    for (;;) {
        uint64_t now = snapshot(m).tick, goal;
        if (now >= target) break;
        goal = now + chunk > target ? target : now + chunk;
        run(m, goal);
    }
    CHECK(snapshot(m).tick == target, "variant landed on the reference checkpoint tick");
}

int main(int argc, char **argv)
{
    checkpoint ref[FIELDS];
    uint64_t ticks[FIELDS];
    size_t next;
    gw_machine *m;
    FILE *f;
    unsigned distinct = 0;
    CHECK(argc == 2, "usage: split_run_equivalence pad_echo.bin");
    f = fopen(argv[1], "rb");
    CHECK(f != NULL, "ROM open");
    rom_size = fread(rom_image, 1, sizeof(rom_image), f);
    CHECK(rom_size >= GW_MIN_ROM_SIZE && fclose(f) == 0, "ROM read");
    build_schedule();

    /* Reference: per-field field-stop calls with the full schedule queued. */
    m = fresh(); next = 0;
    feed(m, &next, UINT64_MAX);
    for (unsigned i = 0; i < FIELDS; ++i) {
        uint64_t target = snapshot(m).tick + 2 * (uint64_t)GW_FIELD_TICKS;
        CHECK(run_field(m, target).stop_reason == GW_STOP_FIELD_COMPLETE, "field-stop call ends at a field");
        ref[i] = capture(m);
        ticks[i] = ref[i].cpu.tick;
        if (i && ref[i].pixel_hash != ref[i - 1].pixel_hash) ++distinct;
    }
    CHECK(next == EVENTS, "whole schedule consumed");
    CHECK(distinct >= 8, "the schedule visibly changes the published fields");
    {
        uint8_t b;
        uint32_t last0 = 0;
        for (unsigned i = 0; i < EVENTS; ++i) if (!schedule_[i].port) last0 = schedule_[i].mask;
        CHECK(gw_peek_memory(m, 0xff0000, &b, 1) == GW_OK, "peek port 0");
        /* Authored oracle: TH-high active-low byte of the last port-0 mask. */
        CHECK(b == (0x40u | ((last0 & GW_BUTTON_C) ? 0u : 0x20u) | ((last0 & GW_BUTTON_B) ? 0u : 0x10u) |
                    ((last0 & GW_BUTTON_RIGHT) ? 0u : 0x08u) | ((last0 & GW_BUTTON_LEFT) ? 0u : 0x04u) |
                    ((last0 & GW_BUTTON_DOWN) ? 0u : 0x02u) | ((last0 & GW_BUTTON_UP) ? 0u : 0x01u)),
              "final port-0 byte follows the documented protocol");
    }
    gw_destroy(m);

    /* One run-to-target call with the whole schedule queued up front. */
    m = fresh(); next = 0;
    feed(m, &next, UINT64_MAX);
    CHECK(next == EVENTS && EVENTS <= GW_EVENT_CAPACITY, "whole schedule fits the queue");
    run(m, ticks[FIELDS - 1]);
    CHECK(snapshot(m).tick == ticks[FIELDS - 1], "single call lands on the final checkpoint");
    {
        checkpoint c = capture(m);
        expect_equal(&ref[FIELDS - 1], &c, "single run-to-target call matches the field-stop reference");
    }
    gw_destroy(m);

    /* Prime-sized run-to-target chunks, compared at every field checkpoint. */
    m = fresh(); next = 0;
    for (unsigned i = 0; i < FIELDS; ++i) {
        checkpoint c;
        advance_to(m, &next, ticks[i], 7919);
        c = capture(m);
        expect_equal(&ref[i], &c, "7919-tick chunks match the reference at each field");
    }
    gw_destroy(m);

    /* Single-instruction steps for the first two fields. */
    m = fresh(); next = 0;
    for (unsigned i = 0; i < 2; ++i) {
        checkpoint c;
        advance_to(m, &next, ticks[i], 1);
        c = capture(m);
        expect_equal(&ref[i], &c, "single-instruction steps match the reference");
    }
    gw_destroy(m);
    puts("split_run_equivalence: PASS");
    return 0;
}
