/* SPDX-License-Identifier: MIT
 * Host input to guest field: per-field stamping, record/replay, and the
 * property that presentation cadence never changes machine results.
 * usage: session_cadence PAD_ECHO_ROM
 */
#include "contract.h"
#include "input_log.h"
#include "rom_file.h"
#include "session.h"
#include <stdint.h>

#define FIELDS 60u

static const gw_config CONFIG = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
    GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}};

static uint8_t rom[GW_MAX_ROM_SIZE];
static size_t rom_size;

typedef struct outcome {
    uint64_t hash[FIELDS];
    uint64_t ram;
    uint64_t sequence[FIELDS];
} outcome;

static uint64_t fnv(uint64_t h, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= UINT64_C(1099511628211); }
    return h;
}

/* The same logical input per emulated field index, whatever the cadence. */
static uint32_t port0_mask(uint64_t field) { return (uint32_t)((field / 5) & 0xff); }
static uint32_t port1_mask(uint64_t field) { return (uint32_t)(((field / 7) * 3) & 0xff); }

static void field_hash(gw_session *s, outcome *out, uint64_t index)
{
    gw_video_field field;
    const uint32_t *pixels = NULL;
    uint64_t h = UINT64_C(14695981039346656037);
    CHECK(gw_session_field(s, &field, &pixels) == 0, "field published");
    for (uint32_t row = 0; row < field.height; ++row)
        h = fnv(h, (const uint8_t *)pixels + (size_t)row * field.pitch_bytes, (size_t)field.width * 4u);
    out->hash[index] = h;
    out->sequence[index] = field.sequence;
}

static void final_ram(gw_session *s, outcome *out)
{
    static uint8_t ram[GW_RAM_SIZE];
    CHECK(gw_peek_memory(s->machine, 0xff0000u, ram, sizeof(ram)) == GW_OK, "peek ram");
    out->ram = fnv(UINT64_C(14695981039346656037), ram, sizeof(ram));
}

/* One emulated field with live host input. */
static void live_field(gw_session *s, outcome *out, int reset_at_25)
{
    uint64_t index = s->fields;
    if (reset_at_25 && index == 25) CHECK(gw_session_reset(s) == 0, "reset");
    gw_session_set_input(s, 0, port0_mask(index));
    gw_session_set_input(s, 1, port1_mask(index));
    CHECK(gw_session_step_field(s) == 0, "step");
    field_hash(s, out, index);
}

/* Drives FIELDS fields as host frames of cadence[i] fields (0 = paused frame). */
static void drive(const unsigned *cadence, size_t count, int reset_at_25, gw_input_log *record, outcome *out)
{
    gw_session s;
    size_t frame = 0;
    CHECK(gw_session_open(&s, &CONFIG, rom, rom_size) == 0, "open");
    if (record) CHECK(gw_session_attach_log(&s, record, GW_SESSION_RECORD) == 0, "attach record");
    while (s.fields < FIELDS) {
        unsigned n = cadence[frame++ % count];
        if (n == 0) {
            gw_session_set_paused(&s, 1);
            CHECK(gw_session_step_field(&s) == GW_SESSION_PAUSED, "paused frame declines");
            gw_session_set_paused(&s, 0);
        }
        for (unsigned i = 0; i < n && s.fields < FIELDS; ++i) live_field(&s, out, reset_at_25);
    }
    CHECK(!s.log_overflow, "log did not overflow");
    final_ram(&s, out);
    gw_session_close(&s);
}

static void replay(gw_input_log *log, outcome *out)
{
    gw_session s;
    CHECK(gw_session_open(&s, &CONFIG, rom, rom_size) == 0, "open replay");
    CHECK(gw_session_attach_log(&s, log, GW_SESSION_REPLAY) == 0, "attach replay");
    /* Host input is ignored while replaying. */
    gw_session_set_input(&s, 0, 0xff);
    while (s.fields < FIELDS) {
        uint64_t index = s.fields;
        CHECK(gw_session_step_field(&s) == 0, "replay step stays within event capacity");
        field_hash(&s, out, index);
    }
    final_ram(&s, out);
    gw_session_close(&s);
}

static void same_outcome(const outcome *a, const outcome *b, const char *what)
{
    for (size_t i = 0; i < FIELDS; ++i) {
        if (a->hash[i] != b->hash[i] || a->sequence[i] != b->sequence[i]) {
            fprintf(stderr, "FAIL: %s differs at field %zu\n", what, i);
            exit(1);
        }
    }
    CHECK(a->ram == b->ram, what);
}

static void record_replay(void)
{
    static const unsigned one[] = {1};
    static outcome live, replayed;
    gw_input_log log;
    size_t changing = 0;
    CHECK(gw_input_log_init(&log) == 0, "log init");
    drive(one, 1, 0, &log, &live);
    CHECK(log.count > 0, "input was recorded");
    for (size_t i = 0; i < log.count; ++i) {
        CHECK(log.entries[i].kind == GW_LOG_PAD, "pad entry");
        CHECK(log.entries[i].tick % GW_FIELD_TICKS == 0 && log.entries[i].tick > 0, "stamped at a field start");
        if (i && log.entries[i].tick != log.entries[i - 1].tick) changing++;
    }
    CHECK(changing > 0, "stamps span several fields");
    replay(&log, &replayed);
    same_outcome(&live, &replayed, "replay matches record");
    /* The guest saw the input: the first and a later field must differ. */
    CHECK(live.hash[0] != live.hash[10], "input changes guest output");
    gw_input_log_free(&log);
}

static void cadence_independence(void)
{
    static const unsigned one[] = {1}, three[] = {3}, irregular[] = {1, 0, 2, 4, 0, 0, 1, 3};
    static outcome a, b, c, d, e;
    gw_input_log log_one, log_irregular;
    CHECK(gw_input_log_init(&log_one) == 0 && gw_input_log_init(&log_irregular) == 0, "log init");
    drive(one, 1, 0, NULL, &a);
    drive(three, 1, 0, NULL, &b);
    drive(irregular, 8, 0, NULL, &c);
    same_outcome(&a, &b, "1 vs 3 fields per frame");
    same_outcome(&a, &c, "1 vs irregular with pauses");

    /* A reset at emulated field 25 is recorded at the same tick under every cadence. */
    drive(one, 1, 1, &log_one, &d);
    drive(irregular, 8, 1, &log_irregular, &e);
    same_outcome(&d, &e, "reset at field 25 across cadences");
    CHECK(log_one.count == log_irregular.count, "same number of log entries");
    for (size_t i = 0; i < log_one.count; ++i)
        CHECK(log_one.entries[i].tick == log_irregular.entries[i].tick &&
              log_one.entries[i].kind == log_irregular.entries[i].kind &&
              log_one.entries[i].mask == log_irregular.entries[i].mask, "identical logs");
    {
        size_t resets = 0;
        static outcome replayed;
        for (size_t i = 0; i < log_one.count; ++i) resets += log_one.entries[i].kind == GW_LOG_RESET;
        CHECK(resets == 1, "one reset recorded");
        replay(&log_one, &replayed);
        same_outcome(&d, &replayed, "replay with reset matches");
    }
    gw_input_log_free(&log_one);
    gw_input_log_free(&log_irregular);
}

static void keys_and_ports(void)
{
    gw_session s;
    gw_config none_port = CONFIG;
    CHECK(gw_session_key_button(GW_KEY_UP) == GW_BUTTON_UP, "up");
    CHECK(gw_session_key_button(GW_KEY_DOWN) == GW_BUTTON_DOWN, "down");
    CHECK(gw_session_key_button(GW_KEY_LEFT) == GW_BUTTON_LEFT, "left");
    CHECK(gw_session_key_button(GW_KEY_RIGHT) == GW_BUTTON_RIGHT, "right");
    CHECK(gw_session_key_button(GW_KEY_Z) == GW_BUTTON_A, "Z is A");
    CHECK(gw_session_key_button(GW_KEY_X) == GW_BUTTON_B, "X is B");
    CHECK(gw_session_key_button(GW_KEY_C) == GW_BUTTON_C, "C is C");
    CHECK(gw_session_key_button(GW_KEY_ENTER) == GW_BUTTON_START, "Enter is Start");

    none_port.port_device[1] = GW_DEVICE_NONE;
    CHECK(gw_session_open(&s, &none_port, rom, rom_size) == 0, "open with port 2 absent");
    gw_session_set_input(&s, 1, 0xff);
    gw_session_set_input(&s, 2, 0xff); /* out of range is ignored */
    CHECK(gw_session_step_field(&s) == 0, "absent port does not fail the step");
    gw_session_close(&s);
}

int main(int argc, char **argv)
{
    const char *reason = NULL;
    CHECK(argc == 2, "usage: session_cadence ROM");
    CHECK(gw_read_rom_file(argv[1], rom, sizeof(rom), &rom_size, &reason) == 0, "read rom");
    record_replay();
    cadence_independence();
    keys_and_ports();
    puts("PASS: session_cadence");
    return 0;
}
