/* SPDX-License-Identifier: MIT
 * SDL-free session contract: field stepping, pause, reset, bounded ROM reads
 * and display sanitizing. The test ROM is authored here as machine words.
 */
#define _POSIX_C_SOURCE 200809L
#include "contract.h"
#include "rom_file.h"
#include "session.h"
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static const gw_config CONFIG = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
    GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}};

/* addq.l #1,d0 ; bra.s back to the addq: D0 counts completed loop passes. */
static void counter_rom(uint8_t *rom)
{
    rom_init(rom, 1024);
    rom[512] = 0x52; rom[513] = 0x80; /* addq.l #1,d0 */
    rom[514] = 0x60; rom[515] = 0xfc; /* bra.s -4 */
}

static uint32_t d0(const gw_session *s)
{
    gw_diagnostic_record d = {0};
    d.struct_size = sizeof(d); d.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(s->machine, &d) == GW_OK, "diagnostics");
    return d.d[0];
}

static uint64_t machine_tick(const gw_session *s)
{
    gw_diagnostic_record d = {0};
    d.struct_size = sizeof(d); d.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(s->machine, &d) == GW_OK, "diagnostics");
    return d.tick;
}

static void stepping_and_pause(void)
{
    uint8_t rom[1024];
    gw_session s, control;
    gw_video_field field;
    const uint32_t *pixels = NULL;
    uint64_t before;
    counter_rom(rom);
    CHECK(gw_session_open(&s, &CONFIG, rom, sizeof(rom)) == 0, "open");
    CHECK(gw_session_field(&s, &field, &pixels) == (int)GW_ERROR_EMPTY, "no field before first step");
    CHECK(gw_session_step_field(&s) == 0, "step 1");
    CHECK(s.fields == 1 && s.tick >= GW_FIELD_TICKS && s.tick < 2 * GW_FIELD_TICKS, "one field target per step");
    CHECK(gw_session_field(&s, &field, &pixels) == 0 && field.sequence == 0, "field 0 published");
    CHECK(gw_session_step_field(&s) == 0, "step 2");
    CHECK(s.tick >= 2 * GW_FIELD_TICKS && s.tick < 3 * GW_FIELD_TICKS, "second target");
    CHECK(gw_session_field(&s, &field, &pixels) == 0 && field.sequence == 1, "field 1 published");

    gw_session_set_paused(&s, 1);
    before = machine_tick(&s);
    CHECK(gw_session_step_field(&s) == GW_SESSION_PAUSED, "paused step declined");
    CHECK(machine_tick(&s) == before && s.fields == 2, "paused session did not run the machine");
    gw_session_set_paused(&s, 0);
    CHECK(gw_session_step_field(&s) == 0 && s.fields == 3, "resumed step runs");

    /* Same ROM stepped without pausing reaches the same machine state. */
    CHECK(gw_session_open(&control, &CONFIG, rom, sizeof(rom)) == 0, "open control");
    for (int i = 0; i < 3; ++i) CHECK(gw_session_step_field(&control) == 0, "control step");
    CHECK(d0(&control) == d0(&s) && machine_tick(&control) == machine_tick(&s), "pause is not observable by the guest");
    gw_session_close(&control);
    gw_session_close(&s);
    CHECK(s.machine == NULL, "close clears the machine");
}

static void reset_behavior(void)
{
    uint8_t rom[1024];
    gw_session s, control;
    gw_video_field field;
    const uint32_t *pixels = NULL;
    uint32_t after_one, after_two, control_two;
    counter_rom(rom);
    CHECK(gw_session_open(&s, &CONFIG, rom, sizeof(rom)) == 0, "open");
    CHECK(gw_session_open(&control, &CONFIG, rom, sizeof(rom)) == 0, "open control");
    CHECK(gw_session_step_field(&s) == 0 && gw_session_step_field(&control) == 0, "first fields");
    after_one = d0(&s);
    CHECK(after_one > 1000, "guest counted during the first field");
    CHECK(gw_session_reset(&s) == 0 && s.resets == 1, "reset request accepted");
    CHECK(gw_session_step_field(&s) == 0 && gw_session_step_field(&control) == 0, "second fields");
    after_two = d0(&s);
    control_two = d0(&control);
    CHECK(control_two > after_one + after_one / 2, "control keeps counting");
    CHECK(after_two < after_one + after_one / 2, "reset zeroed the guest counter at the current tick");
    CHECK(gw_session_field(&s, &field, &pixels) == 0 && field.sequence == 1, "next field still publishes after reset");
    gw_session_close(&control);
    gw_session_close(&s);
}

static void invalid_open(void)
{
    uint8_t rom[1024];
    gw_session s;
    counter_rom(rom);
    rom[7] = 0x01; /* odd reset PC */
    CHECK(gw_session_open(&s, &CONFIG, rom, sizeof(rom)) == (int)GW_ERROR_ROM, "odd reset PC rejected");
    CHECK(s.machine == NULL, "failed open holds no machine");
}

static void write_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    static const uint8_t zero[4096];
    CHECK(f != NULL, "create temp file");
    for (size_t done = 0; done < size;) {
        size_t n = size - done < sizeof(zero) ? size - done : sizeof(zero);
        CHECK(fwrite(zero, 1, n, f) == n, "write temp file");
        done += n;
    }
    CHECK(fclose(f) == 0, "close temp file");
}

static void rom_files(void)
{
    static uint8_t buffer[GW_MAX_ROM_SIZE];
    const char *dir = "session_contract_files"; /* Under the ctest working directory. */
    char path[128], out[16];
    const char *reason = NULL;
    size_t size = 0;
    CHECK(mkdir(dir, 0700) == 0 || errno == EEXIST, "temp dir");

    snprintf(path, sizeof(path), "%s/ok.bin", dir);
    write_file(path, 1024);
    CHECK(gw_read_rom_file(path, buffer, sizeof(buffer), &size, &reason) == 0 && size == 1024, "regular file read");

    snprintf(path, sizeof(path), "%s/absent.bin", dir);
    CHECK(gw_read_rom_file(path, buffer, sizeof(buffer), &size, &reason) != 0 && !strcmp(reason, "missing"), "missing");

    CHECK(gw_read_rom_file(dir, buffer, sizeof(buffer), &size, &reason) != 0 && !strcmp(reason, "not-regular-file"),
        "directory");

    snprintf(path, sizeof(path), "%s/big.bin", dir);
    write_file(path, (size_t)GW_MAX_ROM_SIZE + 2);
    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(gw_read_rom_file(path, buffer, sizeof(buffer), &size, &reason) != 0 && !strcmp(reason, "too-large"), "too large");
    CHECK(buffer[0] == 0xa5 && buffer[sizeof(buffer) - 1] == 0xa5, "oversized file was not read into the buffer");
    CHECK(remove(path) == 0, "remove big");

    snprintf(path, sizeof(path), "%s/odd.bin", dir);
    write_file(path, 1025);
    CHECK(gw_read_rom_file(path, buffer, sizeof(buffer), &size, &reason) != 0 && !strcmp(reason, "odd-size"), "odd size");
    CHECK(remove(path) == 0, "remove odd");
    snprintf(path, sizeof(path), "%s/ok.bin", dir);
    CHECK(remove(path) == 0 && rmdir(dir) == 0, "cleanup");

    gw_sanitize_display("a\x1b[2J\x07z\xc3\xa9", out, sizeof(out));
    CHECK(!strcmp(out, "a?[2J?z??"), "control, escape and non-ASCII bytes replaced");
    gw_sanitize_display("some/dir/name.bin", out, sizeof(out));
    CHECK(!strcmp(out, "name.bin"), "directories are dropped");
    gw_sanitize_display("0123456789abcdefghij", out, 8);
    CHECK(!strcmp(out, "0123456"), "output truncated and terminated");
}

/* addq.w #1,(0xFF0000).l ; mulu d1,d0 (unsupported: sticky stop). RAM word counts boots. */
static void stop_rom(uint8_t *rom)
{
    rom_init(rom, 1024);
    rom[512] = 0x52; rom[513] = 0x79; rom[514] = 0x00; rom[515] = 0xff; rom[516] = 0x00; rom[517] = 0x00;
    rom[518] = 0xc0; rom[519] = 0xc1;
}

static uint16_t boot_count(const gw_session *s)
{
    uint8_t word[2];
    CHECK(gw_peek_memory(s->machine, 0xff0000u, word, 2) == GW_OK, "peek counter");
    return (uint16_t)(word[0] << 8 | word[1]);
}

/* A reset requested after an unsupported stop replays identically (review CR-02). */
static void reset_after_unsupported_stop(void)
{
    uint8_t rom[1024];
    gw_session live, replayed;
    gw_input_log log;
    CHECK(gw_input_log_init(&log) == 0, "log init");
    stop_rom(rom);
    CHECK(gw_session_open(&live, &CONFIG, rom, sizeof(rom)) == 0, "open live");
    CHECK(gw_session_attach_log(&live, &log, GW_SESSION_RECORD) == 0, "record");
    gw_session_set_input(&live, 0, 0x41); /* a pad entry at the stopping step's target */
    CHECK(gw_session_step_field(&live) == 0, "step to the stop");
    CHECK(gw_session_unsupported_stop(&live) && boot_count(&live) == 1, "stopped after one boot");
    CHECK(live.tick < GW_FIELD_TICKS, "stop lands before the step target");
    CHECK(gw_session_reset(&live) == 0, "reset after stop");
    CHECK(!gw_session_unsupported_stop(&live), "reset clears the stop");
    for (int i = 0; i < 3; ++i) CHECK(gw_session_step_field(&live) == 0, "step after reset");
    CHECK(gw_session_unsupported_stop(&live) && boot_count(&live) == 2, "second boot stopped again");
    CHECK(gw_session_reset(&live) == 0 && gw_session_step_field(&live) == 0, "second reset and step");
    CHECK(!live.log_overflow && log.count == 3, "pad and two resets recorded");

    CHECK(gw_session_open(&replayed, &CONFIG, rom, sizeof(rom)) == 0, "open replay");
    CHECK(gw_session_attach_log(&replayed, &log, GW_SESSION_REPLAY) == 0, "replay");
    for (int i = 0; i < 5; ++i) CHECK(gw_session_step_field(&replayed) == 0, "replay step");
    CHECK(replayed.fields == live.fields && replayed.resets == live.resets, "replay counters");
    CHECK(boot_count(&replayed) == boot_count(&live) && boot_count(&live) == 3, "replay reached the same boot count");
    CHECK(replayed.tick == live.tick && replayed.stop_reason == live.stop_reason, "replay stop state matches");
    gw_session_close(&live);
    gw_session_close(&replayed);
    gw_input_log_free(&log);
}

int main(void)
{
    reset_after_unsupported_stop();
    stepping_and_pause();
    reset_behavior();
    invalid_open();
    rom_files();
    puts("PASS: session_contract");
    return 0;
}
