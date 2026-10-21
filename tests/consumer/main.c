/* SPDX-License-Identifier: MIT
 * Independent oracle: constants below follow the authored guest source, not
 * emulator output. This program only includes/links the installed public SDK.
 */
#include <genewhip/genewhip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef GW_TEST_HOOKS
/* Private instrumentation seam, deliberately absent from installed headers. */
extern uint64_t gw_test_allocation_count(const gw_machine *machine);
#endif

#define CHECK(condition, name) do { if (!(condition)) { \
    fprintf(stderr, "FAIL: %s\n", name); exit(1); } } while (0)

static gw_diagnostic_record snapshot(gw_machine *m)
{
    gw_diagnostic_record d = {0};
    d.struct_size = sizeof(d);
    d.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(m, &d) == GW_OK, "snapshot");
    return d;
}

static gw_run_result run(gw_machine *m, uint64_t tick)
{
    gw_run_result result = {0};
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    /* Phase 1 amendment (02-01 option-d): zero flags -> explicit run-to-target request. */
    result.flags = GW_RUN_CONTINUE_PAST_FIELD;
    CHECK(gw_run_until(m, tick, &result) == GW_OK, "run request");
    return result;
}

static void put16(uint8_t *rom, size_t *pos, uint32_t v)
{
    rom[(*pos)++] = (uint8_t)(v >> 8);
    rom[(*pos)++] = (uint8_t)v;
}

/* move.w #imm,(abs).l */
static void move_w_abs(uint8_t *rom, size_t *pos, uint32_t imm, uint32_t address)
{
    put16(rom, pos, 0x33fc); put16(rom, pos, imm);
    put16(rom, pos, address >> 16); put16(rom, pos, address & 0xffffu);
}

/* Installed-SDK video check: an authored ROM programs the VDP; the field is
 * pulled through the public query and compared with the documented table. */
static void field_contract(void)
{
    /* Genewhip convention (docs/video.md): channel v -> level[2 * v]. */
    static const unsigned level[15] = {0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255};
    const uint16_t cram_word = 0x0E2A;
    const uint32_t expected = ((uint32_t)level[2 * ((cram_word >> 1) & 7)] << 16) |
                              ((uint32_t)level[2 * ((cram_word >> 5) & 7)] << 8) |
                              (uint32_t)level[2 * ((cram_word >> 9) & 7)];
    uint8_t rom[1024] = {0};
    size_t pos = 0x200;
    gw_config config = {0};
    gw_machine *m = NULL;
    gw_run_result r = {0};
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    unsigned char first[4];
    unsigned fields = 0, probe = 1;

    rom[0] = 0x00; rom[1] = 0xff; rom[2] = 0xff; rom[3] = 0x00; /* SSP 0xffff00 */
    rom[6] = 0x02; rom[7] = 0x00;                                /* PC 0x200 */
    move_w_abs(rom, &pos, 0x8144, 0xc00004); /* reg 1 */
    move_w_abs(rom, &pos, 0x8c81, 0xc00004); /* reg 12: H40 */
    move_w_abs(rom, &pos, 0x8f02, 0xc00004); /* reg 15: auto-increment 2 */
    move_w_abs(rom, &pos, 0x8701, 0xc00004); /* reg 7: backdrop index 1 */
    put16(rom, &pos, 0x23fc); put16(rom, &pos, 0xc002); put16(rom, &pos, 0x0000);
    put16(rom, &pos, 0x00c0); put16(rom, &pos, 0x0004); /* move.l #0xc0020000,(0xc00004).l: CRAM write at 2 */
    move_w_abs(rom, &pos, cram_word, 0xc00000);
    put16(rom, &pos, 0x60fe); /* bra self */

    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    CHECK(gw_create(&config, &m) == GW_OK, "field create");
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "field load");
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_EMPTY && pixels == NULL,
          "no field on a freshly loaded machine");
    r.struct_size = sizeof(r); r.version = GW_API_VERSION;
    while (fields < 2) {
        r.flags = 0; /* D-27 default field-stop request */
        CHECK(gw_run_until(m, 3 * (uint64_t)GW_FIELD_TICKS, &r) == GW_OK, "field run");
        CHECK(r.stop_reason == GW_STOP_FIELD_COMPLETE, "zero-flag call stops at field end");
        ++fields;
    }
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK && pixels != NULL, "pull field");
    CHECK(f.pixel_format == GW_PIXEL_XRGB8888, "pixel format");
    CHECK(f.width == 320 && f.height == 224, "field geometry");
    CHECK(f.pitch_bytes >= 1280, "pitch holds a row");
    CHECK(f.sequence == 1, "field sequence");
    CHECK(pixels[0] == expected, "first pixel from authored CRAM word");
    memcpy(first, pixels, sizeof(first));
    if (*(const unsigned char *)&probe == 1) { /* little-endian: B, G, R, 0 */
        CHECK(first[0] == (expected & 255) && first[1] == ((expected >> 8) & 255) &&
              first[2] == ((expected >> 16) & 255) && first[3] == 0, "XRGB8888 bytes, little-endian");
    } else { /* big-endian: 0, R, G, B */
        CHECK(first[0] == 0 && first[1] == ((expected >> 16) & 255) &&
              first[2] == ((expected >> 8) & 255) && first[3] == (expected & 255), "XRGB8888 bytes, big-endian");
    }
    gw_destroy(m);
}

static uint64_t expected_audio_frames(uint64_t tick, uint32_t rate)
{
    uint64_t whole = tick / GW_MASTER_HZ;
    uint64_t remainder = tick % GW_MASTER_HZ;
    return whole * rate + (remainder * rate) / GW_MASTER_HZ;
}

static void audio_contract(const uint8_t *rom, size_t rom_size)
{
    gw_config config = {0};
    gw_machine *m = NULL;
    gw_run_result run_result = {0};
    gw_audio_read_result first = {0}, second = {0};
    gw_audio_write writes[16];
    int16_t pcm[4096];
    size_t write_count = 0;
    uint64_t dropped = 0;
    uint32_t first_capacity, second_capacity;
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = 48000;
    CHECK(gw_api_version() == 4, "installed API version 4");
    CHECK(gw_create(&config, &m) == GW_OK, "audio consumer create");
    CHECK(gw_load_rom(m, rom, rom_size) == GW_OK, "audio consumer load");
    CHECK(gw_configure_audio_trace(m, 16) == GW_OK, "configure chip-write trace");
    run_result.struct_size = sizeof(run_result);
    run_result.version = GW_API_VERSION;
    run_result.flags = GW_RUN_CONTINUE_PAST_FIELD;
    CHECK(gw_run_until(m, GW_FIELD_TICKS, &run_result) == GW_OK, "audio run to target");
    CHECK(run_result.actual_tick >= GW_FIELD_TICKS, "audio run reached target");
    first_capacity = (uint32_t)(expected_audio_frames(run_result.actual_tick, 48000) / 2);
    second_capacity = (uint32_t)(expected_audio_frames(run_result.actual_tick, 48000) - first_capacity);
    CHECK(first_capacity > 0 && second_capacity > 0 && first_capacity + second_capacity <= 2048,
          "audio frame count fits two partial reads");
    first.struct_size = sizeof(first); first.version = GW_API_VERSION;
    CHECK(gw_audio_read(m, pcm, first_capacity, &first) == GW_OK, "first partial PCM read");
    second.struct_size = sizeof(second); second.version = GW_API_VERSION;
    CHECK(gw_audio_read(m, pcm + 2 * first_capacity, second_capacity, &second) == GW_OK,
          "second partial PCM read");
    CHECK(first.produced == first_capacity && second.produced == second_capacity,
          "both partial reads produce requested frames");
    CHECK(first.first_index == 0 && second.first_index == first.first_index + first.produced,
          "PCM frame indices are continuous");
    CHECK(first.produced + second.produced == expected_audio_frames(run_result.actual_tick, 48000),
          "PCM count equals consumer-computed N(actual_tick)");
    CHECK(first.lost == 0 && second.lost == 0, "PCM queue did not lose frames");
    CHECK(gw_get_audio_writes(m, writes, 16, &write_count, &dropped) == GW_OK,
          "copy chip-write trace");
    CHECK(write_count <= 16, "trace count respects configured capacity");
    gw_destroy(m);
    m = NULL;
    config.audio_rate_hz = 7999;
    CHECK(gw_create(&config, &m) == GW_ERROR_ARGUMENT && m == NULL,
          "reject audio rate below minimum");
}

static void check_diagnostic(gw_machine *m, unsigned variant, int negative)
{
    static const uint8_t expected_ram[] = {0x12, 0x34, 0x89, 0xab, 0xcd, 0xef, 0xca, 0xfe, 0xbe, 0xef};
    uint8_t ram[sizeof(expected_ram)], stack[6];
    const uint32_t expected_word = variant ? 0x5634u : 0x1234u;
    gw_diagnostic_record d = snapshot(m);
    gw_diagnostic_event events[GW_DIAGNOSTIC_CAPACITY];
    size_t count=0; uint64_t dropped=0;
    CHECK(d.initial_ssp == 0xffff00 && d.initial_pc == 0x200, "reset vectors");
    CHECK(d.d[0] == (expected_word ^ (negative ? 1u : 0u)), "RAM lanes");
    CHECK(d.d[1] == 0x89abcdef && d.d[2] == 0, "RAM longword read");
    CHECK(d.d[3] == 0x2704 && d.d[4] == 0x22a, "exception saved SR and PC");
    CHECK(d.a[7] == 0xffff00 && d.pc == 0x236 && d.sr == 0x2700, "RTE and STOP state");
    CHECK(d.stop_reason == GW_STOP_CPU_STOPPED, "guest completion stop");
    CHECK(d.instructions == 13 && d.exceptions == 1 && d.exception_returns == 1, "retirement counters");
    CHECK(gw_get_diagnostic_events(m,events,GW_DIAGNOSTIC_CAPACITY,&count,&dropped)==GW_OK,
          "installed diagnostic copy-out");
    CHECK(count==13 && dropped==0 && events[0].instruction_address==0x200 &&
          events[12].stop_reason==GW_STOP_CPU_STOPPED,"installed instruction observations");
    CHECK(gw_peek_memory(m, 0xff0000, ram, sizeof(ram)) == GW_OK, "inspect RAM");
    CHECK(ram[0] == (variant ? 0x56 : 0x12) && !memcmp(ram + 1, expected_ram + 1, sizeof(ram) - 1), "RAM result bytes");
    CHECK(gw_peek_memory(m, 0xfffefa, stack, sizeof(stack)) == GW_OK, "inspect exception frame");
    CHECK(stack[0] == 0x27 && stack[1] == 0x04 && stack[2] == 0 && stack[3] == 0 &&
          stack[4] == 0x02 && stack[5] == 0x2a, "real six-byte exception frame");
}

int main(int argc, char **argv)
{
    uint8_t rom[1024], variant[1024], byte;
    gw_machine *a = NULL, *b = NULL;
    gw_config config = {sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1, {0, 0}};
    gw_diagnostic_record da, db;
    gw_run_result result;
    FILE *file;
    unsigned i;
#ifdef GW_TEST_HOOKS
    uint64_t allocations_a, allocations_b;
#endif
    CHECK(argc == 2 || argc == 3, "arguments");
    file = fopen(argv[1], "rb");
    CHECK(file != NULL, "fixture open");
    CHECK(fread(rom, 1, sizeof(rom), file) == sizeof(rom) && fgetc(file) == EOF, "fixture size");
    CHECK(fclose(file) == 0, "fixture close");
    CHECK(gw_api_version() == GW_API_VERSION, "API version");
    CHECK(gw_create(&config, &a) == GW_OK && gw_create(&config, &b) == GW_OK, "create two instances");
    CHECK(gw_console_reset(a) == GW_ERROR_NOT_LOADED, "reset without ROM");
    CHECK(gw_load_rom(a, rom, sizeof(rom)) == GW_OK, "load first ROM");
    memcpy(variant, rom, sizeof(rom));
    variant[0x203] = 0x56; /* immediate operand only: distinct instance result */
    CHECK(gw_load_rom(b, variant, sizeof(variant)) == GW_OK, "load second ROM");
    memset(variant, 0, sizeof(variant)); /* caller-owned input can change immediately */
    da = snapshot(a); db = snapshot(b);
    CHECK(da.pc == 0x200 && da.a[7] == 0xffff00 && da.tick == 112 && da.sr == 0x2700, "initial CPU state");
    CHECK(gw_peek_memory(a, 0xff0000, &byte, 1) == GW_OK && byte == 0, "cold RAM policy");
#ifdef GW_TEST_HOOKS
    allocations_a = gw_test_allocation_count(a);
    allocations_b = gw_test_allocation_count(b);
    CHECK(allocations_a == 2 && allocations_b == 2, "create/load allocations counted");
#endif
    result = run(a, da.tick + 1);
    CHECK(result.stop_reason == GW_STOP_TARGET && result.actual_tick > result.requested_tick, "reported safe-boundary overshoot");
    CHECK(result.overshoot_ticks == result.actual_tick - result.requested_tick, "explicit overshoot ticks");
    CHECK(snapshot(b).tick == db.tick && snapshot(b).pc == db.pc, "other instance not advanced");
    for (i = 0; i < 32; ++i) {
        da = snapshot(a); db = snapshot(b);
        if (da.stop_reason == GW_STOP_TARGET) (void)run(a, da.tick + 1);
        if (db.stop_reason == GW_STOP_TARGET) (void)run(b, db.tick + 71);
        if (snapshot(a).stop_reason && snapshot(b).stop_reason) break;
    }
    CHECK(i < 32, "bounded guest completion");
    check_diagnostic(a, 0, argc == 3);
    check_diagnostic(b, 1, 0);
    audio_contract(rom, sizeof(rom));
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_allocation_count(a) == allocations_a && gw_test_allocation_count(b) == allocations_b,
          "allocation-free interleaved execution");
#endif
    CHECK(gw_load_rom(a, rom, 7) == GW_ERROR_ROM, "reject short ROM");
    check_diagnostic(a, 0, 0);
    CHECK(gw_console_reset(a) == GW_OK, "console reset");
    CHECK(gw_peek_memory(a, 0xff0008, &byte, 1) == GW_OK && byte == 0xbe, "console reset preserves RAM");
    CHECK(gw_cold_init(a) == GW_OK, "cold init");
    CHECK(gw_peek_memory(a, 0xff0008, &byte, 1) == GW_OK && byte == 0, "cold init clears RAM");
    check_diagnostic(b, 1, 0);

    memcpy(variant, rom, sizeof(rom));
    variant[0x200] = 0xc0; variant[0x201] = 0xc0; /* legal MULU.W D0,D0, unsupported */
    CHECK(gw_load_rom(a, variant, sizeof(variant)) == GW_OK, "unsupported fixture load");
    result = run(a, 10000);
    CHECK(result.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION && result.opcode == 0xc0c0 &&
          result.instruction_address == 0x200, "legal unsupported instruction visible");
    CHECK(snapshot(a).exceptions == 0 && snapshot(a).instructions == 0, "unsupported is not illegal exception or success");
    CHECK(run(a, 20000).actual_tick == result.actual_tick, "unsupported stop is sticky");

    memcpy(variant, rom, sizeof(rom));
    variant[0x205] = 0xa1; /* first destination = 0x00a10000, unimplemented I/O */
    CHECK(gw_load_rom(a, variant, sizeof(variant)) == GW_OK, "unmapped fixture load");
    result = run(a, 10000);
    CHECK(result.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS && result.fault_address == 0xa10000,
          "unsupported bus address visible");
    CHECK(snapshot(a).exceptions == 0, "unsupported address not fabricated exception");

    memcpy(variant, rom, sizeof(rom));
    variant[0x200] = 0x4e; variant[0x201] = 0x70; /* RESET */
    variant[0x202] = 0x4e; variant[0x203] = 0x71; /* NOP */
    variant[0x204] = 0x4e; variant[0x205] = 0x72; /* STOP #0x2700 */
    variant[0x206] = 0x27; variant[0x207] = 0x00;
    CHECK(gw_load_rom(a, variant, sizeof(variant)) == GW_OK, "CPU RESET fixture load");
    result = run(a, 10000);
    da = snapshot(a);
    CHECK(result.stop_reason == GW_STOP_CPU_STOPPED && da.pc == 0x208 &&
          da.a[7] == 0xffff00 && da.external_resets == 1 && da.instructions == 3,
          "CPU RESET continues instead of reading reset vectors");

    config.profile = 99;
    CHECK(gw_create(&config, &a) == GW_ERROR_PROFILE, "unsupported profile rejected");
    gw_destroy(a); gw_destroy(b); gw_destroy(NULL);
    field_contract();
    puts("PASS: diagnostic reset/RAM/TRAP/RTE, isolated instances, allocation contract, unsupported stops, video field");
    return 0;
}
