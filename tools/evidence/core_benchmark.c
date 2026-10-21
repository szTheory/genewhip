/* SPDX-License-Identifier: MIT */
#include "genewhip/genewhip.h"
#ifdef GW_TEST_HOOKS
#include "internal.h"
#endif
#include <CommonCrypto/CommonDigest.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define RATE_HZ 48000u
#define WIDTH 320u
#define HEIGHT 224u
#define MAX_PCM_FRAMES 4096u
#define HASH_BYTES 32u

static uint64_t now_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void hex(const unsigned char *bytes, char out[HASH_BYTES * 2u + 1u])
{
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < HASH_BYTES; ++i) {
        out[i * 2u] = digits[bytes[i] >> 4];
        out[i * 2u + 1u] = digits[bytes[i] & 15u];
    }
    out[HASH_BYTES * 2u] = '\0';
}

static int run_field(gw_machine *m, uint64_t field, int16_t *audio,
                     uint32_t *pixels, uint64_t *sequence, uint64_t *end_tick,
                     uint64_t *actual_tick, uint32_t *frame_width,
                     uint64_t *pcm_next_index, uint32_t *pcm_frames)
{
    gw_run_result result = {0};
    gw_video_field video = {0};
    const uint32_t *borrowed = NULL;
    gw_audio_read_result read = {0};
    result.struct_size = sizeof(result); result.version = GW_API_VERSION;
    result.requested_tick = field * GW_FIELD_TICKS;
    result.flags = 0;
    if (gw_run_until(m, result.requested_tick, &result) != GW_OK ||
        result.stop_reason != GW_STOP_FIELD_COMPLETE) {
        fprintf(stderr, "run-field rejected field=%" PRIu64 " stop=%u tick=%" PRIu64 " target=%" PRIu64 "\n",
                field, result.stop_reason, result.actual_tick, result.requested_tick);
        return 1;
    }
    video.struct_size = sizeof(video); video.version = GW_API_VERSION;
    if (gw_get_video_field(m, &video, &borrowed) != GW_OK ||
        (video.width != 256u && video.width != WIDTH) || video.height != HEIGHT || !borrowed ||
        video.sequence != field - 1u) {
        fprintf(stderr, "video rejected field=%" PRIu64 " status=%u dimensions=%ux%u sequence=%" PRIu64 "\n",
                field, gw_get_video_field(m, &video, &borrowed), video.width, video.height, video.sequence);
        return 2;
    }
    for (uint32_t y = 0; y < HEIGHT; ++y)
        memcpy(pixels + (size_t)y * WIDTH,
               (const unsigned char *)borrowed + (size_t)y * video.pitch_bytes,
               video.width * sizeof(uint32_t));
    read.struct_size = sizeof(read); read.version = GW_API_VERSION;
    if (gw_audio_read(m, audio, MAX_PCM_FRAMES, &read) != GW_OK || read.lost ||
        read.first_index != *pcm_next_index ||
        read.produced > MAX_PCM_FRAMES) {
        fprintf(stderr, "audio rejected field=%" PRIu64 " status=%u lost=%" PRIu64 " produced=%u\n",
                field, gw_audio_read(m, audio, MAX_PCM_FRAMES, &read), read.lost, read.produced);
        return 3;
    }
    *sequence = video.sequence;
    *end_tick = video.end_tick;
    *actual_tick = result.actual_tick;
    *frame_width = video.width;
    *pcm_frames = read.produced;
    *pcm_next_index += read.produced;
    return 0;
}

static int schedule(gw_machine *m)
{
    static const struct { uint64_t field; uint32_t mask; } input[] = {
        {1, GW_BUTTON_START}, {2, 0}, {4, GW_BUTTON_RIGHT},
        {84, 0}, {121, GW_BUTTON_B}, {122, 0}
    };
    for (size_t i = 0; i < sizeof(input) / sizeof(input[0]); ++i) {
        gw_event event = {sizeof(event), GW_API_VERSION,
            input[i].field * GW_FIELD_TICKS, GW_EVENT_PAD_STATE, 0, input[i].mask, 0};
        if (gw_schedule_event(m, &event) != GW_OK) return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *rom_file = NULL;
    long rom_length;
    unsigned char *rom = NULL, digest[HASH_BYTES];
    uint32_t warmup, measured, diagnostics;
    int sampled;
    gw_config config = {sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, RATE_HZ};
    gw_machine *machine = NULL;
    uint32_t *pixels = NULL;
    uint64_t *field_ns = NULL;
    uint64_t *sequences = NULL, *end_ticks = NULL;
    uint32_t *pcm_counts = NULL, *video_widths = NULL;
    int16_t *pcm = NULL, *drain = NULL;
    size_t pcm_total = 0;
    uint64_t pcm_next_index = 0;
    uint64_t start_ns, end_ns, field_start, elapsed_ns, tick_start = 0, actual_tick_end = 0;
#ifdef GW_TEST_HOOKS
    uint64_t calls_start, calls_end, current_bytes, peak_bytes;
#endif
    uint32_t completed = 0;
    gw_diagnostic_record state = {0};
    uint8_t ram[GW_RAM_SIZE];
    gw_diagnostic_event events[GW_DIAGNOSTIC_CAPACITY];
    size_t event_count = 0;
    uint64_t dropped = 0;
    struct rusage usage;
    char hash_text[HASH_BYTES * 2u + 1u];

    if (argc != 6) {
        fputs("usage: gw_core_benchmark ROM sampled|aggregate DIAGNOSTICS WARMUP_FIELDS MEASURED_FIELDS\n", stderr);
        return 2;
    }
    sampled = !strcmp(argv[2], "sampled");
    if (!sampled && strcmp(argv[2], "aggregate")) return 2;
    diagnostics = (uint32_t)strtoul(argv[3], NULL, 10);
    warmup = (uint32_t)strtoul(argv[4], NULL, 10);
    measured = (uint32_t)strtoul(argv[5], NULL, 10);
    if (diagnostics > 1 || !measured || measured > 600 || warmup > 120) return 2;

    rom_file = fopen(argv[1], "rb");
    if (!rom_file || fseek(rom_file, 0, SEEK_END) || (rom_length = ftell(rom_file)) <= 0 ||
        fseek(rom_file, 0, SEEK_SET)) return 3;
    rom = (unsigned char *)malloc((size_t)rom_length);
    if (!rom || fread(rom, 1, (size_t)rom_length, rom_file) != (size_t)rom_length || fclose(rom_file)) return 3;
    rom_file = NULL;
    pixels = (uint32_t *)malloc((size_t)measured * WIDTH * HEIGHT * sizeof(uint32_t));
    pcm = (int16_t *)malloc((size_t)measured * MAX_PCM_FRAMES * 2u * sizeof(int16_t));
    drain = (int16_t *)malloc(MAX_PCM_FRAMES * 2u * sizeof(int16_t));
    field_ns = (uint64_t *)calloc(measured, sizeof(*field_ns));
    sequences = (uint64_t *)calloc(measured, sizeof(*sequences));
    end_ticks = (uint64_t *)calloc(measured, sizeof(*end_ticks));
    pcm_counts = (uint32_t *)calloc(measured, sizeof(*pcm_counts));
    video_widths = (uint32_t *)calloc(measured, sizeof(*video_widths));
    if (!pixels || !pcm || !drain || !field_ns || !sequences || !end_ticks || !pcm_counts || !video_widths) return 4;

    config.diagnostics = diagnostics;
    if (gw_create(&config, &machine) != GW_OK || gw_load_rom(machine, rom, (size_t)rom_length) != GW_OK ||
        schedule(machine)) return 5;
    for (uint32_t i = 1; i <= warmup; ++i) {
        uint64_t sequence, end_tick, actual_tick;
        uint32_t width, frames;
        if (run_field(machine, i, drain, pixels, &sequence, &end_tick, &actual_tick,
                      &width, &pcm_next_index, &frames)) return 6;
    }
    { gw_diagnostic_record before = {0};
      before.struct_size = sizeof(before); before.version = GW_API_VERSION;
      if (gw_get_diagnostics(machine, &before) != GW_OK) return 7;
      tick_start = before.tick; }
#ifdef GW_TEST_HOOKS
    calls_start = gw_test_allocation_count(machine);
#endif
    start_ns = now_ns();
    for (uint32_t i = 0; i < measured; ++i) {
        uint64_t sequence, end_tick, actual_tick;
        uint32_t width, frames;
        if (sampled) field_start = now_ns();
        if (run_field(machine, (uint64_t)warmup + i + 1u, drain,
                      pixels + (size_t)i * WIDTH * HEIGHT,
                      &sequence, &end_tick, &actual_tick, &width, &pcm_next_index, &frames)) return 8;
        if (sampled) field_ns[i] = now_ns() - field_start;
        sequences[i] = sequence;
        end_ticks[i] = end_tick;
        actual_tick_end = actual_tick;
        video_widths[i] = width;
        pcm_counts[i] = frames;
        if (pcm_total + frames > (size_t)measured * MAX_PCM_FRAMES) return 9;
        memcpy(pcm + pcm_total * 2u, drain, (size_t)frames * 2u * sizeof(int16_t));
        pcm_total += frames;
        ++completed;
    }
    end_ns = now_ns();
    elapsed_ns = end_ns - start_ns;
#ifdef GW_TEST_HOOKS
    calls_end = gw_test_allocation_count(machine);
    if (completed != measured || calls_end != calls_start) return 10;
#else
    if (completed != measured) return 10;
#endif

    state.struct_size = sizeof(state); state.version = GW_API_VERSION;
    if (gw_get_diagnostics(machine, &state) != GW_OK ||
        gw_peek_memory(machine, UINT32_C(0xff0000), ram, sizeof(ram)) != GW_OK ||
        gw_get_diagnostic_events(machine, events, GW_DIAGNOSTIC_CAPACITY, &event_count, &dropped) != GW_OK)
        return 11;
#ifdef GW_TEST_HOOKS
    current_bytes = gw_test_owned_bytes_current(machine);
    peak_bytes = gw_test_owned_bytes_peak(machine);
#endif
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 12;

    printf("{\"schema\":\"genewhip-core-benchmark-run-v1\",\"mode\":\"%s\",\"diagnostics_enabled\":%s,"
           "\"warmup_fields\":%u,\"measured_fields\":%u,\"fields_completed\":%u,"
           "\"ticks_completed\":%" PRIu64 ",\"actual_tick_start\":%" PRIu64 ",\"actual_tick_end\":%" PRIu64 ","
           "\"last_stop_reason\":%u,\"elapsed_ns\":%" PRIu64 ",\"timed_samples\":%s,\"field_ns\":[",
           sampled ? "sampled" : "aggregate", diagnostics ? "true" : "false",
           warmup, measured, completed, actual_tick_end - tick_start,
           tick_start, actual_tick_end, GW_STOP_FIELD_COMPLETE, elapsed_ns, sampled ? "true" : "false");
    if (sampled)
        for (uint32_t i = 0; i < measured; ++i) printf("%s%" PRIu64, i ? "," : "", field_ns[i]);
    printf("],\"video_fields\":[");
    for (uint32_t i = 0; i < measured; ++i) {
        CC_SHA256_CTX context;
        CC_SHA256_Init(&context);
        for (uint32_t y = 0; y < HEIGHT; ++y)
            CC_SHA256_Update(&context, pixels + (size_t)i * WIDTH * HEIGHT + (size_t)y * WIDTH,
                             video_widths[i] * sizeof(uint32_t));
        CC_SHA256_Final(digest, &context);
        hex(digest, hash_text);
        printf("%s{\"sequence\":%" PRIu64 ",\"end_tick\":%" PRIu64 ",\"width\":%u,\"height\":%u,\"sha256\":\"%s\"}",
               i ? "," : "", sequences[i], end_ticks[i], video_widths[i], HEIGHT, hash_text);
    }
    CC_SHA256((const unsigned char *)pcm, (CC_LONG)(pcm_total * 2u * sizeof(int16_t)), digest);
    hex(digest, hash_text);
    printf("],\"pcm_frames\":%zu,\"pcm_sha256\":\"%s\",", pcm_total, hash_text);
    CC_SHA256(ram, sizeof(ram), digest); hex(digest, hash_text);
    printf("\"ram_sha256\":\"%s\",", hash_text);
    state.instructions = state.exceptions = state.exception_returns = state.external_resets = 0;
    state.diagnostics_enabled = 0;
    CC_SHA256((const unsigned char *)&state, sizeof(state), digest); hex(digest, hash_text);
    printf("\"machine_sha256\":\"%s\",", hash_text);
#ifdef GW_TEST_HOOKS
    printf("\"core_owned_current_bytes\":%" PRIu64 ",\"core_owned_peak_bytes\":%" PRIu64 ",",
           (uint64_t)current_bytes, (uint64_t)peak_bytes);
#else
    printf("\"core_owned_current_bytes\":null,\"core_owned_peak_bytes\":null,");
#endif
    printf("\"process_ru_maxrss_bytes\":%llu,"
           "\"rss_scope\":\"fresh-process whole-process Darwin high-water including harness and capture buffers\",",
           (unsigned long long)usage.ru_maxrss);
#ifdef GW_TEST_HOOKS
    printf("\"allocation_calls_total\":%" PRIu64 ",", calls_end);
#else
    printf("\"allocation_calls_total\":null,");
#endif
    printf("\"diagnostic_records\":%zu,\"diagnostic_dropped\":%" PRIu64 "}\n", event_count, dropped);
    gw_destroy(machine);
    free(video_widths); free(pcm_counts); free(end_ticks); free(sequences); free(field_ns);
    free(drain); free(pcm); free(pixels); free(rom);
    return 0;
}
