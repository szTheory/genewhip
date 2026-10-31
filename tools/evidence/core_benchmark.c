/* SPDX-License-Identifier: MIT */
#include "genewhip/genewhip.h"
#include "route_controller.h"
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
#include <limits.h>

#define RATE_HZ 48000u
#define WIDTH 320u
#define HEIGHT 224u
#define MAX_PCM_FRAMES 4096u
#define HASH_BYTES 32u
#define MAX_CAPTURE_BYTES (UINT64_C(2) * 1024u * 1024u * 1024u)
#define ROUTE_FIXED_CAPTURE_BYTES (4096u * 40u + 64u * 24u + 4096u)

_Static_assert(sizeof(gw_route_input_record) == 40u, "capture input layout changed");
_Static_assert(sizeof(gw_route_predicate_observation) == 24u, "capture predicate layout changed");
_Static_assert(sizeof(gw_route_cpu_observation) == 88u, "capture CPU layout changed");

static uint64_t now_ns(void);
static void hex(const unsigned char *bytes, char out[HASH_BYTES * 2u + 1u]);

static int checked_mul_size(size_t a, size_t b, size_t *out)
{
    if (!out || (b && a > SIZE_MAX / b)) return 0;
    *out = a * b;
    return 1;
}

static int checked_add_size(size_t a, size_t b, size_t *out)
{
    if (!out || a > SIZE_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static int checked_capture_size(size_t fields, size_t *pixels, size_t *pcm, size_t *total)
{
    size_t pixel_count, pcm_count, metadata;
    if (!fields || !checked_mul_size(fields, WIDTH, &pixel_count) ||
        !checked_mul_size(pixel_count, HEIGHT, &pixel_count) ||
        !checked_mul_size(pixel_count, sizeof(uint32_t), pixels) ||
        !checked_mul_size(fields, MAX_PCM_FRAMES, &pcm_count) ||
        !checked_mul_size(pcm_count, 2u, &pcm_count) ||
        !checked_mul_size(pcm_count, sizeof(int16_t), pcm) ||
        !checked_mul_size(fields, 256u, &metadata) ||
        !checked_add_size(*pixels, *pcm, total) ||
        !checked_add_size(*total, metadata, total) ||
        !checked_add_size(*total, ROUTE_FIXED_CAPTURE_BYTES, total) ||
        *total > MAX_CAPTURE_BYTES) return 0;
    return 1;
}

static int child_contracts(void)
{
    size_t pixels = 0, pcm = 0, total = 0;
    if (!checked_capture_size(4196u, &pixels, &pcm, &total) ||
        pixels != (size_t)4196u * WIDTH * HEIGHT * sizeof(uint32_t) ||
        pcm != (size_t)4196u * MAX_PCM_FRAMES * 2u * sizeof(int16_t) ||
        total < pixels + pcm + (size_t)4196u * 256u + ROUTE_FIXED_CAPTURE_BYTES ||
        checked_capture_size(SIZE_MAX, &pixels, &pcm, &total)) return 1;
    puts("v02 child contracts: PASS (6 capture-size and layout assertions)");
    return 0;
}

typedef struct route_media_capture {
    uint32_t *pixels;
    int16_t *pcm;
    uint64_t *sequences, *end_ticks;
    uint32_t *widths, *pcm_counts;
    size_t pixel_capacity, pcm_capacity, fields, pcm_frames;
    uint64_t start_ns, end_ns;
} route_media_capture;

static uint64_t route_clock_ns(void *context)
{
    (void)context;
    return now_ns();
}

static void begin_route_timer(void *context)
{
    route_media_capture *capture = (route_media_capture *)context;
    capture->start_ns = now_ns();
}

static void end_route_timer(void *context)
{
    route_media_capture *capture = (route_media_capture *)context;
    capture->end_ns = now_ns();
}

static int capture_route_field(void *context, const gw_session *session)
{
    route_media_capture *capture = (route_media_capture *)context;
    gw_video_field video = {.struct_size = sizeof(video), .version = GW_API_VERSION};
    const uint32_t *pixels = NULL;
    const int16_t *audio = NULL;
    uint32_t audio_count = 0;
    gw_audio_read_result audio_result = {.struct_size = sizeof(audio_result), .version = GW_API_VERSION};
    if (capture->fields >= capture->pixel_capacity ||
        gw_session_field(session, &video, &pixels) != GW_OK || !pixels ||
        (video.width != 256u && video.width != WIDTH) || video.height != HEIGHT ||
        video.sequence != capture->fields ||
        gw_session_audio(session, &audio, &audio_count, &audio_result) != GW_OK ||
        (audio_count && !audio) || audio_count > MAX_PCM_FRAMES ||
        audio_count > capture->pcm_capacity - capture->pcm_frames) return 1;
    for (uint32_t y = 0; y < HEIGHT; ++y)
        memcpy(capture->pixels + capture->fields * WIDTH * HEIGHT + (size_t)y * WIDTH,
               (const unsigned char *)pixels + (size_t)y * video.pitch_bytes,
               (size_t)video.width * sizeof(uint32_t));
    capture->sequences[capture->fields] = video.sequence;
    capture->end_ticks[capture->fields] = video.end_tick;
    capture->widths[capture->fields] = video.width;
    capture->pcm_counts[capture->fields] = audio_count;
    if (audio_count) memcpy(capture->pcm + capture->pcm_frames * 2u, audio,
                            (size_t)audio_count * 2u * sizeof(int16_t));
    capture->pcm_frames += audio_count;
    ++capture->fields;
    return 0;
}

static int parse_size_arg(const char *text, size_t *value)
{
    char *end = NULL;
    unsigned long long parsed;
    if (!text || !*text || *text == '-') return 0;
    parsed = strtoull(text, &end, 10);
    if (!end || *end || parsed > SIZE_MAX) return 0;
    *value = (size_t)parsed;
    return 1;
}

static void hash_u32(CC_SHA256_CTX *context, uint32_t value)
{
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8),
        (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    CC_SHA256_Update(context, bytes, sizeof(bytes));
}

static void hash_u64(CC_SHA256_CTX *context, uint64_t value)
{
    hash_u32(context, (uint32_t)value);
    hash_u32(context, (uint32_t)(value >> 32));
}

static int run_route_child(const char *rom_path, const char *mode, uint32_t diagnostics,
                           const char *plan_path, size_t capture_limit, int untimed,
                           size_t expected_fields)
{
    FILE *file = NULL;
    unsigned char *rom = NULL, *plan_bytes = NULL;
    long rom_size, plan_size;
    gw_route_controller *plan = NULL;
    gw_session session = {0};
    gw_route_capture route = {0};
    route_media_capture media = {0};
    gw_config config = {sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, RATE_HZ};
    size_t pixel_bytes, pcm_bytes, total_bytes, pcm_capacity;
    uint8_t ram[GW_RAM_SIZE];
    gw_diagnostic_record cpu = {0};
    struct rusage usage;
    unsigned char digest[HASH_BYTES];
    char text_hash[HASH_BYTES * 2u + 1u];
    CC_SHA256_CTX state_hash;
    uint64_t core_current = 0, core_peak = 0, allocation_calls = 0;
    int status = 1, stage = 1;
    if (strcmp(mode, "sampled") && strcmp(mode, "aggregate")) return 2;
    if (!expected_fields || expected_fields > 7200 ||
        !checked_capture_size(expected_fields, &pixel_bytes, &pcm_bytes, &total_bytes) ||
        total_bytes > capture_limit) return 2;
    stage = 2; file = fopen(plan_path, "rb");
    if (!file || fseek(file, 0, SEEK_END) || (plan_size = ftell(file)) <= 0 || plan_size > 1048576 || fseek(file, 0, SEEK_SET)) goto done;
    plan_bytes = (unsigned char *)malloc((size_t)plan_size);
    if (!plan_bytes) goto done;
    size_t plan_read = fread(plan_bytes, 1, (size_t)plan_size, file);
    int plan_close = fclose(file);
    file = NULL;
    if (plan_read != (size_t)plan_size || plan_close) goto done;
    stage = 3; if (gw_route_controller_parse(plan_bytes, (size_t)plan_size, &plan) != GW_OK ||
        (plan->header[2] < 1 || plan->header[2] > 3) ||
        plan->header[3] < expected_fields || plan->header[3] > 7200) goto done;
    file = fopen(rom_path, "rb");
    if (!file || fseek(file, 0, SEEK_END) || (rom_size = ftell(file)) < GW_MIN_ROM_SIZE ||
        rom_size > GW_MAX_ROM_SIZE || (rom_size & 1) || fseek(file, 0, SEEK_SET)) goto done;
    rom = (unsigned char *)malloc((size_t)rom_size);
    if (!rom) goto done;
    size_t rom_read = fread(rom, 1, (size_t)rom_size, file);
    int rom_close = fclose(file);
    file = NULL;
    if (rom_read != (size_t)rom_size || rom_close) goto done;
    pcm_capacity = expected_fields * MAX_PCM_FRAMES;
    stage = 4; media.pixel_capacity = expected_fields; media.pcm_capacity = pcm_capacity;
    media.pixels = (uint32_t *)calloc(1, pixel_bytes);
    media.pcm = (int16_t *)malloc(pcm_bytes);
    media.sequences = (uint64_t *)calloc(media.pixel_capacity, sizeof(*media.sequences));
    media.end_ticks = (uint64_t *)calloc(media.pixel_capacity, sizeof(*media.end_ticks));
    media.widths = (uint32_t *)calloc(media.pixel_capacity, sizeof(*media.widths));
    media.pcm_counts = (uint32_t *)calloc(media.pixel_capacity, sizeof(*media.pcm_counts));
    route.input_capacity = 4096; route.predicate_capacity = 64;
    route.cpu_capacity = expected_fields * 2u;
    route.span_capacity = 4096; route.capacity_bytes = total_bytes;
    route.input_records = (gw_route_input_record *)calloc(route.input_capacity, sizeof(*route.input_records));
    route.predicate_observations = (gw_route_predicate_observation *)calloc(route.predicate_capacity, sizeof(*route.predicate_observations));
    route.cpu_observations = (gw_route_cpu_observation *)calloc(route.cpu_capacity, sizeof(*route.cpu_observations));
    route.span_bytes = (uint8_t *)malloc(route.span_capacity);
    if (!untimed && !strcmp(mode, "sampled")) {
        route.field_ns_capacity = expected_fields;
        route.field_ns = (uint64_t *)calloc(route.field_ns_capacity, sizeof(*route.field_ns));
        route.clock_ns = route_clock_ns;
    }
    if (!media.pixels || !media.pcm || !media.sequences || !media.end_ticks || !media.widths ||
        !media.pcm_counts || !route.input_records || !route.predicate_observations ||
        !route.cpu_observations || !route.span_bytes) goto done;
    if (!untimed && !strcmp(mode, "sampled") && !route.field_ns) goto done;
    stage = 5; config.diagnostics = diagnostics;
    if (gw_session_open(&session, &config, rom, (size_t)rom_size) != 0) goto done;
    session.route_stop_horizon = 308;
    session.route_disable_audio_hash = 1;
    route.begin_execution = begin_route_timer; route.end_execution = end_route_timer; route.timer_context = &media;
    if (untimed) route.begin_execution = route.end_execution = NULL;
    stage = 6;
    { int route_status = gw_route_controller_run_capture(&session, plan, &route, NULL, NULL,
            capture_route_field, &media, 1);
      if (route_status != 0 || media.fields != expected_fields ||
          route.terminal_fields != expected_fields || !route.terminal_active_ticks) {
          fprintf(stderr, "route-status=%d fields=%zu expected=%zu terminal=%" PRIu64 " active=%" PRIu64 "\n",
              route_status, media.fields, expected_fields, route.terminal_fields, route.terminal_active_ticks);
          goto done;
      }
    }
    if (untimed) media.end_ns = media.start_ns = 0;
    if (!untimed && (!media.start_ns || media.end_ns <= media.start_ns)) goto done;
    stage = 7; if (gw_peek_memory(session.machine, UINT32_C(0xff0000), ram, sizeof(ram)) != GW_OK) goto done;
    cpu.struct_size = sizeof(cpu); cpu.version = GW_API_VERSION;
    if (gw_get_diagnostics(session.machine, &cpu) != GW_OK || getrusage(RUSAGE_SELF, &usage) != 0) goto done;
#ifdef GW_TEST_HOOKS
    core_current = gw_test_owned_bytes_current(session.machine);
    core_peak = gw_test_owned_bytes_peak(session.machine);
    allocation_calls = gw_test_allocation_count(session.machine);
#endif
    CC_SHA256(ram, sizeof(ram), digest); hex(digest, text_hash);
    char ram_hash[HASH_BYTES * 2u + 1u]; memcpy(ram_hash, text_hash, sizeof(ram_hash));
    CC_SHA256_Init(&state_hash);
    for (size_t i = 0; i < route.cpu_count; ++i) {
        const gw_route_cpu_observation *observation = &route.cpu_observations[i];
        hash_u64(&state_hash, observation->tick); hash_u32(&state_hash, observation->pc);
        hash_u32(&state_hash, observation->sr);
        for (unsigned r = 0; r < 8; ++r) hash_u32(&state_hash, observation->d[r]);
        for (unsigned r = 0; r < 8; ++r) hash_u32(&state_hash, observation->a[r]);
    }
    hash_u64(&state_hash, cpu.tick); hash_u32(&state_hash, cpu.pc); hash_u32(&state_hash, cpu.sr);
    for (unsigned i = 0; i < 8; ++i) hash_u32(&state_hash, cpu.d[i]);
    for (unsigned i = 0; i < 8; ++i) hash_u32(&state_hash, cpu.a[i]);
    /* Diagnostic instruction counters are observer state and excluded. */
    CC_SHA256_Final(digest, &state_hash); hex(digest, text_hash);
    char cpu_hash[HASH_BYTES * 2u + 1u]; memcpy(cpu_hash, text_hash, sizeof(cpu_hash));
    CC_SHA256_Init(&state_hash);
    hash_u64(&state_hash, route.input_count);
    for (size_t i = 0; i < route.input_count; ++i) {
        const gw_route_input_record *v = &route.input_records[i];
        hash_u64(&state_hash, v->tick); hash_u64(&state_hash, v->field); hash_u64(&state_hash, v->active);
        hash_u32(&state_hash, v->port); hash_u32(&state_hash, v->desired); hash_u32(&state_hash, v->effective);
    }
    hash_u64(&state_hash, route.predicate_count);
    for (size_t i = 0; i < route.predicate_count; ++i) {
        const gw_route_predicate_observation *v = &route.predicate_observations[i];
        hash_u64(&state_hash, v->clock); hash_u32(&state_hash, v->value);
        hash_u32(&state_hash, v->index); hash_u32(&state_hash, (uint32_t)v->reached);
    }
    hash_u64(&state_hash, route.cpu_count);
    for (size_t i = 0; i < route.cpu_count; ++i) {
        const gw_route_cpu_observation *v = &route.cpu_observations[i];
        hash_u64(&state_hash, v->tick); hash_u32(&state_hash, v->pc); hash_u32(&state_hash, v->sr);
        for (unsigned r = 0; r < 8; ++r) hash_u32(&state_hash, v->d[r]);
        for (unsigned r = 0; r < 8; ++r) hash_u32(&state_hash, v->a[r]);
    }
    hash_u64(&state_hash, route.span_count);
    CC_SHA256_Update(&state_hash, route.span_bytes, (CC_LONG)route.span_count);
    hash_u64(&state_hash, route.terminal_tick); hash_u64(&state_hash, route.terminal_fields);
    hash_u64(&state_hash, route.terminal_active_ticks);
    CC_SHA256_Final(digest, &state_hash); hex(digest, text_hash);
    char controller_hash[HASH_BYTES * 2u + 1u]; memcpy(controller_hash, text_hash, sizeof(controller_hash));
    printf("{\"schema\":\"genewhip-core-benchmark-run-v2\",\"workload\":\"route\",\"mode\":\"%s\","
           "\"diagnostics_enabled\":%s,\"untimed\":%s,\"completed_steps\":%" PRIu64 ","
           "\"completed_fields\":%zu,\"fields_completed\":%zu,\"warmup_fields\":0,\"terminal_tick\":%" PRIu64 ","
           "\"actual_tick_start\":0,\"actual_tick_end\":%" PRIu64 ",\"ticks_completed\":%" PRIu64 ",\"route_status\":0,"
           "\"elapsed_ns\":%" PRIu64 ",\"capture_capacity_bytes\":%zu,"
           "\"output_identity\":{\"ram_sha256\":\"%s\",\"cpu_sha256\":\"%s\",\"controller_sha256\":\"%s\",\"video_sha256\":\"",
           mode, diagnostics ? "true" : "false", untimed ? "true" : "false", route.terminal_active_ticks,
           media.fields, media.fields, route.terminal_tick, route.terminal_tick, route.terminal_tick,
           media.end_ns - media.start_ns, route.capacity_bytes, ram_hash, cpu_hash, controller_hash);
    CC_SHA256_Init(&state_hash);
    for (size_t i = 0; i < media.fields; ++i) {
        hash_u64(&state_hash, media.sequences[i]); hash_u64(&state_hash, media.end_ticks[i]);
        hash_u32(&state_hash, media.widths[i]); hash_u32(&state_hash, HEIGHT);
        for (uint32_t y = 0; y < HEIGHT; ++y)
            CC_SHA256_Update(&state_hash, media.pixels + i * WIDTH * HEIGHT + (size_t)y * WIDTH,
                             media.widths[i] * sizeof(uint32_t));
    }
    CC_SHA256_Final(digest, &state_hash); hex(digest, text_hash); printf("%s\",\"pcm_sha256\":\"", text_hash);
    CC_SHA256((const unsigned char *)media.pcm, (CC_LONG)(media.pcm_frames * 2u * sizeof(int16_t)), digest);
    hex(digest, text_hash);
    printf("%s\",\"pcm_frames\":%zu},\"process_ru_maxrss_bytes\":%llu,\"rss_unit_source\":\"Darwin getrusage(2) ru_maxrss bytes\",",
           text_hash, media.pcm_frames, (unsigned long long)usage.ru_maxrss);
#ifdef GW_TEST_HOOKS
    printf("\"core_owned_current_bytes\":%" PRIu64 ",\"core_owned_peak_bytes\":%" PRIu64
           ",\"allocation_calls_total\":%" PRIu64 ",\"allocation_scope\":\"core-owned machine allocations\","
           "\"allocation_unavailable_reason\":null,", core_current, core_peak, allocation_calls);
#else
    fputs("\"core_owned_current_bytes\":null,\"core_owned_peak_bytes\":null,\"allocation_calls_total\":null,"
          "\"allocation_scope\":null,\"allocation_unavailable_reason\":\"test-hooks-disabled\",", stdout);
#endif
    printf("\"timer_boundary\":\"first public guest boundary through terminal observation and PCM drain\",\"timed_samples\":%s,\"field_ns\":[",
           route.field_ns ? "true" : "false");
    if (route.field_ns)
        for (size_t i = 0; i < route.field_ns_count; ++i)
            printf("%s%" PRIu64, i ? "," : "", route.field_ns[i]);
    puts("]}");
    status = 0;
done:
    if (status && stage) fprintf(stderr, "route benchmark failed stage=%d\n", stage);
    if (file) fclose(file);
    gw_session_close(&session); gw_route_controller_free(plan);
    free(route.field_ns); free(route.span_bytes); free(route.cpu_observations); free(route.predicate_observations); free(route.input_records);
    free(media.pcm_counts); free(media.widths); free(media.end_ticks); free(media.sequences);
    free(media.pcm); free(media.pixels); free(plan_bytes); free(rom);
    return status;
}

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
    int sampled, untimed = 0;
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
    if ((argc == 10 || argc == 11) && !strcmp(argv[6], "--route-plan") &&
        !strcmp(argv[8], "--route-capture-limit") && (argc == 10 || !strcmp(argv[10], "--untimed"))) {
        char *end_diag = NULL;
        unsigned long diag = strtoul(argv[3], &end_diag, 10);
        size_t fields = 0, capture_limit = 0;
        if (!end_diag || *end_diag || diag > 1 || strcmp(argv[4], "0") ||
            !parse_size_arg(argv[5], &fields) || !parse_size_arg(argv[9], &capture_limit)) return 2;
        return run_route_child(argv[1], argv[2], (uint32_t)diag, argv[7], capture_limit,
                               argc == 11, fields);
    }

    if (argc == 2 && !strcmp(argv[1], "--v02-child-contracts")) return child_contracts();
    if ((argc != 6 && argc != 7) || (argc == 7 && strcmp(argv[6], "--untimed"))) {
        fputs("usage: gw_core_benchmark ROM sampled|aggregate DIAGNOSTICS WARMUP_FIELDS MEASURED_FIELDS [--untimed]\n", stderr);
        return 2;
    }
    untimed = argc == 7;
    sampled = !strcmp(argv[2], "sampled");
    if (!sampled && strcmp(argv[2], "aggregate")) return 2;
    diagnostics = (uint32_t)strtoul(argv[3], NULL, 10);
    warmup = (uint32_t)strtoul(argv[4], NULL, 10);
    measured = (uint32_t)strtoul(argv[5], NULL, 10);
    if (diagnostics > 1 || !measured || measured > 600 || warmup > 120) return 2;

    rom_file = fopen(argv[1], "rb");
    if (!rom_file) return 3;
    if (fseek(rom_file, 0, SEEK_END) || (rom_length = ftell(rom_file)) <= 0 ||
        fseek(rom_file, 0, SEEK_SET)) { fclose(rom_file); return 3; }
    rom = (unsigned char *)malloc((size_t)rom_length);
    if (!rom) { fclose(rom_file); return 3; }
    size_t legacy_rom_read = fread(rom, 1, (size_t)rom_length, rom_file);
    int legacy_rom_close = fclose(rom_file);
    rom_file = NULL;
    if (legacy_rom_read != (size_t)rom_length || legacy_rom_close) return 3;
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
    if (!untimed) start_ns = now_ns();
    for (uint32_t i = 0; i < measured; ++i) {
        uint64_t sequence, end_tick, actual_tick;
        uint32_t width, frames;
        if (sampled && !untimed) field_start = now_ns();
        if (run_field(machine, (uint64_t)warmup + i + 1u, drain,
                      pixels + (size_t)i * WIDTH * HEIGHT,
                      &sequence, &end_tick, &actual_tick, &width, &pcm_next_index, &frames)) return 8;
        if (sampled && !untimed) field_ns[i] = now_ns() - field_start;
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
    if (!untimed) {
        end_ns = now_ns();
        elapsed_ns = end_ns - start_ns;
    } else elapsed_ns = 0;
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
           "\"last_stop_reason\":%u,\"elapsed_ns\":%" PRIu64 ",\"untimed\":%s,\"timed_samples\":%s,\"field_ns\":[",
           sampled ? "sampled" : "aggregate", diagnostics ? "true" : "false",
           warmup, measured, completed, actual_tick_end - tick_start,
           tick_start, actual_tick_end, GW_STOP_FIELD_COMPLETE, elapsed_ns,
           untimed ? "true" : "false", sampled && !untimed ? "true" : "false");
    if (sampled && !untimed)
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
           "\"rss_unit_source\":\"Darwin getrusage(2) ru_maxrss bytes\","
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
