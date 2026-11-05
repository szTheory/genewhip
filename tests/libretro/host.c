#define _POSIX_C_SOURCE 200809L
/* SPDX-License-Identifier: MIT
 * Actual-library Libretro lifecycle and ABI host. */
#include "libretro.h"
#include "genewhip/genewhip.h"

#include <errno.h>
#include <limits.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition, name) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); \
        exit(1); \
    } \
} while (0)

typedef struct libretro_api {
    void (RETRO_CALLCONV *set_environment)(retro_environment_t);
    void (RETRO_CALLCONV *set_video_refresh)(retro_video_refresh_t);
    void (RETRO_CALLCONV *set_audio_sample)(retro_audio_sample_t);
    void (RETRO_CALLCONV *set_audio_sample_batch)(retro_audio_sample_batch_t);
    void (RETRO_CALLCONV *set_input_poll)(retro_input_poll_t);
    void (RETRO_CALLCONV *set_input_state)(retro_input_state_t);
    void (RETRO_CALLCONV *init)(void);
    void (RETRO_CALLCONV *deinit)(void);
    unsigned (RETRO_CALLCONV *api_version)(void);
    void (RETRO_CALLCONV *get_system_info)(struct retro_system_info *);
    void (RETRO_CALLCONV *get_system_av_info)(struct retro_system_av_info *);
    void (RETRO_CALLCONV *set_controller_port_device)(unsigned, unsigned);
    void (RETRO_CALLCONV *reset)(void);
    void (RETRO_CALLCONV *run)(void);
    size_t (RETRO_CALLCONV *serialize_size)(void);
    bool (RETRO_CALLCONV *serialize)(void *, size_t);
    bool (RETRO_CALLCONV *unserialize)(const void *, size_t);
    void (RETRO_CALLCONV *cheat_reset)(void);
    void (RETRO_CALLCONV *cheat_set)(unsigned, bool, const char *);
    bool (RETRO_CALLCONV *load_game)(const struct retro_game_info *);
    bool (RETRO_CALLCONV *load_game_special)(unsigned,
        const struct retro_game_info *, size_t);
    void (RETRO_CALLCONV *unload_game)(void);
    unsigned (RETRO_CALLCONV *get_region)(void);
    void *(RETRO_CALLCONV *get_memory_data)(unsigned);
    size_t (RETRO_CALLCONV *get_memory_size)(unsigned);
} libretro_api;

static unsigned video_calls;
static unsigned poll_calls;
static unsigned sample_calls;
static size_t audio_frames;
static bool pixel_format_accepted;
static bool callback_geometry_valid;
static bool callback_audio_valid;
static bool environment_accept_xrgb8888;
static bool callback_input_arguments_valid;
static bool callback_polled_before_input;
static int selected_input_port = -1;
static unsigned selected_input_id = RETRO_DEVICE_ID_JOYPAD_MASK;
static unsigned input_queries;
static unsigned batch_calls;
static size_t batch_offered_frames;
static size_t batch_accepted_frames;
static size_t sample_observed_frames;
static size_t audio_observed_frames;
static size_t audio_accept_percent = 100u;
static unsigned poll_delay_microseconds;
static unsigned callback_width;
static unsigned callback_height;
static size_t callback_pitch;
static size_t callback_pixel_bytes;
static size_t callback_video_bytes;
static uint8_t callback_video[320u * 224u * sizeof(uint32_t)];
static int16_t callback_audio[GW_AUDIO_QUEUE_FRAMES * 2u];
static bool fixture_route_input;
static unsigned fixture_route_mask;

typedef struct route_input_event {
    unsigned field;
    unsigned id;
    unsigned asserted;
} route_input_event;

static void install_callbacks(libretro_api *api);
static struct retro_game_info memory_game(const uint8_t *bytes, size_t size);
static void begin_run_observation(void);

static bool RETRO_CALLCONV environment_callback(unsigned command, void *data)
{
    if (command == RETRO_ENVIRONMENT_SET_PIXEL_FORMAT && data != NULL) {
        enum retro_pixel_format format = *(const enum retro_pixel_format *)data;
        pixel_format_accepted = (format == RETRO_PIXEL_FORMAT_XRGB8888) &&
            environment_accept_xrgb8888;
        return pixel_format_accepted;
    }
    return false;
}

static void RETRO_CALLCONV video_callback(const void *data, unsigned width,
    unsigned height, size_t pitch)
{
    ++video_calls;
    callback_geometry_valid = callback_geometry_valid && data != NULL &&
        (width == 256u || width == 320u) && height == 224u;
    callback_width = width;
    callback_height = height;
    callback_pitch = pitch;
    callback_pixel_bytes = pixel_format_accepted ? sizeof(uint32_t) : sizeof(uint16_t);
    callback_video_bytes = 0u;
    if (data == NULL || width > 320u || height > 224u ||
        pitch < (size_t)width * callback_pixel_bytes ||
        (size_t)width * height * callback_pixel_bytes > sizeof(callback_video)) {
        callback_geometry_valid = false;
        return;
    }
    {
        size_t row_bytes = (size_t)width * callback_pixel_bytes;
        unsigned y;
        for (y = 0; y < height; ++y) {
            memcpy(callback_video + (size_t)y * row_bytes,
                (const uint8_t *)data + (size_t)y * pitch, row_bytes);
        }
        callback_video_bytes = row_bytes * height;
    }
}

static void RETRO_CALLCONV audio_callback(int16_t left, int16_t right)
{
    ++sample_calls;
    if (sample_observed_frames < GW_AUDIO_QUEUE_FRAMES) {
        callback_audio[2u * sample_observed_frames] = left;
        callback_audio[2u * sample_observed_frames + 1u] = right;
        ++sample_observed_frames;
    } else {
        callback_audio_valid = false;
    }
}

static size_t RETRO_CALLCONV audio_batch_callback(const int16_t *data,
    size_t frames)
{
    size_t accepted;
    callback_audio_valid = callback_audio_valid && (data != NULL || frames == 0u) &&
        frames <= GW_AUDIO_QUEUE_FRAMES &&
        audio_observed_frames + frames <= GW_AUDIO_QUEUE_FRAMES;
    ++batch_calls;
    batch_offered_frames += frames;
    audio_frames += frames;
    if (data != NULL && frames > 0u &&
        audio_observed_frames + frames <= GW_AUDIO_QUEUE_FRAMES) {
        memcpy(callback_audio + audio_observed_frames * 2u, data,
            frames * 2u * sizeof(int16_t));
        audio_observed_frames += frames;
    }
    accepted = (frames * audio_accept_percent) / 100u;
    batch_accepted_frames += accepted;
    return accepted;
}

static void RETRO_CALLCONV input_poll_callback(void)
{
    ++poll_calls;
    callback_polled_before_input = true;
    if (poll_delay_microseconds > 0u) {
        struct timespec delay;
        delay.tv_sec = (time_t)(poll_delay_microseconds / 1000000u);
        delay.tv_nsec = (long)(poll_delay_microseconds % 1000000u) * 1000L;
        (void)nanosleep(&delay, NULL);
    }
}

static int16_t RETRO_CALLCONV input_state_callback(unsigned port,
    unsigned device, unsigned index, unsigned id)
{
    unsigned route_bit = id == RETRO_DEVICE_ID_JOYPAD_START ? GW_BUTTON_START :
        id == RETRO_DEVICE_ID_JOYPAD_RIGHT ? GW_BUTTON_RIGHT : 0u;
    ++input_queries;
    callback_input_arguments_valid = callback_input_arguments_valid &&
        port < 2u && device == RETRO_DEVICE_JOYPAD && index == 0u &&
        id <= RETRO_DEVICE_ID_JOYPAD_R3;
    callback_polled_before_input = callback_polled_before_input &&
        (poll_calls > 0u);
    if (fixture_route_input)
        return port == 0u && route_bit != 0u &&
            (fixture_route_mask & route_bit) != 0u ? 1 : 0;
    return ((int)port == selected_input_port && id == selected_input_id) ? 1 : 0;
}

static void *required_symbol(void *library, const char *name)
{
    void *symbol;
    (void)dlerror();
    symbol = dlsym(library, name);
    if (symbol == NULL) {
        const char *error = dlerror();
        fprintf(stderr, "FAIL: missing export %s: %s\n", name,
            error != NULL ? error : "unknown loader error");
        exit(1);
    }
    return symbol;
}

#define RESOLVE(library, name, function) do { \
    void *symbol__ = required_symbol((library), (name)); \
    CHECK(sizeof(function) == sizeof(symbol__), "POSIX function pointer representation"); \
    memcpy(&(function), &symbol__, sizeof(function)); \
} while (0)

static void resolve_api(void *library, libretro_api *api)
{
    RESOLVE(library, "retro_set_environment", api->set_environment);
    RESOLVE(library, "retro_set_video_refresh", api->set_video_refresh);
    RESOLVE(library, "retro_set_audio_sample", api->set_audio_sample);
    RESOLVE(library, "retro_set_audio_sample_batch", api->set_audio_sample_batch);
    RESOLVE(library, "retro_set_input_poll", api->set_input_poll);
    RESOLVE(library, "retro_set_input_state", api->set_input_state);
    RESOLVE(library, "retro_init", api->init);
    RESOLVE(library, "retro_deinit", api->deinit);
    RESOLVE(library, "retro_api_version", api->api_version);
    RESOLVE(library, "retro_get_system_info", api->get_system_info);
    RESOLVE(library, "retro_get_system_av_info", api->get_system_av_info);
    RESOLVE(library, "retro_set_controller_port_device", api->set_controller_port_device);
    RESOLVE(library, "retro_reset", api->reset);
    RESOLVE(library, "retro_run", api->run);
    RESOLVE(library, "retro_serialize_size", api->serialize_size);
    RESOLVE(library, "retro_serialize", api->serialize);
    RESOLVE(library, "retro_unserialize", api->unserialize);
    RESOLVE(library, "retro_cheat_reset", api->cheat_reset);
    RESOLVE(library, "retro_cheat_set", api->cheat_set);
    RESOLVE(library, "retro_load_game", api->load_game);
    RESOLVE(library, "retro_load_game_special", api->load_game_special);
    RESOLVE(library, "retro_unload_game", api->unload_game);
    RESOLVE(library, "retro_get_region", api->get_region);
    RESOLVE(library, "retro_get_memory_data", api->get_memory_data);
    RESOLVE(library, "retro_get_memory_size", api->get_memory_size);
}

static uint8_t *read_content(const char *path, size_t *size_out)
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *bytes;
    CHECK(file != NULL, "open diagnostic ROM source");
    CHECK(fseek(file, 0, SEEK_END) == 0, "seek diagnostic ROM source");
    length = ftell(file);
    CHECK(length >= (long)GW_MIN_ROM_SIZE && length <= (long)GW_MAX_ROM_SIZE,
        "bounded ROM length");
    CHECK(fseek(file, 0, SEEK_SET) == 0, "rewind diagnostic ROM source");
    bytes = (uint8_t *)malloc((size_t)length);
    CHECK(bytes != NULL, "allocate caller-owned diagnostic ROM");
    CHECK(fread(bytes, 1, (size_t)length, file) == (size_t)length,
        "read diagnostic ROM source");
    CHECK(fgetc(file) == EOF && fclose(file) == 0,
        "finish diagnostic ROM read");
    *size_out = (size_t)length;
    return bytes;
}

static unsigned parse_unsigned(const char *text, unsigned maximum,
    const char *label)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    CHECK(errno == 0 && end != text && *end == '\0' && parsed <= maximum,
        label);
    return (unsigned)parsed;
}

static size_t parse_route_schedule(const char *text, unsigned fields,
    route_input_event events[16])
{
    char copy[512];
    char *item;
    char *save = NULL;
    size_t count = 0u;
    unsigned previous_field = 0u;
    if (text[0] == '\0' || strcmp(text, "-") == 0)
        return 0u;
    CHECK(strlen(text) < sizeof(copy), "bounded route input schedule");
    memcpy(copy, text, strlen(text) + 1u);
    for (item = strtok_r(copy, ",", &save); item != NULL;
        item = strtok_r(NULL, ",", &save)) {
        unsigned field = 0u, id = 0u, asserted = 0u;
        char extra = '\0';
        CHECK(count < 16u, "bounded route input event count");
        CHECK(sscanf(item, "%u:%u:%u%c", &field, &id, &asserted, &extra) == 3,
            "route input event syntax");
        CHECK(field > previous_field && field <= fields,
            "ordered route input field indexes");
        CHECK((id == RETRO_DEVICE_ID_JOYPAD_START ||
            id == RETRO_DEVICE_ID_JOYPAD_RIGHT) && asserted <= 1u,
            "route input uses only scenario Start and Right events");
        events[count].field = field;
        events[count].id = id;
        events[count].asserted = asserted;
        previous_field = field;
        ++count;
    }
    CHECK(count > 0u, "nonempty route input schedule parses");
    return count;
}

static void write_route_output(FILE *video, FILE *audio, unsigned field,
    unsigned input_mask)
{
    size_t i;
    CHECK(video_calls == 1u && callback_geometry_valid && pixel_format_accepted,
        "fixture route has one valid XRGB8888 video callback per field");
    CHECK(callback_width == 256u || callback_width == 320u,
        "fixture route uses modeled H32 or H40 width");
    CHECK(callback_height == 224u && callback_video_bytes ==
        (size_t)callback_width * callback_height * sizeof(uint32_t),
        "fixture route video callback has complete bounded rows");
    CHECK(callback_pitch >= (size_t)callback_width * sizeof(uint32_t),
        "fixture route pitch covers each row");
    CHECK(callback_audio_valid && batch_calls == 1u && sample_calls == 0u &&
        audio_observed_frames > 0u && audio_observed_frames == batch_offered_frames,
        "fixture route has one complete stereo batch callback per field");
    CHECK(poll_calls == 1u && input_queries == 16u &&
        callback_input_arguments_valid && callback_polled_before_input,
        "fixture route polls both supported controller snapshots once per field");
    CHECK(fwrite(callback_video, 1u, callback_video_bytes, video) ==
        callback_video_bytes, "write bounded callback video observation");
    for (i = 0u; i < audio_observed_frames * 2u; ++i) {
        uint16_t sample = (uint16_t)callback_audio[i];
        CHECK(fputc((int)(sample & UINT16_C(0x00ff)), audio) != EOF &&
            fputc((int)(sample >> 8), audio) != EOF,
            "write canonical little-endian callback PCM");
    }
    printf("GWROUTE,field=%u,width=%u,height=%u,pitch=%zu,pixel_format=XRGB8888,video_bytes=%zu,audio_frames=%zu,poll_calls=%u,input_queries=%u,input_mask=%u\n",
        field, callback_width, callback_height, callback_pitch,
        callback_video_bytes, audio_observed_frames, poll_calls,
        input_queries, input_mask);
}

static void run_fixture_route(libretro_api *api, const char *rom_path,
    const char *field_text, const char *schedule_text, const char *output_dir)
{
    route_input_event events[16] = {{0u, 0u, 0u}};
    size_t event_count;
    size_t rom_size = 0u;
    unsigned fields = parse_unsigned(field_text, 720u,
        "fixture route field count is bounded");
    unsigned field;
    size_t next_event = 0u;
    uint8_t *rom;
    struct retro_game_info game;
    char video_path[4096];
    char audio_path[4096];
    FILE *video;
    FILE *audio;
    CHECK(fields > 0u, "fixture route field count is positive");
    event_count = parse_route_schedule(schedule_text, fields, events);
    {
        int written = snprintf(video_path, sizeof(video_path), "%s/video.raw",
            output_dir);
        CHECK(written > 0 && (size_t)written < sizeof(video_path),
            "bounded route video path");
        written = snprintf(audio_path, sizeof(audio_path), "%s/audio.s16le",
            output_dir);
        CHECK(written > 0 && (size_t)written < sizeof(audio_path),
            "bounded route PCM path");
    }
    video = fopen(video_path, "wb");
    CHECK(video != NULL, "open bounded route video scratch");
    audio = fopen(audio_path, "wb");
    CHECK(audio != NULL, "open bounded route PCM scratch");
    rom = read_content(rom_path, &rom_size);
    install_callbacks(api);
    api->init();
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    game = memory_game(rom, rom_size);
    CHECK(api->load_game(&game), "load admitted fixture bytes from caller memory");
    fixture_route_input = true;
    fixture_route_mask = 0u;
    /* Scenario frame numbers are master-tick boundaries: frame 1 is applied at
     * the start of callback field index 1, after the first field completes. */
    for (field = 0u; field < fields; ++field) {
        begin_run_observation();
        while (next_event < event_count && events[next_event].field == field) {
            unsigned bit = events[next_event].id == RETRO_DEVICE_ID_JOYPAD_START ?
                GW_BUTTON_START : GW_BUTTON_RIGHT;
            if (events[next_event].asserted != 0u)
                fixture_route_mask |= bit;
            else
                fixture_route_mask &= ~bit;
            ++next_event;
        }
        api->run();
        write_route_output(video, audio, field, fixture_route_mask);
    }
    CHECK(next_event == event_count, "all fixture route input events were delivered");
    fixture_route_input = false;
    fixture_route_mask = 0u;
    CHECK(fflush(video) == 0 && fclose(video) == 0,
        "finish bounded route video scratch");
    CHECK(fflush(audio) == 0 && fclose(audio) == 0,
        "finish bounded route PCM scratch");
    api->unload_game();
    api->deinit();
    free(rom);
    puts("PASS: source-scheduled fixture route used actual Libretro input, video and PCM callbacks");
}

static void install_callbacks(libretro_api *api)
{
    video_calls = 0;
    poll_calls = 0;
    sample_calls = 0;
    audio_frames = 0;
    pixel_format_accepted = false;
    callback_geometry_valid = true;
    callback_audio_valid = true;
    callback_input_arguments_valid = true;
    callback_polled_before_input = true;
    selected_input_port = -1;
    selected_input_id = RETRO_DEVICE_ID_JOYPAD_MASK;
    input_queries = 0;
    batch_calls = 0;
    batch_offered_frames = 0;
    batch_accepted_frames = 0;
    sample_observed_frames = 0;
    audio_observed_frames = 0;
    audio_accept_percent = 100u;
    poll_delay_microseconds = 0u;
    callback_width = 0u;
    callback_height = 0u;
    callback_pitch = 0u;
    callback_pixel_bytes = sizeof(uint32_t);
    callback_video_bytes = 0u;
    memset(callback_video, 0, sizeof(callback_video));
    memset(callback_audio, 0, sizeof(callback_audio));
    environment_accept_xrgb8888 = true;
    api->set_environment(environment_callback);
    api->set_video_refresh(video_callback);
    api->set_audio_sample(audio_callback);
    api->set_audio_sample_batch(audio_batch_callback);
    api->set_input_poll(input_poll_callback);
    api->set_input_state(input_state_callback);
}

static struct retro_game_info memory_game(const uint8_t *bytes, size_t size)
{
    struct retro_game_info game = {0};
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = bytes;
    game.size = size;
    return game;
}

static void assert_one_run(libretro_api *api, const char *label)
{
    video_calls = 0;
    poll_calls = 0;
    audio_frames = 0;
    callback_geometry_valid = true;
    callback_audio_valid = true;
    api->run();
    CHECK(video_calls == 1u, label);
    CHECK(callback_geometry_valid, "actual field geometry and byte pitch");
    CHECK(callback_audio_valid && audio_frames > 0u,
        "stereo frames delivered through batch callback");
    CHECK(poll_calls >= 1u, "input polled during run");
}

static void check_system_contract(libretro_api *api)
{
    struct retro_system_info system = {0};
    struct retro_system_av_info av = {0};
    unsigned id;

    CHECK(api->api_version() == RETRO_API_VERSION, "canonical API version");
    api->get_system_info(&system);
    CHECK(system.library_name != NULL && strcmp(system.library_name, "Genewhip") == 0,
        "system name");
    CHECK(system.valid_extensions != NULL && strcmp(system.valid_extensions, "bin|gen") == 0,
        "supported extensions");
    CHECK(!system.need_fullpath && !system.block_extract,
        "memory content and no extraction requirement");
    api->get_system_av_info(&av);
    CHECK(av.geometry.base_width == 320u && av.geometry.base_height == 224u &&
        av.geometry.max_width == 320u && av.geometry.max_height == 224u,
        "reported NTSC geometry");
    CHECK(av.timing.fps == (double)GW_MASTER_HZ / (double)GW_FIELD_TICKS,
        "reported integer-derived field rate");
    CHECK(av.timing.sample_rate == 48000.0, "reported sample rate");
    CHECK(api->get_region() == RETRO_REGION_NTSC, "NTSC region only");
    CHECK(api->serialize_size() == 0u, "serialization is unavailable");
    CHECK(!api->serialize(NULL, 0u) && !api->unserialize(NULL, 0u),
        "serialization operations reject");
    CHECK(api->get_memory_data(RETRO_MEMORY_SAVE_RAM) == NULL &&
        api->get_memory_size(RETRO_MEMORY_SAVE_RAM) == 0u,
        "save RAM is unavailable");
    for (id = RETRO_MEMORY_SYSTEM_RAM; id <= RETRO_MEMORY_ROM; ++id) {
        CHECK(api->get_memory_data(id) == NULL && api->get_memory_size(id) == 0u,
            "other memory regions are unavailable");
    }
    CHECK(!api->load_game_special(0u, NULL, 0u),
        "special content loading is unavailable");
    api->cheat_reset();
    api->cheat_set(0u, true, "inert");
    api->set_controller_port_device(0u, RETRO_DEVICE_ANALOG);
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
}

static void check_rejected_loads(libretro_api *api, const uint8_t *rom,
    size_t rom_size)
{
    struct retro_game_info game = memory_game(rom, rom_size);
    uint8_t *invalid_vectors = (uint8_t *)calloc(rom_size, 1u);
    CHECK(invalid_vectors != NULL, "allocate invalid-vector input");

    CHECK(!api->load_game(NULL), "reject null game");
    game.data = NULL;
    CHECK(!api->load_game(&game), "reject null content pointer");
    game.data = rom;
    game.size = 0u;
    CHECK(!api->load_game(&game), "reject zero-length content");
    game.size = GW_MIN_ROM_SIZE - 2u;
    CHECK(!api->load_game(&game), "reject short even content");
    game.size = rom_size - 1u;
    CHECK(!api->load_game(&game), "reject odd content length");
    game.size = (size_t)GW_MAX_ROM_SIZE + 2u;
    CHECK(!api->load_game(&game), "reject out-of-range content before reading it");
    game.data = invalid_vectors;
    game.size = rom_size;
    CHECK(!api->load_game(&game), "reject invalid reset vectors");
    free(invalid_vectors);

    video_calls = 0;
    audio_frames = 0;
    api->run();
    CHECK(video_calls == 0u && audio_frames == 0u,
        "failed load leaves no running machine or stale output");
}

static void run_smoke(libretro_api *api, const char *rom_path)
{
    size_t rom_size = 0;
    uint8_t *rom = read_content(rom_path, &rom_size);
    struct retro_game_info game;

    install_callbacks(api);
    api->init();
    CHECK(api->api_version() == RETRO_API_VERSION, "canonical API version");
    game = memory_game(rom, rom_size);
    CHECK(api->load_game(&game), "load memory-supplied diagnostic ROM");
    memset(rom, 0, rom_size);
    free(rom);
    assert_one_run(api, "one completed-field video callback");
    CHECK(pixel_format_accepted, "XRGB8888 negotiated");
    api->unload_game();
    api->deinit();
    puts("PASS: actual Libretro module loaded memory content and completed a field");
}

static void run_contract(libretro_api *api, const char *rom_path)
{
    size_t rom_size = 0;
    uint8_t *rom = read_content(rom_path, &rom_size);
    unsigned cycle;

    install_callbacks(api);
    check_system_contract(api);
    api->reset();
    api->init();
    check_rejected_loads(api, rom, rom_size);

    {
        size_t copied_size = rom_size;
        uint8_t *copied = (uint8_t *)malloc(copied_size);
        struct retro_game_info game;
        CHECK(copied != NULL, "allocate content-lifetime probe");
        memcpy(copied, rom, copied_size);
        game = memory_game(copied, copied_size);
        CHECK(api->load_game(&game),
            "inaccessible path is ignored for valid in-memory content");
        memset(copied, 0xa5, copied_size);
        free(copied);
        assert_one_run(api, "valid memory load survives caller buffer release");
    }

    {
        struct retro_game_info replacement = memory_game(rom, rom_size);
        CHECK(api->load_game(&replacement), "replace the currently loaded game");
        api->reset();
        assert_one_run(api, "console reset retains a runnable machine");
    }

    {
        struct retro_game_info bad_replacement = memory_game(NULL, rom_size);
        CHECK(!api->load_game(&bad_replacement), "reject failed replacement load");
        video_calls = 0;
        api->run();
        CHECK(video_calls == 0u,
            "failed replacement clears the owned game and previous output");
        {
            struct retro_game_info recovery = memory_game(rom, rom_size);
            CHECK(api->load_game(&recovery), "valid load recovers after failure");
            assert_one_run(api, "recovered game completes a field");
        }
    }

    api->unload_game();
    api->unload_game();
    api->deinit();
    api->deinit();
    for (cycle = 0; cycle < 32u; ++cycle) {
        struct retro_game_info game = memory_game(rom, rom_size);
        api->init();
        CHECK(api->load_game(&game), "bounded lifecycle cycle loads content");
        if ((cycle & 1u) == 0u)
            api->reset();
        api->unload_game();
        api->unload_game();
        api->deinit();
        api->deinit();
    }
    free(rom);
    puts("PASS: Libretro lifecycle, malformed recovery and capability contract");
}

typedef struct rom_writer {
    uint8_t bytes[1024];
    size_t position;
} rom_writer;

typedef struct field_observation {
    unsigned width;
    unsigned height;
    uint32_t source_pitch;
    size_t pcm_frames;
    uint8_t pixels[320u * 224u * sizeof(uint32_t)];
    int16_t pcm[GW_AUDIO_QUEUE_FRAMES * 2u];
} field_observation;

typedef struct pad_probe {
    unsigned retro_id;
    uint32_t gw_mask;
    unsigned pin;
    bool th_low;
} pad_probe;

static void check_probe_is_visible(const field_observation *observation);

static const pad_probe supported_pads[] = {
    {RETRO_DEVICE_ID_JOYPAD_UP, GW_BUTTON_UP, 0u, false},
    {RETRO_DEVICE_ID_JOYPAD_DOWN, GW_BUTTON_DOWN, 1u, false},
    {RETRO_DEVICE_ID_JOYPAD_LEFT, GW_BUTTON_LEFT, 2u, false},
    {RETRO_DEVICE_ID_JOYPAD_RIGHT, GW_BUTTON_RIGHT, 3u, false},
    {RETRO_DEVICE_ID_JOYPAD_B, GW_BUTTON_B, 4u, false},
    {RETRO_DEVICE_ID_JOYPAD_Y, GW_BUTTON_A, 4u, true},
    {RETRO_DEVICE_ID_JOYPAD_A, GW_BUTTON_C, 5u, false},
    {RETRO_DEVICE_ID_JOYPAD_START, GW_BUTTON_START, 5u, true}
};

static void rom_emit16(rom_writer *writer, uint32_t value)
{
    CHECK(writer->position + 2u <= sizeof(writer->bytes), "input ROM word bound");
    writer->bytes[writer->position++] = (uint8_t)(value >> 8);
    writer->bytes[writer->position++] = (uint8_t)value;
}

static void rom_emit32(rom_writer *writer, uint32_t value)
{
    rom_emit16(writer, value >> 16);
    rom_emit16(writer, value & UINT32_C(0xffff));
}

static void rom_move_w_immediate(rom_writer *writer, uint32_t value,
    uint32_t address)
{
    rom_emit16(writer, UINT32_C(0x33fc)); /* MOVE.W #imm,(xxx).L */
    rom_emit16(writer, value);
    rom_emit32(writer, address);
}

static void rom_move_l_immediate(rom_writer *writer, uint32_t value,
    uint32_t address)
{
    rom_emit16(writer, UINT32_C(0x23fc)); /* MOVE.L #imm,(xxx).L */
    rom_emit32(writer, value);
    rom_emit32(writer, address);
}

static void rom_move_b_immediate(rom_writer *writer, uint32_t value,
    uint32_t address)
{
    rom_emit16(writer, UINT32_C(0x13fc)); /* MOVE.B #imm,(xxx).L */
    rom_emit16(writer, value);
    rom_emit32(writer, address);
}

static void build_pad_probe_rom(uint8_t *rom, unsigned port,
    const pad_probe *probe, bool h40)
{
    const uint32_t data_address = port == 0u
        ? UINT32_C(0x00a10003) : UINT32_C(0x00a10005);
    const uint32_t ctrl0 = UINT32_C(0x00a10009);
    const uint32_t ctrl1 = UINT32_C(0x00a1000b);
    const uint32_t data0 = UINT32_C(0x00a10003);
    const uint32_t data1 = UINT32_C(0x00a10005);
    rom_writer writer = {0};
    size_t bne_position;
    size_t bra_position;
    size_t unpressed_position;
    size_t loop_position;
    int displacement;

    CHECK(port < 2u && probe != NULL, "valid probe selection");
    rom_emit32(&writer, UINT32_C(0x00ffff00));
    rom_emit32(&writer, UINT32_C(0x00000200));
    writer.position = 0x200u;
    rom_move_w_immediate(&writer, UINT32_C(0x8144), UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, h40 ? UINT32_C(0x8c81) : UINT32_C(0x8c00),
        UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x8f02), UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x8701), UINT32_C(0x00c00004));
    rom_move_b_immediate(&writer, UINT32_C(0x40), ctrl0);
    rom_move_b_immediate(&writer, UINT32_C(0x40), ctrl1);
    rom_move_b_immediate(&writer, probe->th_low ? 0u : UINT32_C(0x40), data0);
    rom_move_b_immediate(&writer, probe->th_low ? 0u : UINT32_C(0x40), data1);

    loop_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x1039)); /* MOVE.B data_port,D0 */
    rom_emit32(&writer, data_address);
    rom_emit16(&writer, UINT32_C(0x0800)); /* BTST #pin,D0 */
    rom_emit16(&writer, probe->pin);
    bne_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x6600)); /* BNE.S unpressed */
    rom_emit16(&writer, UINT32_C(0x23fc)); /* Pressed => blue=1. */
    rom_emit32(&writer, UINT32_C(0xc0020000));
    rom_emit32(&writer, UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x0002), UINT32_C(0x00c00000));
    bra_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x6000)); /* BRA.S loop */
    rom_emit16(&writer, 0u);
    unpressed_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x23fc)); /* Released => black. */
    rom_emit32(&writer, UINT32_C(0xc0020000));
    rom_emit32(&writer, UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, 0u, UINT32_C(0x00c00000));
    {
        size_t unpressed_bra = writer.position;
        rom_emit16(&writer, UINT32_C(0x6000));
        rom_emit16(&writer, 0u);
        displacement = (int)unpressed_position - (int)(bne_position + 2u);
        CHECK(displacement >= -128 && displacement <= 127,
            "input probe BNE displacement fits short branch");
        writer.bytes[bne_position + 1u] = (uint8_t)displacement;
        displacement = (int)loop_position - (int)(unpressed_bra + 2u);
        CHECK(displacement >= -128 && displacement <= 127,
            "input probe unpressed branch fits short branch");
        writer.bytes[unpressed_bra + 1u] = (uint8_t)displacement;
    }
    displacement = (int)loop_position - (int)(bra_position + 2u);
    CHECK(displacement >= -128 && displacement <= 127,
        "input probe pressed branch fits short branch");
    writer.bytes[bra_position + 1u] = (uint8_t)displacement;
    memcpy(rom, writer.bytes, sizeof(writer.bytes));
}

static void replace_probe_color(uint8_t *rom, uint16_t color)
{
    static const uint8_t pattern[] = {
        0x33u, 0xfcu, 0x00u, 0x02u, 0x00u, 0xc0u, 0x00u, 0x00u
    };
    size_t i;
    unsigned found = 0u;
    for (i = 0; i + sizeof(pattern) <= 1024u; ++i) {
        if (memcmp(rom + i, pattern, sizeof(pattern)) == 0) {
            rom[i + 2u] = (uint8_t)(color >> 8);
            rom[i + 3u] = (uint8_t)color;
            ++found;
        }
    }
    CHECK(found == 1u, "replace exactly one authored input-probe color");
}

static void build_sticky_stop_rom(uint8_t *rom, bool h40)
{
    rom_writer writer = {0};
    size_t loop_position;
    size_t dbra_position;
    int displacement;

    rom_emit32(&writer, UINT32_C(0x00ffff00));
    rom_emit32(&writer, UINT32_C(0x00000200));
    writer.position = 0x200u;
    rom_move_w_immediate(&writer, UINT32_C(0x8144), UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, h40 ? UINT32_C(0x8c81) : UINT32_C(0x8c00),
        UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x8f02), UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x8701), UINT32_C(0x00c00004));
    rom_move_l_immediate(&writer, UINT32_C(0xc0020000), UINT32_C(0x00c00004));
    rom_move_w_immediate(&writer, UINT32_C(0x0e2a), UINT32_C(0x00c00000));
    rom_emit16(&writer, UINT32_C(0x303c)); /* MOVE.W #20000,D0 */
    rom_emit16(&writer, UINT32_C(20000));
    loop_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x4e71)); /* NOP */
    dbra_position = writer.position;
    rom_emit16(&writer, UINT32_C(0x51c8)); /* DBRA D0,loop */
    displacement = (int)loop_position - (int)(dbra_position + 2u);
    CHECK(displacement >= INT16_MIN && displacement <= INT16_MAX,
        "sticky-stop DBRA displacement fits word branch");
    rom_emit16(&writer, (uint16_t)displacement);
    rom_emit16(&writer, UINT32_C(0xc140)); /* EXG D0,D0: legal, unsupported here */
    memcpy(rom, writer.bytes, sizeof(writer.bytes));
}

static gw_machine *reference_machine(const uint8_t *rom, size_t rom_size)
{
    gw_config config = {0};
    gw_machine *machine = NULL;
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.port_device[0] = GW_DEVICE_PAD3;
    config.port_device[1] = GW_DEVICE_PAD3;
    config.audio_rate_hz = UINT32_C(48000);
    CHECK(gw_create(&config, &machine) == GW_OK,
        "create independent public-core reference");
    CHECK(gw_load_rom(machine, rom, rom_size) == GW_OK,
        "load input diagnostic into independent reference");
    return machine;
}

static void reference_field(gw_machine *machine, uint32_t port0_mask,
    uint32_t port1_mask, uint64_t *audio_total, field_observation *observation)
{
    gw_diagnostic_record diagnostics = {0};
    gw_run_result result = {0};
    gw_video_field field = {0};
    gw_audio_read_result audio = {0};
    const uint32_t masks[2] = {port0_mask, port1_mask};
    const uint32_t ports[2] = {0u, 1u};
    const uint32_t *pixels = NULL;
    int16_t audio_samples[GW_AUDIO_QUEUE_FRAMES * 2u];
    unsigned i;

    diagnostics.struct_size = sizeof(diagnostics);
    diagnostics.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(machine, &diagnostics) == GW_OK,
        "read reference tick before scheduling input");
    for (i = 0; i < 2u; ++i) {
        gw_event event = {0};
        event.struct_size = sizeof(event);
        event.version = GW_API_VERSION;
        event.tick = diagnostics.tick;
        event.type = GW_EVENT_PAD_STATE;
        event.port = ports[i];
        event.mask = masks[i];
        CHECK(gw_schedule_event(machine, &event) == GW_OK,
            "schedule independent reference input");
    }
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    {
        gw_status status = gw_run_until(machine,
            diagnostics.tick + GW_FIELD_TICKS, &result);
        if (status != GW_OK || result.stop_reason != GW_STOP_FIELD_COMPLETE) {
            fprintf(stderr,
                "reference field debug: status=%u reason=%u requested=%llu actual=%llu\n",
                status, result.stop_reason,
                (unsigned long long)result.requested_tick,
                (unsigned long long)result.actual_tick);
            fprintf(stderr,
                "reference fault debug: pc=%06x opcode=%04x fault=%06x\n",
                result.instruction_address, result.opcode, result.fault_address);
        }
        CHECK(status == GW_OK && result.stop_reason == GW_STOP_FIELD_COMPLETE,
            "reference completes one field using integer ticks");
    }
    field.struct_size = sizeof(field);
    field.version = GW_API_VERSION;
    CHECK(gw_get_video_field(machine, &field, &pixels) == GW_OK && pixels != NULL,
        "read independent reference field");
    CHECK(field.width <= 320u && field.height == 224u &&
        field.pitch_bytes >= field.width * sizeof(uint32_t),
        "reference field has bounded dimensions and pitch");
    observation->width = field.width;
    observation->height = field.height;
    observation->source_pitch = field.pitch_bytes;
    for (i = 0; i < field.height; ++i) {
        memcpy(observation->pixels + (size_t)i * field.width * sizeof(uint32_t),
            (const uint8_t *)pixels + (size_t)i * field.pitch_bytes,
            (size_t)field.width * sizeof(uint32_t));
    }
    audio.struct_size = sizeof(audio);
    audio.version = GW_API_VERSION;
    CHECK(gw_audio_read(machine, audio_samples, GW_AUDIO_QUEUE_FRAMES, &audio) == GW_OK &&
        audio.lost == 0u && audio.produced <= GW_AUDIO_QUEUE_FRAMES,
        "drain independent reference stereo frames");
    CHECK(audio.first_index == *audio_total,
        "reference stereo sample indices remain continuous");
    observation->pcm_frames = audio.produced;
    memcpy(observation->pcm, audio_samples,
        (size_t)audio.produced * 2u * sizeof(int16_t));
    *audio_total += audio.produced;
    CHECK(*audio_total == (result.actual_tick * UINT64_C(48000)) / GW_MASTER_HZ,
        "cumulative reference PCM frames follow integer core ticks");
}

static void begin_run_observation(void)
{
    video_calls = 0;
    poll_calls = 0;
    sample_calls = 0;
    audio_frames = 0;
    input_queries = 0;
    batch_calls = 0;
    batch_offered_frames = 0;
    batch_accepted_frames = 0;
    sample_observed_frames = 0;
    audio_observed_frames = 0;
    callback_geometry_valid = true;
    callback_audio_valid = true;
    callback_input_arguments_valid = true;
    callback_polled_before_input = true;
    callback_video_bytes = 0u;
    memset(callback_video, 0, sizeof(callback_video));
    memset(callback_audio, 0, sizeof(callback_audio));
}

static void compare_xrgb_video(const field_observation *expected)
{
    unsigned y;
    CHECK(video_calls == 1u, "one video callback for a completed field");
    CHECK(callback_geometry_valid && callback_width == expected->width &&
        callback_height == expected->height,
        "callback uses current field geometry");
    CHECK(callback_pitch == expected->source_pitch,
        "XRGB callback reports the core field byte pitch");
    CHECK(callback_pixel_bytes == sizeof(uint32_t) &&
        callback_video_bytes == (size_t)expected->width * expected->height * sizeof(uint32_t),
        "XRGB callback carries a complete bounded image");
    for (y = 0; y < expected->height; ++y) {
        size_t row_bytes = (size_t)expected->width * sizeof(uint32_t);
        CHECK(memcmp(callback_video + (size_t)y * row_bytes,
            expected->pixels + (size_t)y * row_bytes, row_bytes) == 0,
            "video callback bytes match independent public-core output");
    }
}

static void compare_xrgb_output(const field_observation *expected)
{
    compare_xrgb_video(expected);
    CHECK(callback_audio_valid && batch_calls == 1u &&
        batch_offered_frames == expected->pcm_frames &&
        audio_observed_frames == expected->pcm_frames,
        "one bounded batch delivers the independent field's stereo frame count");
    CHECK(memcmp(callback_audio, expected->pcm,
        expected->pcm_frames * 2u * sizeof(int16_t)) == 0,
        "stereo PCM order matches independent public-core output");
    CHECK(poll_calls == 1u && input_queries == 16u &&
        callback_input_arguments_valid && callback_polled_before_input,
        "one poll precedes complete supported pad snapshots for both ports");
}

static void run_input_case(libretro_api *api, unsigned port,
    const pad_probe *probe, bool h40, unsigned batch_percent, unsigned delivery_mode,
    unsigned delay_microseconds, field_observation *last_observation)
{
    uint8_t rom[1024];
    struct retro_game_info game = {0};
    gw_machine *reference;
    uint64_t reference_audio_total = 0u;
    field_observation expected = {0};
    unsigned field_number;

    build_pad_probe_rom(rom, port, probe, h40);
    install_callbacks(api);
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    selected_input_port = (int)port;
    selected_input_id = probe->retro_id;
    audio_accept_percent = batch_percent;
    poll_delay_microseconds = delay_microseconds;
    if (delivery_mode == 1u) {
        api->set_audio_sample_batch(NULL);
    } else if (delivery_mode == 2u) {
        api->set_audio_sample_batch(NULL);
        api->set_audio_sample(NULL);
    }
    api->init();
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = rom;
    game.size = sizeof(rom);
    CHECK(api->load_game(&game), "load original input echo diagnostic from memory");
    reference = reference_machine(rom, sizeof(rom));

    for (field_number = 0; field_number < 2u; ++field_number) {
        if (delivery_mode == 2u && field_number == 1u) {
            api->set_video_refresh(video_callback);
            api->set_audio_sample_batch(audio_batch_callback);
        } else if (delivery_mode == 2u) {
            api->set_video_refresh(NULL);
        }
        begin_run_observation();
        api->run();
        reference_field(reference,
            port == 0u ? probe->gw_mask : 0u,
            port == 1u ? probe->gw_mask : 0u,
            &reference_audio_total, &expected);
        if (delivery_mode == 2u && field_number == 0u) {
            CHECK(video_calls == 0u && batch_calls == 0u && sample_calls == 0u,
                "missing video and audio callbacks are safe and discard bounded PCM");
        } else if (delivery_mode == 1u) {
            compare_xrgb_video(&expected);
            CHECK(callback_audio_valid && batch_calls == 0u &&
                sample_calls == expected.pcm_frames &&
                sample_observed_frames == expected.pcm_frames,
                "per-sample fallback emits each stereo frame finitely");
            CHECK(memcmp(callback_audio, expected.pcm,
                expected.pcm_frames * 2u * sizeof(int16_t)) == 0,
                "per-sample fallback preserves ordered left/right PCM");
            CHECK(poll_calls == 1u && input_queries == 16u &&
                callback_input_arguments_valid && callback_polled_before_input,
                "sample fallback retains input poll and snapshot ordering");
        } else {
            compare_xrgb_output(&expected);
        }
        if (field_number == 1u) {
            CHECK(expected.width == (h40 ? 320u : 256u),
                "H32 and H40 callback widths follow guest VDP mode");
            if (!h40) {
                CHECK(expected.source_pitch == 320u * sizeof(uint32_t),
                    "H32 reports the actual 1280-byte native core pitch");
            } else {
                CHECK(expected.source_pitch == expected.width * sizeof(uint32_t),
                    "H40 reports its actual core row pitch");
            }
            check_probe_is_visible(&expected);
            if (last_observation != NULL) {
                *last_observation = expected;
            }
        }
        CHECK(batch_accepted_frames ==
            (batch_offered_frames * batch_percent) / 100u,
            "bounded partial or complete batch acceptance is reported once");
    }
    gw_destroy(reference);
    api->unload_game();
    api->deinit();
}

static void run_unsupported_controller_case(libretro_api *api)
{
    uint8_t rom[1024];
    struct retro_game_info game = {0};
    gw_machine *reference;
    uint64_t reference_audio_total = 0u;
    field_observation expected = {0};
    unsigned field_number;

    build_pad_probe_rom(rom, 0u, &supported_pads[5], false);
    install_callbacks(api);
    api->set_controller_port_device(0u, RETRO_DEVICE_ANALOG);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    selected_input_port = 0;
    selected_input_id = RETRO_DEVICE_ID_JOYPAD_Y;
    api->init();
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = rom;
    game.size = sizeof(rom);
    CHECK(api->load_game(&game), "load unsupported-device diagnostic");
    reference = reference_machine(rom, sizeof(rom));
    for (field_number = 0; field_number < 2u; ++field_number) {
        begin_run_observation();
        api->run();
        reference_field(reference, 0u, 0u, &reference_audio_total, &expected);
        compare_xrgb_video(&expected);
        CHECK(callback_audio_valid && batch_calls == 1u &&
            batch_offered_frames == expected.pcm_frames &&
            audio_observed_frames == expected.pcm_frames &&
            memcmp(callback_audio, expected.pcm,
                expected.pcm_frames * 2u * sizeof(int16_t)) == 0,
            "unsupported device does not change stereo output");
        CHECK(poll_calls == 1u && input_queries == 8u &&
            callback_input_arguments_valid && callback_polled_before_input,
            "analog device is neutral and input is sampled only on the Joypad port");
    }
    gw_destroy(reference);
    api->unload_game();
    api->deinit();
}

static void check_probe_is_visible(const field_observation *observation)
{
    size_t i;
    size_t count = (size_t)observation->width * observation->height;
    const uint32_t visible_red = UINT32_C(0x00310000);
    for (i = 0; i < count; ++i) {
        uint32_t pixel;
        memcpy(&pixel, observation->pixels + i * sizeof(pixel), sizeof(pixel));
        if (pixel == visible_red)
            return;
    }
    CHECK(false, "the selected mapped button changes the guest-visible backdrop");
}

static void run_callbacks(libretro_api *api)
{
    unsigned port;
    size_t button;
    field_observation delayed = {0};
    field_observation partial = {0};
    field_observation complete = {0};

    for (port = 0; port < 2u; ++port) {
        for (button = 0; button < sizeof(supported_pads) / sizeof(supported_pads[0]); ++button) {
            run_input_case(api, port, &supported_pads[button], false, 100u, 0u,
                0u, NULL);
        }
    }

    run_input_case(api, 0u, &supported_pads[3], true, 100u, 0u, 0u, NULL);
    run_input_case(api, 0u, &supported_pads[5], false, 100u, 0u, 0u, &complete);
    run_input_case(api, 0u, &supported_pads[5], false, 50u, 0u, 1000u, &partial);
    CHECK(memcmp(complete.pixels, partial.pixels,
        (size_t)complete.width * complete.height * sizeof(uint32_t)) == 0,
        "frontend delay and partial batch acceptance do not change the guest image");
    CHECK(complete.pcm_frames == partial.pcm_frames &&
        memcmp(complete.pcm, partial.pcm,
            complete.pcm_frames * 2u * sizeof(int16_t)) == 0,
        "frontend delay and partial batch acceptance do not change offered PCM");
    run_input_case(api, 0u, &supported_pads[5], false, 0u, 0u, 0u, &delayed);
    CHECK(delayed.pcm_frames == partial.pcm_frames &&
        memcmp(delayed.pixels, partial.pixels,
            (size_t)delayed.width * delayed.height * sizeof(uint32_t)) == 0 &&
        memcmp(delayed.pcm, partial.pcm,
            delayed.pcm_frames * 2u * sizeof(int16_t)) == 0,
        "zero-accepted batches terminate and preserve guest execution");

    run_input_case(api, 0u, &supported_pads[5], false, 100u, 1u, 0u, NULL);
    run_input_case(api, 0u, &supported_pads[5], false, 100u, 2u, 0u, NULL);
    run_unsupported_controller_case(api);

    puts("PASS: Libretro callback input, field, pitch and integer stereo timing");
}

static uint16_t convert_xrgb_oracle(uint32_t pixel)
{
    uint16_t red = (uint16_t)((pixel >> 19) & UINT32_C(0x1f));
    uint16_t green = (uint16_t)((pixel >> 11) & UINT32_C(0x1f));
    uint16_t blue = (uint16_t)((pixel >> 3) & UINT32_C(0x1f));
    return (uint16_t)((red << 10) | (green << 5) | blue);
}

static void run_pixel_conversion_case(libretro_api *api, uint16_t color,
    bool h40, bool environment_missing)
{
    uint8_t rom[1024];
    struct retro_game_info game = {0};
    gw_machine *reference;
    uint64_t reference_audio_total = 0u;
    field_observation expected = {0};
    unsigned field_number;

    build_pad_probe_rom(rom, 0u, &supported_pads[3], h40);
    replace_probe_color(rom, color);
    install_callbacks(api);
    environment_accept_xrgb8888 = false;
    if (environment_missing)
        api->set_environment(NULL);
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    selected_input_port = 0;
    selected_input_id = RETRO_DEVICE_ID_JOYPAD_RIGHT;
    api->init();
    CHECK(!pixel_format_accepted,
        "rejected or absent pixel negotiation selects the default format");
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = rom;
    game.size = sizeof(rom);
    CHECK(api->load_game(&game), "load pixel-conversion diagnostic from memory");
    reference = reference_machine(rom, sizeof(rom));

    for (field_number = 0; field_number < 2u; ++field_number) {
        size_t row_bytes;
        size_t pixels;
        size_t i;
        begin_run_observation();
        api->run();
        reference_field(reference, GW_BUTTON_RIGHT, 0u,
            &reference_audio_total, &expected);
        CHECK(video_calls == 1u && callback_geometry_valid &&
            callback_width == expected.width && callback_height == expected.height,
            "converted callback keeps the actual field geometry");
        CHECK(callback_pixel_bytes == sizeof(uint16_t) &&
            callback_pitch == (size_t)expected.width * sizeof(uint16_t),
            "0RGB1555 callback reports a bounded converted row pitch");
        CHECK(callback_video_bytes == (size_t)expected.width * expected.height *
            sizeof(uint16_t), "converted image contains every active pixel");
        row_bytes = (size_t)expected.width * sizeof(uint16_t);
        pixels = (size_t)expected.width * expected.height;
        for (i = 0; i < pixels; ++i) {
            uint32_t source_pixel;
            uint16_t actual_pixel;
            memcpy(&source_pixel, expected.pixels + i * sizeof(source_pixel),
                sizeof(source_pixel));
            memcpy(&actual_pixel, callback_video + i * sizeof(actual_pixel),
                sizeof(actual_pixel));
            CHECK(actual_pixel == convert_xrgb_oracle(source_pixel),
                "0RGB1555 channel values match the independent conversion oracle");
        }
        CHECK(callback_audio_valid && batch_calls == 1u &&
            batch_offered_frames == expected.pcm_frames &&
            audio_observed_frames == expected.pcm_frames &&
            memcmp(callback_audio, expected.pcm,
                expected.pcm_frames * 2u * sizeof(int16_t)) == 0,
            "pixel negotiation does not change independent stereo output");
        CHECK(callback_pitch == row_bytes,
            "conversion does not expose the wider borrowed source stride");
        if (field_number == 1u) {
            CHECK(expected.width == (h40 ? 320u : 256u),
                "converted H32/H40 callback uses the current VDP width");
            CHECK(expected.source_pitch == 320u * sizeof(uint32_t),
                "converted H32 and H40 paths read the fixed-width core rows safely");
        }
    }
    gw_destroy(reference);
    api->unload_game();
    api->deinit();
}

static void reference_discard_audio(gw_machine *machine, uint64_t *audio_total)
{
    gw_diagnostic_record diagnostics = {0};
    gw_audio_read_result audio = {0};
    int16_t output[GW_AUDIO_QUEUE_FRAMES * 2u];
    diagnostics.struct_size = sizeof(diagnostics);
    diagnostics.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(machine, &diagnostics) == GW_OK,
        "read terminal reference diagnostics");
    audio.struct_size = sizeof(audio);
    audio.version = GW_API_VERSION;
    CHECK(gw_audio_read(machine, output, GW_AUDIO_QUEUE_FRAMES, &audio) == GW_OK &&
        audio.lost == 0u && audio.produced <= GW_AUDIO_QUEUE_FRAMES &&
        audio.first_index == *audio_total,
        "discard incomplete terminal field PCM once without loss");
    *audio_total += audio.produced;
    CHECK(*audio_total == (diagnostics.tick * UINT64_C(48000)) / GW_MASTER_HZ,
        "terminal PCM discard preserves integer audio index progression");
}

static void assert_terminal_image(const field_observation *last,
    bool terminal_was_reached_during_this_run)
{
    unsigned y;
    size_t row_bytes = (size_t)last->width * sizeof(uint32_t);
    CHECK(video_calls == 1u && callback_geometry_valid &&
        callback_width == last->width && callback_height == last->height &&
        callback_pitch == (size_t)last->width * sizeof(uint32_t) &&
        callback_pixel_bytes == sizeof(uint32_t),
        "sticky stop emits one tightly packed repeat with last-complete geometry");
    for (y = 0; y < last->height; ++y) {
        CHECK(memcmp(callback_video + (size_t)y * row_bytes,
            last->pixels + (size_t)y * row_bytes, row_bytes) == 0,
            "sticky stop repeats the cached complete image byte-for-byte");
    }
    CHECK(batch_calls == 0u && sample_calls == 0u && audio_observed_frames == 0u,
        "sticky stop emits no new audio");
    CHECK(poll_calls == 1u &&
        input_queries == (terminal_was_reached_during_this_run ? 16u : 0u),
        "sticky stop does not query input after the terminal condition is known");
}

static void run_sticky_stop_case(libretro_api *api)
{
    uint8_t rom[1024];
    struct retro_game_info game = {0};
    gw_machine *reference;
    uint64_t reference_audio_total = 0u;
    field_observation expected = {0};
    field_observation last = {0};
    unsigned i;

    build_sticky_stop_rom(rom, false);
    install_callbacks(api);
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    api->init();
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = rom;
    game.size = sizeof(rom);
    CHECK(api->load_game(&game), "load bounded unsupported-stop diagnostic");
    reference = reference_machine(rom, sizeof(rom));

    for (i = 0; i < 2u; ++i) {
        begin_run_observation();
        api->run();
        reference_field(reference, 0u, 0u, &reference_audio_total, &expected);
        compare_xrgb_output(&expected);
        last = expected;
    }

    {
        gw_diagnostic_record before = {0};
        gw_diagnostic_record after = {0};
        gw_run_result result = {0};
        before.struct_size = sizeof(before);
        before.version = GW_API_VERSION;
        CHECK(gw_get_diagnostics(reference, &before) == GW_OK,
            "read core tick before unsupported field");
        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        CHECK(gw_run_until(reference, before.tick + GW_FIELD_TICKS, &result) == GW_OK &&
            result.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION,
            "reference reaches the authored unsupported instruction after complete fields");
        after.struct_size = sizeof(after);
        after.version = GW_API_VERSION;
        CHECK(gw_get_diagnostics(reference, &after) == GW_OK &&
            after.tick == result.actual_tick && after.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION,
            "unsupported stop is visible at its stable core tick");
        reference_discard_audio(reference, &reference_audio_total);

        begin_run_observation();
        api->run();
        assert_terminal_image(&last, true);
    }

    {
        gw_diagnostic_record before = {0};
        gw_diagnostic_record after = {0};
        gw_run_result result = {0};
        before.struct_size = sizeof(before);
        before.version = GW_API_VERSION;
        CHECK(gw_get_diagnostics(reference, &before) == GW_OK,
            "read core tick before sticky retry");
        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        CHECK(gw_run_until(reference, before.tick + GW_FIELD_TICKS, &result) == GW_OK &&
            result.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION &&
            result.actual_tick == before.tick,
            "a later run does not step the sticky core");
        after.struct_size = sizeof(after);
        after.version = GW_API_VERSION;
        CHECK(gw_get_diagnostics(reference, &after) == GW_OK && after.tick == before.tick,
            "sticky retry leaves emulated time unchanged");
        begin_run_observation();
        api->run();
        assert_terminal_image(&last, false);
    }

    CHECK(gw_console_reset(reference) == GW_OK,
        "public-core console reset clears the terminal stop");
    api->reset();
    begin_run_observation();
    api->run();
    reference_field(reference, 0u, 0u, &reference_audio_total, &expected);
    compare_xrgb_output(&expected);
    gw_destroy(reference);
    api->unload_game();
    api->deinit();
}

static void run_blank_then_reload_case(libretro_api *api)
{
    uint8_t unsupported_rom[1024];
    uint8_t working_rom[1024];
    struct retro_game_info game = {0};
    gw_machine *reference;
    uint64_t audio_total = 0u;
    field_observation expected = {0};
    unsigned i;

    build_pad_probe_rom(unsupported_rom, 0u, &supported_pads[3], false);
    unsupported_rom[0x200u] = 0xc1u;
    unsupported_rom[0x201u] = 0x40u;
    install_callbacks(api);
    selected_input_port = 0;
    selected_input_id = supported_pads[3].retro_id;
    api->set_controller_port_device(0u, RETRO_DEVICE_JOYPAD);
    api->set_controller_port_device(1u, RETRO_DEVICE_JOYPAD);
    api->init();
    game.path = "__genewhip_intentionally_missing_rom__.bin";
    game.data = unsupported_rom;
    game.size = sizeof(unsupported_rom);
    CHECK(api->load_game(&game), "load first-instruction unsupported diagnostic");
    for (i = 0; i < 2u; ++i) {
        size_t pixel;
        begin_run_observation();
        api->run();
        CHECK(video_calls == 1u && callback_width == 320u &&
            callback_height == 224u && callback_pitch == 320u * sizeof(uint32_t),
            "pre-field terminal stop uses bounded maximum blank geometry");
        CHECK(callback_audio_valid && batch_calls == 0u && sample_calls == 0u,
            "pre-field terminal stop emits no audio");
        for (pixel = 0; pixel < 320u * 224u; ++pixel) {
            uint32_t value;
            memcpy(&value, callback_video + pixel * sizeof(value), sizeof(value));
            CHECK(value == 0u, "pre-field terminal stop emits deterministic blank pixels");
        }
        CHECK(poll_calls == 1u && input_queries == (i == 0u ? 16u : 0u),
            "first stop-detection run samples pads; sticky retries do not");
    }

    build_pad_probe_rom(working_rom, 0u, &supported_pads[3], false);
    game.data = working_rom;
    game.size = sizeof(working_rom);
    CHECK(api->load_game(&game), "valid replacement recovers from the blank terminal stop");
    reference = reference_machine(working_rom, sizeof(working_rom));
    begin_run_observation();
    api->run();
    reference_field(reference, GW_BUTTON_RIGHT, 0u, &audio_total, &expected);
    compare_xrgb_output(&expected);
    gw_destroy(reference);
    api->unload_game();
    api->deinit();
}

static void run_pixels_stop(libretro_api *api)
{
    static const uint16_t colors[] = {
        0x0000u, 0x000eu, 0x00e0u, 0x0e00u, 0x0eeeu, 0x0e2au
    };
    size_t i;
    for (i = 0; i < sizeof(colors) / sizeof(colors[0]); ++i)
        run_pixel_conversion_case(api, colors[i], false, false);
    run_pixel_conversion_case(api, UINT16_C(0x0e2a), true, false);
    run_pixel_conversion_case(api, UINT16_C(0x0eee), true, true);
    run_sticky_stop_case(api);
    run_blank_then_reload_case(api);
    puts("PASS: bounded 0RGB1555 conversion, sticky stop and recovery");
}

int main(int argc, char **argv)
{
    static const char *const mandatory_exports[] = {
        "retro_set_environment", "retro_set_video_refresh", "retro_set_audio_sample",
        "retro_set_audio_sample_batch", "retro_set_input_poll", "retro_set_input_state",
        "retro_init", "retro_deinit", "retro_api_version", "retro_get_system_info",
        "retro_get_system_av_info", "retro_set_controller_port_device", "retro_reset",
        "retro_run", "retro_serialize_size", "retro_serialize", "retro_unserialize",
        "retro_cheat_reset", "retro_cheat_set", "retro_load_game",
        "retro_load_game_special", "retro_unload_game", "retro_get_region",
        "retro_get_memory_data", "retro_get_memory_size"
    };
    void *library;
    size_t i;
    libretro_api api = {0};

    if (argc < 2 || argc > 7)
        CHECK(false, "usage: libretro_host MODE SHARED_OBJECT ROM [FIELDS SCHEDULE OUTPUT_DIR]");
    CHECK((strcmp(argv[1], "fixture-route") == 0 && argc == 7) ||
        (strcmp(argv[1], "fixture-route") != 0 && argc == 4),
        "mode has the expected bounded arguments");
    library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        const char *error = dlerror();
        fprintf(stderr, "FAIL: dlopen actual core: %s\n",
            error != NULL ? error : "unknown loader error");
        return 1;
    }
    for (i = 0; i < sizeof(mandatory_exports) / sizeof(mandatory_exports[0]); ++i)
        (void)required_symbol(library, mandatory_exports[i]);
    resolve_api(library, &api);

    if (strcmp(argv[1], "smoke") == 0)
        run_smoke(&api, argv[3]);
    else if (strcmp(argv[1], "contract") == 0)
        run_contract(&api, argv[3]);
    else if (strcmp(argv[1], "callbacks") == 0)
        run_callbacks(&api);
    else if (strcmp(argv[1], "pixels-stop") == 0)
        run_pixels_stop(&api);
    else if (strcmp(argv[1], "fixture-route") == 0)
        run_fixture_route(&api, argv[3], argv[4], argv[5], argv[6]);
    else
        CHECK(false, "mode must be smoke, contract, callbacks, pixels-stop or fixture-route");

    CHECK(dlclose(library) == 0, "close actual shared object");
    return 0;
}
