/* SPDX-License-Identifier: MIT
 * Private synchronous Libretro adapter for the Genewhip C17 core. */
#include "libretro.h"
#include "genewhip/genewhip.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define GW_LIBRETRO_AUDIO_RATE UINT32_C(48000)
#define GW_LIBRETRO_MAX_WIDTH UINT32_C(320)
#define GW_LIBRETRO_MAX_PIXELS ((size_t)GW_LIBRETRO_MAX_WIDTH * GW_ACTIVE_LINES)

static retro_environment_t environment_callback;
static retro_video_refresh_t video_callback;
static retro_audio_sample_t audio_sample_callback;
static retro_audio_sample_batch_t audio_batch_callback;
static retro_input_poll_t input_poll_callback;
static retro_input_state_t input_state_callback;

static gw_machine *owned_machine;
static unsigned controller_devices[2] = {
    RETRO_DEVICE_JOYPAD, RETRO_DEVICE_JOYPAD
};
static bool initialized;
static bool use_xrgb8888;
static bool run_failed;
static bool have_last_frame;
static unsigned last_width = GW_LIBRETRO_MAX_WIDTH;
static unsigned last_height = GW_ACTIVE_LINES;
static uint64_t next_audio_index;
static uint32_t last_pixels[GW_LIBRETRO_MAX_PIXELS];
static uint32_t blank_pixels[GW_LIBRETRO_MAX_PIXELS];
static uint16_t converted_pixels[GW_LIBRETRO_MAX_PIXELS];
static int16_t audio_buffer[(size_t)GW_AUDIO_QUEUE_FRAMES * 2u];

typedef struct pad_button_map {
    unsigned retro_id;
    uint32_t gw_mask;
} pad_button_map;

static const pad_button_map pad_buttons[] = {
    {RETRO_DEVICE_ID_JOYPAD_UP, GW_BUTTON_UP},
    {RETRO_DEVICE_ID_JOYPAD_DOWN, GW_BUTTON_DOWN},
    {RETRO_DEVICE_ID_JOYPAD_LEFT, GW_BUTTON_LEFT},
    {RETRO_DEVICE_ID_JOYPAD_RIGHT, GW_BUTTON_RIGHT},
    {RETRO_DEVICE_ID_JOYPAD_B, GW_BUTTON_B},
    {RETRO_DEVICE_ID_JOYPAD_Y, GW_BUTTON_A},
    {RETRO_DEVICE_ID_JOYPAD_A, GW_BUTTON_C},
    {RETRO_DEVICE_ID_JOYPAD_START, GW_BUTTON_START}
};

static bool is_unsupported_stop(uint32_t reason)
{
    return reason == GW_STOP_UNSUPPORTED_INSTRUCTION ||
        reason == GW_STOP_UNSUPPORTED_ADDRESS ||
        reason == GW_STOP_UNSUPPORTED_STATE;
}

static void clear_frame_state(void)
{
    have_last_frame = false;
    last_width = GW_LIBRETRO_MAX_WIDTH;
    last_height = GW_ACTIVE_LINES;
    memset(last_pixels, 0, sizeof(last_pixels));
}

static bool reject_game_load(gw_machine *candidate)
{
    gw_destroy(candidate);
    retro_unload_game();
    return false;
}

static void request_pixel_format(void)
{
    enum retro_pixel_format format = RETRO_PIXEL_FORMAT_XRGB8888;
    use_xrgb8888 = environment_callback != NULL &&
        environment_callback(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &format);
}

static void copy_frame_for_replay(const uint32_t *pixels,
    const gw_video_field *field)
{
    size_t row_bytes = (size_t)field->width * sizeof(uint32_t);
    const uint8_t *source = (const uint8_t *)pixels;
    unsigned y;

    for (y = 0; y < field->height; ++y) {
        memcpy(&last_pixels[(size_t)y * field->width],
            source + (size_t)y * field->pitch_bytes, row_bytes);
    }
    last_width = field->width;
    last_height = field->height;
    have_last_frame = true;
}

static bool valid_field(const gw_video_field *field, const uint32_t *pixels)
{
    if (pixels == NULL || field->pixel_format != GW_PIXEL_XRGB8888 ||
        (field->width != 256u && field->width != 320u) ||
        field->height != GW_ACTIVE_LINES ||
        field->width > GW_LIBRETRO_MAX_WIDTH ||
        field->pitch_bytes < field->width * sizeof(uint32_t) ||
        field->pitch_bytes > GW_LIBRETRO_MAX_WIDTH * sizeof(uint32_t) ||
        field->pitch_bytes % sizeof(uint32_t) != 0u) {
        return false;
    }
    return true;
}

static void emit_pixels(const uint32_t *pixels, unsigned width,
    unsigned height, size_t source_pitch)
{
    unsigned y;

    if (video_callback == NULL)
        return;
    if (use_xrgb8888) {
        video_callback(pixels, width, height, source_pitch);
        return;
    }

    for (y = 0; y < height; ++y) {
        const uint32_t *source = (const uint32_t *)
            ((const uint8_t *)pixels + (size_t)y * source_pitch);
        uint16_t *destination = &converted_pixels[(size_t)y * width];
        unsigned x;

        for (x = 0; x < width; ++x) {
            uint32_t pixel = source[x];
            uint16_t red = (uint16_t)((pixel >> 19) & UINT32_C(0x1f));
            uint16_t green = (uint16_t)((pixel >> 11) & UINT32_C(0x1f));
            uint16_t blue = (uint16_t)((pixel >> 3) & UINT32_C(0x1f));
            destination[x] = (uint16_t)((red << 10) | (green << 5) | blue);
        }
    }
    video_callback(converted_pixels, width, height,
        (size_t)width * sizeof(converted_pixels[0]));
}

static void emit_last_or_blank_frame(void)
{
    const uint32_t *pixels = have_last_frame ? last_pixels : blank_pixels;
    unsigned width = have_last_frame ? last_width : GW_LIBRETRO_MAX_WIDTH;
    unsigned height = have_last_frame ? last_height : GW_ACTIVE_LINES;

    emit_pixels(pixels, width, height, (size_t)width * sizeof(uint32_t));
}

static uint32_t read_pad_mask(unsigned port)
{
    uint32_t mask = 0;
    size_t i;

    if (input_state_callback == NULL || port >= 2u ||
        controller_devices[port] != RETRO_DEVICE_JOYPAD) {
        return 0;
    }
    for (i = 0; i < sizeof(pad_buttons) / sizeof(pad_buttons[0]); ++i) {
        if (input_state_callback(port, RETRO_DEVICE_JOYPAD, 0,
                pad_buttons[i].retro_id) != 0) {
            mask |= pad_buttons[i].gw_mask;
        }
    }
    return mask;
}

static bool schedule_input(uint64_t tick)
{
    unsigned port;

    for (port = 0; port < 2u; ++port) {
        gw_event event = {0};
        event.struct_size = sizeof(event);
        event.version = GW_API_VERSION;
        event.tick = tick;
        event.type = GW_EVENT_PAD_STATE;
        event.port = port;
        event.mask = read_pad_mask(port);
        if (gw_schedule_event(owned_machine, &event) != GW_OK)
            return false;
    }
    return true;
}

static bool drain_audio(void)
{
    unsigned reads;

    for (reads = 0; reads < 2u; ++reads) {
        gw_audio_read_result result = {0};
        uint32_t i;

        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        if (gw_audio_read(owned_machine, audio_buffer,
                GW_AUDIO_QUEUE_FRAMES, &result) != GW_OK ||
            result.lost != 0u || result.produced > GW_AUDIO_QUEUE_FRAMES ||
            result.first_index != next_audio_index) {
            return false;
        }
        if (result.produced == 0u)
            return true;

        next_audio_index += result.produced;
        if (audio_batch_callback != NULL) {
            size_t accepted = audio_batch_callback(audio_buffer,
                result.produced);
            if (accepted > result.produced)
                return false;
            /* A frontend may accept fewer frames; discard the rest once. */
        } else if (audio_sample_callback != NULL) {
            for (i = 0; i < result.produced; ++i) {
                audio_sample_callback(audio_buffer[2u * i],
                    audio_buffer[2u * i + 1u]);
            }
        }
    }
    return true;
}

static bool discard_incomplete_audio(void)
{
    gw_audio_read_result result = {0};

    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    if (gw_audio_read(owned_machine, audio_buffer,
            GW_AUDIO_QUEUE_FRAMES, &result) != GW_OK ||
        result.lost != 0u || result.produced > GW_AUDIO_QUEUE_FRAMES ||
        result.first_index != next_audio_index ||
        result.produced > UINT64_MAX - next_audio_index) {
        return false;
    }
    /* A stopped partial field is not delivered later after reset/recovery. */
    next_audio_index += result.produced;
    return true;
}

static void fail_run(void)
{
    run_failed = true;
    emit_last_or_blank_frame();
}

RETRO_API void retro_set_environment(retro_environment_t callback)
{
    environment_callback = callback;
}

RETRO_API void retro_set_video_refresh(retro_video_refresh_t callback)
{
    video_callback = callback;
}

RETRO_API void retro_set_audio_sample(retro_audio_sample_t callback)
{
    audio_sample_callback = callback;
}

RETRO_API void retro_set_audio_sample_batch(retro_audio_sample_batch_t callback)
{
    audio_batch_callback = callback;
}

RETRO_API void retro_set_input_poll(retro_input_poll_t callback)
{
    input_poll_callback = callback;
}

RETRO_API void retro_set_input_state(retro_input_state_t callback)
{
    input_state_callback = callback;
}

RETRO_API void retro_init(void)
{
    initialized = true;
    run_failed = false;
    request_pixel_format();
}

RETRO_API void retro_deinit(void)
{
    retro_unload_game();
    initialized = false;
    use_xrgb8888 = false;
}

RETRO_API unsigned retro_api_version(void)
{
    return RETRO_API_VERSION;
}

RETRO_API void retro_get_system_info(struct retro_system_info *info)
{
    if (info == NULL)
        return;
    info->library_name = "Genewhip";
    info->library_version = "0.2.0";
    info->valid_extensions = "bin|gen";
    info->need_fullpath = false;
    info->block_extract = false;
}

RETRO_API void retro_get_system_av_info(struct retro_system_av_info *info)
{
    if (info == NULL)
        return;
    info->geometry.base_width = GW_LIBRETRO_MAX_WIDTH;
    info->geometry.base_height = GW_ACTIVE_LINES;
    info->geometry.max_width = GW_LIBRETRO_MAX_WIDTH;
    info->geometry.max_height = GW_ACTIVE_LINES;
    info->geometry.aspect_ratio = 4.0f / 3.0f;
    info->timing.fps = (double)GW_MASTER_HZ / (double)GW_FIELD_TICKS;
    info->timing.sample_rate = (double)GW_LIBRETRO_AUDIO_RATE;
}

RETRO_API void retro_set_controller_port_device(unsigned port, unsigned device)
{
    if (port < 2u)
        controller_devices[port] = device;
}

RETRO_API void retro_reset(void)
{
    if (owned_machine != NULL) {
        if (gw_console_reset(owned_machine) == GW_OK) {
            run_failed = false;
            clear_frame_state();
        } else {
            run_failed = true;
        }
    }
}

RETRO_API void retro_run(void)
{
    gw_diagnostic_record diagnostics = {0};
    gw_run_result result = {0};
    gw_video_field field = {0};
    const uint32_t *pixels = NULL;
    uint64_t target_tick;

    if (!initialized || owned_machine == NULL)
        return;
    if (input_poll_callback != NULL)
        input_poll_callback();
    if (run_failed) {
        emit_last_or_blank_frame();
        return;
    }

    diagnostics.struct_size = sizeof(diagnostics);
    diagnostics.version = GW_API_VERSION;
    if (gw_get_diagnostics(owned_machine, &diagnostics) != GW_OK) {
        fail_run();
        return;
    }
    if (is_unsupported_stop(diagnostics.stop_reason)) {
        emit_last_or_blank_frame();
        return;
    }
    if (diagnostics.tick > GW_MAX_TARGET_TICK - GW_FIELD_TICKS ||
        !schedule_input(diagnostics.tick)) {
        fail_run();
        return;
    }

    target_tick = diagnostics.tick + GW_FIELD_TICKS;
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    result.flags = 0;
    if (gw_run_until(owned_machine, target_tick, &result) != GW_OK) {
        fail_run();
        return;
    }
    if (result.stop_reason != GW_STOP_FIELD_COMPLETE) {
        if (is_unsupported_stop(result.stop_reason)) {
            if (!discard_incomplete_audio())
                run_failed = true;
            emit_last_or_blank_frame();
            return;
        }
        fail_run();
        return;
    }

    field.struct_size = sizeof(field);
    field.version = GW_API_VERSION;
    if (gw_get_video_field(owned_machine, &field, &pixels) != GW_OK ||
        !valid_field(&field, pixels)) {
        fail_run();
        return;
    }
    copy_frame_for_replay(pixels, &field);
    emit_pixels(pixels, field.width, field.height, field.pitch_bytes);
    if (!drain_audio())
        run_failed = true;
}

RETRO_API size_t retro_serialize_size(void)
{
    return 0;
}

RETRO_API bool retro_serialize(void *data, size_t size)
{
    (void)data;
    (void)size;
    return false;
}

RETRO_API bool retro_unserialize(const void *data, size_t size)
{
    (void)data;
    (void)size;
    return false;
}

RETRO_API void retro_cheat_reset(void)
{
}

RETRO_API void retro_cheat_set(unsigned index, bool enabled, const char *code)
{
    (void)index;
    (void)enabled;
    (void)code;
}

RETRO_API bool retro_load_game(const struct retro_game_info *game)
{
    gw_config config = {0};
    gw_machine *candidate = NULL;
    gw_machine *previous;

    if (game == NULL || game->data == NULL ||
        game->size < GW_MIN_ROM_SIZE || game->size > GW_MAX_ROM_SIZE ||
        (game->size & 1u) != 0u) {
        return reject_game_load(NULL);
    }
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.port_device[0] = GW_DEVICE_PAD3;
    config.port_device[1] = GW_DEVICE_PAD3;
    config.audio_rate_hz = GW_LIBRETRO_AUDIO_RATE;
    if (gw_create(&config, &candidate) != GW_OK)
        return reject_game_load(NULL);
    if (gw_load_rom(candidate, game->data, game->size) != GW_OK)
        return reject_game_load(candidate);

    previous = owned_machine;
    owned_machine = candidate;
    run_failed = false;
    next_audio_index = 0;
    memset(audio_buffer, 0, sizeof(audio_buffer));
    clear_frame_state();
    gw_destroy(previous);
    return true;
}

RETRO_API bool retro_load_game_special(unsigned type,
    const struct retro_game_info *info, size_t count)
{
    (void)type;
    (void)info;
    (void)count;
    return false;
}

RETRO_API void retro_unload_game(void)
{
    gw_destroy(owned_machine);
    owned_machine = NULL;
    run_failed = false;
    next_audio_index = 0;
    memset(audio_buffer, 0, sizeof(audio_buffer));
    clear_frame_state();
}

RETRO_API unsigned retro_get_region(void)
{
    return RETRO_REGION_NTSC;
}

RETRO_API void *retro_get_memory_data(unsigned id)
{
    (void)id;
    return NULL;
}

RETRO_API size_t retro_get_memory_size(unsigned id)
{
    (void)id;
    return 0;
}
