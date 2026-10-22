/* SPDX-License-Identifier: MIT
 * Thin SDL3 desktop shell. The runner owns the window, integer scaling, vsync
 * and pacing from the host monotonic clock. Every core interaction goes
 * through the SDL-free gw_session module, which is driven only to field targets.
 */
#include <SDL3/SDL.h>
#include "audio.h"
#include "rom_file.h"
#include "session.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_SCRIPT_MAX 256

#define SCRIPT_LINE_MAX 320
#define SCRIPT_PATH_MAX 256
#define AUDIO_DUMP_BUFFER_BYTES 4096u

typedef enum { ACTION_PAUSE, ACTION_RESUME, ACTION_RESET, ACTION_QUIT, ACTION_PRESS, ACTION_DROP,
    ACTION_MUTE, ACTION_UNMUTE } host_action;
typedef struct {
    uint64_t frame;
    host_action action;
    unsigned port;
    uint32_t mask;
    char path[SCRIPT_PATH_MAX];
} script_entry;

typedef enum { SOURCE_NONE, SOURCE_KEYBOARD, SOURCE_GAMEPAD, SOURCE_AUTO } port_source;

static const struct { SDL_Scancode scancode; gw_host_key key; } KEY_MAP[] = {
    {SDL_SCANCODE_UP, GW_KEY_UP}, {SDL_SCANCODE_DOWN, GW_KEY_DOWN},
    {SDL_SCANCODE_LEFT, GW_KEY_LEFT}, {SDL_SCANCODE_RIGHT, GW_KEY_RIGHT},
    {SDL_SCANCODE_Z, GW_KEY_Z}, {SDL_SCANCODE_X, GW_KEY_X}, {SDL_SCANCODE_C, GW_KEY_C},
    {SDL_SCANCODE_RETURN, GW_KEY_ENTER},
};
static const struct { SDL_GamepadButton button; uint32_t mask; } PAD_MAP[] = {
    {SDL_GAMEPAD_BUTTON_DPAD_UP, GW_BUTTON_UP}, {SDL_GAMEPAD_BUTTON_DPAD_DOWN, GW_BUTTON_DOWN},
    {SDL_GAMEPAD_BUTTON_DPAD_LEFT, GW_BUTTON_LEFT}, {SDL_GAMEPAD_BUTTON_DPAD_RIGHT, GW_BUTTON_RIGHT},
    {SDL_GAMEPAD_BUTTON_WEST, GW_BUTTON_A}, {SDL_GAMEPAD_BUTTON_SOUTH, GW_BUTTON_B},
    {SDL_GAMEPAD_BUTTON_EAST, GW_BUTTON_C}, {SDL_GAMEPAD_BUTTON_START, GW_BUTTON_START},
};
#define MAX_GAMEPADS 4

static uint8_t rom_buffer[GW_MAX_ROM_SIZE];

static int dump_audio_frames(FILE *out, const int16_t *frames, uint32_t count)
{
    uint8_t bytes[AUDIO_DUMP_BUFFER_BYTES];
    uint32_t offset = 0;
    while (offset < count) {
        uint32_t batch = count - offset;
        if (batch > sizeof(bytes) / 4u) batch = (uint32_t)(sizeof(bytes) / 4u);
        for (uint32_t i = 0; i < batch; ++i) {
            uint16_t left = (uint16_t)frames[2u * (offset + i)];
            uint16_t right = (uint16_t)frames[2u * (offset + i) + 1u];
            bytes[4u * i] = (uint8_t)left;
            bytes[4u * i + 1u] = (uint8_t)(left >> 8);
            bytes[4u * i + 2u] = (uint8_t)right;
            bytes[4u * i + 3u] = (uint8_t)(right >> 8);
        }
        if (fwrite(bytes, 4u, batch, out) != batch) return 1;
        offset += batch;
    }
    return 0;
}

static int usage(void)
{
    fputs("usage: genewhip-desktop [--fields N] [--host-script FILE] [--scale N]\n"
          "       [--record LOG | --replay LOG] [--dump-audio FILE] [--print-field-hashes] [--stats FILE]\n"
          "       [--stats-interval N]\n"
          "       [--port1 keyboard|gamepad|none] [--port2 keyboard|gamepad|none] ROM\n", stderr);
    return 2;
}

static int parse_count(const char *text, uint64_t maximum, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;
    if (!text || !*text || *text == '-') return 0;
    value = strtoull(text, &end, 10);
    if (*end != '\0' || value > maximum) return 0;
    *out = (uint64_t)value;
    return 1;
}

/* Host-script lines, frames non-decreasing:
 *   "<frame> pause|resume|reset|quit|mute|unmute", "<frame> press <port 1|2> <mask-hex>",
 *   "<frame> drop <path>". */
static int load_script(const char *path, script_entry *entries, size_t *count)
{
    FILE *file = fopen(path, "r");
    char line[SCRIPT_LINE_MAX];
    uint64_t last = 0;
    *count = 0;
    if (!file) return 0;
    while (fgets(line, sizeof(line), file)) {
        char verb[16];
        unsigned long long frame;
        int consumed = 0;
        script_entry *entry;
        if (line[0] == '\n' || line[0] == '#') continue;
        if (strchr(line, '\n') == NULL && !feof(file)) { (void)fclose(file); return 0; }
        if (sscanf(line, "%llu %15s%n", &frame, verb, &consumed) != 2 || frame < last || *count >= HOST_SCRIPT_MAX) {
            (void)fclose(file);
            return 0;
        }
        entry = &entries[*count];
        memset(entry, 0, sizeof(*entry));
        if (!strcmp(verb, "pause")) entry->action = ACTION_PAUSE;
        else if (!strcmp(verb, "resume")) entry->action = ACTION_RESUME;
        else if (!strcmp(verb, "reset")) entry->action = ACTION_RESET;
        else if (!strcmp(verb, "mute")) entry->action = ACTION_MUTE;
        else if (!strcmp(verb, "unmute")) entry->action = ACTION_UNMUTE;
        else if (!strcmp(verb, "quit")) entry->action = ACTION_QUIT;
        else if (!strcmp(verb, "press")) {
            unsigned port, mask;
            if (sscanf(line + consumed, "%u %x", &port, &mask) != 2 || port < 1 || port > 2 || mask > 0xffu) {
                (void)fclose(file);
                return 0;
            }
            entry->action = ACTION_PRESS;
            entry->port = port - 1;
            entry->mask = mask;
        } else if (!strcmp(verb, "drop")) {
            const char *text = line + consumed;
            size_t length;
            while (*text == ' ') text++;
            length = strcspn(text, "\r\n");
            if (length == 0 || length >= SCRIPT_PATH_MAX) { (void)fclose(file); return 0; }
            memcpy(entry->path, text, length);
            entry->action = ACTION_DROP;
        } else { (void)fclose(file); return 0; }
        entry->frame = (uint64_t)frame;
        last = (uint64_t)frame;
        (*count)++;
    }
    if (ferror(file)) { (void)fclose(file); return 0; }
    (void)fclose(file);
    return 1;
}

static void fatal_box(const char *message)
{
    fprintf(stderr, "ERROR: %s\n", message);
    (void)SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Genewhip", message, NULL);
}

typedef struct runner {
    gw_session session;
    runner_audio *audio;
    runner_stats stats;
    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Texture *texture;
    int tex_w, tex_h;
    int quit;
    uint64_t reset_count_before_loads;
    uint64_t paused_fields;
    int unsupported_shown;
    char name[96];
    port_source source[2];
    unsigned gamepad_slot[2];          /* Which connected gamepad feeds each port. */
    SDL_Gamepad *gamepads[MAX_GAMEPADS];
    uint32_t script_mask[2];           /* Masks from host-script press commands. */
} runner;

static void set_title(runner *r, const char *state)
{
    char title[192];
    uint64_t depth = r->audio && r->audio->enabled ? r->audio->counters.queued_frames : 0;
    uint64_t milliseconds = depth * 1000u / GW_RUNNER_AUDIO_HZ;
    if (state && *state) (void)snprintf(title, sizeof(title), "Genewhip - %s - %s A:%" PRIu64 "ms", r->name, state, milliseconds);
    else (void)snprintf(title, sizeof(title), "Genewhip - %s A:%" PRIu64 "ms", r->name, milliseconds);
    (void)SDL_SetWindowTitle(r->window, title);
}

static void apply_pause(runner *r, int paused)
{
    gw_session_set_paused(&r->session, paused);
    if (paused) runner_audio_pause(r->audio);
    else runner_audio_reprime(r->audio);
    set_title(r, paused ? "Paused" : NULL);
}

static void request_reset(runner *r)
{
    int status = gw_session_reset(&r->session);
    if (status != 0) fprintf(stderr, "WARN: reset request failed (status %d)\n", status);
    else runner_audio_reprime(r->audio);
}

/* Loads a dropped or scripted cartridge through the hardened reader. A
 * failure keeps the running session and reports on stderr. */
static void load_dropped(runner *r, const char *path)
{
    size_t size = 0;
    const char *reason = NULL;
    char name[sizeof(r->name)];
    uint64_t prior_resets = r->session.resets;
    int status;
    gw_sanitize_display(path, name, sizeof(name));
    if (gw_read_rom_file(path, rom_buffer, sizeof(rom_buffer), &size, &reason)) {
        fprintf(stderr, "REJECT: %s %s\n", reason, name);
        return;
    }
    status = gw_session_replace_rom(&r->session, rom_buffer, size);
    if (status != 0) {
        fprintf(stderr, "REJECT: %s %s\n", status == (int)GW_ERROR_ROM ? "invalid-rom" : "load-failed", name);
        return;
    }
    r->reset_count_before_loads += prior_resets;
    memcpy(r->name, name, sizeof(r->name));
    r->unsupported_shown = 0;
    runner_audio_reprime(r->audio);
    set_title(r, r->session.paused ? "Paused" : NULL);
    fprintf(stderr, "LOADED: %s\n", r->name);
}

static void apply_action(runner *r, const script_entry *entry)
{
    switch (entry->action) {
    case ACTION_PAUSE: apply_pause(r, 1); break;
    case ACTION_RESUME: apply_pause(r, 0); break;
    case ACTION_RESET: request_reset(r); break;
    case ACTION_QUIT: r->quit = 1; break;
    case ACTION_PRESS: r->script_mask[entry->port] = entry->mask; break;
    case ACTION_DROP: load_dropped(r, entry->path); break;
    case ACTION_MUTE: runner_audio_set_muted(r->audio, 1); break;
    case ACTION_UNMUTE: runner_audio_set_muted(r->audio, 0); break;
    }
}

static void open_gamepad(runner *r, SDL_JoystickID id)
{
    for (int i = 0; i < MAX_GAMEPADS; ++i) {
        if (!r->gamepads[i]) { r->gamepads[i] = SDL_OpenGamepad(id); return; }
    }
}

static void close_gamepad(runner *r, SDL_JoystickID id)
{
    for (int i = 0; i < MAX_GAMEPADS; ++i) {
        if (r->gamepads[i] && SDL_GetGamepadID(r->gamepads[i]) == id) {
            SDL_CloseGamepad(r->gamepads[i]);
            r->gamepads[i] = NULL;
        }
    }
}

/* Current logical mask for a port from its configured sources and the script. */
static uint32_t sample_port(const runner *r, unsigned port)
{
    uint32_t mask = r->script_mask[port];
    port_source source = r->source[port];
    if (source == SOURCE_KEYBOARD || (source == SOURCE_AUTO && port == 0)) {
        const bool *keys = SDL_GetKeyboardState(NULL);
        for (size_t i = 0; keys && i < sizeof(KEY_MAP) / sizeof(KEY_MAP[0]); ++i)
            if (keys[KEY_MAP[i].scancode]) mask |= gw_session_key_button(KEY_MAP[i].key);
    }
    if (source == SOURCE_GAMEPAD || source == SOURCE_AUTO) {
        unsigned seen = 0;
        for (int i = 0; i < MAX_GAMEPADS; ++i) {
            if (!r->gamepads[i]) continue;
            if (seen++ != r->gamepad_slot[port]) continue;
            for (size_t b = 0; b < sizeof(PAD_MAP) / sizeof(PAD_MAP[0]); ++b)
                if (SDL_GetGamepadButton(r->gamepads[i], PAD_MAP[b].button)) mask |= PAD_MAP[b].mask;
            break;
        }
    }
    return mask;
}

static void handle_events(runner *r)
{
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        if (event.type == SDL_EVENT_QUIT || event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED) {
            r->quit = 1;
        } else if (event.type == SDL_EVENT_KEY_DOWN && !event.key.repeat) {
            SDL_Keycode key = event.key.key;
            if (key == SDLK_ESCAPE || (key == SDLK_Q && (event.key.mod & SDL_KMOD_GUI))) r->quit = 1;
            else if (key == SDLK_P || key == SDLK_SPACE) apply_pause(r, !r->session.paused);
            else if (key == SDLK_R) request_reset(r);
            else if (key == SDLK_M) runner_audio_set_muted(r->audio, !r->audio->muted);
        } else if (event.type == SDL_EVENT_DROP_FILE) {
            if (event.drop.data) load_dropped(r, event.drop.data);
        } else if (event.type == SDL_EVENT_GAMEPAD_ADDED) {
            open_gamepad(r, event.gdevice.which);
        } else if (event.type == SDL_EVENT_GAMEPAD_REMOVED) {
            close_gamepad(r, event.gdevice.which);
        }
    }
}

static int present_field(runner *r)
{
    gw_video_field field;
    const uint32_t *pixels = NULL;
    int status = gw_session_field(&r->session, &field, &pixels);
    if (status == (int)GW_ERROR_EMPTY) return 1;
    if (status != 0) {
        (void)snprintf(r->stats.present_error, sizeof(r->stats.present_error),
            "gw_session_field failed (status %d)", status);
        runner_stats_present(&r->stats, r->session.fields, 0, r->stats.present_error);
        return 0;
    }
    if (field.pixel_format != GW_PIXEL_XRGB8888) {
        runner_stats_present(&r->stats, field.sequence, 0, "unsupported field pixel format");
        return 0;
    }
#define PRESENT_FAILURE(context) do { \
        char detail[GW_RUNNER_PRESENT_ERROR_SIZE]; \
        char message[GW_RUNNER_PRESENT_ERROR_SIZE]; \
        gw_sanitize_display(SDL_GetError(), detail, sizeof(detail)); \
        (void)snprintf(message, sizeof(message), "%s: %s", (context), \
            detail[0] ? detail : "SDL reported no error detail"); \
        runner_stats_present(&r->stats, field.sequence, 0, message); \
        return 0; \
    } while (0)
    if (!r->texture || r->tex_w != (int)field.width || r->tex_h != (int)field.height) {
        if (r->texture) SDL_DestroyTexture(r->texture);
        r->texture = SDL_CreateTexture(r->renderer, SDL_PIXELFORMAT_XRGB8888,
            SDL_TEXTUREACCESS_STREAMING, (int)field.width, (int)field.height);
        if (!r->texture) PRESENT_FAILURE("SDL_CreateTexture");
        r->tex_w = (int)field.width;
        r->tex_h = (int)field.height;
        if (!SDL_SetTextureScaleMode(r->texture, SDL_SCALEMODE_NEAREST))
            PRESENT_FAILURE("SDL_SetTextureScaleMode");
        if (!SDL_SetRenderLogicalPresentation(r->renderer, r->tex_w, r->tex_h,
            SDL_LOGICAL_PRESENTATION_INTEGER_SCALE)) PRESENT_FAILURE("SDL_SetRenderLogicalPresentation");
    }
    if (!SDL_UpdateTexture(r->texture, NULL, pixels, (int)field.pitch_bytes))
        PRESENT_FAILURE("SDL_UpdateTexture");
    if (!SDL_RenderClear(r->renderer)) PRESENT_FAILURE("SDL_RenderClear");
    if (!SDL_RenderTexture(r->renderer, r->texture, NULL, NULL)) PRESENT_FAILURE("SDL_RenderTexture");
    if (!SDL_RenderPresent(r->renderer)) PRESENT_FAILURE("SDL_RenderPresent");
    runner_stats_present(&r->stats, field.sequence, 1, NULL);
#undef PRESENT_FAILURE
    return 1;
}

int main(int argc, char **argv)
{
    gw_config config = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, GW_RUNNER_AUDIO_HZ};
    gw_input_log log;
    int have_log = 0, print_hashes = 0;
    runner r;
    runner_audio audio;
    script_entry script[HOST_SCRIPT_MAX];
    size_t script_count = 0, script_next = 0, rom_size = 0;
    uint64_t max_fields = 0, scale = 3, frame = 0, stats_interval = 0, next_ns, period_ns;
    uint64_t stats_start_ns = 0;
    const char *rom_path = NULL, *script_path = NULL, *reason = NULL, *record_path = NULL, *replay_path = NULL;
    const char *stats_path = NULL, *dump_audio_path = NULL;
    FILE *audio_dump = NULL;
    int status, exit_code = 0;

    memset(&r, 0, sizeof(r));
    r.source[0] = SOURCE_AUTO;
    r.source[1] = SOURCE_GAMEPAD;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--fields") && i + 1 < argc) {
            if (!parse_count(argv[++i], UINT32_MAX, &max_fields) || max_fields == 0) return usage();
        } else if (!strcmp(argv[i], "--scale") && i + 1 < argc) {
            if (!parse_count(argv[++i], 16, &scale) || scale == 0) return usage();
        } else if (!strcmp(argv[i], "--stats-interval") && i + 1 < argc) {
            if (!parse_count(argv[++i], UINT32_MAX, &stats_interval) || stats_interval == 0) return usage();
        } else if (!strcmp(argv[i], "--stats") && i + 1 < argc) {
            stats_path = argv[++i];
        } else if (!strcmp(argv[i], "--host-script") && i + 1 < argc) {
            script_path = argv[++i];
        } else if (!strcmp(argv[i], "--record") && i + 1 < argc) {
            record_path = argv[++i];
        } else if (!strcmp(argv[i], "--replay") && i + 1 < argc) {
            replay_path = argv[++i];
        } else if (!strcmp(argv[i], "--dump-audio") && i + 1 < argc) {
            dump_audio_path = argv[++i];
        } else if (!strcmp(argv[i], "--print-field-hashes")) {
            print_hashes = 1;
        } else if ((!strcmp(argv[i], "--port1") || !strcmp(argv[i], "--port2")) && i + 1 < argc) {
            unsigned port = argv[i][6] == '2';
            const char *value = argv[++i];
            if (!strcmp(value, "keyboard")) r.source[port] = SOURCE_KEYBOARD;
            else if (!strcmp(value, "gamepad")) r.source[port] = SOURCE_GAMEPAD;
            else if (!strcmp(value, "none")) r.source[port] = SOURCE_NONE;
            else return usage();
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            return usage();
        } else if (!rom_path) {
            rom_path = argv[i];
        } else {
            return usage();
        }
    }
    if (!rom_path || (record_path && replay_path)) return usage();
    {
        unsigned used = 0;
        for (unsigned port = 0; port < 2; ++port) {
            config.port_device[port] = r.source[port] == SOURCE_NONE ? GW_DEVICE_NONE : GW_DEVICE_PAD3;
            r.gamepad_slot[port] = used;
            if (r.source[port] == SOURCE_GAMEPAD || r.source[port] == SOURCE_AUTO) used++;
        }
    }
    gw_sanitize_display(rom_path, r.name, sizeof(r.name));

    if (gw_read_rom_file(rom_path, rom_buffer, sizeof(rom_buffer), &rom_size, &reason)) {
        fprintf(stderr, "REJECT: %s %s\n", reason, r.name);
        return 1;
    }
    if (script_path && !load_script(script_path, script, &script_count)) {
        fputs("REJECT: host-script\n", stderr);
        return 1;
    }
    if (record_path || replay_path) {
        if (gw_input_log_init(&log) != 0) { fputs("ERROR: out of memory\n", stderr); return 1; }
        have_log = 1;
        if (replay_path && gw_input_log_read(replay_path, &log, &reason) != 0) {
            fprintf(stderr, "REJECT: input-log %s\n", reason);
            gw_input_log_free(&log);
            return 1;
        }
    }
    status = gw_session_open(&r.session, &config, rom_buffer, rom_size);
    if (status != 0) {
        fprintf(stderr, "REJECT: %s %s\n",
            status == (int)GW_ERROR_ROM ? "invalid-rom" : "load-failed", r.name);
        if (have_log) gw_input_log_free(&log);
        return 1;
    }
    if (have_log) (void)gw_session_attach_log(&r.session, &log, replay_path ? GW_SESSION_REPLAY : GW_SESSION_RECORD);

    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD)) {
        fatal_box("Could not initialise SDL video");
        gw_session_close(&r.session);
        return 1;
    }
    r.window = SDL_CreateWindow("Genewhip", (int)(320 * scale), (int)(224 * scale), SDL_WINDOW_RESIZABLE);
    if (r.window) r.renderer = SDL_CreateRenderer(r.window, NULL);
    if (!r.window || !r.renderer) {
        fatal_box("Could not create the window or renderer");
        if (r.window) SDL_DestroyWindow(r.window);
        SDL_Quit();
        gw_session_close(&r.session);
        return 1;
    }
    (void)runner_audio_open(&audio);
    r.audio = &audio;
    if (dump_audio_path) {
        audio_dump = fopen(dump_audio_path, "wb");
        if (!audio_dump) {
            fputs("ERROR: could not write audio dump\n", stderr);
            runner_audio_close(&audio);
            SDL_DestroyRenderer(r.renderer);
            SDL_DestroyWindow(r.window);
            SDL_Quit();
            gw_session_close(&r.session);
            if (have_log) gw_input_log_free(&log);
            return 1;
        }
    }
    (void)SDL_SetRenderVSync(r.renderer, 1);
    set_title(&r, NULL);

    period_ns = ((uint64_t)GW_FIELD_TICKS * UINT64_C(1000000000)) / GW_MASTER_HZ;
    next_ns = SDL_GetTicksNS();
    stats_start_ns = next_ns;
    while (!r.quit) {
        uint64_t now;
        int due = 0, stepped = 0;
        handle_events(&r);
        now = SDL_GetTicksNS();
        while (!r.quit && now >= next_ns && due < GW_SESSION_CATCHUP_FIELDS) {
            runner_stats_deadline(&r.stats, next_ns, now);
            while (script_next < script_count && script[script_next].frame <= frame)
                apply_action(&r, &script[script_next++]);
            if (r.quit || (max_fields && r.session.fields >= max_fields)) { r.quit = 1; break; }
            if (r.session.paused) {
                r.paused_fields++;
            } else {
                gw_session_set_input(&r.session, 0, sample_port(&r, 0));
                gw_session_set_input(&r.session, 1, sample_port(&r, 1));
                status = gw_session_step_field(&r.session);
                if (status > 0) {
                    fprintf(stderr, "ERROR: core rejected a run request (status %d)\n", status);
                    exit_code = 1;
                    r.quit = 1;
                    break;
                }
                stepped = 1;
                {
                    gw_video_field field;
                    const uint32_t *pixels = NULL;
                    status = gw_session_field(&r.session, &field, &pixels);
                    if (status != 0) {
                        fprintf(stderr, "ERROR: could not observe emulated field (status %d)\n", status);
                        exit_code = 1;
                        r.quit = 1;
                        break;
                    }
                    runner_stats_field(&r.stats, field.sequence, due != 0);
                }
                {
                    const int16_t *audio_frames = NULL;
                    uint32_t audio_count = 0;
                    gw_audio_read_result audio_result;
                    if (gw_session_audio(&r.session, &audio_frames, &audio_count, &audio_result) == 0) {
                        if (audio_dump && dump_audio_frames(audio_dump, audio_frames, audio_count) != 0) {
                            fputs("ERROR: could not write audio dump\n", stderr);
                            exit_code = 1;
                            r.quit = 1;
                        }
                        runner_audio_put_field(&audio, audio_frames, audio_count,
                            r.session.audio_total_frames, audio_result.lost, audio_result.clipped);
                    }
                }
                if (print_hashes && gw_session_print_field(&r.session, stdout) != 0) {
                    fprintf(stderr, "ERROR: could not print the field hash\n");
                    exit_code = 1;
                    r.quit = 1;
                    break;
                }
            }
            frame++;
            if (stats_interval && frame % stats_interval == 0) {
                runner_stats_exposure(&r.stats, SDL_GetTicksNS() - stats_start_ns);
                runner_audio_print_stats(&audio, &r.stats, stderr);
                fputc('\n', stderr);
            }
            next_ns += period_ns;
            due++;
        }
        if (now >= next_ns) {
            runner_stats_discard_wall(&r.stats, now - next_ns);
            next_ns = now; /* Discard debt beyond the catch-up cap. */
        }
        if (stepped) {
            if (!present_field(&r)) {
                fprintf(stderr, "ERROR: could not present the field\n");
                exit_code = 1;
                r.quit = 1;
            }
            if (!r.unsupported_shown && gw_session_unsupported_stop(&r.session)) {
                char text[96];
                r.unsupported_shown = 1;
                (void)snprintf(text, sizeof(text), "Unsupported: opcode %04" PRIx32 " at %06" PRIx32 " (fault %06" PRIx32 ")",
                    r.session.opcode & 0xffffu, r.session.instruction_address, r.session.fault_address);
                set_title(&r, text);
                fprintf(stderr, "STOP: %s\n", text);
            } else if (r.unsupported_shown && !gw_session_unsupported_stop(&r.session)) {
                r.unsupported_shown = 0;
                set_title(&r, r.session.paused ? "Paused" : NULL);
            } else if (!r.unsupported_shown) {
                set_title(&r, r.session.paused ? "Paused" : NULL);
            }
        }
        now = SDL_GetTicksNS();
        if (!r.quit && now < next_ns) SDL_DelayNS(next_ns - now);
    }

    printf("fields=%" PRIu64 " paused_fields=%" PRIu64 " resets=%" PRIu64 " ",
        r.session.fields, r.paused_fields, r.reset_count_before_loads + r.session.resets);
    runner_stats_exposure(&r.stats, SDL_GetTicksNS() - stats_start_ns);
    runner_audio_print_stats(&audio, &r.stats, stdout);
    putchar('\n');
    if (print_hashes && gw_session_print_final(&r.session, stdout) != 0) exit_code = 1;
    if (stats_path) {
        FILE *stats_file = fopen(stats_path, "w");
        if (!stats_file) {
            fputs("ERROR: could not write stats file\n", stderr);
            exit_code = 1;
        } else {
            runner_audio_write_stats_json(&audio, &r.stats, stats_file);
            if (fclose(stats_file) != 0) { fputs("ERROR: could not finish stats file\n", stderr); exit_code = 1; }
        }
    }
    if (record_path) {
        if (r.session.log_overflow) fputs("WARN: input log full, later input not recorded\n", stderr);
        if (gw_input_log_write(record_path, &log) != 0) { fputs("ERROR: could not write the log\n", stderr); exit_code = 1; }
    }
    if (audio_dump && fclose(audio_dump) != 0) {
        fputs("ERROR: could not finish audio dump\n", stderr);
        exit_code = 1;
    }
    if (fflush(stdout) != 0) exit_code = 1;
    for (int i = 0; i < MAX_GAMEPADS; ++i) if (r.gamepads[i]) SDL_CloseGamepad(r.gamepads[i]);
    if (r.texture) SDL_DestroyTexture(r.texture);
    SDL_DestroyRenderer(r.renderer);
    SDL_DestroyWindow(r.window);
    runner_audio_close(&audio);
    SDL_Quit();
    gw_session_close(&r.session);
    if (have_log) gw_input_log_free(&log);
    return exit_code;
}
