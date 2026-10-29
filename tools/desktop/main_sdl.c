/* SPDX-License-Identifier: MIT
 * Thin SDL3 desktop shell. The runner owns the window, integer scaling, vsync
 * and pacing from the host monotonic clock. Every core interaction goes
 * through the SDL-free gw_session module, which is driven only to field targets.
 */
#include <SDL3/SDL.h>
#include "audio.h"
#include "rom_file.h"
#include "session.h"
#include "route_controller.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#define HOST_SCRIPT_MAX 256

#define SCRIPT_LINE_MAX 320
#define SCRIPT_PATH_MAX 256
#define AUDIO_DUMP_BUFFER_BYTES 4096u
#define GW_ROUTE_CAPTURE_AUDIO_MAX_BYTES (16u * 1024u * 1024u)
#define GW_MAX_FIELD_ROW_BYTES (320u * 4u)

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
          "       [--route-plan FILE --route-report FILE]\n"
          "       [--dump-fields DIR [--capture-field N | --capture-attempt-tick A T] --capture-identity SHA256]\n"
          "       [--route-input-source virtual-gamepad --route-diagnostic FILE]\n"
          "       [--renderer-capture-field N --renderer-capture-output FILE]\n"
          "       [--route-input-contract MASK[,MASK...]]\n"
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

static int write_route_capability_report(const char *path, const char *capability)
{
    FILE *out = fopen(path, "wbx");
    int okay;
    if (!out) return 0;
    okay = fprintf(out, "{\"schema\":\"genewhip-phase6-sdl-diagnostic-v1\","
        "\"input_path\":\"unavailable-before-input\",\"core_outcome\":\"unavailable\","
        "\"host_outcome\":\"fail-diagnostic\",\"capability\":\"%s\","
        "\"event_pumps\":0,\"input_events\":[],\"presented_frames\":0,"
        "\"renderer_readback_samples\":0,\"renderer_readback_activity\":false,"
        "\"pcm_frames\":0,\"audio_submitted_frames\":0,"
        "\"audio_device_consumed_frames\":0,\"audio_device_activity\":false}\n", capability) > 0;
    if (fclose(out) != 0) okay = 0;
    return okay;
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
    int route_virtual_gamepad;
    int route_input_suppress;
    FILE *route_audio_dump;
    uint64_t route_audio_dump_bytes;
    int route_print_hashes;
    SDL_JoystickID route_virtual_id;
    SDL_Gamepad *route_virtual_pad;
    SDL_JoystickID route_virtual_ids[2];
    SDL_Gamepad *route_virtual_pads[2];
    uint64_t route_event_pumps, route_presented_frames, route_readback_samples;
    uint64_t route_readback_hash, route_pcm_frames, route_pcm_hash;
    uint32_t route_input_count;
    struct { uint32_t requested, effective, joystick_mask; unsigned port; SDL_JoystickID gamepad_id; } route_inputs[64];
    const char *route_renderer_capture_path;
    uint64_t route_renderer_capture_field;
    uint64_t route_renderer_capture_hash;
    uint32_t route_virtual_add_events, route_virtual_remove_events;
    int route_window_raise_requested;
    int route_renderer_capture_done;
    const char *route_capture_dir;
    const char *route_capture_identity;
    unsigned long long route_capture_field_sequence;
    unsigned long long route_capture_attempt;
    unsigned long long route_capture_source_tick;
    int route_capture_done;
} runner;

static int route_capture_directory_ready(const char *dir)
{
    struct stat info;
    DIR *directory;
    struct dirent *entry;
#ifndef _WIN32
    if (lstat(dir, &info) != 0 || !S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode) || info.st_uid != geteuid()) return 0;
#else
    if (stat(dir, &info) != 0 || !S_ISDIR(info.st_mode)) return 0;
#endif
    directory = opendir(dir);
    if (!directory) return 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            (void)closedir(directory);
            return 0;
        }
    }
    return closedir(directory) == 0;
}

static FILE *route_capture_open_exclusive(const char *path)
{
#ifndef _WIN32
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    FILE *out;
    if (fd < 0) return NULL;
    out = fdopen(fd, "wb");
    if (!out) (void)close(fd);
    return out;
#else
    return fopen(path, "wbx");
#endif
}

static int route_capture_field_pixels(const runner *r, const gw_video_field *field, const uint32_t *pixels)
{
    char path[4096];
    uint8_t row[GW_MAX_FIELD_ROW_BYTES];
    FILE *out;
    if (!r->route_capture_dir || field->width != 320u || field->height != 224u ||
        field->width * 4u > sizeof(row) || !pixels || !route_capture_directory_ready(r->route_capture_dir)) return 1;
    if (snprintf(path, sizeof(path), "%s/field-%llu.bin", r->route_capture_dir,
        (unsigned long long)field->sequence) >= (int)sizeof(path)) return 1;
    out = route_capture_open_exclusive(path);
    if (!out) return 1;
    for (uint32_t y = 0; y < field->height; ++y) {
        const uint32_t *src = (const uint32_t *)((const uint8_t *)pixels + (size_t)y * field->pitch_bytes);
        for (uint32_t x = 0; x < field->width; ++x) {
            row[x * 4u] = (uint8_t)(src[x] & 0xffu);
            row[x * 4u + 1u] = (uint8_t)((src[x] >> 8) & 0xffu);
            row[x * 4u + 2u] = (uint8_t)((src[x] >> 16) & 0xffu);
            row[x * 4u + 3u] = (uint8_t)(src[x] >> 24);
        }
        if (fwrite(row, 1, field->width * 4u, out) != field->width * 4u) {
            (void)fclose(out);
            return 1;
        }
    }
    if (fclose(out) != 0) return 1;
    if (snprintf(path, sizeof(path), "%s/field-%llu.json", r->route_capture_dir,
        (unsigned long long)field->sequence) >= (int)sizeof(path)) return 1;
    out = route_capture_open_exclusive(path);
    if (!out) return 1;
    if (fprintf(out, "{\"sequence\":%llu,\"width\":%u,\"height\":%u,\"row_bytes\":%u,"
            "\"pixel\":\"uint32 0x00RRGGBB little-endian\",\"end_tick\":%llu}\n",
            (unsigned long long)field->sequence, (unsigned)field->width, (unsigned)field->height,
            (unsigned)(field->width * 4u), (unsigned long long)field->end_tick) < 0) {
        (void)fclose(out);
        return 1;
    }
    return fclose(out) != 0;
}

static int route_capture_metadata(runner *r, const gw_session *session, const gw_video_field *field)
{
    uint8_t x_hi[2], y_hi[2];
    uint32_t attempt = 0, source_tick = 0, x = 0, y = 0;
    char path[4096];
    FILE *out;
    int rec = r->route_capture_attempt != 0;
    if (rec) {
        uint8_t attempt_bytes[2], tick_bytes[2];
        if (gw_peek_memory(session->machine, 0x00ff140e, attempt_bytes, 2) != GW_OK ||
            gw_peek_memory(session->machine, 0x00ff1410, tick_bytes, 2) != GW_OK) return 1;
        attempt = (uint32_t)((uint16_t)attempt_bytes[0] << 8 | attempt_bytes[1]);
        source_tick = (uint32_t)((uint16_t)tick_bytes[0] << 8 | tick_bytes[1]);
        if (attempt != r->route_capture_attempt || source_tick < r->route_capture_source_tick) return 0;
        if (gw_peek_memory(session->machine, 0x00ff18c5, x_hi, 2) != GW_OK ||
            gw_peek_memory(session->machine, 0x00ff18c9, y_hi, 2) != GW_OK) return 1;
        x = (uint32_t)x_hi[0] * 256u + x_hi[1];
        y = (uint32_t)y_hi[0] * 256u + y_hi[1];
    } else {
        uint8_t p1x[2], p1y[2], p2x[2], p2y[2];
        if (session->fields != r->route_capture_field_sequence) return 1;
        if (gw_peek_memory(session->machine, 0x00ff042c, p1x, 2) != GW_OK ||
            gw_peek_memory(session->machine, 0x00ff042e, p1y, 2) != GW_OK ||
            gw_peek_memory(session->machine, 0x00ff0438, p2x, 2) != GW_OK ||
            gw_peek_memory(session->machine, 0x00ff043a, p2y, 2) != GW_OK) return 1;
        if (snprintf(path, sizeof(path), "%s/route-capture.json", r->route_capture_dir) >= (int)sizeof(path)) return 1;
        out = route_capture_open_exclusive(path);
        if (!out) return 1;
        if (fprintf(out, "{\"schema\":\"genewhip-phase6-route-capture-v1\",\"candidate_sha256\":\"%s\",\"field_sequence\":%llu,\"field\":%llu,\"p1_x\":%u,\"p1_y\":%u,\"p2_x\":%u,\"p2_y\":%u}\n",
            r->route_capture_identity, (unsigned long long)field->sequence, (unsigned long long)session->fields,
            (unsigned)p1x[0] * 256u + p1x[1], (unsigned)p1y[0] * 256u + p1y[1],
            (unsigned)p2x[0] * 256u + p2x[1], (unsigned)p2y[0] * 256u + p2y[1]) < 0) { (void)fclose(out); return 1; }
        if (fclose(out) != 0) return 1;
        r->route_capture_done = 1;
        return 0;
    }
    if (snprintf(path, sizeof(path), "%s/route-capture.json", r->route_capture_dir) >= (int)sizeof(path)) return 1;
    out = route_capture_open_exclusive(path);
    if (!out) return 1;
    if (fprintf(out, "{\"schema\":\"genewhip-phase6-route-capture-v1\",\"candidate_sha256\":\"%s\",\"field_sequence\":%llu,\"field\":%llu,\"attempt\":%u,\"source_tick\":%u,\"actor_x_px\":%u,\"actor_y_px\":%u}\n",
        r->route_capture_identity, (unsigned long long)field->sequence, (unsigned long long)session->fields,
        attempt, source_tick, x, y) < 0) { (void)fclose(out); return 1; }
    if (fclose(out) != 0) return 1;
    r->route_capture_done = 1;
    return 0;
}

static uint64_t route_hash_bytes(uint64_t hash, const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    if (!hash) hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) { hash ^= bytes[i]; hash *= UINT64_C(1099511628211); }
    return hash;
}

/* Capture one field from the renderer's actual target. SDL3 logical presentation
 * returns the destination rectangle in output pixels; nearest sampling maps
 * the integer-scaled renderer image back to the 320x224 core coordinate grid. */
static int route_capture_renderer_target(runner *r, uint64_t field_sequence)
{
    SDL_FRect logical;
    SDL_Rect crop;
    SDL_Surface *surface;
    uint8_t *rgba;
    size_t rgba_bytes;
    FILE *out;
    uint64_t hash = 0;
    if (!r->route_renderer_capture_path || r->route_renderer_capture_done ||
        field_sequence != r->route_renderer_capture_field) return 1;
    if (!SDL_GetRenderLogicalPresentationRect(r->renderer, &logical)) return 0;
    crop.x = (int)(logical.x + 0.5f);
    crop.y = (int)(logical.y + 0.5f);
    crop.w = (int)(logical.w + 0.5f);
    crop.h = (int)(logical.h + 0.5f);
    if (crop.x < 0 || crop.y < 0 || crop.w < 320 || crop.h < 224) return 0;
    surface = SDL_RenderReadPixels(r->renderer, &crop);
    if (!surface || !surface->pixels || surface->w != crop.w || surface->h != crop.h) {
        if (surface) SDL_DestroySurface(surface);
        return 0;
    }
    if ((size_t)crop.w > SIZE_MAX / 4u / (size_t)crop.h) {
        SDL_DestroySurface(surface);
        return 0;
    }
    rgba_bytes = (size_t)crop.w * (size_t)crop.h * 4u;
    if (rgba_bytes > 80u * 1024u * 1024u) { SDL_DestroySurface(surface); return 0; }
    rgba = (uint8_t *)SDL_malloc(rgba_bytes);
    if (!rgba) { SDL_DestroySurface(surface); return 0; }
    if (!SDL_ConvertPixels(surface->w, surface->h, surface->format, surface->pixels,
            surface->pitch, SDL_PIXELFORMAT_RGBA32, rgba, crop.w * 4)) {
        SDL_free(rgba);
        SDL_DestroySurface(surface);
        return 0;
    }
    out = route_capture_open_exclusive(r->route_renderer_capture_path);
    if (!out) { SDL_free(rgba); SDL_DestroySurface(surface); return 0; }
    for (unsigned y = 0; y < 224; ++y) {
        unsigned sy = (unsigned)(((uint64_t)(2u * y + 1u) * (unsigned)crop.h) / (2u * 224u));
        for (unsigned x = 0; x < 320; ++x) {
            unsigned sx = (unsigned)(((uint64_t)(2u * x + 1u) * (unsigned)crop.w) / (2u * 320u));
            const uint8_t *pixel = rgba + ((size_t)sy * (unsigned)crop.w + sx) * 4u;
            uint8_t serialized[4] = {pixel[2], pixel[1], pixel[0], 0};
            hash = route_hash_bytes(hash, serialized, sizeof(serialized));
            if (fwrite(serialized, 1, sizeof(serialized), out) != sizeof(serialized)) {
                (void)fclose(out); SDL_free(rgba); SDL_DestroySurface(surface); return 0;
            }
        }
    }
    if (fclose(out) != 0) { SDL_free(rgba); SDL_DestroySurface(surface); return 0; }
    SDL_free(rgba);
    SDL_DestroySurface(surface);
    r->route_renderer_capture_done = 1;
    r->route_renderer_capture_hash = hash;
    return 1;
}

static int attach_one_route_virtual_gamepad(runner *r, unsigned port)
{
    SDL_VirtualJoystickDesc desc;
    uint32_t mask = 0;
    for (size_t i = 0; i < sizeof(PAD_MAP) / sizeof(PAD_MAP[0]); ++i)
        if (PAD_MAP[i].mask != GW_BUTTON_UP && PAD_MAP[i].mask != GW_BUTTON_DOWN &&
            PAD_MAP[i].mask != GW_BUTTON_LEFT && PAD_MAP[i].mask != GW_BUTTON_RIGHT)
            mask |= UINT32_C(1) << PAD_MAP[i].button;
    SDL_INIT_INTERFACE(&desc);
    desc.type = SDL_JOYSTICK_TYPE_GAMEPAD;
    desc.nbuttons = SDL_GAMEPAD_BUTTON_COUNT;
    desc.nhats = 1;
    desc.button_mask = mask;
    desc.name = port ? "Genewhip Phase 6 port two" : "Genewhip Phase 6 port one";
    r->route_virtual_ids[port] = SDL_AttachVirtualJoystick(&desc);
    if (!r->route_virtual_ids[port]) return 0;
    {
        SDL_GUID guid = SDL_GetJoystickGUIDForID(r->route_virtual_ids[port]);
        char guid_text[33];
        char mapping[384];
        SDL_GUIDToString(guid, guid_text, sizeof(guid_text));
        if (SDL_snprintf(mapping, sizeof(mapping),
                "%s,Genewhip Phase 6 virtual controller,a:b0,b:b1,x:b2,y:b3,start:b6,"
                "dpup:h0.1,dpright:h0.2,dpdown:h0.4,dpleft:h0.8", guid_text) >= (int)sizeof(mapping) ||
            !SDL_SetGamepadMapping(r->route_virtual_ids[port], mapping)) {
            (void)SDL_DetachVirtualJoystick(r->route_virtual_ids[port]);
            r->route_virtual_ids[port] = 0;
            return 0;
        }
    }
    r->route_virtual_pads[port] = SDL_OpenGamepad(r->route_virtual_ids[port]);
    if (!r->route_virtual_pads[port]) {
        (void)SDL_DetachVirtualJoystick(r->route_virtual_ids[port]);
        r->route_virtual_ids[port] = 0;
        return 0;
    }
    r->gamepads[port] = r->route_virtual_pads[port];
    r->source[port] = SOURCE_GAMEPAD;
    r->gamepad_slot[port] = port;
    if (port == 0) {
        r->route_virtual_id = r->route_virtual_ids[0];
        r->route_virtual_pad = r->route_virtual_pads[0];
    }
    r->route_virtual_gamepad = 1;
    return 1;
}

static int attach_route_virtual_gamepads(runner *r)
{
    if (!attach_one_route_virtual_gamepad(r, 0)) return 0;
    if (attach_one_route_virtual_gamepad(r, 1)) return 1;
    SDL_CloseGamepad(r->route_virtual_pads[0]);
    r->route_virtual_pads[0] = NULL;
    r->gamepads[0] = NULL;
    (void)SDL_DetachVirtualJoystick(r->route_virtual_ids[0]);
    r->route_virtual_ids[0] = 0;
    r->route_virtual_pad = NULL;
    r->route_virtual_id = 0;
    r->route_virtual_gamepad = 0;
    return 0;
}

static int route_apply_mask(void *context, unsigned port, uint32_t mask, uint32_t *effective);
static uint32_t sample_port(const runner *r, unsigned port);

static int route_input_contract(const char *text)
{
    runner r;
    char *copy, *cursor;
    int result = 0, with_video = 0;
    memset(&r, 0, sizeof(r));
    r.source[0] = SOURCE_GAMEPAD;
    r.source[1] = SOURCE_GAMEPAD;
    with_video = SDL_getenv("GENEWHIP_PHASE6_INPUT_VIDEO") &&
        SDL_strcmp(SDL_getenv("GENEWHIP_PHASE6_INPUT_VIDEO"), "1") == 0;
    if (with_video) (void)SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1");
    if (!text || !*text || !SDL_Init(with_video ? (SDL_INIT_VIDEO | SDL_INIT_GAMEPAD) : SDL_INIT_GAMEPAD)) return 1;
    if (with_video) {
        r.window = SDL_CreateWindow("Genewhip input contract", 320, 224, 0);
        if (!r.window) { SDL_Quit(); return 1; }
    }
    if (!attach_route_virtual_gamepads(&r)) {
        if (r.window) SDL_DestroyWindow(r.window);
        SDL_Quit(); return 1;
    }
    if (with_video) r.route_window_raise_requested = SDL_RaiseWindow(r.window) ? 1 : 0;
    copy = SDL_strdup(text);
    if (!copy) { result = 1; goto done; }
    fprintf(stderr, "route-input-contract: checking requested masks through SDL_Gamepad/sample_port\n");
    printf("{\"schema\":\"genewhip-sdl-virtual-input-contract-v1\",\"video_driver\":\"%s\",\"window_flags\":%" PRIu64 ",\"window_input_focus\":%s,\"window_raise_requested\":%s,\"background_events_hint\":\"%s\",\"virtual_gamepad_ids\":[%d,%d],\"inputs\":[\n",
        SDL_GetCurrentVideoDriver() ? SDL_GetCurrentVideoDriver() : "unavailable",
        r.window ? (uint64_t)SDL_GetWindowFlags(r.window) : UINT64_C(0),
        (r.window && (SDL_GetWindowFlags(r.window) & SDL_WINDOW_INPUT_FOCUS)) ? "true" : "false",
        r.route_window_raise_requested ? "true" : "false",
        with_video ? "1" : "unchanged", r.route_virtual_ids[0], r.route_virtual_ids[1]);
    cursor = copy;
    for (unsigned index = 0; cursor && *cursor && index < 64; ++index) {
        char *end = NULL;
        unsigned long port = SDL_strtoul(cursor, &end, 10);
        unsigned long value;
        uint32_t effective = 0, other = 0;
        if (end == cursor || *end != ':' || port > 1) { result = 1; break; }
        value = SDL_strtoul(end + 1, &end, 10);
        if (value > 255 || (*end && *end != ',')) { result = 1; break; }
        if (route_apply_mask(&r, (unsigned)port, (uint32_t)value, &effective) != 0) { result = 1; break; }
        other = sample_port(&r, 1u - (unsigned)port);
        printf("%s{\"port\":%lu,\"requested_mask\":%lu,\"effective_mask\":%u,\"joystick_mask\":%u,\"gamepad_id\":%d,\"other_port_mask\":%u}",
            index ? "," : "", port, value, effective, r.route_inputs[r.route_input_count-1].joystick_mask,
            r.route_inputs[r.route_input_count-1].gamepad_id, other);
        if (effective != value) result = 1;
        cursor = *end == ',' ? end + 1 : NULL;
    }
    if (cursor != NULL) result = 1;
    puts("]}");
    SDL_free(copy);
done:
    for (unsigned port = 0; port < 2; ++port) {
        if (r.route_virtual_pads[port]) SDL_CloseGamepad(r.route_virtual_pads[port]);
        if (r.route_virtual_ids[port]) (void)SDL_DetachVirtualJoystick(r.route_virtual_ids[port]);
    }
    if (r.window) SDL_DestroyWindow(r.window);
    SDL_Quit();
    return result;
}

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
        if (r->gamepads[i] && SDL_GetGamepadID(r->gamepads[i]) == id) return;
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
            for (unsigned port = 0; port < 2; ++port)
                if (event.gdevice.which == r->route_virtual_ids[port]) r->route_virtual_add_events++;
            open_gamepad(r, event.gdevice.which);
        } else if (event.type == SDL_EVENT_GAMEPAD_REMOVED) {
            for (unsigned port = 0; port < 2; ++port)
                if (event.gdevice.which == r->route_virtual_ids[port]) r->route_virtual_remove_events++;
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
    if (r->route_virtual_gamepad) {
        int output_w = 0, output_h = 0;
        if (!SDL_GetRenderOutputSize(r->renderer, &output_w, &output_h) || output_w <= 0 || output_h <= 0)
            PRESENT_FAILURE("SDL_GetRenderOutputSize");
        SDL_Rect probe = {output_w / 2, output_h / 2, 1, 1};
        SDL_Surface *surface = SDL_RenderReadPixels(r->renderer, &probe);
        if (!surface || !surface->pixels || surface->pitch <= 0) {
            if (surface) SDL_DestroySurface(surface);
            PRESENT_FAILURE("SDL_RenderReadPixels");
        }
        r->route_readback_hash = route_hash_bytes(r->route_readback_hash,
            surface->pixels, (size_t)surface->pitch);
        r->route_readback_samples++;
        SDL_DestroySurface(surface);
    }
    if (r->route_renderer_capture_path &&
        !route_capture_renderer_target(r, field.sequence)) PRESENT_FAILURE("SDL renderer field capture");
    if (!SDL_RenderPresent(r->renderer)) PRESENT_FAILURE("SDL_RenderPresent");
    if (r->route_virtual_gamepad) r->route_presented_frames++;
    runner_stats_present(&r->stats, field.sequence, 1, NULL);
#undef PRESENT_FAILURE
    return 1;
}

static int route_field_present(void *context, const gw_session *session)
{
    runner *r = (runner *)context;
    gw_video_field field;
    const uint32_t *pixels = NULL;
    const int16_t *frames = NULL;
    uint32_t count = 0;
    gw_audio_read_result audio_result;
    handle_events(r);
    r->route_event_pumps++;
    if (r->quit) return 1;
    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.version = GW_API_VERSION;
    if (gw_session_field(session, &field, &pixels) != 0) return 1;
    if (r->route_capture_dir && !r->route_capture_done) {
        int selected = 0;
        if (r->route_capture_attempt) {
            uint8_t attempt_bytes[2], tick_bytes[2];
            if (gw_peek_memory(session->machine, 0x00ff140e, attempt_bytes, 2) != GW_OK ||
                gw_peek_memory(session->machine, 0x00ff1410, tick_bytes, 2) != GW_OK) return 1;
            selected = ((uint32_t)attempt_bytes[0] * 256u + attempt_bytes[1]) == r->route_capture_attempt &&
                ((uint32_t)tick_bytes[0] * 256u + tick_bytes[1]) >= r->route_capture_source_tick;
        } else {
            selected = session->fields == r->route_capture_field_sequence;
        }
        if (selected && (route_capture_field_pixels(r, &field, pixels) != 0 ||
            route_capture_metadata(r, session, &field) != 0)) return 1;
    }
    if (r->route_print_hashes && gw_session_print_field(session, stdout) != 0) return 1;
    runner_stats_field(&r->stats, field.sequence, field.sequence != 0);
    if (gw_session_audio(session, &frames, &count, &audio_result) != 0) return 1;
    if (r->route_audio_dump) {
        uint64_t bytes = (uint64_t)count * 4u;
        if (bytes > GW_ROUTE_CAPTURE_AUDIO_MAX_BYTES - r->route_audio_dump_bytes ||
            dump_audio_frames(r->route_audio_dump, frames, count) != 0) return 1;
        r->route_audio_dump_bytes += bytes;
    }
    if (r->route_virtual_gamepad && count && frames) {
        r->route_pcm_hash = route_hash_bytes(r->route_pcm_hash, frames,
            (size_t)count * 2u * sizeof(*frames));
        r->route_pcm_frames += count;
    }
    runner_audio_put_field(r->audio, frames, count, session->audio_total_frames,
        audio_result.lost, audio_result.clipped);
    return present_field(r) ? 0 : 1;
}

static int route_apply_mask(void *context, unsigned port, uint32_t mask, uint32_t *effective)
{
    runner *r = (runner *)context;
    script_entry action;
    if (r->route_virtual_gamepad) {
        SDL_Gamepad *pad;
        SDL_Joystick *joystick;
        Uint8 hat = SDL_HAT_CENTERED;
        int up, down, left, right;
        if (port > 1 || r->route_input_count >= 64) return 1;
        pad = r->route_virtual_pads[port];
        joystick = pad ? SDL_GetGamepadJoystick(pad) : NULL;
        if (!joystick) return 1;
        up = (mask & GW_BUTTON_UP) != 0; down = (mask & GW_BUTTON_DOWN) != 0;
        left = (mask & GW_BUTTON_LEFT) != 0; right = (mask & GW_BUTTON_RIGHT) != 0;
        if (up) hat = left ? SDL_HAT_LEFTUP : right ? SDL_HAT_RIGHTUP : SDL_HAT_UP;
        else if (down) hat = left ? SDL_HAT_LEFTDOWN : right ? SDL_HAT_RIGHTDOWN : SDL_HAT_DOWN;
        else if (left) hat = SDL_HAT_LEFT;
        else if (right) hat = SDL_HAT_RIGHT;
        for (size_t i = 0; i < sizeof(PAD_MAP) / sizeof(PAD_MAP[0]); ++i) {
            if (PAD_MAP[i].mask == GW_BUTTON_UP || PAD_MAP[i].mask == GW_BUTTON_DOWN ||
                PAD_MAP[i].mask == GW_BUTTON_LEFT || PAD_MAP[i].mask == GW_BUTTON_RIGHT) continue;
            if (!SDL_SetJoystickVirtualButton(joystick, (int)PAD_MAP[i].button,
                    !r->route_input_suppress && (mask & PAD_MAP[i].mask) != 0)) return 1;
        }
        if (r->route_input_suppress) hat = SDL_HAT_CENTERED;
        if (!SDL_SetJoystickVirtualHat(joystick, 0, hat)) return 1;
        SDL_UpdateJoysticks();
        handle_events(r);
        r->route_inputs[r->route_input_count].requested = mask;
        r->route_inputs[r->route_input_count].port = port;
        r->route_inputs[r->route_input_count].gamepad_id = SDL_GetGamepadID(pad);
        r->route_inputs[r->route_input_count].joystick_mask = 0;
        for (size_t i = 0; i < sizeof(PAD_MAP) / sizeof(PAD_MAP[0]); ++i) {
            if (PAD_MAP[i].mask == GW_BUTTON_UP || PAD_MAP[i].mask == GW_BUTTON_DOWN ||
                PAD_MAP[i].mask == GW_BUTTON_LEFT || PAD_MAP[i].mask == GW_BUTTON_RIGHT) continue;
            if (SDL_GetJoystickButton(joystick, (int)PAD_MAP[i].button))
                r->route_inputs[r->route_input_count].joystick_mask |= PAD_MAP[i].mask;
        }
        {
            Uint8 actual_hat = SDL_GetJoystickHat(joystick, 0);
            if (actual_hat & SDL_HAT_UP) r->route_inputs[r->route_input_count].joystick_mask |= GW_BUTTON_UP;
            if (actual_hat & SDL_HAT_DOWN) r->route_inputs[r->route_input_count].joystick_mask |= GW_BUTTON_DOWN;
            if (actual_hat & SDL_HAT_LEFT) r->route_inputs[r->route_input_count].joystick_mask |= GW_BUTTON_LEFT;
            if (actual_hat & SDL_HAT_RIGHT) r->route_inputs[r->route_input_count].joystick_mask |= GW_BUTTON_RIGHT;
        }
        *effective = sample_port(r, port);
        r->route_inputs[r->route_input_count].effective = *effective;
        r->route_input_count++;
        return r->quit ? 1 : 0;
    }
    memset(&action, 0, sizeof(action));
    action.action = ACTION_PRESS; action.port = port; action.mask = mask;
    apply_action(r, &action);
    *effective = sample_port(r, port);
    return 0;
}

static int write_route_diagnostic(const runner *r, const runner_audio *audio,
    const char *path, int core_status)
{
    FILE *out = fopen(path, "wb");
    int host_pass;
    if (!out) return 0;
    host_pass = r->route_virtual_gamepad && r->route_input_count > 0 && r->route_event_pumps > 0 &&
        r->route_presented_frames > 0 && r->route_readback_samples > 0 && r->route_pcm_frames > 0 &&
        (!r->route_renderer_capture_path || r->route_renderer_capture_done) &&
        audio->enabled && audio->counters.produced_frames > 0 && audio->counters.consumed_frames > 0;
    for (uint32_t i = 0; host_pass && i < r->route_input_count; ++i)
        if (r->route_inputs[i].requested != r->route_inputs[i].effective) host_pass = 0;
    if (fprintf(out, "{\"schema\":\"genewhip-phase6-sdl-diagnostic-v1\",\"input_path\":\"sdl-virtual-gamepad/sample_port\","
        "\"core_outcome\":\"%s\",\"host_outcome\":\"%s\",\"capability\":\"%s\","
        "\"event_pumps\":%" PRIu64 ",\"input_events\":[", core_status == 0 ? "pass" : "fail",
        host_pass ? "pass-diagnostic" : "fail-diagnostic", audio->enabled ? "audio-enabled" : "audio-unavailable",
        r->route_event_pumps) < 0) goto fail;
    for (uint32_t i = 0; i < r->route_input_count; ++i)
        if (fprintf(out, "%s{\"port\":%u,\"requested_mask\":%u,\"effective_mask\":%u,\"joystick_mask\":%u,\"gamepad_id\":%d,\"handler\":\"SDL_Gamepad/sample_port\"}",
            i ? "," : "", r->route_inputs[i].port, r->route_inputs[i].requested,
            r->route_inputs[i].effective, r->route_inputs[i].joystick_mask, r->route_inputs[i].gamepad_id) < 0) goto fail;
    if (fprintf(out, "],\"presented_frames\":%" PRIu64 ",\"renderer_readback_samples\":%" PRIu64
        ",\"renderer_readback_hash\":\"%016" PRIx64 "\",\"pcm_frames\":%" PRIu64
        ",\"pcm_hash\":\"%016" PRIx64 "\",\"audio_submitted_frames\":%" PRIu64
        ",\"audio_device_consumed_frames\":%" PRIu64 ",\"audio_device_activity\":%s"
        ",\"renderer\":\"%s\",\"video_driver\":\"%s\",\"audio_driver\":\"%s\","
        "\"audio_device_id\":%u,\"audio_device_name\":\"%s\",\"renderer_capture_path\":\"%s\","
        "\"renderer_capture_field\":%" PRIu64 ",\"renderer_capture_fnv1a64\":\"%016" PRIx64 "\","
        "\"virtual_gamepad_ids\":[%d,%d],\"virtual_gamepad_add_events\":%u,\"virtual_gamepad_remove_events\":%u,"
        "\"renderer_capture_pixel\":\"320x224 uint32 0x00RRGGBB little-endian\","
        "\"window_flags\":%" PRIu64 ",\"window_input_focus\":%s,\"window_raise_requested\":%s,"
        "\"renderer_readback_activity\":%s}\n",
        r->route_presented_frames, r->route_readback_samples, r->route_readback_hash,
        r->route_pcm_frames, r->route_pcm_hash, audio->counters.produced_frames,
        audio->counters.consumed_frames, audio->counters.consumed_frames ? "true" : "false",
        r->renderer ? SDL_GetRendererName(r->renderer) : "unavailable",
        SDL_GetCurrentVideoDriver() ? SDL_GetCurrentVideoDriver() : "unavailable",
        SDL_GetCurrentAudioDriver() ? SDL_GetCurrentAudioDriver() : "unavailable",
        audio->stream ? (unsigned)SDL_GetAudioStreamDevice(audio->stream) : 0u,
        audio->stream && SDL_GetAudioDeviceName(SDL_GetAudioStreamDevice(audio->stream)) ?
            SDL_GetAudioDeviceName(SDL_GetAudioStreamDevice(audio->stream)) : "unavailable",
        r->route_renderer_capture_path ? r->route_renderer_capture_path : "",
        r->route_renderer_capture_field, r->route_renderer_capture_hash,
        r->route_virtual_ids[0], r->route_virtual_ids[1], r->route_virtual_add_events, r->route_virtual_remove_events,
        r->window ? (uint64_t)SDL_GetWindowFlags(r->window) : UINT64_C(0),
        (r->window && (SDL_GetWindowFlags(r->window) & SDL_WINDOW_INPUT_FOCUS)) ? "true" : "false",
        r->route_window_raise_requested ? "true" : "false",
        r->route_renderer_capture_done ? "true" : "false") < 0) goto fail;
    return fclose(out) == 0 && host_pass;
fail:
    (void)fclose(out);
    return 0;
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
    const char *route_plan_path = NULL, *route_report_path = NULL;
    const char *route_diagnostic_path = NULL;
    const char *route_input_contract_text = NULL;
    const char *route_capture_dir = NULL, *route_capture_identity = NULL;
    const char *route_renderer_capture_path = NULL;
    unsigned long long route_renderer_capture_field = 0;
    unsigned long long route_capture_field_sequence = 0, route_capture_attempt = 0, route_capture_source_tick = 0;
    int route_virtual_gamepad = 0, route_core_status = 0;
    uint64_t route_probe_pc = 0;
    uint64_t route_stop_horizon = 308;
    int route_instruction_probe = 0;
    int route_probe_only = 0;
    gw_session_route_plan route_plan = {0};
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
        } else if (!strcmp(argv[i], "--dump-fields") && i + 1 < argc) {
            route_capture_dir = argv[++i];
        } else if (!strcmp(argv[i], "--capture-field") && i + 1 < argc) {
            if (!parse_count(argv[++i], UINT32_MAX, &route_capture_field_sequence) || !route_capture_field_sequence) return usage();
        } else if (!strcmp(argv[i], "--capture-attempt-tick") && i + 2 < argc) {
            if (!parse_count(argv[++i], UINT16_MAX, &route_capture_attempt) || !route_capture_attempt ||
                !parse_count(argv[++i], UINT16_MAX, &route_capture_source_tick)) return usage();
        } else if (!strcmp(argv[i], "--capture-identity") && i + 1 < argc) {
            route_capture_identity = argv[++i];
            if (strlen(route_capture_identity) != 64u) return usage();
            for (size_t n = 0; n < 64; ++n)
                if (!((route_capture_identity[n] >= '0' && route_capture_identity[n] <= '9') ||
                      (route_capture_identity[n] >= 'a' && route_capture_identity[n] <= 'f') ||
                      (route_capture_identity[n] >= 'A' && route_capture_identity[n] <= 'F'))) return usage();
        } else if (!strcmp(argv[i], "--route-probe-only")) {
            route_probe_only = 1;
        } else if (!strcmp(argv[i], "--route-stop-horizon") && i + 1 < argc) {
            if (!parse_count(argv[++i], 308, &route_stop_horizon) || !route_stop_horizon) return usage();
        } else if (!strcmp(argv[i], "--route-instruction-probe") && i + 1 < argc) {
            if (!parse_count(argv[++i], 0xffffffu, &route_probe_pc)) return usage();
            route_instruction_probe = 1;
        } else if (!strcmp(argv[i], "--route-plan") && i + 1 < argc) {
            route_plan_path = argv[++i];
            config.diagnostics = 1;
        } else if (!strcmp(argv[i], "--route-report") && i + 1 < argc) {
            route_report_path = argv[++i];
        } else if (!strcmp(argv[i], "--route-diagnostic") && i + 1 < argc) {
            route_diagnostic_path = argv[++i];
        } else if (!strcmp(argv[i], "--route-input-source") && i + 1 < argc) {
            if (strcmp(argv[++i], "virtual-gamepad")) return usage();
            route_virtual_gamepad = 1;
        } else if (!strcmp(argv[i], "--route-input-suppress")) {
            r.route_input_suppress = 1;
        } else if (!strcmp(argv[i], "--route-input-contract") && i + 1 < argc) {
            route_input_contract_text = argv[++i];
        } else if (!strcmp(argv[i], "--renderer-capture-field") && i + 1 < argc) {
            if (!parse_count(argv[++i], UINT32_MAX, &route_renderer_capture_field) || !route_renderer_capture_field) return usage();
        } else if (!strcmp(argv[i], "--renderer-capture-output") && i + 1 < argc) {
            route_renderer_capture_path = argv[++i];
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
    if (route_input_contract_text) {
        if (rom_path || route_plan_path || route_report_path || route_diagnostic_path || script_path ||
            record_path || replay_path || stats_path || dump_audio_path || route_virtual_gamepad)
            return usage();
        return route_input_contract(route_input_contract_text);
    }
    if (!rom_path || (record_path && replay_path) ||
        ((route_plan_path == NULL) != (route_report_path == NULL)) ||
        (route_virtual_gamepad && (!route_plan_path || !route_diagnostic_path)) ||
        (route_diagnostic_path && !route_virtual_gamepad) ||
        (route_probe_only && (!route_instruction_probe || !route_plan_path)) ||
        (route_plan_path && (record_path || replay_path || script_path)) ||
        ((route_capture_dir || route_capture_identity || route_capture_field_sequence || route_capture_attempt || route_capture_source_tick) &&
         (!route_plan_path || !route_capture_dir || !route_capture_identity ||
          !dump_audio_path ||
          (!route_capture_field_sequence && !route_capture_attempt) ||
          (route_capture_field_sequence && route_capture_attempt) || (!route_capture_attempt && route_capture_source_tick) ||
          (route_capture_attempt && route_capture_source_tick == 0))) ||
        ((route_renderer_capture_path == NULL) != (route_renderer_capture_field == 0)) ||
        (route_renderer_capture_path && (!route_plan_path || !route_virtual_gamepad || !route_diagnostic_path)) ||
        (r.route_input_suppress && (!route_plan_path || !route_virtual_gamepad || !route_diagnostic_path))) return usage();
    if (route_plan_path && gw_session_route_load(route_plan_path, &route_plan) != 0) {
        fputs("REJECT: route-plan\n", stderr);
        return 1;
    }
    if (route_probe_only && !route_plan.controller) {
        gw_session_route_plan_free(&route_plan);return usage();
    }
    if (route_virtual_gamepad) { r.source[0] = SOURCE_GAMEPAD; r.source[1] = SOURCE_GAMEPAD; }
    r.route_capture_dir = route_capture_dir;
    r.route_capture_identity = route_capture_identity;
    r.route_capture_field_sequence = route_capture_field_sequence;
    r.route_capture_attempt = route_capture_attempt;
    r.route_capture_source_tick = route_capture_source_tick;
    r.route_renderer_capture_path = route_renderer_capture_path;
    r.route_renderer_capture_field = route_renderer_capture_field;
    if (route_capture_dir && !route_capture_directory_ready(route_capture_dir)) {
        fputs("ERROR: route capture directory must be an existing empty owned directory\n", stderr);
        return 1;
    }
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

    if (route_virtual_gamepad)
        (void)SDL_SetHint(SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, "1");
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD)) {
        if (route_virtual_gamepad && route_diagnostic_path) {
            const char *requested = SDL_getenv("SDL_VIDEODRIVER");
            fprintf(stderr, "ERROR: Could not initialise SDL video; requested_driver=%s; compiled_drivers=",
                requested && *requested ? requested : "automatic");
            for (int i = 0; i < SDL_GetNumVideoDrivers(); ++i)
                fprintf(stderr, "%s%s", i ? "," : "", SDL_GetVideoDriver(i));
            fprintf(stderr, "; SDL_GetError=%s\n", SDL_GetError());
            (void)write_route_capability_report(route_diagnostic_path, "video-unavailable");
            gw_session_close(&r.session);
            return 77;
        }
        fatal_box("Could not initialise SDL video");
        gw_session_close(&r.session);
        return 1;
    }
    r.window = SDL_CreateWindow("Genewhip", (int)(320 * scale), (int)(224 * scale), SDL_WINDOW_RESIZABLE);
    if (r.window) r.renderer = SDL_CreateRenderer(r.window, NULL);
    if (!r.window || !r.renderer) {
        if (route_virtual_gamepad && route_diagnostic_path) {
            const char *requested = SDL_getenv("SDL_VIDEODRIVER");
            fprintf(stderr, "ERROR: Could not create the window or renderer; requested_driver=%s; compiled_drivers=",
                requested && *requested ? requested : "automatic");
            for (int i = 0; i < SDL_GetNumVideoDrivers(); ++i)
                fprintf(stderr, "%s%s", i ? "," : "", SDL_GetVideoDriver(i));
            fprintf(stderr, "; SDL_GetError=%s\n", SDL_GetError());
            (void)write_route_capability_report(route_diagnostic_path, "renderer-unavailable");
            if (r.renderer) SDL_DestroyRenderer(r.renderer);
            if (r.window) SDL_DestroyWindow(r.window);
            SDL_Quit();
            gw_session_close(&r.session);
            return 77;
        }
        fatal_box("Could not create the window or renderer");
        if (r.window) SDL_DestroyWindow(r.window);
        SDL_Quit();
        gw_session_close(&r.session);
        return 1;
    }
    if (route_virtual_gamepad && !attach_route_virtual_gamepads(&r)) {
        fputs("ERROR: could not attach SDL virtual gamepad\n", stderr);
        SDL_DestroyRenderer(r.renderer);
        SDL_DestroyWindow(r.window);
        SDL_Quit();
        gw_session_close(&r.session);
        return 1;
    }
    if (route_virtual_gamepad && SDL_GetCurrentVideoDriver() &&
        SDL_strcmp(SDL_GetCurrentVideoDriver(), "cocoa") == 0)
        r.route_window_raise_requested = SDL_RaiseWindow(r.window) ? 1 : 0;
    (void)runner_audio_open(&audio);
    r.audio = &audio;
    if (dump_audio_path) {
        audio_dump = fopen(dump_audio_path, route_plan_path ? "wbx" : "wb");
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
    r.route_audio_dump = audio_dump;
    r.route_print_hashes = print_hashes;
    (void)SDL_SetRenderVSync(r.renderer, 1);
    set_title(&r, NULL);

    period_ns = ((uint64_t)GW_FIELD_TICKS * UINT64_C(1000000000)) / GW_MASTER_HZ;
    next_ns = SDL_GetTicksNS();
    stats_start_ns = next_ns;
    if (route_plan_path) {
        r.session.route_instruction_probe = route_instruction_probe;
        r.session.route_probe_only = route_probe_only;
        r.session.route_stop_horizon = (uint32_t)route_stop_horizon;
        r.session.route_probe_pc = (uint32_t)route_probe_pc;
        FILE *route_report = fopen(route_report_path, route_capture_dir ? "wbx" : "wb");
        if (!route_report) { fputs("ERROR: could not write route report\n", stderr); exit_code = 1; }
        if (!exit_code && route_plan.controller) {
            route_core_status = gw_route_controller_run(&r.session, route_plan.controller, route_report,
                route_apply_mask, &r, route_field_present, &r, audio.enabled);
            if (route_core_status != 0) exit_code = 1;
            if (fclose(route_report) != 0) exit_code = 1;
        } else {
        if (!exit_code && fprintf(route_report,
            "{\"schema\":\"genewhip-phase6-tracer-v1\",\"host\":{\"renderer\":\"sdl\",\"audio_open\":%s},\"observations\":[",
            audio.enabled ? "true" : "false") < 0)
            exit_code = 1;
        for (size_t n = 0; !exit_code && n < route_plan.operation_count; ++n) {
            gw_session_route_op *op = &route_plan.operations[n];
            uint64_t instructions = 0;
            uint64_t observations_before = r.session.route_observation_count;
            int route_status = gw_session_route_observe(&r.session, &route_plan, op,
                route_field_present, &r, &instructions);
            script_entry action;
            uint32_t effective_mask;
            if (route_status != 0) {
                fprintf(stderr, "ERROR: route observation %zu stopped (status %d)\n", n, route_status);
                exit_code = 1;
                break;
            }
            memset(&action, 0, sizeof(action));
            action.action = ACTION_PRESS;
            action.port = op->port;
            action.mask = op->mask;
            apply_action(&r, &action); /* Same host-script handler used by --host-script. */
            effective_mask = sample_port(&r, op->port);
            route_status = gw_session_route_dispatch(&r.session, op->port, effective_mask, op->dispatch_tick);
            if (route_status != 0) {
                fprintf(stderr, "ERROR: route dispatch %zu failed (status %d)\n", n, route_status);
                exit_code = 1;
                break;
            }
            if (fprintf(route_report, "%s{\"operation\":%zu,\"tick\":%llu,\"instructions\":%llu,\"observations\":%llu,"
                "\"address\":%u,\"value\":%u,\"port\":%u,\"mask\":%u,\"handler\":\"host-script\"}",
                n ? "," : "", n, (unsigned long long)r.session.tick,
                (unsigned long long)instructions,
                (unsigned long long)(r.session.route_observation_count - observations_before),
                op->address, op->value, op->port, effective_mask) < 0) exit_code = 1;
        }
        if (route_report) {
            if (fprintf(route_report, "],\"queue_high_water\":%u}\n", r.session.route_queue_high_water) < 0)
                exit_code = 1;
            if (fclose(route_report) != 0) exit_code = 1;
        }
        }
        if (!exit_code && !route_plan.controller) {
            status = gw_session_step_field(&r.session);
            if (status != 0 || route_field_present(&r, &r.session) != 0) {
                fputs("ERROR: route host field/audio/presentation path failed\n", stderr);
                exit_code = 1;
            }
        }
        if (route_capture_dir && (!r.route_capture_done || !audio.enabled || !r.route_audio_dump_bytes)) {
            fputs("ERROR: route capture failed: no eligible field or enabled PCM output\n", stderr);
            exit_code = 1;
        }
        if (route_diagnostic_path && !write_route_diagnostic(&r, &audio, route_diagnostic_path, route_core_status)) {
            fputs("ERROR: SDL route diagnostic did not establish all host paths\n", stderr);
            exit_code = 1;
        }
        r.quit = 1;
    }
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
    for (unsigned port = 0; port < 2; ++port)
        if (r.route_virtual_ids[port]) (void)SDL_DetachVirtualJoystick(r.route_virtual_ids[port]);
    if (r.texture) SDL_DestroyTexture(r.texture);
    SDL_DestroyRenderer(r.renderer);
    SDL_DestroyWindow(r.window);
    runner_audio_close(&audio);
    SDL_Quit();
    gw_session_close(&r.session);
    gw_session_route_plan_free(&route_plan);
    if (have_log) gw_input_log_free(&log);
    return exit_code;
}
