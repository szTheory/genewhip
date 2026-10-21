/* SPDX-License-Identifier: MIT
 * Generic public-API seam runner. Loads one original seam ROM, runs it to a tick
 * target (never shortened by a field end) and prints a window of work RAM as JSON.
 * It judges nothing: expectations live in NAME.expect.json and are evaluated by
 * seam_check.py, so no expected value is ever learned from this program's output.
 * Usage: gw_seam_runner ROM TICKS RAM_OFFSET RAM_LENGTH [--events FILE] [--port-device P1 P2]
 *                        [--dump-field PATH]
 * --events FILE schedules pad events before the run; each line is "TICK PORT MASK-HEX"
 * (single spaces, at most GW_EVENT_CAPACITY lines); anything else is REJECT: events.
 * --port-device sets each controller port to "none" or "pad3".
 * --dump-field PATH writes the newest completed field to PATH as width * height pixels,
 * each 0x00RRGGBB as four little-endian bytes (pitch removed), and adds a "field" object
 * with width, height and sequence to the JSON line; no completed field is REJECT: no-field.
 */
#include <genewhip/genewhip.h>
#include "identity.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int number(const char *text, uint64_t limit, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;
    if (!text[0] || text[0] == '-') return 0;
    v = strtoull(text, &end, 0);
    if (*end || v > limit) return 0;
    *out = v;
    return 1;
}

static int reject(const char *why)
{
    fprintf(stderr, "REJECT: %s\n", why);
    return 1;
}

/* Strict "TICK PORT MASK-HEX" parse of one line (no trailing newline). */
static int parse_event(char *line, gw_event *event)
{
    char *a = line, *b, *c;
    uint64_t tick, port, mask;
    char *end;
    b = strchr(a, ' ');
    if (!b) return 0;
    *b++ = 0;
    c = strchr(b, ' ');
    if (!c) return 0;
    *c++ = 0;
    if (strchr(c, ' ') || !c[0] || c[0] == '-' || c[0] == '+' || c[1] == 'x' || c[1] == 'X') return 0;
    if (!number(a, GW_MAX_TARGET_TICK, &tick) || !number(b, 1, &port)) return 0;
    mask = strtoull(c, &end, 16);
    if (*end || mask > GW_BUTTON_MASK_PAD3) return 0;
    memset(event, 0, sizeof(*event));
    event->struct_size = sizeof(*event);
    event->version = GW_API_VERSION;
    event->tick = tick;
    event->type = GW_EVENT_PAD_STATE;
    event->port = (uint32_t)port;
    event->mask = (uint32_t)mask;
    return 1;
}

/* Read the whole events file before any machine exists; 0 on any malformation. */
static int read_events(const char *path, gw_event *events, size_t *count)
{
    char line[64];
    FILE *f = fopen(path, "r");
    int ok = 1;
    *count = 0;
    if (!f) return 0;
    while (ok && fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        if (n == 0 || line[n - 1] != '\n' || *count >= GW_EVENT_CAPACITY) { ok = 0; break; }
        line[n - 1] = 0;
        ok = parse_event(line, &events[*count]);
        ++*count;
    }
    if (ferror(f)) ok = 0;
    fclose(f);
    return ok;
}

static int device_kind(const char *text, uint32_t *out)
{
    if (!strcmp(text, "none")) *out = GW_DEVICE_NONE;
    else if (!strcmp(text, "pad3")) *out = GW_DEVICE_PAD3;
    else return 0;
    return 1;
}

/* Writes the newest completed field to path; returns 0 on success. */
static int dump_field(const gw_machine *machine, const char *path, gw_video_field *field)
{
    const uint32_t *pixels = NULL;
    unsigned char row[320u * 4u]; /* widest field row (H40) */
    FILE *out;
    uint32_t x, y;
    memset(field, 0, sizeof(*field));
    field->struct_size = sizeof(*field);
    field->version = GW_API_VERSION;
    if (gw_get_video_field(machine, field, &pixels) != GW_OK || field->width * 4u > sizeof(row)) return 1;
    out = fopen(path, "wb");
    if (!out) return 1;
    for (y = 0; y < field->height; ++y) {
        const uint32_t *src = (const uint32_t *)((const unsigned char *)pixels + (size_t)y * field->pitch_bytes);
        for (x = 0; x < field->width; ++x) {
            row[x * 4u] = (unsigned char)(src[x] & 0xffu);
            row[x * 4u + 1u] = (unsigned char)((src[x] >> 8) & 0xffu);
            row[x * 4u + 2u] = (unsigned char)((src[x] >> 16) & 0xffu);
            row[x * 4u + 3u] = (unsigned char)(src[x] >> 24);
        }
        if (fwrite(row, 1, field->width * 4u, out) != field->width * 4u) { fclose(out); return 1; }
    }
    return fclose(out) != 0;
}

static int drain_audio(gw_machine *machine, FILE *out)
{
    int16_t samples[GW_AUDIO_QUEUE_FRAMES * 2u];
    uint8_t bytes[GW_AUDIO_QUEUE_FRAMES * 4u];
    gw_audio_read_result audio = {0};
    uint32_t n;
    audio.struct_size = sizeof(audio);
    audio.version = GW_API_VERSION;
    if (gw_audio_read(machine, samples, GW_AUDIO_QUEUE_FRAMES, &audio) != GW_OK) {
        fprintf(stderr, "audio-read status failure\n"); return 1;
    }
    if (audio.produced > GW_AUDIO_QUEUE_FRAMES || audio.lost != 0) {
        fprintf(stderr, "audio-read produced=%" PRIu32 " lost=%" PRIu64 "\n", audio.produced, audio.lost);
        return 1;
    }
    for (n = 0; n < audio.produced; ++n) {
        bytes[4u*n] = (uint8_t)samples[2u*n];
        bytes[4u*n+1u] = (uint8_t)((uint16_t)samples[2u*n] >> 8);
        bytes[4u*n+2u] = (uint8_t)samples[2u*n+1u];
        bytes[4u*n+3u] = (uint8_t)((uint16_t)samples[2u*n+1u] >> 8);
    }
    return fwrite(bytes, 4, audio.produced, out) != audio.produced;
}

int main(int argc, char **argv)
{
    static unsigned char rom[GW_MAX_ROM_SIZE + 1u];
    static unsigned char ram[GW_RAM_SIZE];
    uint64_t ticks, offset, length;
    gw_machine *machine = NULL;
    gw_config config = {sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
                        GW_RESET_DETERMINISTIC_ZERO, 1, {0, 0}};
    gw_run_result run = {0};
    FILE *f;
    size_t size, i;
    int io_error;
    gw_event events[GW_EVENT_CAPACITY];
    size_t event_count = 0;
    const char *events_path = NULL, *dump_path = NULL;
    const char *audio_path = NULL, *audio_trace_path = NULL;
    FILE *audio_file = NULL;
    uint64_t audio_rate = 0;
    gw_video_field field;
    int argi = 5;
    if (argc < 5) return reject("usage: gw_seam_runner ROM TICKS RAM_OFFSET RAM_LENGTH [--events FILE] [--port-device P1 P2] [--dump-field PATH]");
    while (argi < argc) {
        if (!strcmp(argv[argi], "--events") && argi + 1 < argc && !events_path) {
            events_path = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--dump-field") && argi + 1 < argc && !dump_path) {
            dump_path = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--audio-rate") && argi + 1 < argc && audio_rate == 0 &&
                   number(argv[argi + 1], 192000, &audio_rate) && audio_rate > 0) {
            config.audio_rate_hz = (uint32_t)audio_rate;
            argi += 2;
        } else if (!strcmp(argv[argi], "--dump-audio") && argi + 1 < argc && !audio_path) {
            audio_path = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--dump-audio-trace") && argi + 1 < argc && !audio_trace_path) {
            audio_trace_path = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--port-device") && argi + 2 < argc &&
                   device_kind(argv[argi + 1], &config.port_device[0]) &&
                   device_kind(argv[argi + 2], &config.port_device[1])) {
            argi += 3;
        } else {
            return reject("bad-argument");
        }
    }
    if (events_path && !read_events(events_path, events, &event_count)) return reject("events");
    if (!number(argv[2], GW_MAX_TARGET_TICK, &ticks) || !number(argv[3], GW_RAM_SIZE, &offset) ||
        !number(argv[4], GW_RAM_SIZE, &length) || length == 0 || offset + length > GW_RAM_SIZE)
        return reject("bad-argument");
    f = fopen(argv[1], "rb");
    if (!f) return reject("missing-rom");
    size = fread(rom, 1, sizeof(rom), f);
    io_error = ferror(f);
    if (fclose(f)) io_error = 1;
    if (io_error || size > GW_MAX_ROM_SIZE) return reject("rom-read");
    run.struct_size = sizeof(run);
    run.version = GW_API_VERSION;
    run.flags = GW_RUN_CONTINUE_PAST_FIELD; /* Run-to-target request: field ends never stop the run. */
    if (gw_create(&config, &machine) != GW_OK) return reject("create");
    if (audio_trace_path && gw_configure_audio_trace(machine, GW_AUDIO_TRACE_CAPACITY) != GW_OK) {
        gw_destroy(machine);
        return reject("audio-trace");
    }
    if (gw_load_rom(machine, rom, size) != GW_OK) {
        gw_destroy(machine);
        return reject("machine-call");
    }
    for (i = 0; i < event_count; ++i) {
        if (gw_schedule_event(machine, &events[i]) != GW_OK) {
            gw_destroy(machine);
            return reject("events");
        }
    }
    if (audio_path) {
        uint64_t now = 0;
        audio_file = fopen(audio_path, "wb");
        if (!audio_file) { gw_destroy(machine); return reject("audio-dump"); }
        while (now < ticks) {
            uint64_t target = ticks - now > UINT64_C(2000000) ? now + UINT64_C(2000000) : ticks;
            memset(&run, 0, sizeof(run));
            run.struct_size = sizeof(run);
            run.version = GW_API_VERSION;
            run.flags = GW_RUN_CONTINUE_PAST_FIELD;
            if (gw_run_until(machine, target, &run) != GW_OK || run.actual_tick <= now ||
                drain_audio(machine, audio_file) != 0) {
                fclose(audio_file); gw_destroy(machine); return reject("audio-dump");
            }
            now = run.actual_tick;
        }
        if (fclose(audio_file)) { gw_destroy(machine); return reject("audio-dump"); }
        audio_file = NULL;
    } else if (gw_run_until(machine, ticks, &run) != GW_OK) {
        gw_destroy(machine);
        return reject("machine-call");
    }
    if (gw_peek_memory(machine, UINT32_C(0xff0000) + (uint32_t)offset, ram, (size_t)length) != GW_OK) {
        gw_destroy(machine);
        return reject("machine-call");
    }
    if (dump_path && dump_field(machine, dump_path, &field) != 0) {
        gw_destroy(machine);
        return reject("no-field");
    }
    if (audio_trace_path) {
        gw_audio_write writes[GW_AUDIO_TRACE_CAPACITY];
        size_t count = 0, n;
        uint64_t dropped = 0;
        FILE *out = fopen(audio_trace_path, "w");
        if (!out || gw_get_audio_writes(machine, writes, GW_AUDIO_TRACE_CAPACITY,
                &count, &dropped) != GW_OK || dropped != 0) {
            if (out) fclose(out);
            gw_destroy(machine);
            return reject("audio-trace");
        }
        for (n = 0; n < count; ++n) {
            if (fprintf(out, "{\"tick\":%" PRIu64 ",\"chip\":%" PRIu32
                    ",\"reg\":%" PRIu32 ",\"value\":%" PRIu32
                    ",\"source\":%" PRIu32 "}\n", writes[n].tick, writes[n].chip,
                    writes[n].reg, writes[n].value, writes[n].source) < 0) {
                fclose(out); gw_destroy(machine); return reject("audio-trace");
            }
        }
        if (fclose(out)) { gw_destroy(machine); return reject("audio-trace"); }
    }
    printf("{\"source_revision\":\"%s\",\"configuration\":\"%s\",\"stop_reason\":%" PRIu32
           ",\"actual_tick\":%" PRIu64 ",\"instruction_address\":%" PRIu32
           ",\"fault_address\":%" PRIu32 ",\"ram\":\"", GW_SOURCE_REVISION, GW_CONFIGURATION,
           run.stop_reason, run.actual_tick, run.instruction_address, run.fault_address);
    for (i = 0; i < length; ++i) printf("%02x", ram[i]);
    if (dump_path)
        printf("\",\"field\":{\"width\":%" PRIu32 ",\"height\":%" PRIu32 ",\"sequence\":%" PRIu64 "}}\n",
               field.width, field.height, field.sequence);
    else
        puts("\"}");
    gw_destroy(machine);
    return 0;
}
