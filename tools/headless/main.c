/* SPDX-License-Identifier: MIT
 * gw_headless: runs a cartridge through the SDL-free session and prints one
 * JSON line per field plus a final line, so a desktop session recorded with an
 * input log can be reproduced and compared exactly.
 */
#include "input_log.h"
#include "rom_file.h"
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GW_MAX_FIELD_ROW_BYTES (320u * 4u)

static uint8_t rom_buffer[GW_MAX_ROM_SIZE];
static gw_audio_write audio_trace[GW_AUDIO_TRACE_CAPACITY];

static int usage(void)
{
    fputs("usage: gw_headless ROM --fields N [--replay LOG] [--record LOG] [--port-device P1 P2]\n"
          "                 [--dump-fields DIR] [--peek ADDRESS LENGTH]\n"
          "                 [--audio-rate N] [--dump-audio FILE] [--dump-audio-trace FILE]\n"
          "  devices: pad3 | none\n", stderr);
    return 2;
}

static int parse_count(const char *text, unsigned long long max, unsigned long long *value)
{
    char *end = NULL;
    unsigned long long parsed;
    if (!text || !text[0] || text[0] == '-') return 0;
    parsed = strtoull(text, &end, 10);
    if (!end || *end || parsed > max) return 0;
    *value = parsed;
    return 1;
}

static int dump_audio_frames(FILE *out, const int16_t *frames, uint32_t count)
{
    uint8_t bytes[4096];
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

static int dump_audio_trace(const gw_machine *machine, const char *path)
{
    size_t count = 0;
    uint64_t dropped = 0;
    FILE *out;
    if (gw_get_audio_writes(machine, audio_trace, GW_AUDIO_TRACE_CAPACITY, &count, &dropped) != GW_OK) return 1;
    out = fopen(path, "wb");
    if (!out) return 1;
    for (size_t i = 0; i < count; ++i) {
        const gw_audio_write *r = &audio_trace[i];
        if (fprintf(out, "{\"tick\":%llu,\"chip\":%u,\"reg\":%u,\"value\":%u,\"source\":%u}\n",
            (unsigned long long)r->tick, (unsigned)r->chip, (unsigned)r->reg,
            (unsigned)r->value, (unsigned)r->source) < 0) { fclose(out); return 1; }
    }
    if (fprintf(out, "{\"dropped\":%llu}\n", (unsigned long long)dropped) < 0) { fclose(out); return 1; }
    return fclose(out) != 0;
}

/* Writes field-<sequence>.bin (height rows of width*4 bytes, pitch removed, each pixel
 * 0x00RRGGBB as four little-endian bytes) and field-<sequence>.json into an existing
 * directory. File names come from the integer sequence only. Returns 0 on success. */
static int dump_field(const gw_session *session, const char *dir)
{
    gw_video_field field;
    const uint32_t *pixels = NULL;
    char path[4096];
    FILE *out;
    uint8_t row[GW_MAX_FIELD_ROW_BYTES];
    if (gw_session_field(session, &field, &pixels) != 0) return 1;
    if (field.width * 4u > sizeof(row)) return 1;
    if (snprintf(path, sizeof(path), "%s/field-%llu.bin", dir, (unsigned long long)field.sequence) >= (int)sizeof(path)) return 1;
    out = fopen(path, "wb");
    if (!out) return 1;
    for (uint32_t y = 0; y < field.height; ++y) {
        const uint32_t *src = (const uint32_t *)((const uint8_t *)pixels + (size_t)y * field.pitch_bytes);
        for (uint32_t x = 0; x < field.width; ++x) {
            row[x * 4u] = (uint8_t)(src[x] & 0xffu);
            row[x * 4u + 1u] = (uint8_t)((src[x] >> 8) & 0xffu);
            row[x * 4u + 2u] = (uint8_t)((src[x] >> 16) & 0xffu);
            row[x * 4u + 3u] = (uint8_t)(src[x] >> 24);
        }
        if (fwrite(row, 1, field.width * 4u, out) != field.width * 4u) { fclose(out); return 1; }
    }
    if (fclose(out) != 0) return 1;
    if (snprintf(path, sizeof(path), "%s/field-%llu.json", dir, (unsigned long long)field.sequence) >= (int)sizeof(path)) return 1;
    out = fopen(path, "wb");
    if (!out) return 1;
    fprintf(out, "{\"sequence\":%llu,\"width\":%u,\"height\":%u,\"row_bytes\":%u,"
            "\"pixel\":\"uint32 0x00RRGGBB little-endian\",\"end_tick\":%llu}\n",
            (unsigned long long)field.sequence, (unsigned)field.width, (unsigned)field.height,
            (unsigned)(field.width * 4u), (unsigned long long)field.end_tick);
    return fclose(out) != 0;
}

static int parse_device(const char *text, uint32_t *device)
{
    if (!strcmp(text, "pad3")) *device = GW_DEVICE_PAD3;
    else if (!strcmp(text, "none")) *device = GW_DEVICE_NONE;
    else return 0;
    return 1;
}

int main(int argc, char **argv)
{
    gw_config config = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, 0};
    gw_session session;
    gw_input_log log;
    const char *rom_path = NULL, *replay_path = NULL, *record_path = NULL, *reason = NULL, *dump_dir = NULL;
    const char *dump_audio_path = NULL, *dump_trace_path = NULL;
    FILE *audio_out = NULL;
    unsigned long long fields = 0, peek_address = 0, peek_length = 0;
    int have_peek = 0;
    size_t rom_size = 0;
    int status, have_fields = 0, exit_code = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--fields") && i + 1 < argc) {
            char *end = NULL;
            if (argv[i + 1][0] == '-') return usage();
            fields = strtoull(argv[++i], &end, 10);
            if (!*argv[i] || *end || fields == 0 || fields > UINT32_MAX) return usage();
            have_fields = 1;
        } else if (!strcmp(argv[i], "--replay") && i + 1 < argc) {
            replay_path = argv[++i];
        } else if (!strcmp(argv[i], "--record") && i + 1 < argc) {
            record_path = argv[++i];
        } else if (!strcmp(argv[i], "--dump-fields") && i + 1 < argc) {
            dump_dir = argv[++i];
        } else if (!strcmp(argv[i], "--peek") && i + 2 < argc) {
            char *end = NULL;
            peek_address = strtoull(argv[i + 1], &end, 0);
            if (!*argv[i + 1] || *end || peek_address > 0xFFFFFFu) return usage();
            peek_length = strtoull(argv[i + 2], &end, 10);
            if (!*argv[i + 2] || *end || peek_length == 0 || peek_length > 64) return usage();
            have_peek = 1;
            i += 2;
        } else if (!strcmp(argv[i], "--audio-rate") && i + 1 < argc) {
            unsigned long long rate;
            if (!parse_count(argv[++i], GW_AUDIO_MAX_RATE_HZ, &rate) ||
                (rate != 0 && rate < GW_AUDIO_MIN_RATE_HZ)) return usage();
            config.audio_rate_hz = (uint32_t)rate;
        } else if (!strcmp(argv[i], "--dump-audio") && i + 1 < argc) {
            dump_audio_path = argv[++i];
        } else if (!strcmp(argv[i], "--dump-audio-trace") && i + 1 < argc) {
            dump_trace_path = argv[++i];
        } else if (!strcmp(argv[i], "--port-device") && i + 2 < argc) {
            if (!parse_device(argv[i + 1], &config.port_device[0]) ||
                !parse_device(argv[i + 2], &config.port_device[1])) return usage();
            i += 2;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            return usage();
        } else if (!rom_path) {
            rom_path = argv[i];
        } else {
            return usage();
        }
    }
    if (!rom_path || !have_fields || (replay_path && record_path)) return usage();

    if (gw_read_rom_file(rom_path, rom_buffer, sizeof(rom_buffer), &rom_size, &reason)) {
        fprintf(stderr, "REJECT: %s\n", reason);
        return 1;
    }
    if (gw_input_log_init(&log) != 0) { fputs("ERROR: out of memory\n", stderr); return 1; }
    if (replay_path && gw_input_log_read(replay_path, &log, &reason) != 0) {
        fprintf(stderr, "REJECT: input-log %s\n", reason);
        gw_input_log_free(&log);
        return 1;
    }
    status = gw_session_open(&session, &config, rom_buffer, rom_size);
    if (status != 0) {
        fprintf(stderr, "REJECT: %s\n", status == (int)GW_ERROR_ROM ? "invalid-rom" : "load-failed");
        gw_input_log_free(&log);
        return 1;
    }
    if (replay_path) (void)gw_session_attach_log(&session, &log, GW_SESSION_REPLAY);
    else if (record_path) (void)gw_session_attach_log(&session, &log, GW_SESSION_RECORD);
    if (dump_audio_path) {
        audio_out = fopen(dump_audio_path, "wb");
        if (!audio_out) { fputs("ERROR: could not write audio dump\n", stderr); exit_code = 1; }
    }
    if (!exit_code && dump_trace_path && gw_configure_audio_trace(session.machine, GW_AUDIO_TRACE_CAPACITY) != GW_OK) {
        fputs("ERROR: could not configure audio trace\n", stderr);
        exit_code = 1;
    }

    for (unsigned long long n = 0; !exit_code && n < fields; ++n) {
        status = gw_session_step_field(&session);
        if (status != 0) {
            fprintf(stderr, "ERROR: core rejected a run request (status %d)\n", status);
            exit_code = 1;
            break;
        }
        if (gw_session_print_field(&session, stdout) != 0) { exit_code = 1; break; }
        if (dump_dir && dump_field(&session, dump_dir) != 0) {
            fputs("ERROR: could not write the field dump\n", stderr);
            exit_code = 1;
            break;
        }
        if (audio_out) {
            const int16_t *frames = NULL;
            uint32_t count = 0;
            gw_audio_read_result last;
            if (gw_session_audio(&session, &frames, &count, &last) != 0 ||
                dump_audio_frames(audio_out, frames, count) != 0) {
                fputs("ERROR: could not write audio dump\n", stderr);
                exit_code = 1;
                break;
            }
        }
    }
    if ((have_peek ? gw_session_print_final_peek(&session, stdout, (uint32_t)peek_address, (size_t)peek_length)
                   : gw_session_print_final(&session, stdout)) != 0) exit_code = 1;
    if (dump_audio_path && gw_session_print_audio_summary(&session, stdout) != 0) exit_code = 1;
    if (audio_out && fclose(audio_out) != 0) exit_code = 1;
    if (dump_trace_path && dump_audio_trace(session.machine, dump_trace_path) != 0) {
        fputs("ERROR: could not write audio trace\n", stderr);
        exit_code = 1;
    }
    if (record_path) {
        if (session.log_overflow) fputs("WARN: input log full, later input not recorded\n", stderr);
        if (gw_input_log_write(record_path, &log) != 0) { fputs("ERROR: could not write the log\n", stderr); exit_code = 1; }
    }
    if (fflush(stdout) != 0) exit_code = 1;
    gw_session_close(&session);
    gw_input_log_free(&log);
    return exit_code;
}
