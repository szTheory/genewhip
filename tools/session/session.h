/* SPDX-License-Identifier: MIT
 * SDL-free session module. It owns one machine and advances it one emulated
 * field per call; it never reads a host clock, so pacing belongs to the caller.
 * Return convention for open/step/reset: 0 on success, GW_SESSION_PAUSED when a
 * paused session declines to step, otherwise a positive gw_status.
 */
#ifndef GENEWHIP_SESSION_H
#define GENEWHIP_SESSION_H

#include <genewhip/genewhip.h>
#include <stdio.h>
#include "input_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Most fields a host may step in one presented frame while catching up; the
 * remaining debt is discarded, so emulated time slows rather than skipping. */
#define GW_SESSION_CATCHUP_FIELDS 4
#define GW_SESSION_PAUSED (-1)
#define GW_SESSION_AUDIO_FRAMES GW_AUDIO_QUEUE_FRAMES

/* Host keys the session understands; the desktop runner translates scancodes. */
typedef enum gw_host_key {
    GW_KEY_UP, GW_KEY_DOWN, GW_KEY_LEFT, GW_KEY_RIGHT,
    GW_KEY_Z, GW_KEY_X, GW_KEY_C, GW_KEY_ENTER
} gw_host_key;

enum { GW_SESSION_RECORD = 1, GW_SESSION_REPLAY = 2 };

typedef struct gw_session {
    gw_config config;       /* Retained so a replacement cartridge gets the same ports. */
    gw_machine *machine;
    uint32_t held[2];       /* Latest host masks per port (sampled once per field). */
    uint32_t scheduled[2];  /* Masks already stamped into the machine. */
    gw_input_log *log;
    int log_mode;           /* 0, GW_SESSION_RECORD or GW_SESSION_REPLAY */
    size_t replay_next;     /* Next unscheduled replay entry. */
    int log_overflow;       /* Recording hit GW_INPUT_LOG_MAX and stopped. */
    uint64_t next_target;   /* Start tick of the field after the next one stepped. */
    uint64_t tick;          /* Machine tick reached by the latest run. */
    uint64_t fields;        /* Fields stepped since open. */
    uint64_t resets;        /* Console resets requested since open. */
    int paused;
    uint32_t stop_reason;   /* Latest run stop reason (GW_STOP_*). */
    uint32_t instruction_address;
    uint32_t opcode;
    uint32_t fault_address;
    int16_t audio_frames[GW_SESSION_AUDIO_FRAMES][2];
    uint32_t audio_count;
    gw_audio_read_result audio_last;
    uint64_t audio_hash;
    uint64_t audio_total_frames;
    int audio_complete;
} gw_session;

/* Creates the machine from the caller's configuration and loads the ROM bytes
 * (copied by the core). On failure the session holds no machine. */
int gw_session_open(gw_session *session, const gw_config *config, const uint8_t *rom, size_t size);
/* Records the latest logical button state (GW_BUTTON_* union) for a port. The
 * session stamps it at the next field-start tick; no clock is read. Ports
 * configured GW_DEVICE_NONE, ports above 1 and bits above 0xFF are ignored.
 * Ignored while replaying. */
void gw_session_set_input(gw_session *session, unsigned port, uint32_t mask);
/* Maps a host key to its GW_BUTTON_* bit (D-pad, Z=A, X=B, C=C, Enter=Start). */
uint32_t gw_session_key_button(gw_host_key key);
/* Attaches a caller-owned log. RECORD appends stamped pad and reset entries;
 * REPLAY feeds the log's entries just in time and ignores host input and
 * reset requests. Returns 0 or GW_ERROR_ARGUMENT. Detach with mode 0. */
int gw_session_attach_log(gw_session *session, gw_input_log *log, int mode);
/* Builds a fresh machine for the new ROM with the same configuration and swaps
 * it in; the session restarts at tick zero (an attached record log is cleared,
 * a replay log rewinds). On failure the current machine is untouched. */
int gw_session_replace_rom(gw_session *session, const uint8_t *rom, size_t size);
/* Runs the machine to the next field target. Does nothing while paused. */
int gw_session_step_field(gw_session *session);
void gw_session_set_paused(gw_session *session, int paused);
/* Console reset applied immediately, between field steps, at the machine tick
 * reached. It also clears a sticky unsupported stop. A recording stamps it with
 * the target of the next step and replay resets at that same point, so a reset
 * after an unsupported stop replays identically. */
int gw_session_reset(gw_session *session);
/* Describes the newest completed field; GW_ERROR_EMPTY before the first. */
int gw_session_field(const gw_session *session, gw_video_field *field, const uint32_t **pixels);
/* Prints the newest field as one JSON line {sequence,width,height,pitch_bytes,
 * end_tick,fnv1a64} (FNV-1a 64 over height rows of width*4 bytes). Returns 0
 * or nonzero when no field exists or the write fails. */
int gw_session_print_field(const gw_session *session, FILE *out);
/* Prints {fields, ram_fnv1a64} (hash of the 64 KiB work RAM). */
int gw_session_print_final(const gw_session *session, FILE *out);
/* Like gw_session_print_final plus "peek" (hex of length <= 64 bytes read through
 * gw_peek_memory) and the latest stop fields. Returns 0 or nonzero on failure. */
int gw_session_print_final_peek(const gw_session *session, FILE *out, uint32_t address, size_t length);
/* Audio from the latest successful step; frames remain valid until the next step. */
int gw_session_audio(const gw_session *session, const int16_t **frames, uint32_t *count,
    gw_audio_read_result *last);
/* Prints the self-describing cumulative output hash as one JSON line. */
int gw_session_print_audio_summary(const gw_session *session, FILE *out);
/* Nonzero when the machine is in a sticky unsupported stop. */
int gw_session_unsupported_stop(const gw_session *session);
void gw_session_close(gw_session *session);

#ifdef __cplusplus
}
#endif
#endif
