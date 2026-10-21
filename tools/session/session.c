/* SPDX-License-Identifier: MIT */
#include "session.h"
#include <inttypes.h>
#include <string.h>

static void reset_audio_summary(gw_session *session);

int gw_session_open(gw_session *session, const gw_config *config, const uint8_t *rom, size_t size)
{
    gw_status status;
    if (!session || !config || !rom) return (int)GW_ERROR_ARGUMENT;
    memset(session, 0, sizeof(*session));
    session->config = *config;
    status = gw_create(config, &session->machine);
    if (status != GW_OK) return (int)status;
    status = gw_load_rom(session->machine, rom, size);
    if (status != GW_OK) {
        gw_destroy(session->machine);
        session->machine = NULL;
        return (int)status;
    }
    session->next_target = GW_FIELD_TICKS;
    reset_audio_summary(session);
    return 0;
}

static int schedule_event(gw_session *session, uint64_t tick, uint32_t type, uint32_t port, uint32_t mask)
{
    gw_event event;
    memset(&event, 0, sizeof(event));
    event.struct_size = sizeof(event);
    event.version = GW_API_VERSION;
    event.tick = tick;
    event.type = type;
    event.port = port;
    event.mask = mask;
    return (int)gw_schedule_event(session->machine, &event);
}

static void record(gw_session *session, uint64_t tick, uint32_t kind, uint32_t port, uint32_t mask)
{
    if (session->log_mode != GW_SESSION_RECORD || !session->log) return;
    if (gw_input_log_add(session->log, tick, kind, port, mask) != 0) session->log_overflow = 1;
}

static int reset_now(gw_session *session);

static uint64_t audio_hash_byte(uint64_t hash, uint8_t byte)
{
    return (hash ^ byte) * UINT64_C(1099511628211);
}

static uint64_t audio_hash_u32(uint64_t hash, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) hash = audio_hash_byte(hash, (uint8_t)(value >> (i * 8u)));
    return hash;
}

static uint64_t audio_hash_seed(uint32_t rate)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    hash = audio_hash_u32(hash, rate);
    hash = audio_hash_u32(hash, GW_AUDIO_MIX_V1);
    hash = audio_hash_u32(hash, GW_AUDIO_FILTER_BLEP_V1);
    hash = audio_hash_byte(hash, 'S'); hash = audio_hash_byte(hash, '1');
    hash = audio_hash_byte(hash, '6'); hash = audio_hash_byte(hash, 'L');
    hash = audio_hash_byte(hash, 'E'); hash = audio_hash_byte(hash, '2');
    return hash;
}

static void reset_audio_summary(gw_session *session)
{
    memset(session->audio_frames, 0, sizeof(session->audio_frames));
    memset(&session->audio_last, 0, sizeof(session->audio_last));
    session->audio_last.struct_size = sizeof(session->audio_last);
    session->audio_last.version = GW_API_VERSION;
    session->audio_last.mix_id = GW_AUDIO_MIX_V1;
    session->audio_last.filter_id = GW_AUDIO_FILTER_BLEP_V1;
    session->audio_count = 0;
    session->audio_total_frames = 0;
    session->audio_hash = audio_hash_seed(session->config.audio_rate_hz);
    session->audio_complete = 1;
}

/* The target the next field step runs to; also the tick a host reset is stamped with. */
static uint64_t step_target(const gw_session *session)
{
    uint64_t target = session->next_target;
    if (target < session->tick) /* A reset or overshoot already passed the target. */
        target = (session->tick / GW_FIELD_TICKS + 1) * GW_FIELD_TICKS;
    return target;
}

/* Stamps host input (or feeds the replay log) before running to target. */
static int schedule_inputs(gw_session *session, uint64_t target)
{
    if (session->log_mode == GW_SESSION_REPLAY && session->log) {
        const gw_input_log *log = session->log;
        while (session->replay_next < log->count && log->entries[session->replay_next].tick <= target) {
            const gw_input_entry *e = &log->entries[session->replay_next];
            int status = 0;
            if (e->kind == GW_LOG_RESET) {
                status = reset_now(session); /* Same point as the recorded host reset. */
            } else if (session->config.port_device[e->port] != GW_DEVICE_NONE) {
                status = schedule_event(session, e->tick, GW_EVENT_PAD_STATE, e->port, e->mask);
            }
            if (status != 0) return status;
            session->replay_next++;
        }
        return 0;
    }
    for (uint32_t port = 0; port < 2; ++port) {
        int status;
        if (session->config.port_device[port] == GW_DEVICE_NONE) continue;
        if (session->held[port] == session->scheduled[port]) continue;
        status = schedule_event(session, target, GW_EVENT_PAD_STATE, port, session->held[port]);
        if (status != 0) return status;
        session->scheduled[port] = session->held[port];
        record(session, target, GW_LOG_PAD, port, session->held[port]);
    }
    return 0;
}

void gw_session_set_input(gw_session *session, unsigned port, uint32_t mask)
{
    if (!session || port > 1 || session->log_mode == GW_SESSION_REPLAY) return;
    session->held[port] = mask & GW_BUTTON_MASK_PAD3;
}

uint32_t gw_session_key_button(gw_host_key key)
{
    switch (key) {
    case GW_KEY_UP: return GW_BUTTON_UP;
    case GW_KEY_DOWN: return GW_BUTTON_DOWN;
    case GW_KEY_LEFT: return GW_BUTTON_LEFT;
    case GW_KEY_RIGHT: return GW_BUTTON_RIGHT;
    case GW_KEY_Z: return GW_BUTTON_A;
    case GW_KEY_X: return GW_BUTTON_B;
    case GW_KEY_C: return GW_BUTTON_C;
    case GW_KEY_ENTER: return GW_BUTTON_START;
    }
    return 0;
}

int gw_session_attach_log(gw_session *session, gw_input_log *log, int mode)
{
    if (!session) return (int)GW_ERROR_ARGUMENT;
    if (mode == 0) {
        session->log = NULL;
        session->log_mode = 0;
        return 0;
    }
    if (!log || !log->entries || (mode != GW_SESSION_RECORD && mode != GW_SESSION_REPLAY))
        return (int)GW_ERROR_ARGUMENT;
    session->log = log;
    session->log_mode = mode;
    session->replay_next = 0;
    session->log_overflow = 0;
    return 0;
}

int gw_session_replace_rom(gw_session *session, const uint8_t *rom, size_t size)
{
    gw_machine *fresh = NULL;
    gw_status status;
    if (!session || !session->machine || !rom) return (int)GW_ERROR_ARGUMENT;
    status = gw_create(&session->config, &fresh);
    if (status != GW_OK) return (int)status;
    status = gw_load_rom(fresh, rom, size);
    if (status != GW_OK) {
        gw_destroy(fresh);
        return (int)status;
    }
    gw_destroy(session->machine);
    session->machine = fresh;
    session->scheduled[0] = session->scheduled[1] = 0;
    session->next_target = GW_FIELD_TICKS;
    session->tick = 0;
    session->fields = 0;
    session->resets = 0;
    session->stop_reason = 0;
    session->instruction_address = session->opcode = session->fault_address = 0;
    reset_audio_summary(session);
    session->replay_next = 0;
    if (session->log_mode == GW_SESSION_RECORD && session->log) session->log->count = 0;
    return 0;
}

int gw_session_step_field(gw_session *session)
{
    gw_run_result result;
    uint64_t target;
    gw_status status;
    if (!session || !session->machine) return (int)GW_ERROR_ARGUMENT;
    if (session->paused) return GW_SESSION_PAUSED;
    target = step_target(session);
    status = (gw_status)schedule_inputs(session, target);
    if (status != GW_OK) return (int)status;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    result.flags = GW_RUN_CONTINUE_PAST_FIELD; /* Run to the field-start target. */
    status = gw_run_until(session->machine, target, &result);
    if (status != GW_OK) return (int)status;
    memset(&session->audio_last, 0, sizeof(session->audio_last));
    session->audio_last.struct_size = sizeof(session->audio_last);
    session->audio_last.version = GW_API_VERSION;
    status = gw_audio_read(session->machine, &session->audio_frames[0][0],
        GW_SESSION_AUDIO_FRAMES, &session->audio_last);
    if (status != GW_OK) return (int)status;
    if (session->audio_last.lost != 0 || session->audio_last.first_index != session->audio_total_frames ||
        session->audio_last.mix_id != GW_AUDIO_MIX_V1 || session->audio_last.filter_id != GW_AUDIO_FILTER_BLEP_V1)
        session->audio_complete = 0;
    for (uint32_t i = 0; i < session->audio_last.produced; ++i) {
        uint16_t left = (uint16_t)session->audio_frames[i][0];
        uint16_t right = (uint16_t)session->audio_frames[i][1];
        session->audio_hash = audio_hash_byte(session->audio_hash, (uint8_t)left);
        session->audio_hash = audio_hash_byte(session->audio_hash, (uint8_t)(left >> 8));
        session->audio_hash = audio_hash_byte(session->audio_hash, (uint8_t)right);
        session->audio_hash = audio_hash_byte(session->audio_hash, (uint8_t)(right >> 8));
    }
    session->audio_count = session->audio_last.produced;
    session->audio_total_frames += session->audio_count;
    session->next_target = target + GW_FIELD_TICKS;
    session->tick = result.actual_tick;
    session->stop_reason = result.stop_reason;
    session->instruction_address = result.instruction_address;
    session->opcode = result.opcode;
    session->fault_address = result.fault_address;
    session->fields++;
    return 0;
}

void gw_session_set_paused(gw_session *session, int paused)
{
    if (session) session->paused = paused != 0;
}

int gw_session_unsupported_stop(const gw_session *session)
{
    return session && (session->stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION ||
        session->stop_reason == GW_STOP_UNSUPPORTED_ADDRESS ||
        session->stop_reason == GW_STOP_UNSUPPORTED_STATE);
}

int gw_session_audio(const gw_session *session, const int16_t **frames, uint32_t *count,
    gw_audio_read_result *last)
{
    if (!session || !frames || !count || !last) return (int)GW_ERROR_ARGUMENT;
    *frames = &session->audio_frames[0][0];
    *count = session->audio_count;
    *last = session->audio_last;
    return 0;
}

int gw_session_print_audio_summary(const gw_session *session, FILE *out)
{
    if (!session || !out) return 1;
    return fprintf(out, "{\"audio_rate_hz\":%u,\"mix_id\":%u,\"filter_id\":%u,\"frames\":%llu,"
        "\"lost\":%llu,\"clipped\":%llu,\"complete\":%s,\"fnv1a64\":\"%016llx\"}\n",
        session->config.audio_rate_hz, (unsigned)session->audio_last.mix_id,
        (unsigned)session->audio_last.filter_id, (unsigned long long)session->audio_total_frames,
        (unsigned long long)session->audio_last.lost, (unsigned long long)session->audio_last.clipped,
        session->audio_complete ? "true" : "false", (unsigned long long)session->audio_hash) < 0;
}

/* Resets the machine immediately. Recording and replay both reset here, between
 * field steps, so a sticky unsupported stop (which gw_run_until never leaves to
 * apply a queued event) cannot make replay diverge from the recorded run. */
static int reset_now(gw_session *session)
{
    gw_status status = gw_console_reset(session->machine);
    if (status != GW_OK) return (int)status;
    if (gw_session_unsupported_stop(session)) session->stop_reason = GW_STOP_TARGET;
    session->resets++;
    return 0;
}

int gw_session_reset(gw_session *session)
{
    int status;
    if (!session || !session->machine) return (int)GW_ERROR_ARGUMENT;
    if (session->log_mode == GW_SESSION_REPLAY) return 0; /* The log owns resets. */
    status = reset_now(session);
    if (status != 0) return status;
    /* Stamped with the target of the step it precedes, like pad changes. */
    record(session, step_target(session), GW_LOG_RESET, 0, 0);
    return 0;
}

int gw_session_field(const gw_session *session, gw_video_field *field, const uint32_t **pixels)
{
    if (!session || !session->machine || !field || !pixels) return (int)GW_ERROR_ARGUMENT;
    memset(field, 0, sizeof(*field));
    field->struct_size = sizeof(*field);
    field->version = GW_API_VERSION;
    return (int)gw_get_video_field(session->machine, field, pixels);
}

static uint64_t fnv_bytes(uint64_t hash, const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

int gw_session_print_field(const gw_session *session, FILE *out)
{
    gw_video_field field;
    const uint32_t *pixels = NULL;
    uint64_t hash = UINT64_C(14695981039346656037);
    if (!out || gw_session_field(session, &field, &pixels) != 0) return 1;
    for (uint32_t row = 0; row < field.height; ++row)
        hash = fnv_bytes(hash, (const uint8_t *)pixels + (size_t)row * field.pitch_bytes, (size_t)field.width * 4u);
    return fprintf(out, "{\"sequence\":%" PRIu64 ",\"width\":%" PRIu32 ",\"height\":%" PRIu32
        ",\"pitch_bytes\":%" PRIu32 ",\"end_tick\":%" PRIu64 ",\"fnv1a64\":\"%016" PRIx64 "\"}\n",
        field.sequence, field.width, field.height, field.pitch_bytes, field.end_tick, hash) < 0;
}

int gw_session_print_final(const gw_session *session, FILE *out)
{
    static uint8_t ram[GW_RAM_SIZE];
    if (!session || !session->machine || !out) return 1;
    if (gw_peek_memory(session->machine, 0xFF0000u, ram, sizeof(ram)) != GW_OK) return 1;
    return fprintf(out, "{\"fields\":%" PRIu64 ",\"ram_fnv1a64\":\"%016" PRIx64 "\"}\n",
        session->fields, fnv_bytes(UINT64_C(14695981039346656037), ram, sizeof(ram))) < 0;
}

int gw_session_print_final_peek(const gw_session *session, FILE *out, uint32_t address, size_t length)
{
    static uint8_t ram[GW_RAM_SIZE];
    uint8_t bytes[64];
    char hex[2 * sizeof(bytes) + 1];
    if (!session || !session->machine || !out || length == 0 || length > sizeof(bytes)) return 1;
    if (gw_peek_memory(session->machine, 0xFF0000u, ram, sizeof(ram)) != GW_OK) return 1;
    if (gw_peek_memory(session->machine, address, bytes, length) != GW_OK) return 1;
    for (size_t i = 0; i < length; ++i) snprintf(hex + 2 * i, 3, "%02x", bytes[i]);
    return fprintf(out, "{\"fields\":%" PRIu64 ",\"ram_fnv1a64\":\"%016" PRIx64 "\",\"peek\":\"%s\","
        "\"unsupported\":%d,\"stop_reason\":%u,\"instruction_address\":%u,\"opcode\":%u,\"fault_address\":%u}\n",
        session->fields, fnv_bytes(UINT64_C(14695981039346656037), ram, sizeof(ram)), hex,
        gw_session_unsupported_stop(session) ? 1 : 0, (unsigned)session->stop_reason,
        (unsigned)session->instruction_address, (unsigned)session->opcode, (unsigned)session->fault_address) < 0;
}

void gw_session_close(gw_session *session)
{
    if (!session) return;
    gw_destroy(session->machine);
    memset(session, 0, sizeof(*session));
}
