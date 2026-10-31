/* SPDX-License-Identifier: MIT */
#include "session.h"
#include "route_controller.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static void reset_audio_summary(gw_session *session);
static uint16_t read_le16(const uint8_t *p);
static uint32_t read_le32(const uint8_t *p);
static uint64_t read_le64(const uint8_t *p);

static void retire_route_events(gw_session *session)
{
    uint32_t keep = 0;
    for (uint32_t i = 0; i < session->route_pending_events; ++i) {
        if (session->route_event_ticks[i] > session->tick)
            session->route_event_ticks[keep++] = session->route_event_ticks[i];
    }
    session->route_pending_events = keep;
}

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

static int capture_audio(gw_session *session)
{
    gw_status status;
    memset(&session->audio_last, 0, sizeof(session->audio_last));
    session->audio_last.struct_size = sizeof(session->audio_last);
    session->audio_last.version = GW_API_VERSION;
    status = gw_audio_read(session->machine, &session->audio_frames[0][0],
        GW_SESSION_AUDIO_FRAMES, &session->audio_last);
    if (status != GW_OK) return (int)status;
    if (session->audio_last.lost != 0 || session->audio_last.first_index != session->audio_total_frames ||
        session->audio_last.mix_id != GW_AUDIO_MIX_V1 || session->audio_last.filter_id != GW_AUDIO_FILTER_BLEP_V1)
        session->audio_complete = 0;
    if (!session->route_disable_audio_hash)
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
    return 0;
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
    status = (gw_status)capture_audio(session);
    if (status != GW_OK) return (int)status;
    session->next_target = target + GW_FIELD_TICKS;
    session->tick = result.actual_tick;
    session->stop_reason = result.stop_reason;
    session->instruction_address = result.instruction_address;
    session->opcode = result.opcode;
    session->fault_address = result.fault_address;
    session->fields++;
    return 0;
}

int gw_session_route_observe(gw_session *session, const gw_session_route_plan *plan,
    const gw_session_route_op *operation, gw_session_route_field_callback field_callback,
    void *context, uint64_t *instructions)
{
    uint64_t count = 0;
    if (!session || !session->machine || !plan || !plan->bytes || !operation ||
        !instructions || operation->type != 1 || operation->span_count == 0 ||
        operation->instruction_limit == 0 || operation->span_offset > plan->byte_count)
        return (int)GW_ERROR_ARGUMENT;
    *instructions = 0;
    while (count < operation->instruction_limit) {
        gw_run_result run;
        gw_diagnostic_record before, after;
        gw_status status;
        uint64_t target;
        memset(&before, 0, sizeof(before));
        before.struct_size = sizeof(before);
        before.version = GW_API_VERSION;
        status = gw_get_diagnostics(session->machine, &before);
        if (status != GW_OK) return (int)status;
        /* Reset-vector fetch advances the public machine before the first run. */
        session->tick = before.tick;
        if (before.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION || before.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS)
            return (int)GW_ERROR_UNSUPPORTED;
        if (session->tick >= GW_MAX_TARGET_TICK) return (int)GW_ERROR_TIME;
        target = session->tick + 1;
        memset(&run, 0, sizeof(run));
        run.struct_size = sizeof(run);
        run.version = GW_API_VERSION;
        run.flags = GW_RUN_CONTINUE_PAST_FIELD;
        status = gw_run_until(session->machine, target, &run);
        if (status != GW_OK) return (int)status;
        session->tick = run.actual_tick;
        retire_route_events(session);
        session->stop_reason = run.stop_reason;
        session->instruction_address = run.instruction_address;
        session->opcode = run.opcode;
        session->fault_address = run.fault_address;
        memset(&after, 0, sizeof(after));
        after.struct_size = sizeof(after);
        after.version = GW_API_VERSION;
        status = gw_get_diagnostics(session->machine, &after);
        if (status != GW_OK) return (int)status;
        session->route_last_d0 = after.d[0];
        if (after.instructions > before.instructions) count += after.instructions - before.instructions;
        else count++;
        if (run.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION || run.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS) {
            *instructions = count;
            return (int)GW_ERROR_UNSUPPORTED;
        }
        /* A one-instruction call may publish a field. Drain its complete PCM
         * queue immediately, retaining the same host evidence as field stepping. */
        {
            gw_video_field field;
            const uint32_t *pixels = NULL;
            memset(&field, 0, sizeof(field));
            field.struct_size = sizeof(field);
            field.version = GW_API_VERSION;
            if (gw_get_video_field(session->machine, &field, &pixels) == GW_OK &&
                field.sequence + 1 > session->fields) {
                session->fields = field.sequence + 1;
                if (capture_audio(session) != 0) return (int)GW_ERROR_ARGUMENT;
                if (field_callback && field_callback(context, session) != 0)
                    return (int)GW_ERROR_ARGUMENT;
            }
        }
        session->route_observation_count++;
        {
            size_t at = operation->span_offset;
            int matched = 1;
            for (uint16_t span_index = 0; span_index < operation->span_count; ++span_index) {
                uint8_t bytes[64];
                uint32_t address;
                uint8_t length;
                if (at > plan->byte_count || plan->byte_count - at < 8u) return (int)GW_ERROR_ARGUMENT;
                address = read_le32(plan->bytes + at);
                length = plan->bytes[at + 4];
                at += 8u;
                if (length == 0 || length > sizeof(bytes) || at > plan->byte_count ||
                    plan->byte_count - at < length) return (int)GW_ERROR_ARGUMENT;
                status = gw_peek_memory(session->machine, address, bytes, length);
                if (status != GW_OK) return (int)status;
                if (memcmp(bytes, plan->bytes + at, length) != 0) matched = 0;
                at += length;
            }
            if (matched) {
                *instructions = count;
                return 0;
            }
        }
        /* STOP may wake at a VDP interrupt. It is not a sticky unsupported stop. */
    }
    *instructions = count;
    return (int)GW_ERROR_CAPACITY;
}

int gw_session_route_dispatch(gw_session *session, unsigned port, uint32_t mask, uint64_t tick)
{
    if (!session || !session->machine || port > 1 || (mask & ~(uint32_t)GW_BUTTON_MASK_PAD3) != 0)
        return (int)GW_ERROR_ARGUMENT;
    if (session->config.port_device[port] == GW_DEVICE_NONE) return (int)GW_ERROR_UNSUPPORTED;
    if (tick == UINT64_MAX) tick = session->tick;
    if (tick < session->tick || tick > GW_MAX_TARGET_TICK) return (int)GW_ERROR_TIME;
    if (mask == session->held[port] && mask == session->scheduled[port]) return 0;
    if (session->route_pending_events >= GW_SESSION_ROUTE_EVENT_CAPACITY) return (int)GW_ERROR_CAPACITY;
    {
        int status = schedule_event(session, tick, GW_EVENT_PAD_STATE, port, mask);
        if (status != 0) return status;
    }
    session->route_pending_events++;
    session->route_event_ticks[session->route_pending_events - 1] = tick;
    if (session->route_pending_events > session->route_queue_high_water)
        session->route_queue_high_water = session->route_pending_events;
    session->held[port] = mask;
    session->scheduled[port] = mask;
    record(session, tick, GW_LOG_PAD, port, mask);
    return 0;
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/* GWRP v1 uses a 12-byte header, 28-byte operation headers and variable spans.
 * Every span is a nonwrapping 24-bit public-memory read with exact expected bytes. */
int gw_session_route_load(const char *path, gw_session_route_plan *plan)
{
    FILE *file;
    long length;
    uint8_t *bytes;
    gw_session_route_op *operations = NULL;
    size_t op_count;
    size_t at;
    uint64_t previous_dispatch_tick = 0;
    int have_previous_dispatch_tick = 0;
    int observed_boundary_tick_seen = 0;
    int result = (int)GW_ERROR_ARGUMENT;
    if (!path || !plan || plan->bytes || plan->operations || plan->controller) return (int)GW_ERROR_ARGUMENT;
    file = fopen(path, "rb");
    if (!file) return (int)GW_ERROR_ARGUMENT;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 12 || length > 1024 * 1024 ||
        fseek(file, 0, SEEK_SET) != 0) { (void)fclose(file); return (int)GW_ERROR_ARGUMENT; }
    bytes = (uint8_t *)malloc((size_t)length);
    if (!bytes) { (void)fclose(file); return (int)GW_ERROR_MEMORY; }
    if (fread(bytes, 1, (size_t)length, file) != (size_t)length || ferror(file)) goto done;
    if (fclose(file) != 0) { file = NULL; goto done; }
    file = NULL;
    if (memcmp(bytes, "GWRC", 4) == 0) {
        result = gw_route_controller_parse(bytes, (size_t)length, &plan->controller);
        goto done;
    }
    if (memcmp(bytes, "GWRP", 4) != 0 || read_le16(bytes + 4) != 1 || read_le32(bytes + 8) != 0) goto done;
    op_count = read_le16(bytes + 6);
    if (op_count == 0 || op_count > GW_SESSION_ROUTE_MAX_OPS) goto done;
    operations = (gw_session_route_op *)calloc(op_count, sizeof(*operations));
    if (!operations) { result = (int)GW_ERROR_MEMORY; goto done; }
    at = 12u;
    for (size_t i = 0; i < op_count; ++i) {
        const uint8_t *p;
        uint16_t span_count;
        if (at > (size_t)length || (size_t)length - at < 28u) goto done;
        p = bytes + at;
        span_count = read_le16(p + 2);
        if (p[0] != 1 || p[1] > 1 || span_count == 0 || span_count > 64 ||
            read_le32(p + 8) != 0 || (read_le32(p + 4) & ~(uint32_t)GW_BUTTON_MASK_PAD3) != 0 ||
            read_le64(p + 12) == 0 || read_le64(p + 12) > UINT64_C(100000) ||
            (read_le64(p + 20) != UINT64_MAX && read_le64(p + 20) > GW_MAX_TARGET_TICK)) goto done;
        operations[i].type = p[0];
        operations[i].port = p[1];
        operations[i].span_count = span_count;
        operations[i].mask = read_le32(p + 4);
        operations[i].instruction_limit = read_le64(p + 12);
        operations[i].dispatch_tick = read_le64(p + 20);
        if (operations[i].dispatch_tick == UINT64_MAX) {
            observed_boundary_tick_seen = 1;
        } else {
            if (observed_boundary_tick_seen ||
                (have_previous_dispatch_tick && operations[i].dispatch_tick < previous_dispatch_tick)) goto done;
            previous_dispatch_tick = operations[i].dispatch_tick;
            have_previous_dispatch_tick = 1;
        }
        at += 28u;
        operations[i].span_offset = at;
        for (uint16_t j = 0; j < span_count; ++j) {
            uint32_t address;
            uint8_t span_length;
            if (at > (size_t)length || (size_t)length - at < 8u) goto done;
            address = read_le32(bytes + at);
            span_length = bytes[at + 4];
            if (address > UINT32_C(0xffffff) || span_length == 0 || span_length > 64 ||
                bytes[at + 5] || bytes[at + 6] || bytes[at + 7] ||
                (uint64_t)address + span_length > UINT64_C(0x1000000)) goto done;
            at += 8u;
            if (at > (size_t)length || (size_t)length - at < span_length) goto done;
            if (j == 0) {
                operations[i].address = address;
                if (span_length == 2) operations[i].value = (uint16_t)(((uint16_t)bytes[at] << 8) | bytes[at + 1]);
            }
            at += span_length;
        }
    }
    if (at != (size_t)length) goto done;
    plan->bytes = bytes;
    plan->byte_count = (size_t)length;
    plan->operations = operations;
    plan->operation_count = op_count;
    bytes = NULL;
    operations = NULL;
    result = 0;
done:
    if (file) (void)fclose(file);
    free(bytes);
    free(operations);
    return result;
}

void gw_session_route_plan_free(gw_session_route_plan *plan)
{
    if (!plan) return;
    free(plan->bytes);
    free(plan->operations);
    gw_route_controller_free(plan->controller);
    memset(plan, 0, sizeof(*plan));
}

int gw_session_route_boundary(gw_session *s, uint64_t target, uint32_t flags,
    gw_session_route_field_callback callback, void *context, int *retired)
{
    gw_diagnostic_record before = {0}, after = {0};
    gw_run_result run = {0};
    gw_video_field field = {0};
    const uint32_t *pixels = NULL;
    int status;
    before.struct_size = after.struct_size = sizeof(before);
    before.version = after.version = GW_API_VERSION;
    run.struct_size = sizeof(run); run.version = GW_API_VERSION; run.flags = flags;
    if (gw_get_diagnostics(s->machine, &before) != GW_OK) return GW_ERROR_ARGUMENT;
    status = (int)gw_run_until(s->machine, target, &run);
    if (status != 0) return status;
    s->tick = run.actual_tick;
    s->stop_reason = run.stop_reason;
    s->instruction_address = run.instruction_address; s->opcode = run.opcode;
    s->fault_address = run.fault_address;
    retire_route_events(s);
    if (gw_get_diagnostics(s->machine, &after) != GW_OK) return GW_ERROR_ARGUMENT;
    /* Diagnostics are optional. The run result identifies the fetched opcode
     * and its address; interrupt entry deliberately clears opcode to zero and
     * pushes six bytes on the supervisor stack. The only supported guest opcode
     * encoded as zero is ORI.B #imm,Dn: it advances PC by four and leaves A7
     * unchanged. These public register observations keep IRQ entry from being
     * mistaken for guest retirement when the optional counter is disabled. */
    *retired = after.instructions > before.instructions ||
        (run.stop_reason != GW_STOP_UNSUPPORTED_INSTRUCTION &&
         run.stop_reason != GW_STOP_UNSUPPORTED_ADDRESS &&
         run.stop_reason != GW_STOP_UNSUPPORTED_STATE && run.instruction_address == before.pc &&
         (run.opcode != 0 || (after.pc == before.pc + 4u && after.a[7] == before.a[7])));
    s->route_last_d0 = after.d[0];
    s->route_observation_count++;
    if (gw_session_unsupported_stop(s)) return GW_ERROR_UNSUPPORTED;
    field.struct_size = sizeof(field); field.version = GW_API_VERSION;
    if (gw_get_video_field(s->machine, &field, &pixels) == GW_OK && field.sequence + 1 > s->fields) {
        s->fields = field.sequence + 1;
        if (capture_audio(s) != 0) return GW_ERROR_ARGUMENT;
        if (callback && callback(context, s) != 0) return GW_ERROR_ARGUMENT;
    }
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
