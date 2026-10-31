/* SPDX-License-Identifier: MIT */
#include "route_controller.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

enum { SIGNALS, MARKERS, ACTIONS, STEPS, TARGETS, CONDITIONS, EVENTS, PREDICATES };
static const unsigned strides[8] = {4, 2, 5, 2, 4, 3, 6, 4};
static const unsigned counts[8] = {6, 7, 8, 9, 10, 11, 12, 13};
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static const uint32_t *row(const gw_route_controller *p, unsigned section, uint32_t index)
{
    return p->words + p->section[section] + (size_t)index * strides[section];
}
static int range(uint32_t start, uint32_t count, uint32_t length)
{
    return start <= length && count <= length - start;
}
static int button(uint32_t port, uint32_t bit)
{
    return port < 2 && bit && bit <= 128 && !(bit & (bit - 1));
}

int gw_route_controller_parse(const uint8_t *bytes, size_t size, gw_route_controller **out)
{
    gw_route_controller *p;
    uint32_t *h;
    size_t at = GW_RC_HEADER_WORDS, records = 0;
    if (!bytes || !out || *out || size < GW_RC_HEADER_WORDS * 4 || size > 1048576 || size % 4 ||
        memcmp(bytes, "GWRC", 4)) return GW_ERROR_ARGUMENT;
    p = (gw_route_controller *)calloc(1, sizeof(*p));
    if (!p) return GW_ERROR_MEMORY;
    p->word_count = size / 4;
    p->words = (uint32_t *)malloc(size);
    if (!p->words) { free(p); return GW_ERROR_MEMORY; }
    for (size_t i = 0; i < p->word_count; ++i) p->words[i] = le32(bytes + 4 * i);
    memcpy(p->header, p->words, sizeof(p->header)); h = p->header;
    if (h[1] != 1 || h[2] < 1 || h[2] > 3 || !h[3] || h[3] > 7200 ||
        !h[4] || h[4] > 3600 || h[5] > h[3] || !h[6] || h[6] > GW_RC_MAX_SIGNALS || h[7] > 64 ||
        h[8] > 32 || h[9] > 128 || h[10] > 256 || h[11] > 1024 || h[12] > 4096 || h[13] > 64 ||
        h[14] >= h[6] || h[19] > 65535 || h[20] > 65535 || h[21] > h[3] ||
        h[22] > h[3] - h[21] || h[25] > 2 || !h[30] || h[30] > 100000000 || h[31]) goto invalid;
    if (h[21] && (!h[22] || !button(h[23], h[24]))) goto invalid;
    if (!h[21] && (h[22] || h[23] || h[24])) goto invalid;
    if (h[25] == 1 && (h[26] == 0 || h[26] > h[3])) goto invalid;
    if (h[2] == 2 && (h[15] >= h[6] || h[16] >= h[6] || h[17] >= h[6] ||
        !h[7] || !h[18] || h[18] > 720 || h[8] || h[21])) goto invalid;
    if (h[2] != 2 && (h[7] || h[15] || h[16] || h[17] || h[18])) goto invalid;
    if (h[2] != 1 && h[8]) goto invalid;
    for (unsigned k = 0; k < 8; ++k) {
        records += h[counts[k]];
        p->section[k] = at;
        at += (size_t)h[counts[k]] * strides[k];
        if (at > p->word_count) goto invalid;
    }
    if (records > GW_RC_MAX_RECORDS || at != p->word_count) goto invalid;
    for (uint32_t i = 0; i < h[6]; ++i) {
        const uint32_t *r = row(p, SIGNALS, i);
        if (r[1] != (r[0] & 0xFFFFFFu) || (r[2] != 1 && r[2] != 2) ||
            r[1] > 0x1000000u - r[2] || r[3] > 1) goto invalid;
        uint32_t span = 0;
        for (; span < p->span_count; ++span) {
            uint32_t low = r[1] < p->span_address[span] ? r[1] : p->span_address[span];
            uint32_t end = r[1] + r[2] > p->span_address[span] + p->span_length[span] ?
                r[1] + r[2] : p->span_address[span] + p->span_length[span];
            if (end - low <= 64) {
                p->span_address[span] = low; p->span_length[span] = end - low; break;
            }
        }
        if (span == p->span_count) {
            if (span == 64) goto invalid;
            p->span_address[span] = r[1]; p->span_length[span] = r[2]; p->span_count++;
        }
        p->signal_span[i] = span;
    }
    for (uint32_t i = 0; i < h[7]; ++i) {
        const uint32_t *r = row(p, MARKERS, i);
        if (r[0] > 0x3FFFFAu || (r[0] & 1) || r[1] != 0x4279) goto invalid;
        for (uint32_t j = 0; j < i; ++j) if (row(p, MARKERS, j)[0] == r[0]) goto invalid;
    }
    if (h[2] == 2) {
        for (unsigned k = 14; k <= 17; ++k) {
            const uint32_t *s = row(p, SIGNALS, h[k]);
            if (s[2] != 2 || s[3]) goto invalid;
        }
    }
    if (h[25] == 2 && (h[2] != 2 || h[28] > h[18] ||
        (h[29] != h[19] && h[29] != h[20]))) goto invalid;
    for (uint32_t i = 0; i < h[8]; ++i) {
        const uint32_t *r = row(p, ACTIONS, i);
        if (!r[1] || !range(r[0], r[1], h[11]) || !r[3] || !range(r[2], r[3], h[9]) ||
            !r[4] || r[4] > h[3]) goto invalid;
    }
    for (uint32_t i = 0; i < h[9]; ++i) {
        const uint32_t *r = row(p, STEPS, i);
        if (!r[1] || r[1] > 16 || !range(r[0], r[1], h[10])) goto invalid;
        uint32_t seen[2] = {0,0};
        for (uint32_t j = 0; j < r[1]; ++j) {
            const uint32_t *t = row(p, TARGETS, r[0] + j);
            if (t[0] > 1 || (seen[t[0]] & t[1])) goto invalid;
            seen[t[0]] |= t[1];
        }
    }
    for (uint32_t i = 0; i < h[10]; ++i) {
        const uint32_t *r = row(p, TARGETS, i);
        if (!button(r[0], r[1]) || !r[3] || !range(r[2], r[3], h[11])) goto invalid;
    }
    for (uint32_t i = 0; i < h[11]; ++i) {
        const uint32_t *r = row(p, CONDITIONS, i);
        if ((r[0] >= h[6] && r[0] != UINT32_MAX) || r[1] > 2) goto invalid;
    }
    for (uint32_t i = 0; i < h[12]; ++i) {
        const uint32_t *r = row(p, EVENTS, i);
        if (!button(r[3], r[4]) || r[5] > 1 || (h[2] == 1) ||
            (h[2] == 2 && (r[0] > 65535 || r[1] > h[18] || (r[2] != h[19] && r[2] != h[20]))) ||
            (h[2] == 3 && (r[0] || r[2] || r[1] > h[3]))) goto invalid;
        if (i) {
            const uint32_t *prev = row(p, EVENTS, i - 1);
            if (r[0] < prev[0] || (r[0] == prev[0] && r[1] < prev[1])) goto invalid;
        }
    }
    for (uint32_t i = 0; i < h[13]; ++i) {
        const uint32_t *r = row(p, PREDICATES, i);
        if (r[0] >= h[6] || r[2] > r[3] || r[3] > h[4]) goto invalid;
    }
    *out = p;
    return 0;
invalid:
    gw_route_controller_free(p);
    return GW_ERROR_ARGUMENT;
}

void gw_route_controller_free(gw_route_controller *p)
{
    if (p) { free(p->words); free(p); }
}

typedef gw_route_input_record input_record;
typedef struct stack_observation {
    uint32_t source_a7, base32, addresses24[4];
    uint8_t bytes[4];
    int status[4];
    uint32_t read_calls;
    int enabled;
} stack_observation;
typedef struct boundary_state {
    gw_diagnostic_record cpu;
    uint8_t spans[64][64];
    uint64_t dropped;
    stack_observation stack;
} boundary_state;
typedef struct boundary_pair {
    boundary_state before, after;
    uint64_t target, fields, active;
    uint32_t instruction_address, opcode, fault_address, stop_reason, masks[2], event;
    int available, retired;
} boundary_pair;
typedef struct controller_run {
    const gw_route_controller *plan;
    gw_session *session;
    uint32_t values[GW_RC_MAX_SIGNALS], masks[2], last_attempt, last_tick;
    uint32_t action, step, event;
    uint64_t active, action_start, render_tick;
    uint32_t predicate_value[64];
    uint64_t predicate_clock[64];
    int predicate_seen[64], started, rendered, sample_comma;
    input_record inputs[4096]; size_t input_count;
    uint64_t stack_read_calls;
    gw_route_input_callback input; void *input_context;
    FILE *out;
    gw_route_capture *capture;
    boundary_pair last, probe;
} controller_run;

static void stack_snapshot(controller_run *r, stack_observation *o, uint32_t source_a7)
{
    memset(o, 0, sizeof(*o));
    o->enabled = 1;
    o->source_a7 = source_a7;
    o->base32 = source_a7 - UINT32_C(4);
    for (unsigned i = 0; i < 4; ++i) {
        o->addresses24[i] = (o->base32 + (uint32_t)i) & UINT32_C(0x00ffffff);
        o->status[i] = (int)gw_peek_memory(r->session->machine, o->addresses24[i], &o->bytes[i], 1);
        ++r->stack_read_calls;
        ++o->read_calls;
    }
}

static int boundary_snapshot(controller_run *r, boundary_state *s)
{
    gw_diagnostic_event events[GW_DIAGNOSTIC_CAPACITY];
    size_t count = 0;
    s->cpu.struct_size = sizeof(s->cpu); s->cpu.version = GW_API_VERSION;
    if (gw_get_diagnostics(r->session->machine, &s->cpu) != GW_OK ||
        gw_get_diagnostic_events(r->session->machine, events, GW_DIAGNOSTIC_CAPACITY,
            &count, &s->dropped) != GW_OK) return GW_ERROR_ARGUMENT;
    for (uint32_t i = 0; i < r->plan->span_count; ++i)
        if (gw_peek_memory(r->session->machine, r->plan->span_address[i], s->spans[i],
            r->plan->span_length[i]) != GW_OK) return GW_ERROR_ARGUMENT;
    memset(&s->stack, 0, sizeof(s->stack));
    return 0;
}

static int print_boundary_state(FILE *out, const gw_route_controller *p, const boundary_state *s)
{
    const gw_diagnostic_record *d = &s->cpu;
    if (fprintf(out, "{\"tick\":%" PRIu64 ",\"pc\":%u,\"sr\":%u,\"instructions\":%" PRIu64
        ",\"diagnostic_dropped\":%" PRIu64 ",\"d\":[", d->tick,d->pc,d->sr,d->instructions,s->dropped)<0) return GW_ERROR_ARGUMENT;
    for (unsigned i=0;i<8;i++) if(fprintf(out,"%s%u",i?",":"",d->d[i])<0) return GW_ERROR_ARGUMENT;
    if(fputs("],\"a\":[",out)==EOF) return GW_ERROR_ARGUMENT;
    for (unsigned i=0;i<8;i++) if(fprintf(out,"%s%u",i?",":"",d->a[i])<0) return GW_ERROR_ARGUMENT;
    if(fputs("],\"spans\":[",out)==EOF) return GW_ERROR_ARGUMENT;
    for(uint32_t i=0;i<p->span_count;i++) {
        if(fprintf(out,"%s{\"address\":%u,\"bytes\":\"",i?",":"",p->span_address[i])<0) return GW_ERROR_ARGUMENT;
        for(uint32_t j=0;j<p->span_length[i];j++) if(fprintf(out,"%02x",s->spans[i][j])<0) return GW_ERROR_ARGUMENT;
        if(fputs("\"}",out)==EOF) return GW_ERROR_ARGUMENT;
    }
    if (fputs("]", out) == EOF) return GW_ERROR_ARGUMENT;
    if (s->stack.enabled) {
        int success = 1;
        for (unsigned i = 0; i < 4; ++i) if (s->stack.status[i] != GW_OK) success = 0;
        if (fprintf(out, ",\"stack_observation\":{\"source_a7\":%u,\"base32\":%u,\"read_calls\":%u,\"addresses24\":[",
            s->stack.source_a7, s->stack.base32, s->stack.read_calls) < 0) return GW_ERROR_ARGUMENT;
        for (unsigned i = 0; i < 4; ++i)
            if (fprintf(out, "%s%u", i ? "," : "", s->stack.addresses24[i]) < 0) return GW_ERROR_ARGUMENT;
        if (fputs("],\"bytes\":[", out) == EOF) return GW_ERROR_ARGUMENT;
        for (unsigned i = 0; i < 4; ++i) {
            if (fprintf(out, "%s", i ? "," : "") < 0) return GW_ERROR_ARGUMENT;
            if (s->stack.status[i] == GW_OK) {
                if (fprintf(out, "%u", s->stack.bytes[i]) < 0) return GW_ERROR_ARGUMENT;
            } else if (fputs("null", out) == EOF) return GW_ERROR_ARGUMENT;
        }
        if (fputs("],\"status\":[", out) == EOF) return GW_ERROR_ARGUMENT;
        for (unsigned i = 0; i < 4; ++i)
            if (fprintf(out, "%s%d", i ? "," : "", s->stack.status[i]) < 0) return GW_ERROR_ARGUMENT;
        if (fprintf(out, "],\"disposition\":\"%s\"}", success ? "observed" : "observation-error") < 0)
            return GW_ERROR_ARGUMENT;
    }
    return fputs("}",out)==EOF?GW_ERROR_ARGUMENT:0;
}
static int print_boundary(FILE *out, const gw_route_controller *p, const boundary_pair *b)
{
    if(!b->available) return fputs("null",out)==EOF?GW_ERROR_ARGUMENT:0;
    if(fprintf(out,"{\"instruction_address\":%u,\"opcode\":%u,\"fault_address\":%u,\"stop_reason\":%u,"
        "\"target_tick\":%" PRIu64 ",\"returned_overshoot\":%" PRIu64 ",\"fields\":%" PRIu64
        ",\"returned_undershoot\":%" PRIu64 ",\"active_ticks\":%" PRIu64 ",\"event_index\":%u,\"masks\":[%u,%u],\"retired\":%s,\"before\":",
        b->instruction_address,b->opcode,b->fault_address,b->stop_reason,b->target,
        b->after.cpu.tick>b->target?b->after.cpu.tick-b->target:0,b->fields,
        b->target>b->after.cpu.tick?b->target-b->after.cpu.tick:0,b->active,b->event,
        b->masks[0],b->masks[1],b->retired?"true":"false")<0) return GW_ERROR_ARGUMENT;
    if(print_boundary_state(out,p,&b->before) || fputs(",\"after\":",out)==EOF ||
        print_boundary_state(out,p,&b->after)) return GW_ERROR_ARGUMENT;
    return fputs("}",out)==EOF?GW_ERROR_ARGUMENT:0;
}

static int snapshot(controller_run *r)
{
    uint8_t spans[64][64];
    for (uint32_t i = 0; i < r->plan->span_count; ++i) {
        int status = (int)gw_peek_memory(r->session->machine, r->plan->span_address[i], spans[i], r->plan->span_length[i]);
        if (status) return status;
    }
    for (uint32_t i = 0; i < r->plan->header[6]; ++i) {
        const uint32_t *s = row(r->plan, SIGNALS, i);
        uint32_t span = r->plan->signal_span[i];
        const uint8_t *b = spans[span] + (s[1] - r->plan->span_address[span]);
        r->values[i] = b[0];
        if (s[2] == 2) r->values[i] = s[3] ? (uint32_t)b[0] | ((uint32_t)b[1] << 8) :
            ((uint32_t)b[0] << 8) | b[1];
    }
    return 0;
}
static int matches(const controller_run *r, uint32_t first, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t *c = row(r->plan, CONDITIONS, first + i);
        uint64_t v = c[0] == UINT32_MAX ? r->active : r->values[c[0]];
        if ((c[1] == 0 && v != c[2]) || (c[1] == 1 && v < c[2]) || (c[1] == 2 && v >= c[2])) return 0;
    }
    return 1;
}
static int set_mask(controller_run *r, unsigned port, uint32_t mask)
{
    uint32_t effective = mask;
    int status;
    if (r->masks[port] == mask) return 0;
    if (r->input_count == 4096 || (r->capture && r->capture->input_count >= r->capture->input_capacity)) return GW_ERROR_CAPACITY;
    if (r->input && r->input(r->input_context, port, mask, &effective)) return GW_ERROR_ARGUMENT;
    status = gw_session_route_dispatch(r->session, port, effective, r->session->tick);
    if (status) return status;
    r->masks[port] = mask;
    r->inputs[r->input_count++] = (input_record){r->session->tick, r->session->fields, r->active,
        port, mask, effective};
    if (r->capture) r->capture->input_records[r->capture->input_count++] = r->inputs[r->input_count - 1];
    return 0;
}
static int set_control(controller_run *r, unsigned port, uint32_t bit, int asserted)
{
    uint32_t mask = asserted ? r->masks[port] | bit : r->masks[port] & ~bit;
    return set_mask(r, port, mask);
}
static int events(controller_run *r, int meta_only)
{
    const uint32_t *h = r->plan->header;
    while (r->event < h[12]) {
        const uint32_t *e = row(r->plan, EVENTS, r->event);
        int ready = h[2] == 3 ? r->session->fields >= e[1] :
            r->values[h[15]] == e[0] && r->values[h[16]] >= e[1] && r->values[h[14]] == e[2];
        if (!ready || (meta_only && (e[3] != 0 || e[4] != GW_BUTTON_C))) break;
        int status = set_control(r, e[3], e[4], e[5] != 0);
        if (status) return status;
        r->event++;
    }
    return 0;
}
static int field_actions(controller_run *r)
{
    const uint32_t *h = r->plan->header;
    int status;
    if (h[21] && r->session->fields == h[21]) {
        status = set_control(r, h[23], h[24], 1); if (status) return status;
    } else if (h[21] && r->session->fields == h[21] + h[22]) {
        status = set_control(r, h[23], h[24], 0); if (status) return status;
    }
    if (r->action < h[8]) {
        const uint32_t *a = row(r->plan, ACTIONS, r->action);
        if (r->started || matches(r, a[0], a[1])) {
            if (!r->started) { r->started = 1; r->action_start = r->session->fields; }
            if (r->session->fields - r->action_start > a[4]) return GW_ERROR_TIME;
            const uint32_t *s = row(r->plan, STEPS, a[2] + r->step);
            int complete = 1;
            for (uint32_t i = 0; i < s[1]; ++i) {
                const uint32_t *t = row(r->plan, TARGETS, s[0] + i);
                int reached = matches(r, t[2], t[3]);
                status = set_control(r, t[0], t[1], !reached);
                if (status) return status;
                if (!reached) complete = 0;
            }
            if (complete && ++r->step == a[3]) { r->action++; r->step = 0; r->started = 0; }
        }
    }
    return 0;
}
static int sample(controller_run *r, uint32_t attempt, uint32_t tick, uint32_t state)
{
    const uint32_t *h = r->plan->header;
    for (uint32_t i = 0; i < h[13]; ++i) {
        const uint32_t *p = row(r->plan, PREDICATES, i);
        if (!r->predicate_seen[i] && r->active >= p[2] && r->active <= p[3] && r->values[p[0]] == p[1]) {
            r->predicate_seen[i] = 1; r->predicate_value[i] = r->values[p[0]]; r->predicate_clock[i] = r->active;
            if (r->capture) {
                if (r->capture->predicate_count >= r->capture->predicate_capacity) return GW_ERROR_CAPACITY;
                r->capture->predicate_observations[r->capture->predicate_count++] =
                    (gw_route_predicate_observation){r->active, r->values[p[0]], i, 1};
            }
        }
    }
    if (!r->rendered && ((h[25] == 1 && r->session->fields >= h[26]) ||
        (h[25] == 2 && attempt == h[27] && tick >= h[28] && state == h[29]))) {
        r->rendered = 1; r->render_tick = r->session->tick;
    }
    if (r->capture) {
        gw_diagnostic_record d = {0};
        if (r->capture->cpu_count >= r->capture->cpu_capacity) return GW_ERROR_CAPACITY;
        d.struct_size = sizeof(d); d.version = GW_API_VERSION;
        if (gw_get_diagnostics(r->session->machine, &d) != GW_OK) return GW_ERROR_ARGUMENT;
        gw_route_cpu_observation *o = &r->capture->cpu_observations[r->capture->cpu_count++];
        o->tick = d.tick; o->instructions = d.instructions; o->pc = d.pc; o->sr = d.sr;
        memcpy(o->d, d.d, sizeof(o->d)); memcpy(o->a, d.a, sizeof(o->a));
        ++r->capture->observed_count;
    }
    if (r->out && fprintf(r->out, "%s{\"field\":%" PRIu64 ",\"active_ticks\":%" PRIu64
        ",\"attempt\":%u,\"tick\":%u,\"state\":%u,\"values\":[", r->sample_comma ? "," : "",
        r->session->fields, r->active, attempt, tick, state) < 0) return GW_ERROR_ARGUMENT;
    if (r->out) {
        r->sample_comma = 1;
        for (uint32_t i = 0; i < h[6]; ++i) if (fprintf(r->out, "%s%u", i ? "," : "", r->values[i]) < 0) return GW_ERROR_ARGUMENT;
        if (fputs("]}", r->out) == EOF) return GW_ERROR_ARGUMENT;
    }
    return 0;
}

static int route_controller_run(gw_session *session, const gw_route_controller *plan, FILE *out,
    gw_route_input_callback input, void *input_context,
    gw_session_route_field_callback field_callback, void *field_context, int audio_open,
    gw_route_capture *capture)
{
    controller_run storage;
    controller_run *r = &storage;
    const uint32_t *h = plan->header;
    gw_diagnostic_record diagnostic = {0};
    uint64_t calls = 0, rejected_calls = 0, first_stop = 0, field_start_ns = 0;
    uint64_t plan_hash = UINT64_C(14695981039346656037);
    int status = 0, probe_stop = 0, capture_timer_started = 0;
    if (!session || !plan || (!out && !capture) || (!capture && !session->config.diagnostics)) return GW_ERROR_ARGUMENT;
    memset(r, 0, sizeof(*r));
    r->plan = plan; r->session = session; r->input = input; r->input_context = input_context; r->out = out; r->capture = capture;
    if (capture && ((capture->input_capacity && !capture->input_records) ||
        (capture->predicate_capacity && !capture->predicate_observations) ||
        (capture->cpu_capacity && !capture->cpu_observations) ||
        (capture->span_capacity && !capture->span_bytes))) return GW_ERROR_ARGUMENT;
    diagnostic.struct_size = sizeof(diagnostic); diagnostic.version = GW_API_VERSION;
    if (gw_get_diagnostics(session->machine, &diagnostic) != GW_OK) return GW_ERROR_ARGUMENT;
    session->tick = diagnostic.tick;
    if (!capture) for (size_t i = 0; i < plan->word_count; ++i)
        for (unsigned byte = 0; byte < 4; ++byte)
            plan_hash = (plan_hash ^ (uint8_t)(plan->words[i] >> (8u * byte))) * UINT64_C(1099511628211);
    /* Verify every marker is the promised completed write before execution. */
    for (uint32_t i = 0; i < h[7]; ++i) {
        uint8_t b[6]; const uint32_t *m = row(plan, MARKERS, i);
        uint32_t phase_address = row(plan, SIGNALS, h[17])[1];
        if (gw_peek_memory(session->machine, m[0], b, 6) != GW_OK || b[0] != 0x42 || b[1] != 0x79 ||
            b[2] != 0 || b[3] != (uint8_t)(phase_address >> 16) || b[4] != (uint8_t)(phase_address >> 8) ||
            b[5] != (uint8_t)phase_address) return GW_ERROR_ARGUMENT;
    }
    if (out && fprintf(out, "{\"schema\":\"genewhip-route-native-v1\",\"plan_fnv1a64\":\"%016" PRIx64
        "\",\"handler\":\"%s\",\"audio_open\":%s,\"samples\":[", plan_hash,
        input ? "host-script" : "headless", audio_open ? "true" : "false") < 0) status = GW_ERROR_ARGUMENT;
    while (!status && session->fields < h[3] && r->active < h[4]) {
        uint64_t old_fields = session->fields;
        int instruction_probe = session->route_instruction_probe;
        uint64_t delta = h[2] == 2 || instruction_probe ? 1 : GW_FIELD_TICKS;
        /* GWRC queues only pad events, never reset. While STOP waits, a normal
         * instruction cannot resume until an IRQ entry completes (44 CPU
         * clocks/308 master ticks in this core's documented public model).
         * A horizon <=308 therefore returns before any resumed instruction;
         * an entry fault is sticky and returns immediately. Keep horizon1 as
         * the private equivalence reference. Never apply this to a running CPU. */
        if(delta==1 && session->stop_reason==GW_STOP_CPU_STOPPED && session->route_stop_horizon) {
            if(session->route_stop_horizon>308) {status=GW_ERROR_ARGUMENT;break;}
            delta=session->route_stop_horizon;
        }
        int retired = 0;
        if (calls >= h[30]) { ++rejected_calls; status = GW_ERROR_CAPACITY; break; }
        if (session->tick > GW_MAX_TARGET_TICK - delta) { status = GW_ERROR_TIME; break; }
        if(instruction_probe) {
            status = boundary_snapshot(r,&r->last.before); if(status) break;
            if (session->route_probe_stack_before_a7 && !r->probe.available &&
                r->last.before.cpu.pc == session->route_probe_pc)
                stack_snapshot(r, &r->last.before.stack, r->last.before.cpu.a[7]);
            r->last.target=session->tick+delta; r->last.fields=session->fields; r->last.active=r->active;
            r->last.event=r->event; r->last.masks[0]=r->masks[0]; r->last.masks[1]=r->masks[1];
        }
        if (capture && !capture_timer_started) {
            if (capture->begin_execution) capture->begin_execution(capture->timer_context);
            if (capture->field_ns && capture->clock_ns) field_start_ns = capture->clock_ns(capture->timer_context);
            capture_timer_started = 1;
        }
        ++calls;
        status = gw_session_route_boundary(session, session->tick + delta,
            h[2] == 2 && delta==1 ? GW_RUN_CONTINUE_PAST_FIELD : 0, field_callback, field_context, &retired);
        if(instruction_probe) {
            int observed=boundary_snapshot(r,&r->last.after);
            if(observed) {status=observed;break;}
            if (r->last.before.stack.enabled)
                stack_snapshot(r, &r->last.after.stack, r->last.before.stack.source_a7);
            r->last.available=1; r->last.retired=retired;
            r->last.instruction_address=session->instruction_address; r->last.opcode=session->opcode;
            r->last.fault_address=session->fault_address; r->last.stop_reason=session->stop_reason;
            if(!r->probe.available && session->instruction_address==session->route_probe_pc && session->opcode &&
                r->last.before.cpu.pc==session->route_probe_pc) r->probe=r->last;
        }
        if (status) { if (gw_session_unsupported_stop(session)) first_stop = session->tick; break; }
        if (capture && capture->field_ns && session->fields > old_fields) {
            uint64_t added = session->fields - old_fields;
            if (!capture->clock_ns || capture->field_ns_count > capture->field_ns_capacity ||
                added > capture->field_ns_capacity - capture->field_ns_count) {
                status = GW_ERROR_CAPACITY; break;
            }
            uint64_t now = capture->clock_ns(capture->timer_context);
            for (uint64_t i = 0; i < added; ++i)
                capture->field_ns[capture->field_ns_count++] = now - field_start_ns;
            field_start_ns = now;
        }
        if (h[2] == 2 && retired) {
            int marker = 0;
            for (uint32_t i = 0; i < h[7]; ++i) {
                const uint32_t *m = row(plan, MARKERS, i);
                if (session->instruction_address == m[0] && session->opcode == m[1]) marker = 1;
            }
            if (marker) {
                uint32_t attempt, tick, state;
                status = snapshot(r); if (status) break;
                attempt = r->values[h[15]]; tick = r->values[h[16]]; state = r->values[h[14]];
                if (r->values[h[17]]) { status = GW_ERROR_ARGUMENT; break; }
                if (tick && (attempt != r->last_attempt || tick != r->last_tick)) {
                    if (!((attempt == r->last_attempt && tick == r->last_tick + 1) ||
                        (attempt == r->last_attempt + 1 && r->last_tick == h[18] && tick == 1)) ||
                        (state != h[19] && state != h[20])) { status = GW_ERROR_ARGUMENT; break; }
                    r->last_attempt = attempt; r->last_tick = tick; r->active++;
                    status = events(r, 0);
                    if (!status) status = sample(r, attempt, tick, state);
                }
            }
        }
        if (!status && session->fields != old_fields) {
            status = snapshot(r); if (status) break;
            if (h[2] == 2) {
                status = events(r, 1);
                if (!status && session->fields > h[5] && !r->active) status = GW_ERROR_TIME;
            } else {
                if (h[2] == 3 || r->values[h[14]] == h[19]) r->active++;
                status = h[2] == 1 ? field_actions(r) : events(r, 0);
                if (!status) status = sample(r, 0, 0, r->values[h[14]]);
            }
        }
        if(!status && session->route_probe_only && r->probe.available) {probe_stop=1;break;}
    }
    if (!status && !probe_stop && r->active < h[4]) status = GW_ERROR_TIME;
    if (!status && !probe_stop && h[2] == 1 && r->action < h[8]) status = GW_ERROR_TIME;
    if (capture && !status) {
        for (uint32_t i = 0; i < h[13]; ++i)
            if (!r->predicate_seen[i]) { status = GW_ERROR_TIME; break; }
    }
    /* Release even on timeout/error, through the same host path. */
    for (unsigned port = 0; port < 2; ++port) {
        int release_status = set_mask(r, port, 0);
        if (!status && release_status) status = release_status;
    }
    if (capture) {
        for (uint32_t i = 0; i < plan->span_count; ++i) {
            size_t length = plan->span_length[i];
            if (length > capture->span_capacity - capture->span_count) { status = GW_ERROR_CAPACITY; break; }
            if (gw_peek_memory(session->machine, plan->span_address[i], capture->span_bytes + capture->span_count, length) != GW_OK) {
                status = GW_ERROR_ARGUMENT; break;
            }
            capture->span_count += length;
        }
        capture->terminal_tick = session->tick;
        capture->terminal_fields = session->fields;
        capture->terminal_active_ticks = r->active;
    }
    if (capture && capture->end_execution) capture->end_execution(capture->timer_context);
    if (out && fprintf(out, "],\"inputs\":[") < 0) status = GW_ERROR_ARGUMENT;
    for (size_t i = 0; i < r->input_count; ++i) {
        const input_record *v = &r->inputs[i];
        if (out && fprintf(out, "%s{\"machine_tick\":%" PRIu64 ",\"field\":%" PRIu64 ",\"active_ticks\":%" PRIu64
            ",\"port\":%u,\"desired\":%u,\"effective\":%u}", i ? "," : "", v->tick, v->field,
            v->active, v->port, v->desired, v->effective) < 0) status = GW_ERROR_ARGUMENT;
    }
    if (out && fprintf(out, "],\"predicates\":[") < 0) status = GW_ERROR_ARGUMENT;
    for (uint32_t i = 0; out && i < h[13]; ++i) if (fprintf(out,
        "%s{\"reached\":%s,\"value\":%u,\"clock\":%" PRIu64 "}", i ? "," : "",
        r->predicate_seen[i] ? "true" : "false", r->predicate_value[i], r->predicate_clock[i]) < 0) status = GW_ERROR_ARGUMENT;
    if (out && fprintf(out, "],\"status\":%d,\"active_ticks\":%" PRIu64 ",\"fields\":%" PRIu64
        ",\"final_tick\":%" PRIu64 ",\"first_stop_tick\":", status, r->active, session->fields, session->tick) < 0) status = GW_ERROR_ARGUMENT;
    if (out && first_stop) { if (fprintf(out, "%" PRIu64, first_stop) < 0) status = GW_ERROR_ARGUMENT; }
    else if (out && fputs("null", out) == EOF) status = GW_ERROR_ARGUMENT;
    if (out && fprintf(out, ",\"stop_reason\":%u,\"instruction_address\":%u,\"opcode\":%u,\"render_requested\":%s,"
        "\"render_tick\":%" PRIu64 ",\"boundary_calls\":%" PRIu64 ",\"selected_boundary_calls\":%u,\"boundary_attempts\":%" PRIu64 ",\"rejected_boundary_attempts\":%" PRIu64 ",\"queue_high_water\":%u,"
        "\"audio_complete\":%s,\"audio_frames\":%" PRIu64 ",\"audio_hash\":\"%016" PRIx64 "\",\"termination\":\"%s\",\"probe_boundary\":",
        session->stop_reason, session->instruction_address, session->opcode, r->rendered ? "true" : "false",
        r->render_tick, calls, h[30], calls + rejected_calls, rejected_calls, session->route_queue_high_water, session->audio_complete ? "true" : "false",
        session->audio_total_frames,session->audio_hash,probe_stop?"diagnostic-prefix":
        status?"error":r->active>=h[4]?"active-limit":"field-limit") < 0) status = GW_ERROR_ARGUMENT;
    if (out && (print_boundary(out,plan,&r->probe) || fputs(",\"last_boundary\":",out)==EOF ||
        print_boundary(out,plan,&r->last) || fputs("}\n",out)==EOF)) status=GW_ERROR_ARGUMENT;
    if (status && capture) fprintf(stderr, "route capture error=%d fields=%" PRIu64 " active=%" PRIu64
        " inputs=%zu cpu=%zu preds=%zu queue=%u calls=%" PRIu64 "\n", status,
        session->fields, r->active, r->input_count, capture->cpu_count, capture->predicate_count,
        session->route_pending_events, calls);
    return status;
}

int gw_route_controller_run(gw_session *session, const gw_route_controller *plan, FILE *out,
    gw_route_input_callback input, void *input_context,
    gw_session_route_field_callback field_callback, void *field_context, int audio_open)
{
    return route_controller_run(session, plan, out, input, input_context, field_callback, field_context, audio_open, NULL);
}

int gw_route_controller_run_capture(gw_session *session, const gw_route_controller *plan, gw_route_capture *capture,
    gw_route_input_callback input, void *input_context,
    gw_session_route_field_callback field_callback, void *field_context, int audio_open)
{
    if (!capture) return GW_ERROR_ARGUMENT;
    capture->input_count = capture->predicate_count = capture->cpu_count = 0;
    capture->span_count = capture->observed_count = 0;
    return route_controller_run(session, plan, NULL, input, input_context, field_callback, field_context, audio_open, capture);
}
