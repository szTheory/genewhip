/* SPDX-License-Identifier: MIT */
#include "input_log.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_BYTES 64

int gw_input_log_init(gw_input_log *log)
{
    if (!log) return 1;
    log->count = 0;
    log->entries = (gw_input_entry *)calloc(GW_INPUT_LOG_MAX, sizeof(gw_input_entry));
    return log->entries ? 0 : 1;
}

void gw_input_log_free(gw_input_log *log)
{
    if (!log) return;
    free(log->entries);
    log->entries = NULL;
    log->count = 0;
}

int gw_input_log_add(gw_input_log *log, uint64_t tick, uint32_t kind, uint32_t port, uint32_t mask)
{
    gw_input_entry *entry;
    if (!log || !log->entries || log->count >= GW_INPUT_LOG_MAX) return 1;
    if (kind != GW_LOG_PAD && kind != GW_LOG_RESET) return 1;
    if (kind == GW_LOG_PAD && (port > 1 || mask > 0xffu)) return 1;
    if (kind == GW_LOG_RESET && (port != 0 || mask != 0)) return 1;
    if (log->count && tick < log->entries[log->count - 1].tick) return 1;
    entry = &log->entries[log->count++];
    entry->tick = tick;
    entry->kind = kind;
    entry->port = port;
    entry->mask = mask;
    return 0;
}

static int all_digits(const char *s, int hex)
{
    if (!*s) return 0;
    for (; *s; ++s) {
        if (*s >= '0' && *s <= '9') continue;
        if (hex && ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))) continue;
        return 0;
    }
    return 1;
}

static int fail(gw_input_log *log, FILE *file, const char **reason, const char *why)
{
    if (file) (void)fclose(file);
    log->count = 0;
    *reason = why;
    return 1;
}

int gw_input_log_read(const char *path, gw_input_log *log, const char **reason)
{
    static const char header[] = "genewhip-input-log 1";
    const char *unused = NULL;
    FILE *file;
    char line[LINE_MAX_BYTES];
    int first = 1;
    if (!reason) reason = &unused;
    *reason = NULL;
    if (!path || !log || !log->entries) { if (log) log->count = 0; *reason = "io"; return 1; }
    log->count = 0;
    file = fopen(path, "rb");
    if (!file) return fail(log, NULL, reason, "io");
    while (fgets(line, sizeof(line), file)) {
        size_t length = strlen(line);
        char tick_text[24], kind_text[8], port_text[8], mask_text[16], extra[4];
        unsigned long long tick;
        int fields;
        /* An embedded NUL at the start of a line leaves length 0: reject it. */
        if (length == 0 || line[length - 1] != '\n') return fail(log, file, reason, first ? "header" : "syntax");
        line[length - 1] = '\0';
        if (first) {
            first = 0;
            if (strcmp(line, header) != 0) return fail(log, file, reason, "header");
            continue;
        }
        if (log->count >= GW_INPUT_LOG_MAX) return fail(log, file, reason, "capacity");
        fields = sscanf(line, "%23s %7s %7s %15s %3s", tick_text, kind_text, port_text, mask_text, extra);
        if (fields < 2 || !all_digits(tick_text, 0) || strlen(tick_text) > 19) return fail(log, file, reason, "syntax");
        tick = strtoull(tick_text, NULL, 10);
        if (!strcmp(kind_text, "reset")) {
            if (fields != 2) return fail(log, file, reason, "syntax");
            if (log->count && tick < log->entries[log->count - 1].tick) return fail(log, file, reason, "order");
            (void)gw_input_log_add(log, tick, GW_LOG_RESET, 0, 0);
        } else if (!strcmp(kind_text, "pad")) {
            unsigned long port, mask;
            if (fields != 4 || !all_digits(port_text, 0) || !all_digits(mask_text, 1)) return fail(log, file, reason, "syntax");
            if (strlen(port_text) > 3) return fail(log, file, reason, "port");
            port = strtoul(port_text, NULL, 10);
            if (port > 1) return fail(log, file, reason, "port");
            if (strlen(mask_text) > 8) return fail(log, file, reason, "mask");
            mask = strtoul(mask_text, NULL, 16);
            if (mask > 0xfful) return fail(log, file, reason, "mask");
            if (log->count && tick < log->entries[log->count - 1].tick) return fail(log, file, reason, "order");
            (void)gw_input_log_add(log, tick, GW_LOG_PAD, (uint32_t)port, (uint32_t)mask);
        } else {
            return fail(log, file, reason, "syntax");
        }
    }
    if (ferror(file)) return fail(log, file, reason, "io");
    if (first) return fail(log, file, reason, "header");
    (void)fclose(file);
    return 0;
}

int gw_input_log_write(const char *path, const gw_input_log *log)
{
    FILE *file;
    if (!path || !log) return 1;
    file = fopen(path, "wb");
    if (!file) return 1;
    if (fputs("genewhip-input-log 1\n", file) < 0) { (void)fclose(file); return 1; }
    for (size_t i = 0; i < log->count; ++i) {
        const gw_input_entry *e = &log->entries[i];
        int status;
        if (e->kind == GW_LOG_RESET) status = fprintf(file, "%" PRIu64 " reset\n", e->tick);
        else status = fprintf(file, "%" PRIu64 " pad %u %02x\n", e->tick, (unsigned)e->port, (unsigned)e->mask);
        if (status < 0) { (void)fclose(file); return 1; }
    }
    return fclose(file) == 0 ? 0 : 1;
}
