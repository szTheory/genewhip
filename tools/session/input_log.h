/* SPDX-License-Identifier: MIT
 * Bounded input/reset log. Text format, one entry per line after the header:
 *   genewhip-input-log 1
 *   <tick> pad <port> <mask-hex>
 *   <tick> reset
 * Ticks are decimal master ticks, non-decreasing; port is 0 or 1; mask is at
 * most 0xFF. Logs carry no paths or host data.
 */
#ifndef GENEWHIP_INPUT_LOG_H
#define GENEWHIP_INPUT_LOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GW_INPUT_LOG_MAX 65536u

enum { GW_LOG_PAD = 0, GW_LOG_RESET = 1 };

typedef struct gw_input_entry {
    uint64_t tick;
    uint32_t kind;  /* GW_LOG_PAD or GW_LOG_RESET */
    uint32_t port;
    uint32_t mask;
} gw_input_entry;

typedef struct gw_input_log {
    gw_input_entry *entries; /* GW_INPUT_LOG_MAX slots, heap-owned */
    size_t count;
} gw_input_log;

/* Allocates storage; returns 0 on success, nonzero on allocation failure. */
int gw_input_log_init(gw_input_log *log);
void gw_input_log_free(gw_input_log *log);
/* Appends an entry; returns 0, or nonzero when the log is full or the entry
 * would break tick order, port or mask limits. */
int gw_input_log_add(gw_input_log *log, uint64_t tick, uint32_t kind, uint32_t port, uint32_t mask);

/* Reads a log. Returns 0, or nonzero with *reason set to one of: "header",
 * "syntax", "order", "port", "mask", "capacity", "io". On failure the log is
 * left empty. A final line without a newline is "syntax". */
int gw_input_log_read(const char *path, gw_input_log *log, const char **reason);
/* Writes a log; returns 0 or nonzero on I/O failure. */
int gw_input_log_write(const char *path, const gw_input_log *log);

#ifdef __cplusplus
}
#endif
#endif
