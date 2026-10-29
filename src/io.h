/* SPDX-License-Identifier: MIT */
#ifndef GW_IO_H
#define GW_IO_H
#include "genewhip/genewhip.h"

#define GW_IO_PORTS 2u

/* Machine-owned I/O state. `buttons` is the logical host mask (bit set =
 * pressed, GW_BUTTON_* layout). `data` and `ctrl` are the guest-visible latches. */
typedef struct gw_io {
    uint8_t version;
    uint8_t device[GW_IO_PORTS];
    uint8_t data[GW_IO_PORTS];
    uint8_t ctrl[GW_IO_PORTS];
    uint8_t buttons[GW_IO_PORTS];
    uint8_t ext_data, ext_ctrl; /* On-chip GPIO only; no third host peripheral. */
} gw_io;

/* Cold init clears latches and held buttons and takes devices from the config;
 * console reset clears only the latches. */
void gw_io_cold_init(gw_machine *m);
void gw_io_console_reset(gw_machine *m);
/* Apply every pad event at the head of the queue with tick <= `tick`. Stops at
 * the first non-pad event so queued resets keep their place in the order. */
void gw_io_advance(gw_machine *m, uint64_t tick);
/* 1 when `address` is a modeled byte register (version, data, control). */
int gw_io_decodes(uint32_t address);
/* Byte access at a modeled register; the caller has advanced the bus tick and
 * called gw_io_advance. */
void gw_io_read(gw_machine *m, uint32_t address, uint32_t *value);
void gw_io_write(gw_machine *m, uint32_t address, uint32_t value);
/* Input pin levels (active low, bit 7 clear) a three-button pad presents for a
 * logical button mask and TH level. Bit 6 reports the TH level itself. */
uint32_t gw_io_pad_pins(uint32_t buttons, int th_high);
#endif
