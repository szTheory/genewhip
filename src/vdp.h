/* SPDX-License-Identifier: MIT */
#ifndef GW_VDP_H
#define GW_VDP_H
#include "genewhip/genewhip.h"

#define GW_VDP_REGISTERS 24u
#define GW_VDP_FIFO_DEPTH 4u
#define GW_VDP_MAX_WIDTH 320u

typedef struct gw_vdp_fifo_entry {
    uint64_t commit_tick; /* Modeled access-slot tick at which the write lands. */
    uint16_t address;
    uint16_t data;
    uint8_t code;
} gw_vdp_fifo_entry;

/* External-access slots per line. Independent hardware observation: Nemesis VRAM-access
 * measurements, gendev forum thread t=851 (H32 16 active / 166 blank, H40 18 / 204 after
 * the thread's follow-up correction). Model-scoped approximations; see docs/video.md. */
enum { GW_VDP_DMA_RATE_H32_ACTIVE = 16, GW_VDP_DMA_RATE_H32_BLANK = 166,
       GW_VDP_DMA_RATE_H40_ACTIVE = 18, GW_VDP_DMA_RATE_H40_BLANK = 204 };
/* Slots consumed per transfer unit (model-scoped): a VRAM word is two byte accesses, a
 * CRAM/VSRAM word one; a fill byte one; a copy byte two (read plus write), which halves
 * the copy rate as reported for hardware in the gendev forum. */
enum { GW_VDP_DMA_COST_VRAM_WORD = 2, GW_VDP_DMA_COST_CRAM_WORD = 1,
       GW_VDP_DMA_COST_FILL_BYTE = 1, GW_VDP_DMA_COST_COPY_BYTE = 2 };

/* VINT assertion offset inside line 224, in master ticks. Model-scoped: the documented fact
 * is only that VINT is raised once per field at the start of vertical blanking (line 224).
 * No independent primary or hardware-observation figure for the sub-line offset was found,
 * so the true value is classed unknown (docs/video.md) and no reference-emulator figure is
 * attributed. Applies to H32 and H40 alike. */
#define GW_VDP_VINT_OFFSET_TICKS 0u

enum { GW_VDP_DMA_IDLE = 0, GW_VDP_DMA_68K, GW_VDP_DMA_FILL, GW_VDP_DMA_COPY };

/* DMA state. 68000-to-VDP transfers run synchronously inside the halting bus access
 * (mode is GW_VDP_DMA_68K only while that access executes); fill and copy persist
 * across CPU instructions and are advanced by gw_vdp_advance. */
typedef struct gw_vdp_dma {
    uint8_t mode;
    uint8_t fill_pending; /* Fill command seen; the next data-port write starts it. */
    uint8_t target_code;  /* CODE_* the transfer writes (VRAM for fill and copy). */
    uint8_t fill_byte;
    uint8_t increment;    /* Register 15 captured at start (fill and copy). */
    uint16_t dest;        /* Fill/copy destination VRAM byte address. */
    uint32_t source;      /* 68k: 23-bit word address; copy: VRAM byte address. */
    uint32_t remaining;   /* Units left: words (68k) or bytes (fill, copy). */
    uint64_t next_tick;   /* Slot tick of the next fill/copy byte. */
} gw_vdp_dma;

typedef struct gw_vdp {
    uint8_t reg[GW_VDP_REGISTERS];
    uint8_t vram[65536];
    uint16_t cram[64];
    uint16_t vsram[40];
    uint16_t latch_first; /* First command word while latch_pending. */
    uint8_t latch_pending;
    uint8_t code;     /* Active access code (CD3..CD0 subset). */
    uint16_t address; /* Active address, auto-incremented by register 15. */
    gw_vdp_fifo_entry fifo[GW_VDP_FIFO_DEPTH];
    uint8_t fifo_count;
    gw_vdp_dma dma;
    uint8_t vint_pending;   /* Raised once per field; cleared by acknowledgement (level 6). */
    uint8_t hint_pending;   /* Raised when the counter expires; cleared by acknowledgement (level 4). */
    uint8_t hint_counter;   /* Lines left before the next HINT; reloaded from register 10. */
    uint8_t vint_scheduled; /* A VINT assertion is waiting for vint_tick. */
    uint64_t vint_tick;
    uint8_t sprite_flags; /* Status SOVR 0x40 / SCOL 0x20; set by the sprite engine, cleared by status reads. */
    uint64_t advanced_tick;
} gw_vdp;

typedef struct gw_video_out {
    uint32_t buffers[2][GW_ACTIVE_LINES][GW_VDP_MAX_WIDTH]; /* XRGB8888 */
    uint8_t back;          /* Index being rendered; the other is the front. */
    uint8_t has_field;
    uint32_t back_width;   /* Latched at line 0 of the field being rendered. */
    uint32_t front_width;
    uint64_t front_sequence;
    uint64_t dropped;
    uint64_t fields_this_run; /* Per-call scratch, not observable machine state. */
    uint64_t next_line;       /* Absolute index of the next line to render. */
    uint64_t next_line_tick;  /* next_line * GW_LINE_TICKS. */
} gw_video_out;

void gw_vdp_cold_init(gw_machine *m);
void gw_vdp_console_reset(gw_machine *m);
/* Bring the VDP to master tick `tick`: commit due FIFO writes, render each line
 * at its start tick and publish at line 224. May set an unsupported-state stop. */
void gw_vdp_advance(gw_machine *m, uint64_t tick);
/* Port accesses; return 0 with an unsupported-address stop for unmodeled ones. */
int gw_vdp_read(gw_machine *m, uint32_t address, unsigned size, uint32_t *value);
int gw_vdp_write(gw_machine *m, uint32_t address, unsigned size, uint32_t value);
/* Interrupt request level the VDP presents (6 VINT, 4 HINT, 0 none): a pending source
 * counts only while its enable bit (register 1 IE0, register 0 IE1) is set. VINT wins. */
int gw_vdp_irq_level(const gw_machine *m);
/* Acknowledge the source taken at `level` (6 or 4); the other source is untouched and is
 * re-evaluated by the next gw_vdp_irq_level call. */
void gw_vdp_irq_ack(gw_machine *m, int level);
/* First modeled external-access slot at or after `tick`. */
uint64_t gw_vdp_next_slot(const gw_machine *m, uint64_t tick);

void gw_render_line(gw_machine *m, uint32_t line);
void gw_render_publish(gw_machine *m, uint64_t sequence);
uint32_t gw_cram_to_xrgb(uint16_t cram_word);
/* Shadow/highlight resolution (Genewhip convention, docs/video.md). */
enum { GW_INTENSITY_NORMAL = 0, GW_INTENSITY_SHADOW = 1, GW_INTENSITY_HIGHLIGHT = 2 };
uint32_t gw_cram_to_xrgb_intensity(uint16_t cram_word, unsigned intensity);
#endif
