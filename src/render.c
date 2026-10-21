/* SPDX-License-Identifier: MIT
 * Original per-line renderer and field publisher. Conventions follow the other
 * core modules; the CRAM conversion table is a Genewhip convention (see
 * docs/video.md), not a measured hardware transfer curve. Name-table, tile and
 * scroll formats follow the documented layouts summarised in docs/video.md.
 * Sprites follow the format and limits in the sprite model comment below.
 * Every VRAM address derived from guest-controlled tables is masked to 16 bits and
 * every scroll value to the plane size, so no guest value can index outside VRAM.
 */
#include "internal.h"

/* Genewhip convention: 3-bit CRAM channel v maps to level table[2 * v]. */
static const uint8_t level_table[15] = {
    0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255
};

/* Shadow/highlight (register 12 bit 3, S/TE) resolves inside the core to final XRGB8888 with
 * the same 15-level table, a Genewhip convention (assumption A5, never measured DAC output):
 * normal level_table[2v], shadow level_table[v], highlight level_table[v + 7]. The intensity
 * is validated and the index is at most 14, so no input indexes outside the table. */
static unsigned intensity_level(unsigned v, unsigned intensity)
{
    unsigned index = intensity == GW_INTENSITY_SHADOW ? v : intensity == GW_INTENSITY_HIGHLIGHT ? v + 7u : 2u * v;
    return level_table[index > 14u ? 14u : index];
}

uint32_t gw_cram_to_xrgb_intensity(uint16_t cram_word, unsigned intensity)
{
    uint32_t r = intensity_level((cram_word >> 1) & 7u, intensity);
    uint32_t g = intensity_level((cram_word >> 5) & 7u, intensity);
    uint32_t b = intensity_level((cram_word >> 9) & 7u, intensity);
    return (r << 16) | (g << 8) | b;
}

uint32_t gw_cram_to_xrgb(uint16_t cram_word)
{
    return gw_cram_to_xrgb_intensity(cram_word, GW_INTENSITY_NORMAL);
}


enum { PLANE_A = 0, PLANE_B = 1 };

/* Plane dimension in cells from a register-16 size code. Code 2 is documented as
 * prohibited; Genewhip treats it as 32 cells (Genewhip-defined, class unknown). */
static unsigned plane_cells(unsigned code)
{
    return code == 1u ? 64u : code == 3u ? 128u : 32u;
}

static unsigned vram_word(const gw_vdp *v, unsigned address)
{
    address &= 0xffffu;
    return ((unsigned)v->vram[address] << 8) | v->vram[(address + 1u) & 0xffffu];
}

/* Horizontal scroll of a plane for a line (register 11 bits 1-0: 0 full screen, 2 per
 * 8-line cell, 3 per line; 1 is prohibited and read as full screen, class unknown).
 * The table at register 13 holds plane A then plane B per line (4 bytes); cell mode reads
 * the entry of the first line of the cell, line & ~7 (YaVDP; see docs/video.md). */
static unsigned hscroll_for_line(const gw_vdp *v, unsigned line, unsigned plane)
{
    unsigned mode = v->reg[11] & 3u;
    unsigned entry = mode == 3u ? line * 4u : mode == 2u ? (line & ~7u) * 4u : 0u;
    return vram_word(v, (((unsigned)v->reg[13] & 0x3fu) << 10) + entry + plane * 2u) & 0x3ffu;
}

/* Vertical scroll of a plane for the 16-pixel column holding pixel x (register 11 bit 2:
 * 0 full screen, entry 0/1; 1 per 2-cell column, entries 2k/2k+1). */
static unsigned vscroll_for_column(const gw_vdp *v, unsigned x, unsigned plane)
{
    unsigned index = (v->reg[11] & 4u) ? (x >> 4) * 2u + plane : plane;
    return index < 40u ? (unsigned)v->vsram[index] & 0x3ffu : 0u;
}

/* One 4-bpp pattern pixel (8 pixels per 32-bit row, leftmost in the high nibble). */
static unsigned tile_pixel(const gw_vdp *v, unsigned entry, unsigned px, unsigned py)
{
    unsigned row = (entry & 0x1000u) ? 7u - (py & 7u) : (py & 7u);
    unsigned col = (entry & 0x0800u) ? 7u - (px & 7u) : (px & 7u);
    unsigned byte = v->vram[((entry & 0x7ffu) * 32u + row * 4u + (col >> 1)) & 0xffffu];
    return (col & 1u) ? byte & 15u : byte >> 4;
}

/* Fill index (palette line * 16 + colour, 0 = transparent) and priority for one line. */
static void render_plane(gw_machine *m, unsigned line, unsigned plane, uint8_t *priority, uint8_t *index)
{
    const gw_vdp *v = &m->vdp;
    unsigned base = plane == PLANE_B ? ((unsigned)v->reg[4] & 7u) << 13 : ((unsigned)v->reg[2] & 0x38u) << 10;
    unsigned w = plane_cells(v->reg[16] & 3u), h = plane_cells((v->reg[16] >> 4) & 3u);
    unsigned hs = hscroll_for_line(v, line, plane), x;
    for (x = 0; x < m->video.back_width; ++x) {
        unsigned px = (x - hs) & (w * 8u - 1u);
        unsigned py = (line + vscroll_for_column(v, x, plane)) & (h * 8u - 1u);
        unsigned entry = vram_word(v, base + ((py >> 3) * w + (px >> 3)) * 2u);
        unsigned colour = tile_pixel(v, entry, px, py);
        index[x] = (uint8_t)(colour ? ((entry >> 9) & 0x30u) + colour : 0u);
        priority[x] = (uint8_t)(entry >> 15);
    }
}

/* Window region test (registers 17 and 18): horizontally x is covered left of (RIGHT = 0) or
 * from (RIGHT = 1) twice the position in cells; vertically the same with 8-line units. A
 * pixel is in the window when either condition holds. */
static int window_covers(const gw_vdp *v, unsigned x, unsigned line)
{
    unsigned hp = ((unsigned)v->reg[17] & 0x1fu) * 16u, vp = ((unsigned)v->reg[18] & 0x1fu) * 8u;
    int h = (v->reg[17] & 0x80u) ? x >= hp : x < hp;
    int d = (v->reg[18] & 0x80u) ? line >= vp : line < vp;
    return h || d;
}

/* The window plane replaces plane A where it covers. It does not scroll. Its name table
 * is 64 cells wide in H40 and 32 in H32; the H40 base ignores register 3 bit 1. */
static void render_window(gw_machine *m, unsigned line, uint8_t *priority, uint8_t *index)
{
    const gw_vdp *v = &m->vdp;
    int h40 = (v->reg[12] & 1u) != 0;
    unsigned base = ((unsigned)v->reg[3] & (h40 ? 0x3cu : 0x3eu)) << 10, w = h40 ? 64u : 32u, x;
    for (x = 0; x < m->video.back_width; ++x) {
        unsigned entry, colour;
        if (!window_covers(v, x, line)) continue;
        entry = vram_word(v, base + ((line >> 3) * w + (x >> 3)) * 2u);
        colour = tile_pixel(v, entry, x, line);
        index[x] = (uint8_t)(colour ? ((entry >> 9) & 0x30u) + colour : 0u);
        priority[x] = (uint8_t)(entry >> 15);
    }
}

/* Sprite model (plutiedev sprites for the entry format and limits; masking, overflow and
 * collision semantics are reference-derived or unknown, see docs/video.md). The table is at
 * register 5 << 9 (register 5 bit 0 is ignored in H40). An 8-byte entry is: Y (word, 10 bits,
 * offset 128), size (byte: width cells - 1 in bits 3-2, height cells - 1 in bits 1-0), link
 * (byte, 7 bits, 0 ends the list), pattern word (priority 15, palette 14-13, V-flip 12, H-flip
 * 11, first tile 10-0) and X (word, 9 bits, offset 128). Tiles run column-major. Traversal
 * starts at entry 0, follows links and visits at most 80 (H40) or 64 (H32) entries, so a cyclic
 * list terminates. A line draws at most 20/16 sprites (more set sprite_overflow) and spends at
 * most 320/256 sprite pixel columns (a sprite crossing the budget draws its left columns and
 * sets sprite_overflow). The first sprite drawn wins a pixel; two opaque sprite pixels on one
 * position set sprite_collision. Every address is masked to 16 bits and every x is clipped to
 * the active width before it indexes a line buffer. */
enum { SPRITE_OVERFLOW = 0x40, SPRITE_COLLISION = 0x20 };

static void render_sprites(gw_machine *m, unsigned line, uint8_t *priority, uint8_t *index)
{
    gw_vdp *v = &m->vdp;
    int h40 = (v->reg[12] & 1u) != 0;
    unsigned frame_limit = h40 ? 80u : 64u, line_limit = h40 ? 20u : 16u;
    unsigned pixel_budget = h40 ? 320u : 256u;
    unsigned base = ((unsigned)v->reg[5] & (h40 ? 0x7eu : 0x7fu)) << 9;
    unsigned visible[20], count = 0, entry = 0, visits, n, x;
    for (x = 0; x < m->video.back_width; ++x) {
        index[x] = 0;
        priority[x] = 0;
    }
    for (visits = 0; visits < frame_limit; ++visits) {
        unsigned at = base + entry * 8u;
        int top = (int)(vram_word(v, at) & 0x3ffu) - 128;
        unsigned size = v->vram[(at + 2u) & 0xffffu], link = v->vram[(at + 3u) & 0xffffu] & 0x7fu;
        int rows = (int)((size & 3u) + 1u) * 8, row = (int)line - top;
        if (row >= 0 && row < rows) {
            if (count == line_limit) {
                v->sprite_flags |= SPRITE_OVERFLOW; /* sprite_overflow: line limit exceeded */
                break;
            }
            visible[count++] = at;
        }
        if (link == 0) break;
        entry = link;
    }
    for (n = 0; n < count; ++n) {
        unsigned at = visible[n], size = v->vram[(at + 2u) & 0xffffu];
        unsigned pattern = vram_word(v, at + 4u);
        unsigned w_cells = ((size >> 2) & 3u) + 1u, h_cells = (size & 3u) + 1u, i;
        int left = (int)(vram_word(v, at + 6u) & 0x1ffu) - 128;
        unsigned py = (unsigned)((int)line - ((int)(vram_word(v, at) & 0x3ffu) - 128));
        unsigned columns = w_cells * 8u;
        if (pixel_budget < columns) { /* Dot limit: draw the leftmost columns left in the budget. */
            v->sprite_flags |= SPRITE_OVERFLOW;
            columns = pixel_budget;
        }
        pixel_budget -= columns;
        if (pattern & 0x1000u) py = h_cells * 8u - 1u - py;
        for (i = 0; i < columns; ++i) {
            int sx = left + (int)i;
            unsigned px = (pattern & 0x0800u) ? w_cells * 8u - 1u - i : i;
            unsigned tile = ((pattern & 0x7ffu) + (px >> 3) * h_cells + (py >> 3)) & 0x7ffu;
            unsigned colour;
            if (sx < 0 || sx >= (int)m->video.back_width) continue;
            colour = tile_pixel(v, tile, px, py);
            if (!colour) continue;
            if (index[sx]) {
                v->sprite_flags |= SPRITE_COLLISION; /* sprite_collision: opaque pixels overlap */
                continue;
            }
            index[sx] = (uint8_t)(((pattern >> 9) & 0x30u) + colour);
            priority[sx] = (uint8_t)(pattern >> 15);
        }
    }
}

/* Layer order, front to back: sprite high, A high, B high, sprite low, A low, B low, backdrop.
 * Index 0 of a layer is transparent. With S/TE (register 12 bit 3) the winning layer's priority
 * bit selects the base intensity (high normal, low or backdrop shadow) and sprite pixels of
 * palette 3 colour 14 (highlight operator) and 15 (shadow operator) are not drawn: they move
 * the intensity of whatever lies below (highlight: shadow to normal, normal to highlight;
 * shadow: always shadow). Genewhip convention, see docs/video.md. */
enum { OP_HIGHLIGHT = 0x3e, OP_SHADOW = 0x3f };

static void compose_line(gw_machine *m, uint32_t *row, uint16_t backdrop_word,
    const uint8_t *a_pri, const uint8_t *a_idx, const uint8_t *b_pri, const uint8_t *b_idx,
    const uint8_t *s_pri, const uint8_t *s_idx)
{
    const gw_vdp *v = &m->vdp;
    int sh = (v->reg[12] & 8u) != 0;
    unsigned x;
    for (x = 0; x < m->video.back_width; ++x) {
        unsigned pick = 0, high = 0, op = 0, spr = s_idx[x], intensity = GW_INTENSITY_NORMAL;
        if (sh && (spr == OP_HIGHLIGHT || spr == OP_SHADOW)) { op = spr; spr = 0; }
        if (spr && s_pri[x]) { pick = spr; high = 1; }
        else if (a_idx[x] && a_pri[x]) { pick = a_idx[x]; high = 1; }
        else if (b_idx[x] && b_pri[x]) { pick = b_idx[x]; high = 1; }
        else if (spr) pick = spr;
        else if (a_idx[x]) pick = a_idx[x];
        else if (b_idx[x]) pick = b_idx[x];
        if (sh) {
            intensity = high ? GW_INTENSITY_NORMAL : GW_INTENSITY_SHADOW;
            if (op == OP_HIGHLIGHT) intensity = intensity == GW_INTENSITY_SHADOW ? GW_INTENSITY_NORMAL : GW_INTENSITY_HIGHLIGHT;
            else if (op == OP_SHADOW) intensity = GW_INTENSITY_SHADOW;
        }
        row[x] = gw_cram_to_xrgb_intensity(pick ? v->cram[pick] : backdrop_word, intensity);
    }
}

void gw_render_line(gw_machine *m, uint32_t line)
{
    gw_video_out *o = &m->video;
    const gw_vdp *v = &m->vdp;
    uint32_t *row = o->buffers[o->back][line];
    uint32_t backdrop, x;
    uint16_t backdrop_word;
    uint8_t a_pri[GW_VDP_MAX_WIDTH], a_idx[GW_VDP_MAX_WIDTH];
    uint8_t b_pri[GW_VDP_MAX_WIDTH], b_idx[GW_VDP_MAX_WIDTH];
    uint8_t s_pri[GW_VDP_MAX_WIDTH], s_idx[GW_VDP_MAX_WIDTH];
    if (line == 0) o->back_width = (v->reg[12] & 1u) ? 320u : 256u; /* Latched per field. */
    backdrop_word = v->cram[v->reg[7] & 0x3fu];
    backdrop = gw_cram_to_xrgb(backdrop_word);
    if (!(v->reg[1] & 0x40u)) { /* Display disabled: backdrop only. */
        for (x = 0; x < o->back_width; ++x) row[x] = backdrop;
        return;
    }
    render_plane(m, line, PLANE_A, a_pri, a_idx);
    render_plane(m, line, PLANE_B, b_pri, b_idx);
    render_window(m, line, a_pri, a_idx);
    render_sprites(m, line, s_pri, s_idx);
    compose_line(m, row, backdrop_word, a_pri, a_idx, b_pri, b_idx, s_pri, s_idx);
}

void gw_render_publish(gw_machine *m, uint64_t sequence)
{
    gw_video_out *o = &m->video;
    o->front_width = o->back_width;
    o->front_sequence = sequence;
    o->has_field = 1;
    o->back ^= 1u;
    ++o->fields_this_run;
}
