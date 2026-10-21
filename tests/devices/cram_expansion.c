/* SPDX-License-Identifier: MIT
 * CRAM expansion and shadow/highlight convention check (plan GW-02-19, D-28).
 *
 * This is a GENEWHIP CONVENTION test, not hardware evidence (assumption A5): the 15-level
 * table, normal level[2v], shadow level[v], highlight level[v + 7], is chosen by Genewhip
 * and documented in docs/video.md. The test renders small in-memory ROMs through the public
 * video output only; the expected values below are authored here from the stated table.
 */
#include "contract.h"

static const unsigned level[15] = {0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255};

static unsigned cram_word(unsigned v) { return (v << 9) | (v << 5) | (v << 1); }
static uint32_t grey(unsigned l) { return (l << 16) | (l << 8) | l; }

typedef struct { uint8_t rom[2048]; size_t pos; } builder;

static void put16(builder *b, uint32_t v) { b->rom[b->pos++] = (uint8_t)(v >> 8); b->rom[b->pos++] = (uint8_t)v; }
static void put_long_imm(builder *b, uint32_t imm, uint32_t address) /* move.l #imm,(abs).l */
{
    put16(b, 0x23fc); put16(b, imm >> 16); put16(b, imm & 0xffffu);
    put16(b, address >> 16); put16(b, address & 0xffffu);
}
static void vdp_reg(builder *b, uint32_t value) /* move.w #value,(0xC00004).l */
{
    put16(b, 0x33fc); put16(b, value); put16(b, 0x00c0); put16(b, 0x0004);
}
static void vdp_cmd(builder *b, uint32_t command) { put_long_imm(b, command, 0xc00004); }
static void vdp_data(builder *b, uint32_t data) { put_long_imm(b, data, 0xc00000); }
static uint32_t vram_write(uint32_t address) { return 0x40000000u | ((address & 0x3fffu) << 16) | ((address >> 14) & 3u); }

/* Backdrop = CRAM entry 0 and plane colour 1 = word. The plane A row 0 cells, left to right:
 * 0 high, 1 low, 2 high, 3 high, 4 low (tile 1, palette 0, colour 1). Sprites (palette 3):
 * highlight operator (colour 14) over cell 0 and cell 1, shadow operator (colour 15) over
 * cell 3, all on line 0. */
static void build(builder *b, unsigned word, unsigned reg12)
{
    int i;
    memset(b, 0, sizeof(*b));
    put32(b->rom, 0xffff00); put32(b->rom + 4, 0x200);
    b->pos = 0x200;
    vdp_reg(b, 0x8144);        /* display on, Mode 5 */
    vdp_reg(b, 0x8c00 | reg12);
    vdp_reg(b, 0x8f02);        /* auto-increment 2 */
    vdp_reg(b, 0x8230);        /* plane A at VRAM 0xC000 */
    vdp_reg(b, 0x8578);        /* sprite table at VRAM 0xF000 */
    vdp_cmd(b, 0xc0000000u);   /* CRAM write at 0 */
    vdp_data(b, (word << 16) | word); /* entries 0 and 1 */
    vdp_cmd(b, vram_write(0x20));
    for (i = 0; i < 8; ++i) vdp_data(b, 0x11111111u);  /* tile 1: colour 1 */
    for (i = 0; i < 8; ++i) vdp_data(b, 0xeeeeeeeeu);  /* tile 2: colour 14 */
    for (i = 0; i < 8; ++i) vdp_data(b, 0xffffffffu);  /* tile 3: colour 15 */
    vdp_cmd(b, vram_write(0xc000));
    vdp_data(b, 0x80010001u); /* cells 0 (high) and 1 (low) */
    vdp_data(b, 0x80018001u); /* cells 2 and 3 (high) */
    vdp_data(b, 0x00010000u); /* cell 4 (low), cell 5 empty */
    vdp_cmd(b, vram_write(0xf000));
    vdp_data(b, 0x00800001u); vdp_data(b, 0x60020080u); /* sprite 0: Y line 0, link 1, pal 3 tile 2, X 0 */
    vdp_data(b, 0x00800002u); vdp_data(b, 0x60020088u); /* sprite 1: link 2, X 8 */
    vdp_data(b, 0x00800000u); vdp_data(b, 0x60030098u); /* sprite 2: end, tile 3, X 24 */
    put16(b, 0x60fe);                                   /* bra self */
}

static void render(builder *b, uint32_t *out, const char *label)
{
    gw_config config = {0};
    gw_machine *m = NULL;
    gw_run_result r = {0};
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    int fields;
    config.struct_size = sizeof(config); config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U; config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    CHECK(gw_create(&config, &m) == GW_OK, label);
    CHECK(gw_load_rom(m, b->rom, sizeof(b->rom)) == GW_OK, label);
    r.struct_size = sizeof(r); r.version = GW_API_VERSION;
    for (fields = 0; fields < 2; ++fields) {
        r.flags = 0;
        CHECK(gw_run_until(m, 3 * (uint64_t)GW_FIELD_TICKS, &r) == GW_OK, label);
        CHECK(r.stop_reason == GW_STOP_FIELD_COMPLETE, label);
    }
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK && pixels != NULL, label);
    CHECK(f.width == 320 && f.height == 224 && f.pitch_bytes >= 1280, label);
    out[0] = pixels[0];     /* cell 0 */
    out[1] = pixels[8];     /* cell 1 */
    out[2] = pixels[16];    /* cell 2 */
    out[3] = pixels[24];    /* cell 3 */
    out[4] = pixels[32];    /* cell 4 */
    out[5] = pixels[100];   /* backdrop on line 0 */
    out[6] = pixels[(size_t)f.pitch_bytes / 4u * 100u + 100u]; /* backdrop elsewhere */
    gw_destroy(m);
}

int main(void)
{
    static builder b;
    unsigned v;
    uint32_t px[7];

    /* Exact endpoints: normal black and white (table[0] and table[14]). */
    build(&b, 0x0000, 0x81); render(&b, px, "normal black");
    CHECK(px[0] == 0x000000 && px[5] == 0x000000, "CRAM 0x0000 expands to black");
    build(&b, 0x0eee, 0x81); render(&b, px, "normal white");
    CHECK(px[0] == 0xffffff && px[5] == 0xffffff, "CRAM 0x0EEE expands to white");

    for (v = 0; v < 8; ++v) {
        uint32_t normal = grey(level[2 * v]), shadow = grey(level[v]), highlight = grey(level[v + 7]);
        /* Ordering of the convention table: shadow <= normal <= highlight; strict wherever the
         * table has room (v = 0 has no darker level; v = 7 normal is already the top level). */
        CHECK(level[v] <= level[2 * v] && level[2 * v] <= level[v + 7], "shadow <= normal <= highlight");
        CHECK(v == 0 || level[v] < level[2 * v], "shadow darker than normal above black");
        CHECK(v == 7 || level[2 * v] < level[v + 7], "highlight brighter than normal below white");
        CHECK(level[7 + 7] == 255, "highlight of channel level 7 is 255");

        build(&b, cram_word(v), 0x81); render(&b, px, "S/TE off");
        CHECK(px[2] == normal && px[4] == normal && px[5] == normal && px[6] == normal, "S/TE off is normal everywhere");

        build(&b, cram_word(v), 0x89); render(&b, px, "S/TE on");
        CHECK(px[0] == highlight, "high plane + highlight operator = highlight");
        CHECK(px[1] == normal, "low plane + highlight operator = normal");
        CHECK(px[2] == normal, "high plane alone = normal");
        CHECK(px[3] == shadow, "high plane + shadow operator = shadow");
        CHECK(px[4] == shadow, "low plane alone = shadow");
        CHECK(px[5] == shadow && px[6] == shadow, "backdrop = shadow");
    }
    puts("PASS: cram expansion and shadow/highlight (Genewhip convention, not hardware evidence)");
    return 0;
}
