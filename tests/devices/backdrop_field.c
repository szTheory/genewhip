/* SPDX-License-Identifier: MIT
 * Headless public-API check: an original ROM programs the VDP through the CPU
 * and bus, and the field pulled through gw_get_video_field carries its colour.
 * Expected pixels come from the authored CRAM word and the documented table,
 * never from captured Genewhip output.
 */
#include "genewhip/genewhip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c, name) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); exit(1); } } while (0)

/* Documented Genewhip convention (docs/video.md): channel v -> level[2 * v]. */
static const unsigned level[15] = {0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255};

int main(int argc, char **argv)
{
    static uint8_t rom[4096];
    const uint16_t cram_word = 0x0E2A; /* Authored in backdrop.S. */
    const uint32_t expected = (level[2 * ((cram_word >> 1) & 7)] << 16) |
                              (level[2 * ((cram_word >> 5) & 7)] << 8) |
                              level[2 * ((cram_word >> 9) & 7)];
    gw_config config = {sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 0, {0, 0}};
    gw_machine *m = NULL;
    gw_run_result r = {0};
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    const unsigned char *bytes;
    size_t size;
    unsigned fields = 0, x, y, probe = 1;
    FILE *file;
    CHECK(argc == 2, "usage");
    file = fopen(argv[1], "rb");
    CHECK(file != NULL, "ROM open");
    size = fread(rom, 1, sizeof(rom), file);
    CHECK(size >= GW_MIN_ROM_SIZE && fclose(file) == 0, "ROM read");
    CHECK(gw_create(&config, &m) == GW_OK, "create");
    CHECK(gw_load_rom(m, rom, size) == GW_OK, "load");
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_ERROR_EMPTY, "no field before the first run");
    r.struct_size = sizeof(r); r.version = GW_API_VERSION;
    while (fields < 2) {
        CHECK(gw_run_until(m, 3 * (uint64_t)GW_FIELD_TICKS, &r) == GW_OK, "run");
        CHECK(r.stop_reason == GW_STOP_FIELD_COMPLETE, "zero-flag call stops at field end");
        ++fields;
    }
    CHECK(gw_get_video_field(m, &f, &pixels) == GW_OK && pixels != NULL, "pull field");
    CHECK(f.width == 320 && f.height == 224, "H40 V28 geometry");
    CHECK(f.pitch_bytes >= f.width * 4, "pitch holds a row");
    CHECK(f.pixel_format == GW_PIXEL_XRGB8888, "pixel format");
    CHECK(f.sequence == 1, "second field");
    CHECK(f.start_tick == GW_FIELD_TICKS, "start_tick is line 0 of the field");
    CHECK(f.end_tick == GW_FIELD_TICKS + 224 * GW_LINE_TICKS, "end_tick is line 224");
    CHECK(f.dropped == 0 && f.flags == 0, "no drops with field stops");
    for (y = 0; y < f.height; ++y) {
        const uint32_t *row = (const uint32_t *)((const unsigned char *)pixels + (size_t)y * f.pitch_bytes);
        for (x = 0; x < f.width; ++x) CHECK(row[x] == expected, "backdrop pixel from authored CRAM word");
    }
    bytes = (const unsigned char *)pixels;
    if (*(const unsigned char *)&probe == 1) { /* little-endian: B, G, R, 0 */
        CHECK(bytes[0] == (expected & 255) && bytes[1] == ((expected >> 8) & 255) &&
              bytes[2] == ((expected >> 16) & 255) && bytes[3] == 0, "XRGB8888 bytes, little-endian");
    } else { /* big-endian: 0, R, G, B */
        CHECK(bytes[0] == 0 && bytes[1] == ((expected >> 16) & 255) &&
              bytes[2] == ((expected >> 8) & 255) && bytes[3] == (expected & 255), "XRGB8888 bytes, big-endian");
    }
    gw_destroy(m);
    puts("backdrop_field: PASS");
    return 0;
}
