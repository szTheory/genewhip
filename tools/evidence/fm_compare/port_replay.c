/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct record { uint64_t tick; unsigned reg, value; } record;

int main(int argc, char **argv)
{
    FILE *in;
    record *rows = NULL;
    size_t count = 0, capacity = 0, i = 0;
    uint64_t last_tick = 0, sample = 0;
    gw_machine *m = NULL;
    gw_config config = {0};
    if (argc != 2 || !(in = fopen(argv[1], "r"))) return 2;
    while (!feof(in)) {
        record row;
        int got = fscanf(in, "%" SCNu64 " %u %u", &row.tick, &row.reg, &row.value);
        if (got == EOF) break;
        if (got != 3 || row.reg > 0x1ff || row.value > 0xff) { fclose(in); free(rows); return 2; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 512;
            record *grown = (record *)realloc(rows, next * sizeof(*rows));
            if (!grown) { fclose(in); free(rows); return 2; }
            rows = grown; capacity = next;
        }
        rows[count++] = row;
        if (row.tick > last_tick) last_tick = row.tick;
    }
    if (fclose(in) || !count) { free(rows); return 2; }
    config.struct_size = sizeof(config); config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    if (gw_create(&config, &m) != GW_OK) { free(rows); return 2; }
    /* The trace contains register writes only. Use a cold, released chip at tick 0;
       guest reset assertion/release is outside this comparator's input contract. */
    gw_test_ym_release_reset(m);
    for (sample = 1; sample * GW_FM_SAMPLE_TICKS <= last_tick + GW_FM_SAMPLE_TICKS; ++sample) {
        uint64_t tick = sample * GW_FM_SAMPLE_TICKS;
        while (i < count && rows[i].tick <= tick) {
            unsigned port = (rows[i].reg >> 8 ? 2u : 0u);
            m->tick = rows[i].tick;
            gw_test_ym_write(m, port, (uint8_t)rows[i].reg);
            gw_test_ym_write(m, port + 1u, (uint8_t)rows[i].value);
            ++i;
        }
        m->tick = tick;
        int32_t left, right;
        if (!gw_test_ym_sample(m, &left, &right)) {
            fprintf(stderr, "no YM sample at requested boundary sample=%" PRIu64 " tick=%" PRIu64 " after_write_tick=%" PRIu64 "\n", sample, tick, m->tick);
            gw_destroy(m); free(rows); return 3;
        }
        printf("%" PRIu64 " %" PRId32 " %" PRId32 " %u\n", sample, left, right,
               (unsigned)gw_ym2612_read_status(m, tick));
    }
    gw_destroy(m);
    free(rows);
    return 0;
}
