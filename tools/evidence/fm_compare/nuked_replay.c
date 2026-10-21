/* SPDX-License-Identifier: MIT
 * Thin evidence adapter. Nuked-OPN2 remains in ignored build/audio-refs only. */
#include "ym3438.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct record { uint64_t tick; unsigned reg, value; } record;

int main(int argc, char **argv)
{
    FILE *in;
    record *rows = NULL;
    size_t count = 0, capacity = 0, i = 0;
    uint64_t last_tick = 0, step = 0;
    int64_t sample_left = 0, sample_right = 0;
    unsigned sample_count = 0;
    unsigned pending_port = 0, pending_value = 0;
    unsigned write_phase = 0;
    ym3438_t chip;
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
    OPN2_SetChipType(ym3438_mode_ym2612); /* process-global: one script per process */
    OPN2_Reset(&chip);                    /* readmode remains unset */
    while (step < (last_tick / 42u + 24u) / 24u * 24u) {
        Bit16s output[2] = {0, 0};
        if (write_phase == 0 && i < count && rows[i].tick / 42u <= step) {
            pending_port = (rows[i].reg & 0x100u) ? 2u : 0u;
            pending_value = rows[i].value;
            OPN2_Write(&chip, pending_port, (Bit8u)rows[i].reg);
            write_phase = 1;
            ++i;
        }
        OPN2_Clock(&chip, output);
        if (write_phase == 1) write_phase = 2;
        else if (write_phase == 2) {
            OPN2_Write(&chip, pending_port + 1u, (Bit8u)pending_value);
            write_phase = 3;
        } else if (write_phase == 3) write_phase = 4;
        else if (write_phase == 4) write_phase = 0;
        ++step;
        /* YM3438 output is six-channel multiplexed: one value per channel
         * every fourth internal slot. Sum a complete frame and convert the
         * x3 raw DAC units into ymfm's output stage: (sum/3) * 128*64/(6*65).
         * Keep the exact rational and truncate once, as the port does. */
        if (chip.cycles % 4u == 0u) {
            sample_left += output[0];
            sample_right += output[1];
            ++sample_count;
        }
        if (step % 24u == 0) {
            uint64_t sample = step / 24u;
            if (sample_count != 6u) { free(rows); return 3; }
            printf("%" PRIu64 " %" PRId64 " %" PRId64 " %u\n", sample,
                   (sample_left * 8192) / 1170, (sample_right * 8192) / 1170,
                   (unsigned)OPN2_Read(&chip, 0));
            sample_left = sample_right = 0;
            sample_count = 0;
        }
    }
    free(rows);
    return 0;
}
