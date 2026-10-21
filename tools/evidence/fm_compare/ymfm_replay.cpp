/* SPDX-License-Identifier: BSD-3-Clause
 * Evidence-only adapter against the BSD-3-Clause ymfm 81aec25 pin. */
#include "ymfm_opn.h"
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

struct Record { uint64_t tick; unsigned reg, value; };

class ReplayInterface final : public ymfm::ymfm_interface {
public:
    uint64_t now = 0;
    uint64_t timer_deadline[2] = {UINT64_MAX, UINT64_MAX};
    uint64_t busy_deadline = 0;
    void ymfm_set_timer(uint32_t n, int32_t duration) override {
        if (n > 1) std::abort();
        timer_deadline[n] = duration < 0 ? UINT64_MAX : now + uint64_t(duration) * 7;
    }
    void ymfm_set_busy_end(uint32_t clocks) override { busy_deadline = now + uint64_t(clocks) * 7; }
    bool ymfm_is_busy() override { return now < busy_deadline; }
    void advance_to(uint64_t tick) {
        for (;;) {
            unsigned n = timer_deadline[0] <= timer_deadline[1] ? 0 : 1;
            if (timer_deadline[n] > tick) break;
            now = timer_deadline[n];
            timer_deadline[n] = UINT64_MAX;
            m_engine->engine_timer_expired(n);
        }
        now = tick;
    }
};

static void write_register(ymfm::ym2612 &chip, unsigned reg, unsigned value)
{
    if (reg & 0x100) { chip.write_address_hi(uint8_t(reg)); chip.write_data_hi(uint8_t(value)); }
    else { chip.write_address(uint8_t(reg)); chip.write_data(uint8_t(value)); }
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *in = std::fopen(argv[1], "r");
    if (!in) return 2;
    std::vector<Record> rows;
    Record row{};
    while (true) {
        int got = std::fscanf(in, "%" SCNu64 " %u %u", &row.tick, &row.reg, &row.value);
        if (got == EOF) break;
        if (got != 3 || row.reg > 0x1ff || row.value > 0xff) { std::fclose(in); return 2; }
        rows.push_back(row);
    }
    if (std::fclose(in) || rows.empty()) return 2;
    uint64_t last_tick = 0;
    for (auto const &r : rows) if (r.tick > last_tick) last_tick = r.tick;
    ReplayInterface intf;
    ymfm::ym2612 chip(intf);
    chip.reset();
    size_t i = 0;
    for (uint64_t sample = 1; sample * 1008 <= last_tick + 1008; ++sample) {
        uint64_t tick = sample * 1008;
        while (i < rows.size() && rows[i].tick <= tick) {
            intf.advance_to(rows[i].tick);
            write_register(chip, rows[i].reg, rows[i].value);
            ++i;
        }
        intf.advance_to(tick);
        ymfm::ym2612::output_data output{};
        chip.generate(&output);
        std::printf("%" PRIu64 " %d %d %u\n", sample, output.data[0], output.data[1],
                    unsigned(chip.read_status()));
    }
    return 0;
}
