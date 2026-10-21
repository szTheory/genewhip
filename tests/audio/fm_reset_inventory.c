/* SPDX-License-Identifier: MIT
 * Pinned-ymfm reset inventory and approved provisional wrapper contract.
 * These are implementation assertions, never a hardware reset oracle.
 */
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c,n) do { if (!(c)) { fprintf(stderr,"FAIL: %s (line %d)\n",n,__LINE__); exit(1); } } while (0)
static void write_reg(gw_machine *m, unsigned reg, uint8_t data)
{
    gw_ym2612_write_at(m, m->ym.advanced_tick, reg >= 256 ? 2 : 0, (uint8_t)reg, GW_AUDIO_SOURCE_68000);
    gw_ym2612_write_at(m, m->ym.advanced_tick, reg >= 256 ? 3 : 1, data, GW_AUDIO_SOURCE_68000);
}

int main(void)
{
    gw_config config = {0};
    gw_machine *m = NULL;
    gw_ym2612 before;
    gw_audio audio_before;
    uint64_t edge = 9u * GW_FM_SAMPLE_TICKS + 100u;
    config.struct_size=sizeof(config); config.version=GW_API_VERSION;
    config.profile=GW_PROFILE_VA3_NTSC_U; config.reset_policy=GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz=48000;
    CHECK(gw_create(&config,&m)==GW_OK, "create inventory machine");
    gw_ym2612_reset_line(m,0,0);
    write_reg(m,0x30,1); write_reg(m,0x50,31); write_reg(m,0xb0,7);
    write_reg(m,0xa4,0x22); write_reg(m,0xa0,0x84); write_reg(m,0x28,0x10);
    write_reg(m,0x22,15); write_reg(m,0x24,0xff); write_reg(m,0x25,3);
    write_reg(m,0x27,5); write_reg(m,0x2a,0x7e); write_reg(m,0x2b,0x80);
    gw_audio_sync(m,edge);
    /* Set the interface busy end and address immediately before assertion. */
    write_reg(m,0x40,0x12);
    before=m->ym; audio_before=m->audio;
    CHECK(before.operator[0].key_state && before.timer_running[0] && (before.status&1),
        "sounding/timer-active precondition");
    CHECK(before.dac_enable && before.dac_data && before.lfo_counter, "DAC and LFO precondition");
    gw_ym2612_reset_line(m,edge,1);
    CHECK(m->tick==0, "reset helper preserves machine master time");
    CHECK(m->ym.next_sample_tick==before.next_sample_tick, "reset preserves global sample grid");
    CHECK(m->audio.queue_count==audio_before.queue_count && m->audio.first_index==audio_before.first_index &&
        m->audio.finalised_frames==audio_before.finalised_frames &&
        memcmp(m->audio.queue,audio_before.queue,sizeof(m->audio.queue))==0 &&
        memcmp(m->audio.integrator,audio_before.integrator,sizeof(m->audio.integrator))==0,
        "reset preserves existing PCM queue, indices and integrator");
    CHECK(m->ym.last_output[0]==0 && m->ym.last_output[1]==0, "reset emits silence mix step");
    for (unsigned i=0;i<512;++i) {
        uint8_t expected=(i==0xb4||i==0xb5||i==0xb6||i==0x1b4||i==0x1b5||i==0x1b6)?0xc0:0;
        CHECK(m->ym.regdata[i]==expected,"all reset register defaults including frequency latches");
    }
    CHECK(m->ym.status==0 && m->ym.irq_state==0 && !m->ym.timer_running[0] && !m->ym.timer_running[1],
        "reset clears status, IRQ and both timers");
    CHECK(m->ym.timer_tick[0]==UINT64_MAX && m->ym.timer_tick[1]==UINT64_MAX,"reset cancels timer deadlines");
    CHECK(m->ym.address==before.address && m->ym.dac_data==before.dac_data && m->ym.dac_enable==before.dac_enable &&
        m->ym.busy_end_tick==before.busy_end_tick,"upstream retains address, DAC and interface busy deadline");
    CHECK(m->ym.lfo_counter==before.lfo_counter && m->ym.lfo_am==before.lfo_am &&
        m->ym.env_counter==before.env_counter && m->ym.total_clocks==before.total_clocks &&
        m->ym.clock_prescale==before.clock_prescale && m->ym.irq_mask==before.irq_mask &&
        m->ym.prepare_count==before.prepare_count && m->ym.active_channels==before.active_channels,
        "upstream retains LFO, envelope and clock/prepare counters");
    CHECK(m->ym.modified_channels==63,"reset invalidates caches via mode write");
    for (unsigned i=0;i<24;++i) {
        const gw_ym_operator *o=&m->ym.operator[i], *old=&before.operator[i];
        CHECK(o->phase==0 && o->env_attenuation==0x3ff && o->env_state==4 &&
            !o->ssg_inverted && !o->key_state && !o->keyon_live,"operator reset inventory");
        CHECK(o->choffs==old->choffs && o->opoffs==old->opoffs &&
            memcmp(&o->cache,&old->cache,sizeof(o->cache))==0,"operator mapping/cache retention");
    }
    for (unsigned i=0;i<6;++i) {
        CHECK(!m->ym.channel[i].feedback[0] && !m->ym.channel[i].feedback[1] && !m->ym.channel[i].feedback_in,
            "channel feedback reset");
        CHECK(m->ym.channel[i].choffs==before.channel[i].choffs &&
            memcmp(m->ym.channel[i].op,before.channel[i].op,4)==0,"channel mapping retention");
    }
    before=m->ym;
    write_reg(m,0x2b,0); write_reg(m,0x28,0xf0);
    CHECK(memcmp(&before,&m->ym,sizeof(before))==0,"YM writes ignored while held");
    gw_ym2612_reset_line(m,edge,1);
    CHECK(memcmp(&before,&m->ym,sizeof(before))==0,"repeated asserted level does not reinitialize");
    gw_audio_sync(m,edge+3*GW_FM_SAMPLE_TICKS);
    CHECK(m->ym.last_output[0]==0 && m->ym.env_counter==before.env_counter,"held reset freezes engine and silences contribution");
    CHECK(m->ym.next_sample_tick==before.next_sample_tick+3*GW_FM_SAMPLE_TICKS,"held grid advances without rewind");
    gw_ym2612_reset_line(m,m->ym.advanced_tick,0);
    CHECK(!m->ym.operator[0].key_state && !m->ym.operator[0].keyon_live,"release does not restore FM note");
    gw_destroy(m);
    puts("fm_reset_inventory: PASS (implementation contract; hardware fidelity unknown)");
    return 0;
}
