/* SPDX-License-Identifier: MIT */
#include "contract.h"

#ifdef GW_TEST_HOOKS
extern int gw_test_bus_write(const gw_machine *, size_t, uint64_t *, uint32_t *, uint32_t *, uint32_t *);
static void ordered_writes(void)
{
    uint8_t rom[1024], bytes[4]; gw_machine *m=machine();
    uint64_t tick; uint32_t address,value,prior;
    const uint8_t code[]={0x23,0xfc,0x12,0x34,0x56,0x78,0,0xff,0,0};
    rom_init(rom,sizeof(rom)); memcpy(rom+512,code,sizeof(code));
    CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"bus ROM");
    CHECK(run(m,113).actual_tick==308,"longword instruction retirement");
    CHECK(gw_test_bus_write(m,0,&tick,&address,&value,&prior),"first write exists");
    CHECK(tick==280 && address==0xff0000 && value==0x1234 && prior==0,"high word at first transfer");
    CHECK(gw_test_bus_write(m,1,&tick,&address,&value,&prior),"second write exists");
    CHECK(tick==308 && address==0xff0002 && value==0x5678 && prior==0x12340000,"first effect visible before second transfer");
    CHECK(!gw_test_bus_write(m,2,&tick,&address,&value,&prior),"no extra writes");
    CHECK(gw_peek_memory(m,0xff0000,bytes,4)==GW_OK && bytes[0]==0x12 && bytes[1]==0x34 && bytes[2]==0x56 && bytes[3]==0x78,"public longword result");
    gw_destroy(m);
}
#endif

static void event(gw_machine *m, uint64_t tick)
{
    gw_event e = {sizeof(e), GW_API_VERSION, tick, GW_EVENT_CONSOLE_RESET, 0};
    CHECK(gw_schedule_event(m, &e) == GW_OK, "schedule reset");
}

int main(void)
{
    uint8_t rom[1024]; gw_machine *a = machine(), *b = machine();
    gw_run_result r, untouched, before;
    gw_event e = {sizeof(e), GW_API_VERSION, 112, GW_EVENT_CONSOLE_RESET, 0};
#ifdef GW_TEST_HOOKS
    ordered_writes();
#endif
    rom_init(rom, sizeof(rom));
    CHECK(gw_load_rom(a, rom, sizeof(rom)) == GW_OK, "load a");
    event(a, 112); r = run(a, 112);
    CHECK(r.actual_tick == 224 && r.requested_tick == 112, "event at current target settles before return");
    CHECK(r.stop_reason == GW_STOP_TARGET, "target reason");
    CHECK(gw_cold_init(a) == GW_OK, "cold init");
    event(a, 182); r = run(a, 113); /* BRA retires at 182, then reset fetch 112. */
    CHECK(r.actual_tick == 294, "event at overshot retirement settles before return");
    CHECK(r.actual_tick-r.requested_tick == 181, "observable overshoot");
    CHECK(r.overshoot_ticks==181,"explicit overshoot field");
    CHECK(gw_cold_init(a) == GW_OK, "cold a");
    CHECK(gw_load_rom(b, rom, sizeof(rom)) == GW_OK, "load b");
    /* Deliberately unsorted insertions, duplicate timestamps and nearby events. */
    { const uint64_t ticks[] = {900,182,400,400,401,1400};
      for (size_t i=0;i<sizeof(ticks)/sizeof(ticks[0]);++i) { event(a,ticks[i]); event(b,ticks[i]); } }
    r = run(a, 2000);
    for (uint64_t t=112; t<2000;) {
        gw_run_result split = run(b, t+1); t=split.actual_tick;
        CHECK(split.stop_reason == GW_STOP_TARGET, "split target reason");
    }
    same(a,b); CHECK(r.actual_tick == snapshot(b).tick, "split time");
    memset(&untouched, 0x5a, sizeof(untouched));
    untouched.struct_size=sizeof(untouched); untouched.version=GW_API_VERSION; before=untouched;
    CHECK(gw_run_until(a, r.actual_tick-1, &untouched) == GW_ERROR_TIME, "past target rejected");
    CHECK(memcmp(&before,&untouched,sizeof(before)) == 0, "invalid run preserves result");
    CHECK(gw_run_until(a, UINT64_MAX, &untouched) == GW_ERROR_TIME, "overflow target rejected");
    untouched.version=GW_API_VERSION-1;
    CHECK(gw_run_until(a,r.actual_tick,&untouched)==GW_ERROR_VERSION,"old run result version rejected");
    untouched.version=GW_API_VERSION; untouched.struct_size--;
    CHECK(gw_run_until(a,r.actual_tick,&untouched)==GW_ERROR_VERSION,"wrong run result size rejected");
    untouched=before;
    CHECK(gw_run_until(a,r.actual_tick,NULL)==GW_ERROR_ARGUMENT,"null result rejected");
    CHECK(gw_run_until(NULL,r.actual_tick,&untouched)==GW_ERROR_ARGUMENT,"null machine rejected");
    same(a,b);
    e.tick=r.actual_tick-1;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_TIME,"late event rejected");
    e.tick=UINT64_MAX;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_TIME,"overflow event rejected");
    e.tick=r.actual_tick; e.type=99;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_UNSUPPORTED,"unknown event rejected");
    e.type=GW_EVENT_CONSOLE_RESET; e.reserved=1;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_ARGUMENT,"reserved event rejected");
    e.reserved=0; e.version++;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_VERSION,"event version rejected");
    e.version=GW_API_VERSION; e.struct_size--;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_VERSION,"event size rejected");
    same(a,b);
    CHECK(gw_cold_init(a)==GW_OK,"queue reset");
    for (unsigned i=0;i<GW_EVENT_CAPACITY;++i) event(a,112);
    e.struct_size=sizeof(e); e.tick=112;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_CAPACITY,"one above capacity rejected");
    r=run(a,112);
    CHECK(r.actual_tick==112+GW_EVENT_CAPACITY*112,"all equal-time resets retained");
    event(a,r.actual_tick); /* Capacity reclaimed. */
    CHECK(gw_cold_init(a)==GW_OK,"clear queue");
    CHECK(run(a,112).actual_tick==112,"cold clears queued events");
    /* STOP does not advance without a wake event; upper targets can be tested
     * without executing an enormous loop or consulting a host clock. */
    rom[512]=0x4e; rom[513]=0x72; rom[514]=0x27; rom[515]=0;
    CHECK(gw_load_rom(a,rom,sizeof(rom))==GW_OK,"STOP load");
    r=run(a,113); CHECK(r.actual_tick==168 && r.stop_reason==GW_STOP_CPU_STOPPED,"STOP boundary");
    /* Phase 1 amendment (02-18): run(a,1000).actual_tick==168 -> 1000. A STOP with no wake
     * source now advances emulated time (and devices) to the requested target. */
    r=run(a,1000);
    CHECK(r.actual_tick==1000 && r.stop_reason==GW_STOP_CPU_STOPPED,"STOP with no wake source advances to the target");
    /* Phase 1 amendment (02-18): early stop has zero overshoot -> zero overshoot at the target. */
    CHECK(run(a,1000).overshoot_ticks==0 && r.overshoot_ticks==0,"stopped run has zero overshoot at the target");
    event(a,1000); r=run(a,1000);
    CHECK(r.actual_tick==1112 && r.stop_reason==GW_STOP_TARGET,"STOP wake at target");
    r=run(a,1113); CHECK(r.stop_reason==GW_STOP_CPU_STOPPED,"STOP again");
    /* Phase 1 amendment (02-18): both stopped runs returned the unchanged STOP tick
     * (r.actual_tick) -> they end exactly at their targets (GW_MAX_TARGET_TICK - 1, GW_MAX_TARGET_TICK).
     * Amendment (02 review CR-03): the maximum moved from UINT64_MAX-4096 to UINT64_MAX-2^32. */
    CHECK(run(a,GW_MAX_TARGET_TICK-1).actual_tick==GW_MAX_TARGET_TICK-1,"below maximum target accepted");
    CHECK(run(a,GW_MAX_TARGET_TICK).actual_tick==GW_MAX_TARGET_TICK,"maximum target accepted");
    CHECK(gw_run_until(a,GW_MAX_TARGET_TICK+1,&untouched)==GW_ERROR_TIME,"above maximum target rejected");
    event(a,GW_MAX_TARGET_TICK); r=run(a,GW_MAX_TARGET_TICK);
    CHECK(r.actual_tick==GW_MAX_TARGET_TICK+112,"large integer event timestamp exact");
    CHECK(gw_console_reset(a)==GW_ERROR_TIME,"reset refuses exhausted time headroom");
    CHECK(gw_cold_init(a)==GW_OK && snapshot(a).tick==112,"cold recovers timeline");
    gw_destroy(a); gw_destroy(b); puts("time_contract: PASS"); return 0;
}
