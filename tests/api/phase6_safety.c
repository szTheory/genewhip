/* SPDX-License-Identifier: MIT */
#include "contract.h"

int main(void)
{
    uint8_t rom[1024];
    gw_machine *a=machine(), *b=machine();
    gw_run_result before={0}, after={0};
    gw_event e={sizeof(e),GW_API_VERSION,112,GW_EVENT_CONSOLE_RESET,0,0,0};
    rom_init(rom,sizeof(rom));
    CHECK(gw_load_rom(a,rom,sizeof(rom))==GW_OK,"load a");
    CHECK(gw_load_rom(b,rom,sizeof(rom))==GW_OK,"load b");
    before.struct_size=sizeof(before);before.version=GW_API_VERSION;
    CHECK(gw_run_until(a,112,&before)==GW_OK,"baseline run");

    /* Invalid descriptors and out-of-range times are rejected before either
       caller output or machine progress changes. */
    after=before; after.actual_tick^=UINT64_C(0x55aa);
    gw_run_result untouched=after;
    CHECK(gw_run_until(a,UINT64_MAX,&after)==GW_ERROR_TIME,"overflow target rejected");
    CHECK(memcmp(&after,&untouched,sizeof(after))==0,"overflow preserves result");
    e.tick=before.actual_tick-1;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_TIME,"past event rejected");
    e.tick=before.actual_tick;
    e.reserved=1;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_ARGUMENT,"reserved event rejected");
    e.reserved=0; e.version++;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_VERSION,"version rejected");
    e.version=GW_API_VERSION;e.struct_size--;
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_VERSION,"size rejected");
    same(a,b);

    /* The 64th queued event is accepted; the 65th is rejected without losing
       any earlier event, then both machines reach the same valid boundary. */
    CHECK(gw_cold_init(a)==GW_OK && gw_cold_init(b)==GW_OK,"reset pair");
    for (unsigned i=0;i<GW_EVENT_CAPACITY;i++) {
        e=(gw_event){sizeof(e),GW_API_VERSION,112,GW_EVENT_CONSOLE_RESET,0,0,0};
        CHECK(gw_schedule_event(a,&e)==GW_OK,"queue boundary event");
    }
    CHECK(gw_schedule_event(a,&e)==GW_ERROR_CAPACITY,"queue overflow rejected");
    e=(gw_event){sizeof(e),GW_API_VERSION,112,GW_EVENT_CONSOLE_RESET,0,0,0};
    for (unsigned i=0;i<GW_EVENT_CAPACITY;i++) CHECK(gw_schedule_event(b,&e)==GW_OK,"reference queue");
    CHECK(gw_run_until(a,112,&before)==GW_OK && gw_run_until(b,112,&after)==GW_OK,"valid continuation");
    CHECK(before.actual_tick==after.actual_tick,"continuation time");
    same(a,b);
    puts("phase6_safety: PASS");
    gw_destroy(a);gw_destroy(b);return 0;
}
