/* SPDX-License-Identifier: MIT */
#include "contract.h"

int main(void)
{
    uint8_t rom[1024], ram[2]; gw_machine *m=machine();
    gw_diagnostic_record d; gw_run_result r;
    gw_event e={sizeof(e),GW_API_VERSION,2000,GW_EVENT_CONSOLE_RESET,0};
    const uint8_t code[]={
        0x70,0x2a, /* MOVEQ #42,D0 */
        0x33,0xfc,0xbe,0xef,0,0xff,0,0, /* MOVE.W #beef,$ff0000 */
        0x4e,0x70, /* RESET, continues */
        0x72,0x07, /* MOVEQ #7,D1 */
        0x4e,0x72,0x27,0 /* STOP */
    };
    CHECK(gw_cold_init(m)==GW_ERROR_NOT_LOADED,"cold unloaded");
    CHECK(gw_console_reset(m)==GW_ERROR_NOT_LOADED,"console unloaded");
    CHECK(gw_cold_init(NULL)==GW_ERROR_ARGUMENT && gw_console_reset(NULL)==GW_ERROR_ARGUMENT,"null reset");
    rom_init(rom,sizeof(rom)); memcpy(rom+512,code,sizeof(code));
    CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"reset ROM load");
    d=snapshot(m);
    CHECK(d.tick==112 && d.pc==512 && d.a[7]==0xffff00 && d.sr==0x2700,"cold vectors and time");
    r=run(m,1+112+28+140); /* Just enter guest RESET. */
    d=snapshot(m);
    CHECK(d.pc==524 && d.d[0]==42 && d.d[1]==0 && d.external_resets==1,"guest RESET preserves CPU and continues");
    CHECK(d.tick==1204,"guest RESET explicit transfer plus internal delay");
    CHECK(gw_peek_memory(m,0xff0000,ram,sizeof(ram))==GW_OK && ram[0]==0xbe && ram[1]==0xef,"guest RESET preserves RAM");
    r=run(m,1500); d=snapshot(m);
    CHECK(r.stop_reason==GW_STOP_CPU_STOPPED && d.d[1]==7,"guest instruction after RESET executes");
    CHECK(gw_schedule_event(m,&e)==GW_OK,"future reset");
    CHECK(gw_console_reset(m)==GW_OK,"console reset");
    { gw_diagnostic_record reset=snapshot(m);
      CHECK(reset.tick==d.tick+112 && reset.pc==512 && reset.a[7]==0xffff00 && reset.sr==0x2700,"console vectors monotonic time");
      CHECK(reset.d[0]==0 && reset.d[1]==0 && reset.instructions==d.instructions && reset.external_resets==1,"console CPU policy and retained counters"); }
    CHECK(gw_peek_memory(m,0xff0000,ram,sizeof(ram))==GW_OK && ram[0]==0xbe,"console RAM retained");
    r=run(m,2000); CHECK(r.actual_tick>2000 && snapshot(m).pc==512,"console retains event across guest RESET");
    CHECK(gw_cold_init(m)==GW_OK,"cold restart");
    d=snapshot(m); CHECK(d.tick==112 && d.pc==512 && d.instructions==0 && d.external_resets==0,"cold counters and time");
    CHECK(gw_peek_memory(m,0xff0000,ram,sizeof(ram))==GW_OK && ram[0]==0 && ram[1]==0,"cold RAM policy");
    CHECK(gw_cold_init(m)==GW_OK,"repeated cold init");
    { gw_diagnostic_record twice=snapshot(m); CHECK(memcmp(&d,&twice,sizeof(d))==0,"cold init repeat deterministic"); }
    rom[512]=0xff; rom[513]=0xff;
    CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"unknown opcode ROM");
    r=run(m,113); CHECK(r.stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"unsupported sticky stop");
    e.tick=r.actual_tick; CHECK(gw_schedule_event(m,&e)==GW_OK,"queue at unsupported stop");
    CHECK(run(m,1000).actual_tick==r.actual_tick,"queued event cannot clear unsupported stop");
    CHECK(gw_console_reset(m)==GW_OK && snapshot(m).stop_reason==GW_STOP_TARGET,"direct reset clears unsupported stop");
    gw_destroy(m); puts("reset_contract: PASS"); return 0;
}
