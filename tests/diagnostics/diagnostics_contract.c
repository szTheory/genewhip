/* SPDX-License-Identifier: MIT */
#include "../api/contract.h"
#ifdef GW_TEST_HOOKS
extern uint64_t gw_test_allocation_count(const gw_machine *);
#endif

static void equivalent(gw_machine *a, gw_machine *b)
{
    gw_diagnostic_record x=snapshot(a), y=snapshot(b);
    uint8_t ax[GW_RAM_SIZE], bx[GW_RAM_SIZE];
    x.diagnostics_enabled=y.diagnostics_enabled=0;
    x.instructions=y.instructions=0;
    x.exceptions=y.exceptions=0;
    x.exception_returns=y.exception_returns=0;
    x.external_resets=y.external_resets=0;
    CHECK(memcmp(&x,&y,sizeof(x))==0,"enabled/disabled complete CPU and time equivalence");
    CHECK(gw_peek_memory(a,0xff0000,ax,sizeof(ax))==GW_OK,"RAM a");
    CHECK(gw_peek_memory(b,0xff0000,bx,sizeof(bx))==GW_OK,"RAM b");
    CHECK(memcmp(ax,bx,sizeof(ax))==0,"enabled/disabled complete RAM equivalence");
}

int main(int argc, char **argv)
{
    uint8_t rom[1024];
    gw_machine *enabled=machine(), *disabled=NULL;
    gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0};
    gw_diagnostic_event records[GW_DIAGNOSTIC_CAPACITY], saved[2];
    size_t count=99; uint64_t dropped=99;
    FILE *file;
    CHECK(argc==2,"fixture argument"); file=fopen(argv[1],"rb");
    CHECK(file && fread(rom,1,sizeof(rom),file)==sizeof(rom),"original fixture read"); fclose(file);
    CHECK(gw_create(&c,&disabled)==GW_OK,"default disabled create");
    CHECK(gw_configure_diagnostics(enabled,2)==GW_OK,"caller-declared diagnostic capacity accepted");
    CHECK(gw_load_rom(enabled,rom,sizeof(rom))==GW_OK,"enabled load");
    CHECK(gw_load_rom(disabled,rom,sizeof(rom))==GW_OK,"disabled load");
#ifdef GW_TEST_HOOKS
    uint64_t alloc=gw_test_allocation_count(enabled);
#endif
    for (unsigned i=0;i<2;++i) {
        gw_event e={sizeof(e),GW_API_VERSION,2000+i*2000,GW_EVENT_CONSOLE_RESET,0};
        CHECK(gw_schedule_event(enabled,&e)==GW_OK && gw_schedule_event(disabled,&e)==GW_OK,"identical events");
    }
    gw_run_result a=run(enabled,5000), b=run(disabled,5000);
    CHECK(memcmp(&a,&b,sizeof(a))==0,"identical run results"); equivalent(enabled,disabled);
    CHECK(gw_get_diagnostic_events(enabled,records,GW_DIAGNOSTIC_CAPACITY,&count,&dropped)==GW_OK,"read events");
    CHECK(count==2 && dropped>0,"bounded retained records and explicit overflow");
    CHECK(count+dropped==snapshot(enabled).instructions,"all retired attempts accounted for");
    CHECK(records[0].instruction_address==0x200 && records[0].opcode==0x13fc && records[0].tick==252,"first instruction identity/time");
    CHECK(records[1].tick>records[0].tick,"ordered records"); memcpy(saved,records,sizeof(saved));
    size_t original_count=count; uint64_t original_dropped=dropped;
    CHECK(gw_get_diagnostic_events(enabled,records,1,&count,&dropped)==GW_ERROR_CAPACITY,"short copy rejected");
    CHECK(count==original_count && dropped==original_dropped && memcmp(saved,records,sizeof(saved))==0,"short copy preserves outputs");
    CHECK(gw_configure_diagnostics(enabled,GW_DIAGNOSTIC_CAPACITY+1)==GW_ERROR_CAPACITY,"above maximum rejected");
    CHECK(gw_get_diagnostic_events(enabled,records,2,&count,&dropped)==GW_OK && dropped==original_dropped,"invalid config preserves records");
    CHECK(gw_get_diagnostic_events(disabled,NULL,0,&count,&dropped)==GW_OK && count==0 && dropped==0,"disabled emits no records");
    CHECK(snapshot(disabled).instructions==0 && snapshot(disabled).exceptions==0,"disabled counters zero");
    CHECK(gw_configure_diagnostics(disabled,1)==GW_OK,"second instance enables independently");
    CHECK(gw_get_diagnostic_events(disabled,NULL,0,&count,&dropped)==GW_OK && count==0 && dropped==0,"second instance starts empty");
    CHECK(gw_get_diagnostic_events(enabled,records,2,&count,&dropped)==GW_OK && count==2 && dropped==original_dropped && memcmp(saved,records,sizeof(saved))==0,"second instance cannot clear first records");
    CHECK(gw_configure_diagnostics(disabled,0)==GW_OK,"second instance disables independently");
    CHECK(gw_get_diagnostic_events(enabled,NULL,1,&count,&dropped)==GW_ERROR_ARGUMENT,"null record storage rejected");
    CHECK(gw_get_diagnostic_events(enabled,records,2,NULL,&dropped)==GW_ERROR_ARGUMENT,"null count rejected");
    CHECK(gw_get_diagnostic_events(enabled,records,2,&count,NULL)==GW_ERROR_ARGUMENT,"null dropped rejected");
    CHECK(gw_configure_diagnostics(NULL,1)==GW_ERROR_ARGUMENT,"null machine rejected");
    CHECK(gw_configure_diagnostics(enabled,0)==GW_OK,"disable and clear"); equivalent(enabled,disabled);
    CHECK(gw_get_diagnostic_events(enabled,NULL,0,&count,&dropped)==GW_OK && count==0 && dropped==0,"disable clears records");
    CHECK(gw_configure_diagnostics(enabled,GW_DIAGNOSTIC_CAPACITY)==GW_OK,"maximum capacity");
    rom_init(rom,sizeof(rom)); CHECK(gw_load_rom(enabled,rom,sizeof(rom))==GW_OK,"loop fixture");
    run(enabled,112+70*GW_DIAGNOSTIC_CAPACITY);
    CHECK(gw_get_diagnostic_events(enabled,records,GW_DIAGNOSTIC_CAPACITY,&count,&dropped)==GW_OK && count==GW_DIAGNOSTIC_CAPACITY && dropped==0,"exact capacity");
    run(enabled,snapshot(enabled).tick+1);
    CHECK(gw_get_diagnostic_events(enabled,records,GW_DIAGNOSTIC_CAPACITY,&count,&dropped)==GW_OK && count==GW_DIAGNOSTIC_CAPACITY && dropped==1,"one beyond capacity");
    CHECK(gw_cold_init(enabled)==GW_OK,"cold clears diagnostics");
    CHECK(gw_get_diagnostic_events(enabled,NULL,0,&count,&dropped)==GW_OK && count==0 && dropped==0,"cold clear observed");
    rom[512]=0x4a; rom[513]=0xfc;
    CHECK(gw_load_rom(enabled,rom,sizeof(rom))==GW_OK,"unsupported fixture"); run(enabled,1000); run(enabled,1000);
    CHECK(gw_get_diagnostic_events(enabled,records,GW_DIAGNOSTIC_CAPACITY,&count,&dropped)==GW_OK && count==1,"sticky stop recorded once");
    CHECK(records[0].opcode==0x4afc && records[0].stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"unsupported attempt visible");
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_allocation_count(enabled)==alloc+2,"only explicit replacement loads allocate");
#endif
    gw_destroy(enabled); gw_destroy(disabled); puts("diagnostics_contract: PASS"); return 0;
}
