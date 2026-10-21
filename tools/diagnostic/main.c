/* SPDX-License-Identifier: MIT
 * Public-API headless client. Expectations are authored from diagnostic.S;
 * they are not learned from emulator output or MAME vectors.
 */
#include <genewhip/genewhip.h>
#include "diagnostic_identity.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Explicit set: GW_STOP_FIELD_COMPLETE (5) is a normal run result, never unsupported. */
static int unsupported_stop(uint32_t r)
{
    return r==GW_STOP_UNSUPPORTED_INSTRUCTION || r==GW_STOP_UNSUPPORTED_ADDRESS ||
           r==GW_STOP_UNSUPPORTED_STATE;
}

int main(int argc, char **argv)
{
    unsigned char rom[1025], ram[10]={0}, stack[6]={0};
    static const unsigned char expected_ram[10]={0x12,0x34,0x89,0xab,0xcd,0xef,0xca,0xfe,0xbe,0xef};
    static const unsigned char expected_stack[6]={0x27,0x04,0,0,2,0x2a};
    gw_machine *machine=NULL;
    gw_config config={sizeof(config),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,1,{0,0}};
    gw_run_result run={0}; gw_diagnostic_record d={0};
    const char *outcome[6]; char observed[6][129];
    FILE *f; size_t size; int good[6]={0}, ok=1, io_error;
    if(argc!=2) { fputs("usage: gw_diagnostic_runner diagnostic.bin\n",stderr); return 2; }
    f=fopen(argv[1],"rb");
    if(!f) { fputs("REJECT: missing-fixture\n",stderr); return 1; }
    size=fread(rom,1,sizeof(rom),f); io_error=ferror(f);
    if(fclose(f)) io_error=1;
    if(io_error || size!=sizeof(gw_admitted_rom) || memcmp(rom,gw_admitted_rom,sizeof(gw_admitted_rom))) {
        fputs("REJECT: fixture-content\n",stderr); return 1;
    }
    run.struct_size=sizeof(run); run.version=GW_API_VERSION;
    d.struct_size=sizeof(d); d.version=GW_API_VERSION;
    if(gw_create(&config,&machine)!=GW_OK || gw_load_rom(machine,rom,size)!=GW_OK ||
       gw_run_until(machine,10000,&run)!=GW_OK || gw_get_diagnostics(machine,&d)!=GW_OK ||
       gw_peek_memory(machine,0xff0000,ram,sizeof(ram))!=GW_OK ||
       gw_peek_memory(machine,0xfffefa,stack,sizeof(stack))!=GW_OK) ok=0;
    good[0]=d.initial_ssp==0xffff00 && d.initial_pc==0x200;
    good[1]=d.d[0]==0x1234 && d.d[1]==0x89abcdef && !memcmp(ram,expected_ram,10);
    good[2]=d.d[3]==0x2704 && d.d[4]==0x22a && !memcmp(stack,expected_stack,6);
    good[3]=d.a[7]==0xffff00 && d.pc==0x236 && d.sr==0x2700;
    good[4]=run.stop_reason==GW_STOP_CPU_STOPPED;
    good[5]=d.instructions==13 && d.exceptions==1 && d.exception_returns==1 && run.actual_tick<=10000;
    (void)snprintf(observed[0],129,"ssp-%08" PRIx32 "-pc-%08" PRIx32,d.initial_ssp,d.initial_pc);
    (void)snprintf(observed[1],129,"d0-%08" PRIx32 "-d1-%08" PRIx32,d.d[0],d.d[1]);
    (void)snprintf(observed[2],129,"sr-%08" PRIx32 "-pc-%08" PRIx32,d.d[3],d.d[4]);
    (void)snprintf(observed[3],129,"a7-%08" PRIx32 "-pc-%08" PRIx32 "-sr-%04" PRIx32,d.a[7],d.pc,d.sr);
    (void)snprintf(observed[4],129,"stop-%" PRIu32,run.stop_reason);
    (void)snprintf(observed[5],129,"instructions-%" PRIu64 "-exceptions-%" PRIu64 "-returns-%" PRIu64 "-ticks-%" PRIu64,
        d.instructions,d.exceptions,d.exception_returns,run.actual_tick);
    for(size_t i=0;i<6;++i) {
        outcome[i]=!ok ? "infrastructure-error" :
            unsupported_stop(run.stop_reason) ? "unsupported" : good[i] ? "pass" : "fail";
    }
    printf("{\"schema_version\":1,\"source_revision\":\"%s\",\"source_state\":\"%s\","
        "\"configuration\":\"%s\",\"fixture\":\"%s\",\"input\":\"%s\","
        "\"profile\":\"%s\",\"oracle\":\"%s\",\"expected\":6,\"results\":[",
        GW_SOURCE_REVISION,GW_SOURCE_STATE,GW_CONFIGURATION,GW_FIXTURE,GW_INPUT,
        gw_diagnostic_identity.profile,gw_diagnostic_identity.oracle);
    for(size_t i=0;i<6;++i)
        printf("%s{\"id\":\"%s\",\"outcome\":\"%s\",\"observed\":\"%s\"}",
            i ? "," : "",gw_diagnostic_cases[i],outcome[i],observed[i]);
    puts("]}");
    gw_destroy(machine);
    if(ferror(stdout)) return 1;
    for(size_t i=0;i<6;++i) if(strcmp(outcome[i],"pass")) return 1;
    return 0;
}
