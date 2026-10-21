/* SPDX-License-Identifier: MIT */
#include "contract.h"
#ifdef GW_TEST_HOOKS
#include "internal.h"
#include "state_digest.h"
#endif

static int poll_order(const uint8_t *bits,size_t count)
{
    int clear_seen=0;
    if (!count) return 0;
    for (size_t i=0;i<count;++i) {
        if ((bits[i]&1u)==0u) clear_seen=1;
        else if (clear_seen) return 0;
    }
    return clear_seen;
}

static int tracer(const char *path)
{
    uint8_t image[1024],result=0,log[64],count_bytes[2];
    uint16_t count;
    FILE *f=fopen(path,"rb"); CHECK(f!=NULL,"ROM open");
    size_t n=fread(image,1,sizeof(image),f); CHECK(n==sizeof(image)&&fclose(f)==0,"ROM read");
    gw_machine *m=machine(); CHECK(gw_load_rom(m,image,n)==GW_OK,"ROM load");
    gw_run_result rr=run(m,UINT64_C(4)*GW_FIELD_TICKS);
    CHECK(rr.stop_reason!=GW_STOP_UNSUPPORTED_ADDRESS&&rr.stop_reason!=GW_STOP_UNSUPPORTED_INSTRUCTION&&
          rr.stop_reason!=GW_STOP_UNSUPPORTED_STATE,"run has no unsupported stop");
    CHECK(gw_peek_memory(m,0xff0000,&result,1)==GW_OK,"read Z80 result");
    CHECK(result==0x5a,"Z80 result 0x5A");
    CHECK(gw_peek_memory(m,0xff0002,count_bytes,2)==GW_OK,"poll count");
    count=(uint16_t)(((uint16_t)count_bytes[0]<<8)|count_bytes[1]);
    CHECK(count>0&&count<=sizeof(log),"poll count bounded");
    CHECK(gw_peek_memory(m,0xff0100,log,count)==GW_OK,"poll log");
    CHECK(poll_order(log,count),"poll order");
    gw_destroy(m); return 0;
}

#ifdef GW_TEST_HOOKS
static int arb_order(const gw_test_z80_arb_event *events,size_t count)
{
    uint64_t prior=0; int requested=0,granted=0,released=0;
    for(size_t i=0;i<count;++i) {
        if(i&&events[i].tick<=prior)return 0;
        prior=events[i].tick;
        if(events[i].kind==GW_TEST_Z80_ARB_REQUEST&&!requested&&!granted) requested=1;
        else if(events[i].kind==GW_TEST_Z80_ARB_GRANT&&requested&&!granted) {granted=1;requested=0;}
        else if(events[i].kind==GW_TEST_Z80_ARB_RELEASE&&granted) {granted=0;released=1;}
        else return 0;
    }
    return count>=2&&released&&!granted;
}

static gw_machine *arb_machine(void)
{
    gw_machine *m=machine();
    gw_test_z80_state s={0};
    CHECK(gw_test_z80_set_state(m,&s),"initialize Z80 test state");
    memset(m->z80.ram,0,sizeof(m->z80.ram)); /* NOP stream */
    return m;
}

static int grant_contract(void)
{
    for(uint64_t offset=0;offset<50;++offset) {
        gw_machine *m=arb_machine();
        gw_test_z80_arb_event ev;
        uint32_t request=UINT32_C(0x0100);
        gw_z80_sync(m,0);
        m->tick=offset;
        CHECK(gw_bus_write(m,UINT32_C(0x00a11100),2,request),"request write");
        CHECK(gw_test_z80_arb_event_count(m)==1,"request latched before boundary");
        CHECK(gw_test_z80_arb_event_get(m,0,&ev)&&ev.kind==GW_TEST_Z80_ARB_REQUEST,"request event first");
        uint64_t request_tick=ev.tick;
        gw_z80_sync(m,request_tick+UINT64_C(7)*GW_Z80_DIVIDER);
        CHECK(gw_test_z80_arb_event_count(m)==2,"request and grant trace entries");
        CHECK(gw_test_z80_arb_event_get(m,0,&ev)&&ev.kind==GW_TEST_Z80_ARB_REQUEST,"request event first");
        CHECK(gw_test_z80_arb_event_get(m,1,&ev)&&ev.kind==GW_TEST_Z80_ARB_GRANT,"grant event second");
        uint64_t expected=(request_tick/60u+1u)*60u;
        CHECK(ev.tick==expected,"grant at first Z80 cycle boundary");
        CHECK(ev.tick-request_tick<UINT64_C(7)*GW_Z80_DIVIDER,"grant within longest machine cycle");
        CHECK(m->z80.busreq,"grant stops Z80 cycle issue");
        /* Releasing well after the held boundary must resume only at the next
         * absolute Z80 clock edge, never by replaying old cycle starts. */
        m->tick=240;
        uint64_t before=m->z80.next_cycle_tick;
        CHECK(gw_bus_write(m,UINT32_C(0x00a11100),2,0),"release write");
        uint64_t release_tick=m->tick;
        uint64_t resume_tick=((release_tick/GW_Z80_DIVIDER)+1u)*GW_Z80_DIVIDER;
        gw_z80_sync(m,resume_tick-1u);
        CHECK(!m->z80.busreq&&m->z80.next_cycle_tick==resume_tick&&before<resume_tick,
              "release waits for next absolute edge");
        gw_z80_sync(m,resume_tick);
        CHECK(m->z80.next_cycle_tick>resume_tick,
              "release resumes at next clock edge");
        gw_test_z80_arb_event ordered[4];
        size_t event_count=gw_test_z80_arb_event_count(m);
        CHECK(event_count<=4,"arbitration trace bounded for contract");
        for(size_t i=0;i<event_count;++i)CHECK(gw_test_z80_arb_event_get(m,i,&ordered[i]),"arbitration event read");
        CHECK(arb_order(ordered,event_count),"arbitration order");
        gw_destroy(m);
    }
    puts("z80_arbitration_contract: PASS grant timing");
    return 0;
}

static int sync_limit_contract(void)
{
    gw_machine *m=arb_machine();
    m->z80.ram[0]=0x18; m->z80.ram[1]=0xfe; /* JR $ keeps the fetch in mapped RAM. */
    gw_z80_sync(m,UINT64_C(120000000));
    CHECK(m->cpu.stop_reason==GW_STOP_UNSUPPORTED_STATE,"bounded sync reports unsupported state");
    gw_destroy(m);
    puts("z80_sync_limit: PASS bounded work is explicit");
    return 0;
}

static int midinstr_contract(void)
{
    gw_machine *m=arb_machine();
    gw_test_z80_arb_event event;
    m->z80.ram[0]=0x31; m->z80.ram[1]=0xff; m->z80.ram[2]=0x17; /* LD SP,17FF */
    m->z80.ram[3]=0x01; m->z80.ram[4]=0x34; m->z80.ram[5]=0x12; /* LD BC,1234 */
    m->z80.ram[6]=0xc5; m->z80.ram[7]=0x18; m->z80.ram[8]=0xfe; /* PUSH BC; JR $ */
    m->z80.ram[0x17fe]=0xaa; m->z80.ram[0x17fd]=0xbb;
    for(unsigned i=0;i<40 && !(m->z80.instruction_active && m->z80.opcode==0xc5 && m->z80.stage==20);++i)
        gw_z80_sync(m,m->z80.next_cycle_tick);
    CHECK(m->z80.instruction_active && m->z80.opcode==0xc5 && m->z80.stage==20,
        "reach PUSH high-byte micro-operation");
    m->z80.busreq_pending=1; m->z80.busreq_tick=m->z80.next_cycle_tick;
    gw_z80_sync(m,m->z80.next_cycle_tick+UINT64_C(3)*GW_Z80_DIVIDER);
    CHECK(m->z80.busreq && m->z80.ram[0x17fe]==0x12 && m->z80.ram[0x17fd]==0xbb,
        "grant preserves only completed PUSH high byte");
    CHECK(gw_test_z80_arb_event_get(m,gw_test_z80_arb_event_count(m)-1,&event) &&
        event.kind==GW_TEST_Z80_ARB_GRANT && event.instruction_active && event.opcode==0xc5 && event.stage==13,
        "grant trace identifies the second PUSH write micro-operation");
    m->tick=m->z80.next_cycle_tick;
    CHECK(gw_bus_write(m,UINT32_C(0x00a11100),2,0),"release after mid-PUSH grant");
    gw_z80_sync(m,m->tick+UINT64_C(300)*GW_Z80_DIVIDER);
    CHECK(m->z80.ram[0x17fe]==0x12 && m->z80.ram[0x17fd]==0x34,
        "PUSH completes exactly once after release");
    gw_destroy(m);

    m=arb_machine();
    m->z80.ram[0]=0xed; m->z80.ram[1]=0xb0; /* LDIR */
    m->z80.hl=0x1800; m->z80.de=0x1900; m->z80.bc=4;
    memcpy(&m->z80.ram[0x1800],"ABCD",4);
    for(unsigned i=0;i<12 && m->z80.stage!=76u;++i) CHECK(gw_z80_cycle(m),"advance to LDIR destination write");
    CHECK(m->z80.stage==76u,"reach LDIR destination write");
    m->z80.busreq_pending=1; m->z80.busreq_tick=m->z80.next_cycle_tick;
    gw_z80_sync(m,m->z80.next_cycle_tick+UINT64_C(3)*GW_Z80_DIVIDER);
    CHECK(m->z80.busreq && m->z80.ram[0x1900]=='A' && m->z80.bc==4,
        "grant occurs after LDIR write before iteration retirement");
    m->tick=m->z80.next_cycle_tick;
    CHECK(gw_bus_write(m,UINT32_C(0x00a11100),2,0),"release during LDIR");
    gw_z80_sync(m,m->tick+UINT64_C(1000)*GW_Z80_DIVIDER);
    CHECK(m->z80.bc==0 && memcmp(&m->z80.ram[0x1900],"ABCD",4)==0,
        "LDIR copies exactly N bytes across the grant");
    gw_destroy(m);
    puts("z80_midinstr_contract: PASS PUSH and LDIR resume once");
    return 0;
}

static int map_contract(void)
{
    gw_machine *m=arb_machine();
    uint8_t rom[UINT16_C(0x8002)]={0};
    uint8_t value=0;
    rom[1]=UINT8_C(0xff); rom[2]=UINT8_C(0xff);
    rom[4]=UINT8_C(0x00); rom[5]=UINT8_C(0x00); rom[6]=UINT8_C(0x02); rom[7]=UINT8_C(0x00);
    rom[UINT16_C(0x8000)]=UINT8_C('G');
    CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"load ROM with bank-one final byte");
    for (unsigned bit=0;bit<9;++bit)
        CHECK(gw_z80_mem_write(m,UINT16_C(0x6000),bit==0?1u:0u,3),"shift LSB-first bank bit");
    CHECK(m->z80.bank==1 && m->z80.bank_shift_count==0,"nine LSB-first bits select bank one");
    uint64_t before=m->z80.next_cycle_tick;
    CHECK(gw_z80_mem_read(m,UINT16_C(0x8000),&value,0,3),"read loaded ROM through bank window");
    CHECK(value==UINT8_C('G') && m->z80.next_cycle_tick==before+GW_Z80_DIVIDER,
        "window uses actual ROM byte and model-scoped wait");
    CHECK(gw_load_rom(m,rom,UINT32_C(0x8000))==GW_OK,"reload shorter ROM");
    m->z80.bank=1;
    CHECK(!gw_z80_mem_read(m,UINT16_C(0x8000),&value,0,3) &&
        m->cpu.stop_reason==GW_STOP_UNSUPPORTED_ADDRESS && m->cpu.fault_address==UINT32_C(0x40008000),
        "bank window rejects bytes beyond actual ROM size");
    m->cpu.stop_reason=GW_STOP_TARGET;
    CHECK(gw_z80_mem_read(m,UINT16_C(0x4000),&value,0,3) && value==0,
        "YM status route exists after Plan 03-17");
    CHECK(!gw_z80_mem_read(m,UINT16_C(0x4004),&value,0,3) &&
        m->cpu.fault_address==UINT32_C(0x40004004),"range immediately above YM fails closed");
    gw_destroy(m);
    puts("z80_map_contract: PASS LSB-first bank and actual-ROM bound");
    return 0;
}

static uint32_t idempotence_rng=UINT32_C(0x90d42);
static uint32_t next_random(void)
{ idempotence_rng=idempotence_rng*UINT32_C(1664525)+UINT32_C(1013904223); return idempotence_rng; }

static gw_machine *idempotence_machine(const char *path)
{
    uint8_t rom[4096]; FILE *f=fopen(path,"rb"); CHECK(f!=NULL,"idempotence ROM open");
    size_t n=fread(rom,1,sizeof(rom),f); CHECK(n>=GW_MIN_ROM_SIZE&&fclose(f)==0,"idempotence ROM read");
    gw_machine *m=machine(); CHECK(gw_load_rom(m,rom,n)==GW_OK,"idempotence ROM load");
    gw_test_z80_state s={0}; CHECK(gw_test_z80_set_state(m,&s),"idempotence Z80 setup");
    m->z80.ram[0]=0x3e; m->z80.ram[1]=0x5a; /* LD A,$5A */
    m->z80.ram[2]=0x32; m->z80.ram[3]=0x00; m->z80.ram[4]=0x10; /* LD ($1000),A */
    m->z80.ram[5]=0x18; m->z80.ram[6]=0xfe; /* JR $ */
    return m;
}

static int same_arb_trace(const gw_machine *a,const gw_machine *b)
{
    size_t n=gw_test_z80_arb_event_count(a);
    if(n!=gw_test_z80_arb_event_count(b))return 0;
    for(size_t i=0;i<n;++i){gw_test_z80_arb_event x,y;
        if(!gw_test_z80_arb_event_get(a,i,&x)||!gw_test_z80_arb_event_get(b,i,&y)||x.kind!=y.kind||x.tick!=y.tick)return 0;}
    return 1;
}

static int add_arb_episode(gw_machine *m)
{
    m->tick=UINT64_C(90000);
    if(!gw_bus_write(m,UINT32_C(0x00a11100),2,UINT32_C(0x0100)))return 0;
    gw_z80_sync(m,m->tick+UINT64_C(7)*GW_Z80_DIVIDER);
    if(!m->z80.busreq)return 0;
    return gw_bus_write(m,UINT32_C(0x00a11100),2,0);
}

static int idempotence_contract(const char *path)
{
    const uint64_t horizon=UINT64_C(60000),end=UINT64_C(90000);
    gw_machine *plain=idempotence_machine(path),*split=idempotence_machine(path);
    gw_z80_sync(plain,horizon);
    uint64_t cursor=0;
    for(unsigned i=0;i<200;++i){cursor+=next_random()%300u; if(cursor>horizon)cursor=horizon;gw_z80_sync(split,cursor);}
    gw_z80_sync(split,horizon);
    CHECK(gw_test_state_digest(plain)==gw_test_state_digest(split),"machine digest after extra sync points");
    CHECK(gw_z80_digest(&plain->z80,UINT64_C(1469598103934665603))==
          gw_z80_digest(&split->z80,UINT64_C(1469598103934665603)),"Z80 digest after extra sync points");
    CHECK(memcmp(plain->z80.ram,split->z80.ram,sizeof(plain->z80.ram))==0,"Z80 RAM after extra sync points");
    CHECK(same_arb_trace(plain,split),"arbitration trace after extra sync points");
    /* Explicit partition identity: sync(a); sync(b) equals sync(b). */
    gw_z80_sync(plain,horizon+1234u); gw_z80_sync(plain,end);
    gw_z80_sync(split,end);
    CHECK(gw_z80_digest(&plain->z80,UINT64_C(1469598103934665603))==
          gw_z80_digest(&split->z80,UINT64_C(1469598103934665603)),"sync(a); sync(b) equals sync(b)");
    CHECK(memcmp(plain->z80.ram,split->z80.ram,sizeof(plain->z80.ram))==0,"final Z80 RAM identity");
    CHECK(add_arb_episode(plain)&&add_arb_episode(split),"matching arbitration episodes");
    CHECK(gw_test_z80_arb_event_count(plain)>=3&&same_arb_trace(plain,split),"nonempty arbitration trace identity");
    CHECK(same_arb_trace(plain,split),"final arbitration trace identity");
    gw_destroy(plain); gw_destroy(split);
    puts("z80_sync_idempotence: PASS 200 extra sync points");
    return 0;
}
#endif

int main(int argc,char **argv)
{
    if(argc==2&&strcmp(argv[1],"poll-order-negative")==0) {
        const uint8_t reversed[]={0,1};
        CHECK(!poll_order(reversed,sizeof(reversed)),"poll order");
        puts("poll order: PASS negative control"); return 0;
    }
#ifdef GW_TEST_HOOKS
    if(argc==2&&strcmp(argv[1],"arbitration-order-negative")==0) {
        const gw_test_z80_arb_event bad[]={
            {.kind=GW_TEST_Z80_ARB_GRANT,.tick=15},
            {.kind=GW_TEST_Z80_ARB_REQUEST,.tick=30}};
        CHECK(!arb_order(bad,sizeof(bad)),"arbitration order");
        puts("arbitration order: PASS negative control"); return 0;
    }
    if(argc==2&&strcmp(argv[1],"grant")==0) return grant_contract();
    if(argc==2&&strcmp(argv[1],"sync-limit")==0) return sync_limit_contract();
    if(argc==2&&strcmp(argv[1],"midinstr")==0) return midinstr_contract();
    if(argc==2&&strcmp(argv[1],"map")==0) return map_contract();
    if(argc==3&&strcmp(argv[1],"idempotence")==0) return idempotence_contract(argv[2]);
#endif
    CHECK(argc==3&&strcmp(argv[1],"tracer")==0,"usage: z80_arbitration_contract tracer ROM");
    return tracer(argv[2]);
}
