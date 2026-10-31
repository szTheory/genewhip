/* SPDX-License-Identifier: MIT
 * Original guest oracles: NXP M68000PRM p474 (USP), pp241-242 (MULU);
 * MC68000UM table8-12 and section8.3. No emulator-derived expectations.
 */
#include "../../src/internal.h"
#include "../../src/state_digest.h"
#include "contract.h"

static void word(uint8_t *p,unsigned v) {p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static void step(gw_machine *m,const char *name)
{ CHECK(run(m,m->tick+1).stop_reason==GW_STOP_TARGET,name); }
static gw_machine *guest(const uint8_t *code,size_t size)
{
    uint8_t rom[2048];rom_init(rom,sizeof(rom));memcpy(rom+512,code,size);
    gw_machine *m=machine();CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"load original repair guest");return m;
}
static void usp(void)
{
    uint32_t values[]={0,1,0xffff,0x80000000u,0xe1000000u,0xffffffffu};
    for(unsigned reg=0;reg<8;reg++) for(unsigned k=0;k<6;k++) {
        uint8_t code[20]={0};
        word(code,0x207c+(reg<<9));put32(code+2,values[k]); /* MOVEA.L */
        word(code+6,0x003c);word(code+8,0x1f);
        word(code+10,0x4e60+reg);word(code+12,0x4e68+((reg+1)%8));
        gw_machine *m=guest(code,sizeof(code));step(m,"USP source setup");step(m,"CCR setup");
        gw_cpu before=m->cpu;uint64_t tick=m->tick;
        step(m,"observed MOVE An,USP executes");
        CHECK(m->tick==tick+28 && m->cpu.pc==524,"USP store four clocks and PC");
        CHECK(!memcmp(before.a,m->cpu.a,sizeof(before.a)) && !memcmp(before.d,m->cpu.d,sizeof(before.d)) && m->cpu.sr==0x271f,"USP store preserves all general registers and CCR");
        step(m,"MOVE USP,An executes");
        CHECK(m->cpu.a[(reg+1)%8]==values[k],"USP full32 stored value read back, not SSP or truncated word");
        CHECK(m->cpu.a[reg]==values[k] && m->cpu.sr==0x271f,"USP source/CCR unchanged");
        CHECK(gw_console_reset(m)==GW_OK,"console reset");
        /* Read untouched zero-policy USP at reset entry (private ROM test setup). */
        word(m->rom+512,0x4e68);step(m,"USP read after reset");
        CHECK(m->cpu.a[0]==0,"reset clears USP as deterministic emulator policy");
        gw_destroy(m);
    }
    /* State discrimination without changing RAM, tick, PC, other registers or
     * counters: ROM is excluded from the state digest; guests normalize A0. */
#ifdef GW_TEST_HOOKS
    uint64_t digests[33];
    for(unsigned bit=0;bit<33;bit++) {
        uint8_t code[14];word(code,0x207c);put32(code+2,bit==32?0:UINT32_C(1)<<bit);
        word(code+6,0x4e60);word(code+8,0x207c);put32(code+10,0);
        gw_machine *m=guest(code,sizeof(code));step(m,"digest source");step(m,"digest USP store");step(m,"normalize visible address register");
        digests[bit]=gw_test_state_digest(m);gw_destroy(m);
    }
    for(unsigned i=0;i<33;i++)for(unsigned j=0;j<i;j++)CHECK(digests[i]!=digests[j],"every USP bit enters future-state digest");
#endif
}
static unsigned ones(unsigned v) {unsigned n=0;for(unsigned b=0;b<16;b++)n+=(v>>b)&1;return n;}
static void mulu(void)
{
    uint32_t sources[]={0,1,2,0x7fff,0x8000,0xffff};
    uint32_t dests[]={0,1,0x8000,0xffff,0xabcdffff};
    for(unsigned s=0;s<6;s++)for(unsigned d=0;d<5;d++)for(unsigned reg=0;reg<8;reg++) {
        uint8_t code[16]={0};word(code,0x203c+(reg<<9));put32(code+2,dests[d]);
        word(code+6,0x003c);word(code+8,0x1f);word(code+10,0xc0fc+(reg<<9));word(code+12,sources[s]);
        gw_machine *m=guest(code,sizeof(code));step(m,"MULU destination setup");step(m,"CCR setup");
        gw_cpu before=m->cpu;uint64_t tick=m->tick;uint32_t expected=(dests[d]&0xffffu)*sources[s];
        step(m,"observed MULU immediate executes");
        CHECK(m->cpu.d[reg]==expected,"unsigned low16 operands replace full32 product");
        CHECK(m->cpu.sr==(0x2710u|(expected==0?4u:0u)|((expected&0x80000000u)?8u:0u)),"MULU X preserved N/Z product V/C cleared");
        CHECK(m->tick-tick==(42u+2*ones(sources[s]))*7u,"MULU source-popcount exact immediate clocks");
        for(unsigned i=0;i<8;i++)CHECK(m->cpu.a[i]==before.a[i]&&(i==reg||m->cpu.d[i]==before.d[i]),"MULU unrelated registers unchanged");
        CHECK(m->cpu.pc==526,"MULU extension PC");gw_destroy(m);
    }
}
static void muls(void)
{
    /* Specified signed operand oracle; transitions independently tabulated
     * from the17-bit source ending in0, MC68000UM8.3/table8-4. */
    const struct {unsigned bits,transitions;int32_t value;} cases[]={
        {0,0,0},{1,2,1},{0xffff,1,-1},{0x7fff,2,32767},
        {0x8000,1,-32768},{0x8001,3,-32767},{0x5555,16,21845},
        {0xaaaa,15,-21846},{2,2,2},{0xfffe,1,-2}
    };
    for(unsigned s=0;s<10;s++)for(unsigned d=0;d<10;d++)for(unsigned reg=0;reg<8;reg++)for(unsigned x=0;x<2;x++) {
        uint8_t code[4];word(code,0xc1fcu+(reg<<9));word(code+2,cases[s].bits);
        gw_machine *m=guest(code,sizeof(code));
        m->cpu.d[reg]=0xabc00000u|cases[d].bits;m->cpu.sr=(uint16_t)(0x270fu|(x<<4));
        gw_cpu before=m->cpu;uint64_t tick=m->tick;
        uint32_t expected=(uint32_t)(cases[s].value*cases[d].value);
        step(m,"MULS signed lowword operands execute");
        CHECK(m->cpu.d[reg]==expected,"MULS signed product replaces all32bits and ignores upper destination");
        CHECK(m->cpu.sr==(0x2700u|(x<<4)|(expected==0?4u:0u)|((expected&0x80000000u)?8u:0u)),"MULS productN/Z clearsV/C preserves both X states");
        CHECK(m->cpu.pc==516&&m->tick-tick==(42u+2u*cases[s].transitions)*GW_CPU_DIVIDER,"MULS immediate PC and independently tabulated source-transition timing");
        for(unsigned i=0;i<8;i++)CHECK(m->cpu.a[i]==before.a[i]&&(i==reg||m->cpu.d[i]==before.d[i]),"MULS preserves unrelated registers");gw_destroy(m);
    }
    for(unsigned reg=0;reg<8;reg++) {
        uint8_t code[2];word(code,0xc1c0u+(reg<<9)+reg);gw_machine *m=guest(code,2);
        m->cpu.d[reg]=0xabcd8000;uint64_t tick=m->tick;step(m,"MULS self-alias source captured before write");
        CHECK(m->cpu.d[reg]==0x40000000&&m->tick-tick==40u*GW_CPU_DIVIDER,"MULS minimumsigned squared full32 result and register timing");gw_destroy(m);
    }
    uint8_t sequence[]={0x70,0x7f,0xc1,0xfc,0xff,0xfe,0x60,0xfe};
    gw_machine *whole=guest(sequence,sizeof(sequence)),*split=guest(sequence,sizeof(sequence));
    gw_diagnostic_record untouched=snapshot(split);uint64_t end=whole->tick+48u*GW_CPU_DIVIDER;
    (void)run(whole,end);gw_diagnostic_record after=snapshot(split);
    CHECK(!memcmp(&untouched,&after,sizeof(after)),"MULS instance isolation");step(split,"split MULS setup");step(split,"split MULS");same(whole,split);
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"MULS complete split-run state");
#endif
    CHECK(gw_console_reset(split)==GW_OK,"MULS reset");step(split,"MULS setup after reset");step(split,"MULS after reset");
    CHECK(split->cpu.d[0]==0xffffff02&&split->cpu.sr==0x2708,"MULS no hidden reset state");gw_destroy(whole);gw_destroy(split);
    uint8_t later[]={0x4c,0x3c,0x08,0,0,0,0,2};gw_machine *m=guest(later,sizeof(later));
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION&&m->cpu.pc==514,"68020 long multiply remains unsupported before extensions");gw_destroy(m);
    for(unsigned pre=0;pre<2;pre++) {
        uint8_t fault[2];word(fault,pre?0xc1e0:0xc1d8);m=guest(fault,2);
        m->cpu.a[0]=pre?0x603:0x601;m->cpu.d[0]=0x1234ffff;m->cpu.sr=0x271f;
        uint64_t tick=m->tick,instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"MULS odd pre/post source rejects");
        CHECK(m->cpu.a[0]==(pre?0x601u:0x603u)&&m->cpu.d[0]==0x1234ffff&&m->cpu.sr==0x271f,"MULS operand fault retains EA update but preserves result and flags");
        CHECK(m->cpu.fault_address==0x601&&m->cpu.pc==514&&m->tick-tick==4u*GW_CPU_DIVIDER&&m->instructions==instructions,"MULS fault charges fetched opcode only and never retires");gw_destroy(m);
    }
}
static void multiply_divide_modes(int divide)
{
    unsigned eas[]={1,0x10,0x18,0x20,0x28,0x30,0x38,0x39,0x3a,0x3b,0x3c};
    unsigned ea_clocks[]={0,4,4,6,8,10,8,12,8,10,4};
    for(unsigned i=0;i<11;i++) {
        uint8_t code[40]={0};unsigned ea=eas[i],extbytes=0,ext=0;
        uint32_t base=ea==0x20?0x602:ea==0x30?0x5fd:0x600,address=0x600;
        word(code,0x207c);put32(code+2,base);word(code+6,0x7007);
        word(code+8,0x223c);put32(code+10,ea==1?0x8001:3);
        word(code+14,0x003c);word(code+16,0x1f);word(code+18,(divide==2?0xc1c0:divide?0x80c0:0xc0c0)+ea);
        if(ea==0x28||ea==0x30||ea==0x38||ea==0x3a||ea==0x3b||ea==0x3c)extbytes=2;
        if(ea==0x30)ext=0x1000;
        if(ea==0x38)ext=0x600;
        if(ea==0x39){extbytes=4;ext=0x600;}
        if(ea==0x3a)ext=0x600-(512+20);
        if(ea==0x3b){ext=0x1001;address=512+24;}
        if(ea==0x3c)ext=0x8001;
        if(extbytes==2)word(code+20,ext);
        if(extbytes==4)put32(code+20,ext);
        gw_machine *m=guest(code,sizeof(code));word(m->rom+address,0x8001);
        for(unsigned n=0;n<4;n++)step(m,"MULU EA guest setup");
        uint64_t tick=m->tick;step(m,"MULU documented data EA");
        CHECK(m->cpu.d[0]==(divide==2?(uint32_t)(-32767*7):divide?0x00070000u:7u*0x8001u),"multiply/divide EA independently specified result");
        CHECK(m->tick-tick==((divide==2?44u:divide?140u:42u)+ea_clocks[i])*7u,"multiply/divide EA clock contract");
        if(divide==2)CHECK(m->cpu.sr==0x2718,"MULS every dataEA uses signed source and product flags");
        CHECK(m->cpu.pc==512+20+extbytes,"MULU EA extension consumption");
        CHECK(m->cpu.a[0]==(ea==0x18?0x602:ea==0x20?0x600:base),"MULU pre/post base effects");
        gw_destroy(m);
    }
    unsigned illegal[]={0xc0c8,0xc0fd,0xc0fe,0xc0ff};
    for(unsigned i=0;i<4;i++) {
        uint8_t code[4];word(code,divide==2?illegal[i]+0x100u:illegal[i]-(divide?0x4000:0));word(code+2,0xffff);
        gw_machine *m=guest(code,sizeof(code));
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"illegal MULU EA rejects before extensions");
        CHECK(m->cpu.pc==514&&m->cpu.d[0]==0,"illegal MULU unchanged destination");gw_destroy(m);
    }
    uint8_t code[]={0x20,0x7c,0,0,6,1,0xc0,0xd0};
    if(divide==2)code[7]=0xd0,code[6]=0xc1;
    else if(divide)code[6]=0x80;
    gw_machine *m=guest(code,sizeof(code));step(m,"odd-source setup");
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS&&m->cpu.fault_address==0x601,"MULU operand fault classification");
    CHECK(m->cpu.d[0]==0&&m->cpu.sr==0x2700,"MULU fault leaves result/CCR unchanged");gw_destroy(m);
}
static void divu(void)
{
    uint32_t dividends[]={0,1,9,10,11,0x7fff,0x8000,0xffff,0x10000,0x12345678,0xffffffff};
    unsigned divisors[]={1,2,10,0x7fff,0x8000,0xffff};
    for(unsigned d=0;d<11;d++)for(unsigned s=0;s<6;s++)for(unsigned reg=0;reg<8;reg++) {
        uint8_t code[14];word(code,0x203c+(reg<<9));put32(code+2,dividends[d]);
        word(code+6,0x003c);word(code+8,0x1f);word(code+10,0x80fc+(reg<<9));word(code+12,divisors[s]);
        gw_machine *m=guest(code,sizeof(code));step(m,"DIVU dividend setup");step(m,"DIVU CCR setup");
        step(m,"observed DIVU immediate executes");
        uint32_t q=dividends[d]/divisors[s],rem=dividends[d]%divisors[s];
        if(q>0xffff) {
            CHECK(m->cpu.d[reg]==dividends[d],"DIVU overflow retains original full32 dividend");
            CHECK((m->cpu.sr&0x13)==0x12,"DIVU overflow V set C clear X retained");
        } else {
            CHECK(m->cpu.d[reg]==((rem<<16)|q),"unsigned full32 dividend, remainder high16 quotient low16");
            CHECK(m->cpu.sr==(0x2710u|(q==0?4u:0u)|((q&0x8000)?8u:0u)),"DIVU flags derive from quotient, not packed remainder");
        }
        CHECK(m->cpu.pc==526,"DIVU immediate extension consumed");gw_destroy(m);
    }
    uint8_t zero[]={0x70,1,0x80,0xfc,0,0};
    gw_machine *m=guest(zero,sizeof(zero));step(m,"zero-divisor setup");
    uint16_t sr=m->cpu.sr;
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_STATE,"unmodeled divide-zero exception is explicit");
    CHECK(m->cpu.d[0]==1&&m->cpu.sr==sr,"divide-zero stops without invented quotient or flags");gw_destroy(m);
}
static void io_word_read(void)
{
    /* Meaningful low lanes and reset controls: Sega Genesis Software Manual
     * p74; even/odd read aliases independently reported by C.MacDonald v0.8
     * section3. Upper-byte duplication is an explicit coherent model policy. */
    uint8_t code[]={0x4a,0xb9,0,0xa1,0,8,
        0x13,0xfc,0,0x12,0,0xa1,0,9,0x13,0xfc,0,0x34,0,0xa1,0,0x0b,
        0x20,0x39,0,0xa1,0,8};
    gw_machine *m=guest(code,sizeof(code));
    step(m,"observed TST.L I/O controls executes");
    CHECK((m->cpu.sr&15)==4,"cold control words both read zero");
    step(m,"port0 byte control write");step(m,"port1 byte control write");
    uint64_t tick=m->tick;step(m,"long I/O read comprises ordered two word reads");
    CHECK((m->cpu.d[0]&0x00ff00ffu)==0x00120034u,"independent control-register low lanes, no port conflation");
    CHECK(m->cpu.d[0]==0x12123434u,"documented duplicated-upper-byte model policy");
    CHECK(m->tick-tick==20u*7u,"opcode two extensions and two I/O word bus cycles");gw_destroy(m);
    /* Preserve byte-even and odd-word rejection; the observed correction is
     * aligned word reads, not a speculative full I/O bus implementation. */
    uint8_t invalid[]={0x30,0x39,0,0xa1,0,9};m=guest(invalid,sizeof(invalid));
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS&&m->cpu.fault_address==0xa10009,"odd I/O word fails closed");gw_destroy(m);
}
static void cartridge_disable(void)
{
    uint8_t code[]={0x13,0xfc,0,0,0,0xa1,0x30,0xf1};
    gw_machine *m=guest(code,sizeof(code));
    uint8_t before[8];
    memcpy(before,m->rom+512,sizeof(before));
    gw_cpu cpu_before=m->cpu;
    uint64_t tick=m->tick;
    step(m,"zero byte cartridge-disable guest operation");
    CHECK(m->cpu.pc==520 && m->cpu.sr==0x2704,"cartridge-disable move advances PC and sets byte zero flag");
    CHECK(m->tick-tick==20u*GW_CPU_DIVIDER,"MOVE.B immediate absolute timing includes four-clock control byte transfer");
    CHECK(!memcmp(before,m->rom+512,sizeof(before)),"cartridge-disable operation preserves ROM bytes");
    CHECK(!memcmp(cpu_before.d,m->cpu.d,sizeof(cpu_before.d))&&!memcmp(cpu_before.a,m->cpu.a,sizeof(cpu_before.a)),"successful cartridge MOVE preserves every data and address register");
    gw_destroy(m);
    const struct {unsigned op,size,value;uint32_t address;} bad[]={
        {0x13fc,1,0,0xa130f0},{0x13fc,1,0,0xa130f2},
        {0x13fc,1,1,0xa130f1},{0x13fc,1,2,0xa130f1},{0x13fc,1,255,0xa130f1},
        {0x33fc,2,0,0xa130f1},{0x23fc,4,0,0xa130f1}
    };
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        uint8_t negative[10]={0};word(negative,bad[i].op);
        unsigned address_offset=bad[i].size==4?6:4;
        word(negative+2,bad[i].value);put32(negative+address_offset,bad[i].address);
        m=guest(negative,sizeof(negative));m->cpu.sr=0x271f;m->ram[16]=0xa5;
        tick=m->tick;uint64_t instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"unsupported cartridge guest operation fails closed");
        CHECK(m->cpu.fault_address==bad[i].address,"cartridge failure records exact address");
        CHECK(m->cpu.pc==512+address_offset+4&&m->cpu.sr==0x271f&&m->instructions==instructions,"failed MOVE fetches extensions but preserves flags and retirement count");
        CHECK(m->tick-tick==(bad[i].size==4?20u:16u)*GW_CPU_DIVIDER,"failed cartridge transfer charges fetched words only");
        CHECK(m->ram[16]==0xa5&&!memcmp(m->rom+512,negative,sizeof(negative)),"cartridge rejection preserves RAM and ROM");
        gw_destroy(m);
    }
    uint8_t read[]={0x10,0x39,0,0xa1,0x30,0xf1};m=guest(read,sizeof(read));
    tick=m->tick;
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"cartridge register read is unsupported");
    CHECK(m->cpu.pc==518&&m->tick-tick==12u*GW_CPU_DIVIDER&&m->cpu.d[0]==0&&m->cpu.sr==0x2700,"cartridge read fault preserves destination and flags after address fetch");gw_destroy(m);
    /* Existing bus masks to24bits; successful alias is the same operation. */
    uint8_t sequence[]={0x13,0xfc,0,0,1,0xa1,0x30,0xf1,0x13,0xfc,0,0,0,0xa1,0x30,0xf1,0x60,0xfe};
    gw_machine *whole=guest(sequence,sizeof(sequence)),*split=guest(sequence,sizeof(sequence));
    gw_diagnostic_record isolated=snapshot(split);
    uint64_t end=whole->tick+40u*GW_CPU_DIVIDER;
    (void)run(whole,end);
    gw_diagnostic_record unchanged=snapshot(split);
    CHECK(!memcmp(&isolated,&unchanged,sizeof(isolated)),"cartridge operations cannot mutate another instance");
    step(split,"24-bit aliased cartridge byte");step(split,"ordinary cartridge byte");same(whole,split);
    CHECK(split->tick==end&&split->cpu.pc==528,"two cartridge operations preserve exact modeled time and PC");
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"cartridge complete split-run state");
#endif
    CHECK(gw_console_reset(split)==GW_OK,"cartridge reset");step(split,"cartridge operation after reset");
    CHECK(split->cpu.pc==520&&split->cpu.sr==0x2704,"cartridge reset adds no hidden state");
    gw_destroy(whole);gw_destroy(split);
}
static void ext_gpio(void)
{
    uint8_t code[]={0x30,0x39,0,0xa1,0,0x0c,0x12,0x39,0,0xa1,0,7,
        0x13,0xfc,0,0xff,0,0xa1,0,0x0d,0x13,0xfc,0,0xa5,0,0xa1,0,7,
        0x14,0x39,0,0xa1,0,7};
    gw_machine *m=guest(code,sizeof(code));step(m,"observed EXT control word executes");
    CHECK(m->cpu.d[0]==0,"EXT cold/reset control zero");step(m,"EXT empty pins read");
    CHECK(m->cpu.d[1]==0x7f,"EXT empty input pins pulled high");
    step(m,"EXT control latch write");step(m,"EXT data latch write");step(m,"EXT output read");
    CHECK(m->cpu.d[2]==0xa5,"EXT output pins come from separate data latch");
    CHECK(m->io.ctrl[0]==0&&m->io.ctrl[1]==0&&m->io.data[0]==0&&m->io.data[1]==0,"EXT never aliases either public pad");
    CHECK(gw_console_reset(m)==GW_OK,"EXT console reset");step(m,"EXT control read after reset");step(m,"EXT data read after reset");
    CHECK(m->cpu.d[0]==0&&m->cpu.d[1]==0x7f,"EXT deterministic reset policy");
    gw_event e={0};e.struct_size=sizeof(e);e.version=GW_API_VERSION;e.tick=m->tick;e.type=GW_EVENT_PAD_STATE;e.port=2;e.mask=1;
    gw_diagnostic_record before=snapshot(m);
    CHECK(gw_schedule_event(m,&e)==GW_ERROR_ARGUMENT,"EXT does not authorize a public third pad");
    gw_diagnostic_record after=snapshot(m);CHECK(!memcmp(&before,&after,sizeof(before)),"invalid third-pad event leaves machine unchanged");gw_destroy(m);
#ifdef GW_TEST_HOOKS
    uint64_t digests[17];
    for(unsigned i=0;i<17;i++) {
        uint8_t seed[]={0x13,0xfc,0,0,0,0xa1,0,7,0x13,0xfc,0,0,0,0xa1,0,0x0d,0x02,0x3c,0,0};
        if(i<8)seed[3]=(uint8_t)(1u<<i);else if(i<16)seed[11]=(uint8_t)(1u<<(i-8));
        m=guest(seed,sizeof(seed));step(m,"EXT digest data");step(m,"EXT digest control");step(m,"EXT normalize CCR");
        digests[i]=gw_test_state_digest(m);gw_destroy(m);
    }
    for(unsigned i=0;i<17;i++)for(unsigned j=0;j<i;j++)CHECK(digests[i]!=digests[j],"EXT latch bits enter future-state digest");
#endif
}
static void pea(void)
{
    /* 0x4840..0x4847 are existing SWAP instructions, not illegal PEA EAs. */
    for (unsigned reg=0;reg<8;reg++) {
        uint8_t code[2];word(code,0x4840u+reg);
        gw_machine *m=guest(code,sizeof(code));
        m->cpu.d[reg]=0x80001234u;m->cpu.sr=0x271fu;
        uint32_t stack=m->cpu.a[7];
        step(m,"PEA dispatch preserves existing SWAP for every data register");
        CHECK(m->cpu.d[reg]==0x12348000u&&m->cpu.sr==0x2710u,
              "SWAP retains word exchange and condition-code semantics");
        CHECK(m->cpu.a[7]==stack,"SWAP does not push a PEA stack operand");
        gw_destroy(m);
    }
    /* NXP M68000PRM, PEA (4-159): absolute-long EA is pushed as a longword;
     * flags are not affected. This is the original public CPU contract. */
    const struct { unsigned op, ext, ext_words; uint32_t ea, a0, d0, d1; unsigned cycles; } cases[]={
        /* MC68000UM section8 (16-bit bus), table8-10, page8-8.
         * Section7/table7-11 instead describes the 8-bit bus. */
        {0x4850,0,0,0x00e00020,0x00e00020,0,0,12}, /* (A0) */
        {0x4868,0xfff0,1,0x00e00010,0x00e00020,0,0,16}, /* d16(A0) */
        {0x4870,0x0000,1,0x00e00020,0x00e00010,0x10,0,20}, /* d8(A0,D0.w) */
        {0x4878,0x8000,1,0xffff8000,0,0,0,16}, /* abs.w, sign extended */
        {0x4879,0x00e00010,2,0x00e00010,0,0,0,20}, /* abs.l */
        {0x487a,0x0020,1,0x00000222,0,0,0,16}, /* d16(PC), base is extension address */
        {0x487b,0x1002,1,0x00000207,0,0,3,20}, /* d8(PC,D1.w) */
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        uint8_t code[8]={0};word(code,cases[i].op);
        if(cases[i].ext_words==1)word(code+2,cases[i].ext);
        if(cases[i].ext_words==2)put32(code+2,cases[i].ext);
        gw_machine *m=guest(code,sizeof(code));
        m->cpu.a[0]=cases[i].a0;m->cpu.d[0]=cases[i].d0;m->cpu.d[1]=cases[i].d1;
        m->cpu.a[7]=0xffff00u;m->cpu.sr=0x271fu;
        uint64_t tick=m->tick;
        step(m,"PEA documented control EA executes");
        CHECK(m->cpu.a[7]==0xfffefcu,"PEA decrements active stack by four");
        CHECK(m->cpu.sr==0x271fu,"PEA preserves condition codes");
        CHECK(m->tick-tick==(uint64_t)cases[i].cycles*7u,"PEA current-model cycles by EA");
        uint8_t pushed[4]={0};
        CHECK(gw_peek_memory(m,0xfffefcu,pushed,sizeof(pushed))==GW_OK,"PEA stack bytes readable");
        CHECK(pushed[0]==(uint8_t)(cases[i].ea>>24)&&pushed[1]==(uint8_t)(cases[i].ea>>16)&&
              pushed[2]==(uint8_t)(cases[i].ea>>8)&&pushed[3]==(uint8_t)cases[i].ea,
              "PEA pushes effective address big-endian without reading its operand");
        CHECK(m->cpu.pc==512u+2u+2u*cases[i].ext_words,"PEA consumes the expected extension words");
        gw_destroy(m);
    }
    /* The stack register remains 32-bit while bus addresses wrap to 24 bits. */
    uint8_t code[]={0x48,0x79,0x00,0xe0,0x00,0x10};
    gw_machine *m=guest(code,sizeof(code));m->cpu.a[7]=0x01e00004u;
    step(m,"PEA high stack register executes");
    CHECK(m->cpu.a[7]==0x01e00000u,"PEA preserves high A7 bits while decrementing");
    uint8_t wrapped[4]={0};CHECK(gw_peek_memory(m,0xe00000,wrapped,sizeof(wrapped))==GW_OK,"PEA stack bus wraps");
    CHECK(wrapped[0]==0&&wrapped[1]==0xe0&&wrapped[2]==0&&wrapped[3]==0x10,"PEA stores full EA through 24-bit bus");
    gw_destroy(m);

    /* Address-register, postincrement, predecrement and immediate EAs are
     * unsupported here; data-register encodings belong to SWAP above. */
    const unsigned illegal[]={0x4848,0x4858,0x4860,0x487c};
    for(unsigned i=0;i<sizeof(illegal)/sizeof(illegal[0]);i++) {
        uint8_t bad[4];word(bad,illegal[i]);word(bad+2,0x1234);m=guest(bad,sizeof(bad));
        uint32_t old_sp=m->cpu.a[7],old_sr=m->cpu.sr;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"PEA rejects non-control EA");
        CHECK(m->cpu.a[7]==old_sp&&m->cpu.sr==old_sr&&m->cpu.pc==514,"illegal PEA does not mutate stack, flags or extension PC");
        gw_destroy(m);
    }
    /* Current bus model leaves the decremented A7 visible on a failed push. */
    m=guest(code,sizeof(code));m->cpu.a[7]=0x1004;
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"PEA stack write fault is explicit");
    CHECK(m->cpu.fault_address==0x1000&&m->cpu.a[7]==0x1000,"PEA stack fault records current-model partial state");
    gw_destroy(m);
}
static void pea_mutant(const char *kind)
{
    uint8_t code[]={0x48,0x79,0x00,0xe0,0x00,0x10};
    gw_machine *m=guest(code,sizeof(code));m->cpu.a[7]=0xffff00u;
    step(m,"PEA mutant setup executes");
    if(!strcmp(kind,"wrong-address")) m->ram[0xfefc+3]^=4u;
    else { uint8_t *p=m->ram+0xfefc;uint8_t t=p[0];p[0]=p[3];p[3]=t;t=p[1];p[1]=p[2];p[2]=t; }
    uint8_t pushed[4]={0};CHECK(gw_peek_memory(m,0xfffefcu,pushed,sizeof(pushed))==GW_OK,"mutant stack readable");
    CHECK(pushed[0]==0&&pushed[1]==0xe0&&pushed[2]==0&&pushed[3]==0x10,
          "PEA expected-memory assertion rejects wrong-address/stack-order mutant");
    gw_destroy(m);
}
static void scc_dn(void)
{
    /* Original oracle: M68000PRM pp4-172–4-173 and table3-19.
     * Bit k of each mask is the result for NZVC=k. X is independent.
     * MC68000UM section8 table8-6: Dn false4 / true6 clocks. */
    static const uint16_t truth[16]={
        0xffff,0x0000,0x0505,0xfafa,0x5555,0xaaaa,0x0f0f,0xf0f0,
        0x3333,0xcccc,0x00ff,0xff00,0xcc33,0x33cc,0x0c03,0xf3fc
    };
    /* Start with the exact reported SNE D0 before the complete truth table. */
    uint8_t sne[]={0x56,0xc0};gw_machine *m=guest(sne,sizeof(sne));
    m->cpu.d[0]=0x12345678;step(m,"reported SNE D0 retires");
    CHECK(m->cpu.d[0]==0x123456ff,"reported SNE changes only low byte");gw_destroy(m);
    for(unsigned cc=0;cc<16;cc++)for(unsigned flags=0;flags<32;flags++)for(unsigned reg=0;reg<8;reg++) {
        uint8_t code[2];word(code,0x50c0u+(cc<<8)+reg);m=guest(code,sizeof(code));
        for(unsigned r=0;r<8;r++)m->cpu.d[r]=0x89abcd00u+r*17u;
        m->cpu.sr=(uint16_t)(0x2700u|flags);
        gw_cpu before=m->cpu;uint64_t tick=m->tick,instructions=m->instructions;
        unsigned yes=(truth[cc]>>(flags&15u))&1u;
        step(m,"documented Scc Dn condition retires");
        CHECK(m->cpu.d[reg]==((before.d[reg]&0xffffff00u)|(yes?0xffu:0u)),"Scc independent truth table and byte-only destination");
        CHECK(m->cpu.sr==before.sr,"Scc preserves every CCR bit including X");
        CHECK(m->cpu.pc==514&&m->instructions==instructions+1,"Scc two-byte PC and exactly one retirement");
        CHECK(m->tick-tick==(yes?6u:4u)*GW_CPU_DIVIDER,"Scc true/false documented register timing");
        CHECK(!memcmp(m->cpu.a,before.a,sizeof(before.a)),"Scc preserves address registers");
        for(unsigned r=0;r<8;r++)if(r!=reg)CHECK(m->cpu.d[r]==before.d[r],"Scc preserves other data registers");
        gw_destroy(m);
    }
    /* Memory Scc forms are not added by this bounded Dn implementation. */
    const unsigned rejected[]={0x56d0,0x56d8,0x56e0,0x56e8,0x56f0,0x56f8,0x56f9,0x56fa,0x56fb,0x56fc,0x56fd,0x56fe,0x56ff};
    for(unsigned i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) {
        uint8_t code[6];word(code,rejected[i]);put32(code+2,0x00ff0010);m=guest(code,sizeof(code));
        gw_cpu before=m->cpu;uint64_t tick=m->tick,instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"unimplemented memory/illegal Scc remains explicit");
        CHECK(m->cpu.pc==514&&m->cpu.sr==before.sr&&!memcmp(m->cpu.a,before.a,sizeof(before.a)),"rejected Scc has no extension or EA side effects");
        CHECK(!memcmp(m->cpu.d,before.d,sizeof(before.d))&&m->instructions==instructions&&m->tick-tick==4u*GW_CPU_DIVIDER&&m->cpu.fault_address==before.fault_address,"rejected Scc preserves data registers and fault address, charges opcode only, does not retire");
        gw_destroy(m);
    }
    /* Mode001 in this opcode group is DBcc, not Scc An. */
    uint8_t dbf[]={0x51,0xc8,0,2};m=guest(dbf,sizeof(dbf));uint64_t tick=m->tick;
    step(m,"Scc dispatch preserves adjacent DBF encoding");
    CHECK(m->cpu.d[0]==0xffff&&m->cpu.pc==516&&m->tick-tick==14u*GW_CPU_DIVIDER,"DBF exhausted low-word counter keeps existing semantics");gw_destroy(m);
    /* A run target inside an instruction retires that instruction exactly once;
     * splitting at its actual end must match the uninterrupted execution. */
    uint8_t sequence[]={0x56,0xc0,0x57,0xc1,0x50,0xc7,0x51,0xc6,0x60,0xfe};
    gw_machine *whole=guest(sequence,sizeof(sequence)),*split=guest(sequence,sizeof(sequence));
    whole->cpu.sr=split->cpu.sr=0x2714;
    uint64_t end=whole->tick+20u*GW_CPU_DIVIDER;
    (void)run(whole,end);
    for(unsigned i=0;i<4;i++)step(split,"split Scc instruction");
    CHECK(split->tick==end,"split Scc exact final target");same(whole,split);
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"Scc complete state split-run equality");
#endif
    CHECK(gw_console_reset(split)==GW_OK,"Scc reset");
    CHECK(split->cpu.d[0]==0&&split->cpu.sr==0x2700,"Scc adds no hidden persistent state");
    gw_destroy(whole);gw_destroy(split);
}
static void addx_dn(void)
{
    /* Original independently calculated edge table, scaled by operand width.
     * Kinds0/1/2/3/4 denote zero/one/maxpositive/signbit/mask. */
    static const unsigned cases[][6]={
        {0,0,0,1,0,0x04},{0,0,0,0,0,0x00},
        {4,0,1,1,0,0x15},{4,0,1,0,0,0x11},
        {2,0,1,1,3,0x0a},{3,3,0,1,0,0x17},
        {4,4,1,1,4,0x19},{3,0,0,1,3,0x08},
        {0,1,0,1,1,0x00},{1,4,0,1,0,0x15},
        {2,3,1,1,0,0x15}
    };
    for(unsigned sizecode=0;sizecode<3;sizecode++) {
        unsigned size=1u<<sizecode;
        uint32_t mask=size==1?0xffu:size==2?0xffffu:UINT32_MAX;
        uint32_t sign=size==1?0x80u:size==2?0x8000u:0x80000000u;
        uint32_t values[]={0,1,sign-1u,sign,mask};
        for(unsigned src=0;src<8;src++)for(unsigned dst=0;dst<8;dst++)if(src!=dst)
        for(unsigned row=0;row<sizeof(cases)/sizeof(cases[0]);row++)for(unsigned stale=0;stale<2;stale++) {
            uint8_t code[2];word(code,0xd100u+(dst<<9)+(sizecode<<6)+src);
            gw_machine *m=guest(code,sizeof(code));
            for(unsigned r=0;r<8;r++)m->cpu.d[r]=0x11223300u+r;
            m->cpu.d[src]=(0x89abcdefu&~mask)|values[cases[row][1]];
            m->cpu.d[dst]=(0x76543210u&~mask)|values[cases[row][0]];
            m->cpu.sr=(uint16_t)(0x2700u|(cases[row][2]<<4)|(cases[row][3]<<2)|(stale?0xbu:0));
            gw_cpu before=m->cpu;uint64_t tick=m->tick,instructions=m->instructions;
            step(m,"ADDX documented register form retires");
            CHECK(m->cpu.d[dst]==((before.d[dst]&~mask)|values[cases[row][4]]),"ADDX specified result and partial-register preservation");
            CHECK(m->cpu.sr==(0x2700u|cases[row][5]),"ADDX independent XNZVC table and cumulative zero");
            CHECK(m->cpu.pc==514&&m->instructions==instructions+1,"ADDX exact opcode length and retirement");
            CHECK(m->tick-tick==(size==4?8u:4u)*GW_CPU_DIVIDER,"original68000 ADDX BW4 L8 clocks");
            CHECK(!memcmp(m->cpu.a,before.a,sizeof(before.a)),"ADDX Dn leaves every address register unchanged");
            for(unsigned r=0;r<8;r++)if(r!=dst)CHECK(m->cpu.d[r]==before.d[r],"ADDX preserves source and unrelated registers");
            gw_destroy(m);
        }
        for(unsigned reg=0;reg<8;reg++)for(unsigned x=0;x<2;x++)for(unsigned z=0;z<2;z++) {
            uint8_t code[2];word(code,0xd100u+(reg<<9)+(sizecode<<6)+reg);
            gw_machine *m=guest(code,sizeof(code));m->cpu.d[reg]=(0x89abcdefu&~mask)|sign;
            m->cpu.sr=(uint16_t)(0x2700u|(x<<4)|(z<<2));
            uint32_t upper=m->cpu.d[reg]&~mask;
            step(m,"ADDX alias reads both old operands before writing");
            CHECK(m->cpu.d[reg]==(upper|x)&&m->cpu.sr==(0x2713u|(!x&&z?4u:0)),"ADDX self-alias sign-plus-sign with carry and cumulative Z");gw_destroy(m);
        }
        /* Bit3 is memory predecrement, not another register encoding. */
        uint8_t memory[2];word(memory,0xd108u+(sizecode<<6));
        gw_machine *m=guest(memory,sizeof(memory));gw_cpu before=m->cpu;uint64_t tick=m->tick;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"ADDX memory form remains explicitly unsupported");
        CHECK(m->cpu.pc==514&&m->tick-tick==4u*GW_CPU_DIVIDER&&m->instructions==0&&m->cpu.sr==before.sr&&!memcmp(m->cpu.a,before.a,sizeof(before.a))&&!memcmp(m->cpu.d,before.d,sizeof(before.d)),"unimplemented ADDX memory has no predecrement or operand side effects");gw_destroy(m);
    }
    /* Size11 is ADDA.L, so it must fall through to existing arithmetic. */
    uint8_t adda[]={0xd7,0xc3};gw_machine *m=guest(adda,sizeof(adda));m->cpu.d[3]=5;m->cpu.a[3]=0x100;m->cpu.sr=0x271f;
    step(m,"ADDX decode preserves adjacent ADDA.L");CHECK(m->cpu.a[3]==0x105&&m->cpu.d[3]==5&&m->cpu.sr==0x271f,"ADDA full address result and unchanged flags");gw_destroy(m);
    uint8_t add[]={0xd6,0x03};m=guest(add,sizeof(add));m->cpu.d[3]=0xff;m->cpu.sr=0x2714;
    step(m,"ADDX decode preserves ordinary ADD");CHECK(m->cpu.d[3]==0xfe&&m->cpu.sr==0x2719,"ordinary ADD ignores old X and has fresh flags");gw_destroy(m);
    uint8_t sequence[]={0xd3,0x00,0xd7,0x02,0x60,0xfe};
    gw_machine *whole=guest(sequence,sizeof(sequence)),*split=guest(sequence,sizeof(sequence));
    whole->cpu.d[0]=split->cpu.d[0]=0xff;whole->cpu.sr=split->cpu.sr=0x2714;
    uint64_t end=whole->tick+8u*GW_CPU_DIVIDER;(void)run(whole,end);
    step(split,"ADDX first chained zero with carry");CHECK(split->cpu.d[1]==0&&split->cpu.sr==0x2715,"ADDX chain retains Z and propagates X");
    step(split,"ADDX second chained addition");CHECK(split->cpu.d[3]==1&&split->cpu.sr==0x2700,"ADDX chain consumes X and clears cumulative Z");same(whole,split);
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"ADDX full-state split-run equality");
#endif
    CHECK(gw_console_reset(split)==GW_OK&&split->cpu.d[1]==0&&split->cpu.sr==0x2700,"ADDX reset introduces no hidden state");gw_destroy(whole);gw_destroy(split);
}
static void bank_68000(void)
{
    /* Sega Technical Overview p.77; MacDonald v0.8 sections2.1/2.3:
     * nine low bits, LSB first. Partial visibility/reset/timing below assert
     * the existing Genewhip model, not unknown physical partial-write behavior. */
    uint8_t code[64]={0x33,0xfc,1,0,0,0xa1,0x11,0, /* request BUSREQ */
                      0x20,0x7c,0,0xa0,0x60,0};    /* MOVEA.L #A06000,A0 */
    for(unsigned i=0;i<9;i++){word(code+14+4*i,0x10bc);word(code+16+4*i,0);}
    word(code+50,0x60fe);
    for(unsigned bank=0;bank<512;bank++) {
        for(unsigned i=0;i<9;i++)word(code+16+4*i,0xfeu|((bank>>i)&1u));
        gw_machine *m=guest(code,52);
        step(m,"bank bus request");step(m,"bank address setup");
        CHECK(m->z80.busreq&&m->z80.reset_asserted,"bank ownership granted while reset held");
        for(unsigned i=0;i<9;i++) {
            gw_cpu before=m->cpu;uint64_t tick=m->tick,n=m->instructions;
            step(m,"granted 68000 bank byte retires");
            unsigned partial=(bank&((1u<<(i+1))-1u))<<(8-i);
            CHECK(m->z80.bank==partial&&m->z80.bank_shift_count==(i==8?0:i+1),"bank nine-bit serial order, partial state and upper data masking");
            CHECK(m->tick-tick==12u*GW_CPU_DIVIDER&&m->cpu.pc==530u+4u*i&&m->instructions==n+1,"bank MOVE exact existing bus timing, PC and retirement");
            CHECK(m->cpu.sr==0x2708,"bank MOVE byte flags derive from full byte FE/FF, not just serial bit");
            CHECK(!memcmp(before.a,m->cpu.a,sizeof(before.a))&&!memcmp(before.d,m->cpu.d,sizeof(before.d)),"bank MOVE preserves all registers");
        }
        CHECK(m->z80.bank==bank&&m->z80.bank_shift_count==0,"all nine-bit bank choices independently specified");
        gw_destroy(m);
    }
    /* Same existing state is shared with the Z80-side writer, including the
     * model's count-zero clear and subsequent right shifts. */
    uint8_t one[]={0x13,0xfc,0,1,0,0xa0,0x60,0};
    gw_machine *m=guest(one,sizeof(one));
    CHECK(gw_bus_write(m,0xa11100,2,0x100),"request bank bus through existing control");
    gw_z80_sync(m,m->tick+GW_Z80_DIVIDER);
    CHECK(gw_z80_mem_write(m,0x6000,1,0),"first serial bit via existing Z80 writer");
    step(m,"second serial bit via original 68000 guest");
    CHECK(m->z80.bank==0x180&&m->z80.bank_shift_count==2,"both masters update one shared bank/count");
    CHECK(gw_bus_write(m,0xa11200,2,0),"assert existing reset");
    CHECK(m->z80.bank==0x180&&m->z80.bank_shift_count==2,"reset assertion preserves existing partial bank model");
    CHECK(gw_bus_write(m,0xa11200,2,0x100),"release existing reset");
    gw_z80_sync(m,m->z80.reset_tick);
    CHECK(!m->z80.reset_asserted&&m->z80.bank==0&&m->z80.bank_shift_count==0,"existing reset release edge clears serial state");
    CHECK(gw_z80_mem_write(m,0x60ff,1,0),"existing Z80 mirror still works");
    CHECK(gw_console_reset(m)==GW_OK&&m->z80.bank==0&&m->z80.bank_shift_count==0,"console reset clears bank and partial count");gw_destroy(m);

    /* Ungranted byte writes retire and consume the same transfer but cannot
     * mutate the latch, even while reset is held. No new reset gate. */
    for(unsigned held=0;held<2;held++) {
        m=guest(one,sizeof(one));
        if(!held){CHECK(gw_bus_write(m,0xa11200,2,0x100),"release reset for ungranted case");gw_z80_sync(m,m->z80.reset_tick);}
        uint64_t tick=m->tick;step(m,"ungranted bank write retires as ignored");
        CHECK(!m->z80.busreq&&m->z80.bank==0&&m->z80.bank_shift_count==0&&m->tick-tick==20u*GW_CPU_DIVIDER,"ungranted bank write cannot shift either state field");gw_destroy(m);
    }
    const struct {unsigned op,size;uint32_t address;} rejected[]={
        {0x13fc,1,0xa05fff},{0x13fc,1,0xa06001},{0x13fc,1,0xa060ff},
        {0x13fc,1,0xa06100},{0x33fc,2,0xa06000},{0x23fc,4,0xa06000},
        {0x1039,0,0xa06000},{0x3039,0,0xa06000},{0x2039,0,0xa06000}
    };
    for(unsigned i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) {
        uint8_t bad[10]={0};unsigned at=rejected[i].size==4?6:rejected[i].size?4:2;
        word(bad,rejected[i].op);word(bad+2,1);put32(bad+at,rejected[i].address);
        m=guest(bad,at+4);CHECK(gw_bus_write(m,0xa11100,2,0x100),"negative bank bus request");gw_z80_sync(m,m->tick+GW_Z80_DIVIDER);
        CHECK(gw_z80_mem_write(m,0x6000,1,0),"seed partial bank for failure discrimination");
        gw_cpu before=m->cpu;uint64_t n=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS&&m->cpu.fault_address==rejected[i].address,"unmodeled bank read, width or neighbor fails closed");
        CHECK(m->z80.bank==0x100&&m->z80.bank_shift_count==1&&m->instructions==n&&m->cpu.sr==before.sr,"rejected bank access preserves partial state, flags and retirement");
        CHECK(!memcmp(before.a,m->cpu.a,sizeof(before.a))&&!memcmp(before.d,m->cpu.d,sizeof(before.d)),"rejected bank access preserves operand registers");gw_destroy(m);
    }
    /* Drive bank one through guest bytes, then observe the existing Z80 ROM
     * mapping at both loaded neighbors and the first excluded byte. */
    for(unsigned i=0;i<9;i++)word(code+16+4*i,i==0?1:0);
    uint8_t rom[0x8002];rom_init(rom,sizeof(rom));memcpy(rom+512,code,52);
    rom[0x8000]=0x5a;rom[0x8001]=0xa5;m=machine();CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"load original bank-mapping guest");
    for(unsigned i=0;i<11;i++)step(m,"bank mapping guest setup");
    uint8_t value;uint64_t ztick=m->z80.next_cycle_tick;
    CHECK(gw_z80_mem_read(m,0x8000,&value,0,0)&&value==0x5a,"68000-selected bank maps actual ROM base");
    CHECK(m->z80.next_cycle_tick==ztick+GW_Z80_DIVIDER,"existing banked read wait remains one model T-state");
    CHECK(gw_z80_mem_read(m,0x8001,&value,0,0)&&value==0xa5,"bank mapping actual ROM last byte");
    CHECK(!gw_z80_mem_read(m,0x8002,&value,0,0)&&m->cpu.fault_address==0x40008002,"bank mapping rejects first byte outside loaded ROM");gw_destroy(m);

    /* The tenth write starts the next nine-write model sequence. */
    m=guest(one,sizeof(one));CHECK(gw_bus_write(m,0xa11100,2,0x100),"wrap bus request");gw_z80_sync(m,m->tick+GW_Z80_DIVIDER);
    for(unsigned i=0;i<9;i++)CHECK(gw_z80_mem_write(m,0x6000,1,0),"seed all nine bank bits");
    step(m,"tenth bank bit via 68000 guest");CHECK(m->z80.bank==0x100&&m->z80.bank_shift_count==1,"new serial group retains established count-zero clear policy");gw_destroy(m);

    /* One whole execution and instruction-sized partitions, including a high
     * 32-bit address-register alias masked at the existing 24-bit bus. */
    code[10]=1; /* MOVEA #01A06000,A0 */
    gw_machine *whole=guest(code,52),*split=guest(code,52);
    uint64_t untouched=gw_z80_digest(&split->z80,0),end=whole->tick+(20u+12u+9u*12u)*GW_CPU_DIVIDER;
    (void)run(whole,end);
    CHECK(gw_z80_digest(&split->z80,0)==untouched,"bank updates cannot mutate another machine");
    for(unsigned i=0;i<11;i++)step(split,"split bank guest");
    CHECK(whole->tick==end&&split->tick==end&&split->cpu.a[0]==0x01a06000&&split->z80.bank==1,"24-bit bus alias preserves full address register and bank selection");same(whole,split);
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"bank complete machine split-run digest");
#endif
    gw_destroy(whole);gw_destroy(split);
}
static void link_unlk(void)
{
    /* Independent original oracle: M68000PRM4-111/4-194, word signed
     * displacement, long frame save, unchanged CCR; MC68000UM table8-12. */
    const unsigned disps[]={0,1,0x7fff,0x8000,0xffef,0xfff0,0xffff};
    for(unsigned reg=0;reg<7;reg++)for(unsigned n=0;n<sizeof(disps)/sizeof(disps[0]);n++) {
        uint8_t code[6];word(code,0x4e50u+reg);word(code+2,disps[n]);word(code+4,0x4e58u+reg);
        gw_machine *m=guest(code,sizeof(code));
        for(unsigned i=0;i<8;i++){m->cpu.a[i]=0x12345678u+i;m->cpu.d[i]=0x87654321u+i;}
        m->cpu.a[7]=0x01ff9000u;m->cpu.sr=0x271fu;
        gw_cpu before=m->cpu;uint64_t tick=m->tick;
        uint32_t displacement=disps[n]<0x8000u?disps[n]:UINT32_C(0xffff0000)|disps[n];
        step(m,"LINK.W original frame setup");
        CHECK(m->cpu.a[reg]==0x01ff8ffcu&&m->cpu.a[7]==0x01ff8ffcu+displacement,"LINK full32 frame pointer and signed displacement");
        CHECK(m->cpu.pc==516&&m->cpu.sr==before.sr&&m->tick-tick==16u*GW_CPU_DIVIDER,"LINK word PC unchanged flags sixteen clocks");
        uint8_t saved[4];CHECK(gw_peek_memory(m,0xff8ffc,saved,4)==GW_OK,"LINK saved frame readable through24bit bus");
        CHECK(saved[0]==0x12&&saved[1]==0x34&&saved[2]==0x56&&saved[3]==0x78u+reg,"LINK saves old full32 An in big endian order");
        for(unsigned i=0;i<8;i++)CHECK(m->cpu.d[i]==before.d[i]&&(i==reg||i==7||m->cpu.a[i]==before.a[i]),"LINK preserves unrelated general registers");
        tick=m->tick;step(m,"UNLK discards local allocation and restores frame");
        CHECK(!memcmp(m->cpu.a,before.a,sizeof(before.a))&&!memcmp(m->cpu.d,before.d,sizeof(before.d)),"UNLK restores original frame and SP including high bits");
        CHECK(m->cpu.pc==518&&m->cpu.sr==before.sr&&m->tick-tick==12u*GW_CPU_DIVIDER,"UNLK PC unchanged flags twelve clocks");
        gw_destroy(m);
    }
    /* An=A7 stays explicit unsupported until its physical alias ordering has
     * an independent oracle. LINK.L is a68020 encoding, not LINK.W. */
    const unsigned rejected[]={0x4e57,0x4e5f,0x4808,0x480e,0x4e74};
    for(unsigned i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) {
        uint8_t code[6];word(code,rejected[i]);put32(code+2,0x12345678);
        gw_machine *m=guest(code,sizeof(code));gw_cpu before=m->cpu;uint64_t instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"LINK unsupported alias/long/neighbor encoding rejects");
        CHECK(m->cpu.pc==514&&m->cpu.sr==before.sr&&!memcmp(m->cpu.a,before.a,sizeof(before.a))&&m->instructions==instructions,"rejected frame form does not consume extension or change registers");gw_destroy(m);
    }
    /* Fault state is the existing bus model, not an exception/rollback claim. */
    const uint32_t bad_sp[]={0x00ffff01,0x00400004};
    for(unsigned i=0;i<2;i++) {
        uint8_t code[]={0x4e,0x56,0xff,0xf0};gw_machine *m=guest(code,sizeof(code));
        m->cpu.a[6]=0x12345678;m->cpu.a[7]=bad_sp[i];m->cpu.sr=0x271f;
        uint64_t tick=m->tick,instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"LINK odd/unmapped stack write rejects");
        CHECK(m->cpu.a[7]==bad_sp[i]-4u&&m->cpu.a[6]==0x12345678&&m->cpu.pc==516&&m->cpu.sr==0x271f,"LINK failed push retains decremented SP but unchanged frame An and flags");
        CHECK(m->cpu.fault_address==bad_sp[i]-4u&&m->instructions==instructions&&m->tick-tick==8u*GW_CPU_DIVIDER,"LINK fault records exact address fetch time and no retirement");gw_destroy(m);
        uint8_t unlk[]={0x4e,0x5e};m=guest(unlk,sizeof(unlk));m->cpu.a[6]=bad_sp[i]-4u;m->cpu.a[7]=0xffff00;m->cpu.sr=0x271f;
        tick=m->tick;instructions=m->instructions;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"UNLK odd/unmapped frame read rejects");
        CHECK(m->cpu.a[7]==bad_sp[i]-4u&&m->cpu.a[6]==bad_sp[i]-4u&&m->cpu.pc==514&&m->cpu.sr==0x271f,"UNLK failed read exposes frame SP without restoring An");
        CHECK(m->cpu.fault_address==bad_sp[i]-4u&&m->instructions==instructions&&m->tick-tick==4u*GW_CPU_DIVIDER,"UNLK fault records address opcode time and no retirement");gw_destroy(m);
    }
    {
        uint8_t code[]={0x4e,0x56,0,0};gw_machine *m=guest(code,sizeof(code));
        m->cpu.a[6]=0x12345678;m->cpu.a[7]=0x01000002;uint64_t tick=m->tick;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"LINK second-word stack write fails at24bit wrap");
        CHECK(m->cpu.a[7]==0xfffffe&&m->cpu.a[6]==0x12345678&&m->cpu.fault_address==0&&m->tick-tick==12u*GW_CPU_DIVIDER,"LINK partial write preserves frame source and completed bus time");
        CHECK(m->ram[0xfffe]==0x12&&m->ram[0xffff]==0x34,"LINK completed high word remains after low-word write failure");gw_destroy(m);
        uint8_t unlk[]={0x4e,0x5e};m=guest(unlk,sizeof(unlk));m->cpu.a[6]=2046;m->cpu.a[7]=0xffff00;tick=m->tick;
        CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"UNLK second-word read past ROM fails");
        CHECK(m->cpu.a[7]==2046&&m->cpu.a[6]==2046&&m->cpu.fault_address==2048&&m->tick-tick==8u*GW_CPU_DIVIDER,"UNLK partial read exposes frame SP and completed read time");gw_destroy(m);
    }
    uint8_t code[]={0x4e,0x56,0xff,0xf0,0x4e,0x5e,0x60,0xfe};
    gw_machine *whole=guest(code,sizeof(code)),*split=guest(code,sizeof(code));
    whole->cpu.a[6]=split->cpu.a[6]=0x12345678;whole->cpu.sr=split->cpu.sr=0x271f;
    gw_diagnostic_record untouched=snapshot(split);uint64_t end=whole->tick+28u*GW_CPU_DIVIDER;
    (void)run(whole,end);gw_diagnostic_record after=snapshot(split);
    CHECK(!memcmp(&untouched,&after,sizeof(after)),"frame operations preserve another instance");
    step(split,"split LINK");step(split,"split UNLK");same(whole,split);
    CHECK(whole->tick==end&&split->tick==end,"frame exact combined time");
#ifdef GW_TEST_HOOKS
    CHECK(gw_test_state_digest(whole)==gw_test_state_digest(split),"frame complete split-run state");
#endif
    CHECK(gw_console_reset(split)==GW_OK,"frame console reset");step(split,"LINK after reset");step(split,"UNLK after reset");
    CHECK(split->cpu.a[6]==0&&split->cpu.a[7]==0xffff00,"frame operations add no hidden reset state");gw_destroy(whole);gw_destroy(split);
}
int main(int argc,char **argv)
{
    if(argc<2 || !strcmp(argv[1],"usp"))usp();
    if(argc<2 || !strcmp(argv[1],"mulu")){mulu();multiply_divide_modes(0);}
    if(argc<2 || !strcmp(argv[1],"muls")){muls();multiply_divide_modes(2);}
    if(argc<2 || !strcmp(argv[1],"divu")){divu();multiply_divide_modes(1);}
    if(argc<2 || !strcmp(argv[1],"io"))io_word_read();
    if(argc<2 || !strcmp(argv[1],"cartridge"))cartridge_disable();
    if(argc<2 || !strcmp(argv[1],"ext"))ext_gpio();
    if(argc<2 || !strcmp(argv[1],"pea"))pea();
    if(argc<2 || !strcmp(argv[1],"scc"))scc_dn();
    if(argc<2 || !strcmp(argv[1],"addx"))addx_dn();
    if(argc<2 || !strcmp(argv[1],"bank"))bank_68000();
    if(argc<2 || !strcmp(argv[1],"link"))link_unlk();
    if(argc==2 && (!strcmp(argv[1],"pea-mutant-address")||!strcmp(argv[1],"pea-mutant-stack")))
        pea_mutant(!strcmp(argv[1],"pea-mutant-address")?"wrong-address":"wrong-stack-order");
    puts("phase6_repairs_contract: PASS");return 0;
}
