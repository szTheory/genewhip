/* SPDX-License-Identifier: MIT
 * Independent oracle: NXP M68000PRM pp.231-233 (4-128..130),
 * MC68000UM table8-10. No emulator implementation or output supplies expectations.
 * Load, setup, execution and memory inspection use public APIs. Existing private
 * state/write observations supplement exact boundary/cycle/word-order assertions.
 */
#include "../../src/internal.h"
#include "contract.h"

static void word(uint8_t *p, unsigned v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static uint32_t peek(gw_machine *m, uint32_t address, unsigned size)
{
    uint8_t b[4]; uint32_t v=0;
    CHECK(gw_peek_memory(m,address,b,size)==GW_OK,"public memory inspection");
    for(unsigned i=0;i<size;i++) v=(v<<8)|b[i];
    return v;
}
static uint32_t regval(unsigned r) { return UINT32_C(0x12348000)+r*0x101u; }

/* All registers are initialized by real MOVE.L/MOVEA.L guest instructions.
 * A0 is the effective-address base, A7 the initial stack. */
static gw_machine *fresh(unsigned op, unsigned mask, uint32_t base, unsigned ext,
                         unsigned extbytes, uint32_t *pc)
{
    uint8_t rom[2048]; gw_machine *m=machine(); unsigned at=512;
    rom_init(rom,sizeof(rom));
    for(unsigned r=0;r<16;r++) {
        word(rom+at, r<8 ? 0x203cu+(r<<9) : 0x207cu+((r-8)<<9));
        put32(rom+at+2,r==8?base:r==15?0x00ffff00u:regval(r)); at+=6;
    }
    word(rom+at,0x003c); word(rom+at+2,0x1f); at+=4; /* ORI CCR */
    *pc=at;
    word(rom+at,op); word(rom+at+2,mask);
    if(extbytes==2) word(rom+at+4,ext);
    if(extbytes==4) put32(rom+at+4,ext);
    word(rom+at+4+extbytes,0x4afc); /* unsupported sentinel */
    CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"load MOVEM public guest");
    for(unsigned i=0;i<17;i++) CHECK(run(m,m->tick+1).stop_reason==GW_STOP_TARGET,"guest setup");
    CHECK(m->cpu.pc==*pc && m->cpu.sr==0x271f,"setup boundary and flags");
    return m;
}

static void predecrement(void)
{
    unsigned masks[]={0,1,0x8000,0xffff,0x8181};
    for(unsigned size=2;size<=4;size+=2) for(unsigned k=0;k<5;k++) {
        uint32_t pc,sp=0x00ffff00u; unsigned n=0;
        gw_machine *m=fresh(size==4?0x48e7:0x48a7,masks[k],0xff1000,0,0,&pc);
        uint64_t before=m->tick;
        CHECK(run(m,before+1).stop_reason==GW_STOP_TARGET,"observed MOVEM predecrement executes");
        for(unsigned bit=0;bit<16;bit++) if(masks[k]&(1u<<bit)) {
            unsigned r=15-bit; uint32_t value=r==15?0x00ffff00u:r==8?0xff1000u:regval(r);
            sp-=size; ++n;
            CHECK(peek(m,sp,size)==(size==2?value&0xffffu:value),"reversed mask/order and original MC68000 base value");
            if(r==15) CHECK(peek(m,sp,size)!=(size==2?(value-size)&0xffffu:value-size),"reject later-generation initial-minus-size oracle");
#ifdef GW_TEST_HOOKS
            if((n-1)*(size/2)<16) {
                size_t i=(n-1)*(size/2);
                CHECK(m->writes[i].address==sp && m->writes[i].value==(size==4?value>>16:value&0xffffu),"ordered first bus word");
                CHECK(m->writes[i].tick==before+(8u+(n-1)*size*2u+4u)*7u,"exact first word bus tick");
                if(size==4 && i+1<16) CHECK(m->writes[i+1].address==sp+2 && m->writes[i+1].value==(value&0xffffu),"ordered low bus word");
            }
#endif
        }
        CHECK(m->cpu.a[7]==sp && m->cpu.pc==pc+4 && m->cpu.sr==0x271f,"base, extension PC and unchanged flags");
        CHECK(m->tick-before==(8u+2u*size*n)*7u,"predecrement clocks 8+4n/8n");
        gw_destroy(m);
    }
}

/* All fourteen MC68000 direction/EA combinations, both sizes. Single D0
 * transfers discriminate extension PC (PC relative starts after the mask),
 * normal mask order, sign extension and each timing denominator. */
static void modes(void)
{
    unsigned eas[]={0x10,0x20,0x28,0x30,0x38,0x39,0x10,0x18,0x28,0x30,0x38,0x39,0x3a,0x3b};
    for(unsigned i=0;i<14;i++) for(unsigned size=2;size<=4;size+=2) {
        int load=i>=6; unsigned ea=eas[i],mode=ea>>3,extbytes=0,ext=0,extra=0;
        uint32_t pc,address=0xff1000,base=address;
        if(mode==4) base+=size;
        if(mode==5) {extbytes=2;ext=0x10;base-=0x10;extra=4;}
        if(mode==6) {extbytes=2;extra=6;}
        if(ea==0x38) {extbytes=2;ext=0x9000;address=0xff9000;extra=4;}
        if(ea==0x39) {extbytes=4;ext=address;extra=8;}
        /* Indexed A1.w = 0x8909, negative; displacement 0, A0 compensates. */
        if(mode==6) {ext=0x9000;base=address-UINT32_C(0xffff8909);}
        if(ea==0x3a || ea==0x3b) {extbytes=2;extra=ea==0x3a?4:6; address=0x300; ext=ea==0x3a?0x98:0x0098;}
        gw_machine *m=fresh((load?0x4c80:0x4880)+(size==4?0x40:0)+ea,
                           mode==4?0x8000:1,base,ext,extbytes,&pc);
        /* PC base is pc+4, after the register mask. */
        if(ea==0x3a) address=pc+4+0x98;
        if(ea==0x3b) {
            gw_destroy(m); ext=0x8800; base=0xff1000-pc-4;
            m=fresh(0x4c80+(size==4?0x40:0)+ea,1,base,ext,2,&pc);
            address=0xff1000;
        }
        if(load) {
            /* Test-only memory seed: unlike fixture probes, original unit guests
             * may initialize memory. ROM source words are written before running. */
            if(address<2048) { m->rom[address]=0x80; m->rom[address+1]=1; if(size==4){m->rom[address+2]=0x12;m->rom[address+3]=0x34;} }
            else {
                /* address may have high CPU bits; bus masks to24. */
                uint32_t physical=address&0xffffffu;
                CHECK(physical>=0xe00000,"indexed test source mapped");
                m->ram[physical&0xffffu]=0x80;m->ram[(physical+1)&0xffffu]=1;
                if(size==4){m->ram[(physical+2)&0xffffu]=0x12;m->ram[(physical+3)&0xffffu]=0x34;}
            }
        }
        uint64_t before=m->tick;
        CHECK(run(m,before+1).stop_reason==GW_STOP_TARGET,"supported direction/EA executes");
        if(load) CHECK(m->cpu.d[0]==(size==2?UINT32_C(0xffff8001):UINT32_C(0x80011234)),"memory load and word sign extension");
        else CHECK(peek(m,address,size)==(size==2?regval(0)&0xffffu:regval(0)),"normal store mask");
        CHECK(m->cpu.pc==pc+4+extbytes && m->cpu.sr==0x271f,"EA extension PC and flags");
        CHECK(m->tick-before==((load?12u:8u)+extra+size*2u)*7u,"direction/EA exact clock denominator");
        if(mode==3) CHECK(m->cpu.a[0]==base+size,"postincrement base");
        gw_destroy(m);
    }
}

static void boundaries(void)
{
    uint32_t pc; gw_machine *m;
    unsigned illegal[]={0x4890+8,0x48ba,0x48bc,0x4ca0,0x4c88,0x4cbc};
    for(unsigned i=0;i<sizeof(illegal)/sizeof(illegal[0]);i++) {
        m=fresh(illegal[i],0xffff,0xff1000,0,0,&pc); uint64_t before=m->tick;
        CHECK(run(m,before+1).stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"illegal EA rejects");
        CHECK(m->cpu.pc==pc+2 && m->cpu.a[0]==0xff1000 && m->cpu.sr==0x271f,"reject before mask or EA mutation");
        gw_destroy(m);
    }
    /* Postincrement base in list ignores loaded A0 and retains final address. */
    m=fresh(0x4c98,0x0101,0xff1000,0,0,&pc);
    m->ram[0x1000]=0x80;m->ram[0x1001]=1;m->ram[0x1002]=0xff;m->ram[0x1003]=0xff;
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_TARGET,"postincrement conflict executes");
    CHECK(m->cpu.d[0]==UINT32_C(0xffff8001) && m->cpu.a[0]==0xff1004,"word extension and postincrement wins");gw_destroy(m);
    /* One store succeeds at E00000, second predecrement hits unmapped DFFFFE. */
    m=fresh(0x48a0,0x8001,0xe00002,0,0,&pc);
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"partial transfer is address fault");
    CHECK(peek(m,0xe00000,2)==0xff00 && m->cpu.a[0]==0xdffffe,"completed store retained; failing predecrement visible");
    CHECK(m->cpu.fault_address==0xdffffe && m->cpu.pc==pc+4 && m->cpu.sr==0x271f,"precise fault and PC/flags");
    CHECK(run(m,m->tick+100).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"fault remains sticky");gw_destroy(m);
    /* Long load crosses ROM boundary: D0 commits, D1 stays original. */
    m=fresh(0x4cd8,3,2040,0,0,&pc); put32(m->rom+2040,0x80011234);
    m->rom_size=2046;
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS,"partial long load fault");
    CHECK(m->cpu.d[0]==0x80011234 && m->cpu.d[1]==regval(1) && m->cpu.a[0]==2044,"only completed loads and increments commit");
    CHECK(m->cpu.fault_address==2046,"second word exact fault");gw_destroy(m);
    m=fresh(0x48d0,1,0xff1001,0,0,&pc);
    CHECK(run(m,m->tick+1).stop_reason==GW_STOP_UNSUPPORTED_ADDRESS && m->cpu.fault_address==0xff1001,"odd store address fault");gw_destroy(m);
}

static void list_boundaries(void)
{
    unsigned masks[]={0,1,0x8000,0xffff};
    for(unsigned size=2;size<=4;size+=2) for(unsigned k=0;k<4;k++) {
        uint32_t pc,initial[16]; unsigned n=0;
        gw_machine *m=fresh(size==4?0x48d0:0x4890,masks[k],0xff1000,0,0,&pc);
        for(unsigned r=0;r<16;r++) initial[r]=r<8?m->cpu.d[r]:m->cpu.a[r-8];
        uint64_t before=m->tick;
        CHECK(run(m,before+1).stop_reason==GW_STOP_TARGET,"normal list store executes");
        for(unsigned r=0;r<16;r++) if(masks[k]&(1u<<r)) {
            CHECK(peek(m,0xff1000+n*size,size)==(size==2?initial[r]&0xffffu:initial[r]),"normal D0..A7 mask/order");++n;
        }
        CHECK(m->cpu.a[0]==0xff1000 && m->tick-before==(8+2*size*n)*7,"control EA unchanged and exact mask count");
        gw_destroy(m);
        m=fresh(size==4?0x4cd8:0x4c98,masks[k],0xff1000,0,0,&pc);
        for(unsigned r=0;r<16;r++) { unsigned at=0x1000+r*size; m->ram[at]=0x80;m->ram[at+1]=(uint8_t)r;
            if(size==4){m->ram[at+2]=0x12;m->ram[at+3]=(uint8_t)(r+1);}}
        before=m->tick;n=0;
        CHECK(run(m,before+1).stop_reason==GW_STOP_TARGET,"normal list load executes");
        for(unsigned r=0;r<16;r++) if(masks[k]&(1u<<r)) {
            uint32_t expected=size==2?UINT32_C(0xffff8000)+n:UINT32_C(0x80001201)+n*0x10001u;
            if(r!=8) CHECK((r<8?m->cpu.d[r]:m->cpu.a[r-8])==expected,"full load list order and address/data sign extension");
            ++n;
        }
        CHECK(m->cpu.a[0]==0xff1000+n*size && m->tick-before==(12+2*size*n)*7,"postincrement wins for full/empty/single mask");
        CHECK(m->cpu.sr==0x271f,"all mask loads preserve flags");gw_destroy(m);
    }
}

int main(void)
{
    predecrement(); modes(); boundaries(); list_boundaries();
    puts("movem_contract: PASS (28 direction/size/EA forms; masks, generation, cycles, faults)");
    return 0;
}
