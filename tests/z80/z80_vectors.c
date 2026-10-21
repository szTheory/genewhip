/* SPDX-License-Identifier: MIT
 * Hooks-only SingleStepTests adapter. Data is parsed/validated by the Python
 * harness; this process checks every state, memory byte and ordered cycle. */
#include "../../src/internal.h"
#include "../api/contract.h"
#include <inttypes.h>

typedef struct { uint16_t address; uint8_t value; } memory_byte;
static size_t read_memory(memory_byte *rows)
{
    uint32_t n; CHECK(scanf("%" SCNu32, &n)==1 && n<=GW_TEST_MEMORY_CAPACITY,"memory count");
    for(size_t i=0;i<n;++i){uint32_t a,v;CHECK(scanf("%" SCNu32 " %" SCNu32,&a,&v)==2,"memory pair");CHECK(a<=65535&&v<=255,"memory range");rows[i].address=(uint16_t)a;rows[i].value=(uint8_t)v;}return n;
}
static int reg_values(const gw_test_z80_state *s,uint16_t *out)
{
    out[0]=s->af;out[1]=s->bc;out[2]=s->de;out[3]=s->hl;out[4]=s->af_alt;out[5]=s->bc_alt;out[6]=s->de_alt;out[7]=s->hl_alt;out[8]=s->ix;out[9]=s->iy;out[10]=s->sp;out[11]=s->pc;out[12]=s->wz;return 1;
}
static void cycle_resume_contract(void)
{
    gw_machine *m=machine(); uint8_t rom[1024]; gw_test_z80_state s={0},out;
    rom_init(rom,sizeof(rom)); CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"cycle ROM");
    gw_test_z80_overlay_reset(m); CHECK(gw_test_z80_overlay_set(m,0x0200,0x46),"cycle opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0301,0xa5),"cycle operand");
    s.bc=0x1200;s.hl=0x0301;s.pc=0x0200;s.r=5;
    CHECK(gw_test_z80_set_state(m,&s),"cycle state"); uint64_t start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m),"first machine cycle");
    CHECK(m->z80.instruction_active&&!m->z80.retired&&!gw_z80_at_boundary(&m->z80),"instruction paused after M1");
    CHECK(m->z80.pc==0x0201&&m->z80.r==6&&m->z80.next_cycle_tick-start==4u*GW_Z80_DIVIDER,"M1 fetch and refresh accounting");
    CHECK(gw_z80_cycle(m),"resume second machine cycle");
    CHECK(gw_z80_at_boundary(&m->z80)&&m->z80.retired,"instruction retires after memory read");
    CHECK(gw_test_z80_get_state(m,&out)&&((out.bc>>8)==0xa5),"resumed instruction commits once");
    CHECK(m->z80.next_cycle_tick-start==7u*GW_Z80_DIVIDER,"resumed T-state total");

    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0x10),"DJNZ opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x02),"DJNZ displacement");
    s=(gw_test_z80_state){.bc=0x0100,.pc=0x0200};
    CHECK(gw_test_z80_set_state(m,&s),"DJNZ not-taken state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"DJNZ pauses after M1");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active&&m->z80.pending_cycles==1,"DJNZ retains one internal T-state before retirement");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"DJNZ not-taken resumes and retires");
    CHECK(m->z80.next_cycle_tick-start==8u*GW_Z80_DIVIDER,"DJNZ not-taken timing is eight T-states");

    CHECK(gw_test_z80_set_state(m,&(gw_test_z80_state){.bc=0x0200,.pc=0x0200}),"DJNZ taken state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&gw_z80_cycle(m)&&m->z80.pending_cycles==6,"DJNZ taken path retains six internal T-states");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"DJNZ taken resumes and retires");
    CHECK(m->z80.next_cycle_tick-start==13u*GW_Z80_DIVIDER,"DJNZ taken timing is thirteen T-states");

    /* CB register operations preserve both M1 cycles across an arbitration
     * boundary and emit the documented flags and result exactly once. */
    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0xcb),"CB prefix");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x00),"RLC B opcode");
    s=(gw_test_z80_state){0};s.bc=0x8100;s.pc=0x0200;
    CHECK(gw_test_z80_set_state(m,&s),"CB state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active&&m->z80.prefix==0xcb,"pause after CB prefix M1");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"resume and retire CB register opcode");
    CHECK(gw_test_z80_get_state(m,&out)&&out.bc==0x0300&&(out.af&0xffu)==5u,"RLC B result and carry/parity");
    CHECK(m->z80.next_cycle_tick-start==8u*GW_Z80_DIVIDER,"CB register T-state count");

    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0xcb),"CB memory prefix");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x06),"RLC (HL) opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0301,0x81),"RLC (HL) byte");
    s=(gw_test_z80_state){0};s.hl=0x0301;s.pc=0x0200;
    CHECK(gw_test_z80_set_state(m,&s),"CB memory state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&gw_z80_cycle(m)&&m->z80.instruction_active,"CB memory pauses before operand read");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"CB memory pauses before write cycle");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"CB memory write resumes and retires");
    uint8_t cb_value=0;
    CHECK(gw_test_z80_overlay_get(m,0x0301,&cb_value)&&cb_value==0x03,"CB memory mutation");
    CHECK(m->z80.next_cycle_tick-start==15u*GW_Z80_DIVIDER,"CB memory T-state count");

    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0xdd),"DD prefix");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x21),"LD IX,nn opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0202,0x34)&&gw_test_z80_overlay_set(m,0x0203,0x12),"LD IX,nn operand");
    s=(gw_test_z80_state){.hl=0xabcd,.ix=0x5678,.pc=0x0200};
    CHECK(gw_test_z80_set_state(m,&s),"DD state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"DD pauses after prefix");
    CHECK(gw_z80_cycle(m)&&!m->z80.instruction_active&&m->z80.prefetched,"DD retains secondary opcode");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"DD enters prefetched instruction state");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"DD reads immediate low byte");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"DD retires after immediate high byte");
    CHECK(gw_test_z80_get_state(m,&out)&&out.ix==0x1234&&out.hl==0xabcd,"DD load commits IX and preserves HL");
    CHECK(m->z80.next_cycle_tick-start==14u*GW_Z80_DIVIDER,"DD load T-state count");

    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0xdd)&&gw_test_z80_overlay_set(m,0x0201,0x46)&&gw_test_z80_overlay_set(m,0x0202,0x02),"LD B,(IX+d) bytes");
    CHECK(gw_test_z80_overlay_set(m,0x0302,0xa5),"LD B,(IX+d) source");
    s=(gw_test_z80_state){.hl=0xabcd,.ix=0x0300,.pc=0x0200};
    CHECK(gw_test_z80_set_state(m,&s),"indexed load state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active&&m->z80.prefix==0xdd,"indexed load pauses after DD");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active&&m->z80.subopcode==0x46,"indexed load decodes opcode");
    CHECK(gw_z80_cycle(m)&&!m->z80.instruction_active&&m->z80.prefetched&&m->z80.effective_address==0x0302,"indexed load reads displacement");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"indexed load resumes decoded operation");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"indexed load reads effective address and retires");
    CHECK(gw_test_z80_get_state(m,&out)&&((out.bc>>8)&0xffu)==0xa5u&&out.hl==0xabcd&&out.ix==0x0300,"indexed load commits B and restores HL");
    CHECK(m->z80.next_cycle_tick-start==19u*GW_Z80_DIVIDER,"indexed load T-state count");

    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m,0x0200,0xdd)&&gw_test_z80_overlay_set(m,0x0201,0xcb)&&gw_test_z80_overlay_set(m,0x0202,0x02)&&gw_test_z80_overlay_set(m,0x0203,0x06),"DDCB RLC (IX+d) bytes");
    CHECK(gw_test_z80_overlay_set(m,0x0302,0x81),"DDCB operand");
    s=(gw_test_z80_state){.ix=0x0300,.hl=0xabcd,.pc=0x0200};
    CHECK(gw_test_z80_set_state(m,&s),"DDCB state");start=m->z80.next_cycle_tick;
    CHECK(gw_z80_cycle(m)&&gw_z80_cycle(m)&&m->z80.instruction_active,"DDCB prefix cycles");
    CHECK(gw_z80_cycle(m)&&gw_z80_cycle(m)&&m->z80.instruction_active,"DDCB displacement and opcode cycles");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"DDCB read and transform pauses before write");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"DDCB write resumes and retires");
    CHECK(gw_test_z80_overlay_get(m,0x0302,&cb_value)&&cb_value==0x03,"DDCB memory mutation");
    CHECK(gw_test_z80_get_state(m,&out)&&out.hl==0xabcd&&out.ix==0x0300&&(out.af&0xffu)==5u,"DDCB result, flags, and register preservation");
    CHECK(m->z80.next_cycle_tick-start==23u*GW_Z80_DIVIDER,"DDCB T-state count");

    gw_test_z80_overlay_reset(m);CHECK(gw_test_z80_overlay_set(m,0x0200,0xd3),"OUT opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x34),"OUT port operand");
    s=(gw_test_z80_state){0};s.af=0x1200;s.pc=0x0200;
    CHECK(gw_test_z80_set_state(m,&s),"OUT state");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active,"OUT pauses after M1");
    CHECK(gw_z80_cycle(m)&&m->z80.instruction_active&&m->z80.pc==0x0202,"OUT pauses after immediate read");
    CHECK(gw_test_z80_transaction_count(m)==3,"OUT has not emitted early");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80),"OUT resumes through I/O cycle");
    gw_test_z80_transaction io_tx;
    CHECK(gw_test_z80_transaction_get(m,3,&io_tx)&&io_tx.type==4&&io_tx.address==0x1234&&io_tx.data==0x12,"OUT address/data committed on final cycle");

    gw_test_z80_overlay_reset(m);CHECK(gw_test_z80_overlay_set(m,0x0200,0x76),"HALT opcode");
    CHECK(gw_test_z80_set_state(m,&(gw_test_z80_state){.pc=0x0200}),"HALT state");
    CHECK(gw_z80_cycle(m)&&m->z80.halted&&gw_z80_at_boundary(&m->z80),"HALT enters halt state");
    CHECK(m->z80.pc==0x0201,"HALT retains post-opcode PC");
    CHECK(gw_z80_cycle(m)&&m->z80.pc==0x0201,"HALT repeats M1 without advancing PC");
    gw_test_z80_transaction halt_tx;
    CHECK(gw_test_z80_transaction_get(m,2,&halt_tx)&&halt_tx.type==0&&halt_tx.address==0x0200,"HALT repetition fetches held opcode address");

    gw_test_z80_overlay_reset(m);CHECK(gw_test_z80_overlay_set(m,0x0200,0xfb),"EI opcode");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x00),"post-EI NOP");
    CHECK(gw_test_z80_set_state(m,&(gw_test_z80_state){.pc=0x0200}),"EI state");
    CHECK(gw_z80_cycle(m)&&m->z80.ei_delay==1&&m->z80.iff1&&m->z80.iff2,"EI records one-instruction inhibit window");
    CHECK(gw_z80_cycle(m)&&gw_z80_at_boundary(&m->z80)&&m->z80.ei_delay==0&&m->z80.pc==0x0202,"EI latency expires after following instruction");

    gw_test_z80_overlay_reset(m);CHECK(gw_test_z80_overlay_set(m,0x0200,0xed),"unsupported ED prefix family");
    CHECK(gw_test_z80_overlay_set(m,0x0201,0x00),"unsupported ED opcode");
    s.pc=0x0200;CHECK(gw_test_z80_set_state(m,&s),"unsupported opcode state");
    CHECK(gw_z80_cycle(m)&&!gw_z80_cycle(m)&&m->cpu.stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION,"unsupported opcode stop");
    CHECK(m->cpu.fault_address==(UINT32_C(0x40000000)|UINT32_C(0x0200))&&m->cpu.opcode==0xed00,"unsupported opcode fault encoding");

    /* Plan 03-17 supports 0x4000-3; keep the adjacent unmapped range closed. */
    m->z80_overlay_active=0;m->z80.ram[0x0200]=0x7e;s.pc=0x0200;s.hl=0x4004;
    CHECK(gw_test_z80_set_state(m,&s),"unsupported address state");
    CHECK(gw_z80_cycle(m),"unsupported address M1");CHECK(!gw_z80_cycle(m),"unsupported address data cycle");
    CHECK(m->cpu.stop_reason==GW_STOP_UNSUPPORTED_ADDRESS&&m->cpu.fault_address==(UINT32_C(0x40000000)|0x4004u)&&m->cpu.opcode==0x7e,"unsupported address fault encoding");
    gw_destroy(m);
}

int main(int argc,char **argv)
{
    if(argc==2&&strcmp(argv[1],"--cycle-contract")==0){cycle_resume_contract();puts("z80_cycle_resume: PASS");return 0;}
    CHECK(argc==1,"runner arguments");
    gw_machine *m=machine();
    uint8_t rom[1024]; static memory_byte initial[GW_TEST_MEMORY_CAPACITY],final[GW_TEST_MEMORY_CAPACITY];
    rom_init(rom,sizeof(rom)); CHECK(gw_configure_diagnostics(m,0)==GW_OK,"disable diagnostics");
    uint32_t opcode,mask;
    while(scanf("%" SCNu32 " %" SCNu32,&opcode,&mask)==2){
        CHECK(mask<=15,"field gate mask");
        uint32_t a[21],b[21],tc,xc; gw_test_z80_state si={0},sf={0},actual;uint16_t got[13],want[13];
        for(size_t i=0;i<21;i++)CHECK(scanf("%" SCNu32,&a[i])==1,"initial state");
        for(size_t i=0;i<21;i++)CHECK(scanf("%" SCNu32,&b[i])==1,"final state");
        size_t ni=read_memory(initial),nf=read_memory(final); uint64_t start_tick;
        uint32_t pc_count; CHECK(scanf("%" SCNu32, &pc_count)==1&&pc_count<=8,"port count");
        uint16_t port_address[8]; uint8_t port_value[8];
        for(size_t i=0;i<pc_count;i++){uint32_t address,value;CHECK(scanf("%" SCNu32 " %" SCNu32,&address,&value)==2&&address<=65535&&value<=255,"port pair");port_address[i]=(uint16_t)address;port_value[i]=(uint8_t)value;}
        CHECK(scanf("%" SCNu32 " %" SCNu32,&tc,&xc)==2&&tc<32&&xc<16,"cycle counts");
        gw_test_z80_transaction expected[16];
        for(size_t i=0;i<xc;i++){uint32_t t,ad,d,ts;CHECK(scanf("%" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32,&t,&ad,&d,&ts)==4,"transaction");CHECK(t<=255&&ad<=65535&&d<=255&&ts<=255,"transaction range");expected[i]=(gw_test_z80_transaction){(uint8_t)t,(uint8_t)d,(uint8_t)ts,(uint16_t)ad};}
        si.af=(uint16_t)a[0];si.bc=(uint16_t)a[1];si.de=(uint16_t)a[2];si.hl=(uint16_t)a[3];si.af_alt=(uint16_t)a[4];si.bc_alt=(uint16_t)a[5];si.de_alt=(uint16_t)a[6];si.hl_alt=(uint16_t)a[7];si.ix=(uint16_t)a[8];si.iy=(uint16_t)a[9];si.sp=(uint16_t)a[10];si.pc=(uint16_t)a[11];si.wz=(uint16_t)a[12];si.i=(uint8_t)a[13];si.r=(uint8_t)a[14];si.iff1=(uint8_t)a[15];si.iff2=(uint8_t)a[16];si.im=(uint8_t)a[17];si.q=(uint8_t)a[18];si.halted=(uint8_t)a[19];si.ei_delay=(uint8_t)a[20];
        sf.af=(uint16_t)b[0];sf.bc=(uint16_t)b[1];sf.de=(uint16_t)b[2];sf.hl=(uint16_t)b[3];sf.af_alt=(uint16_t)b[4];sf.bc_alt=(uint16_t)b[5];sf.de_alt=(uint16_t)b[6];sf.hl_alt=(uint16_t)b[7];sf.ix=(uint16_t)b[8];sf.iy=(uint16_t)b[9];sf.sp=(uint16_t)b[10];sf.pc=(uint16_t)b[11];sf.wz=(uint16_t)b[12];sf.i=(uint8_t)b[13];sf.r=(uint8_t)b[14];sf.iff1=(uint8_t)b[15];sf.iff2=(uint8_t)b[16];sf.im=(uint8_t)b[17];sf.q=(uint8_t)b[18];sf.halted=(uint8_t)b[19];sf.ei_delay=(uint8_t)b[20];
        gw_test_z80_overlay_reset(m);CHECK(gw_load_rom(m,rom,sizeof(rom))==GW_OK,"load adapter ROM");
        for(size_t i=0;i<ni;i++)CHECK(gw_test_z80_overlay_set(m,initial[i].address,initial[i].value),"load overlay");
        for(size_t i=0;i<pc_count;i++)CHECK(gw_test_z80_overlay_port_set(m,port_address[i],port_value[i]),"load port overlay");
        start_tick=m->tick;
        CHECK(gw_test_z80_set_state(m,&si),"set registers");
        int stepped=gw_test_z80_step_instruction(m);const char *why="PASS";
        if(!stepped){fprintf(stderr,"opcode=%02" PRIx32 " stop=%u fault=%08" PRIx32 " overlay=%u miss=%u/%04x\n",opcode,m->cpu.stop_reason,m->cpu.fault_address,m->z80_overlay_active,m->z80_overlay_miss,m->z80_overlay_miss_address);why=m->cpu.stop_reason==GW_STOP_UNSUPPORTED_INSTRUCTION?"UNSUPPORTED opcode":m->cpu.stop_reason==GW_STOP_UNSUPPORTED_ADDRESS?"UNSUPPORTED address":"cycle failure";}
        else if(!gw_test_z80_get_state(m,&actual))why="state read failure";
        else {reg_values(&actual,got);reg_values(&sf,want);for(size_t i=0;i<13;i++){if(i==12u&&(mask&1u))continue;uint16_t av=got[i],wv=want[i];if(i==0u&&(mask&4u)){av&=UINT16_C(0xffd7);wv&=UINT16_C(0xffd7);}if(i==0u&&(mask&8u)){av&=UINT16_C(0xff6b);wv&=UINT16_C(0xff6b);}if(av!=wv){fprintf(stderr,"opcode=%02" PRIx32 " reg[%zu]=%04x expected=%04x\n",opcode,i,av,wv);why="register mismatch";break;}}
            if(why[0]=='P'&&(actual.i!=sf.i||actual.r!=sf.r||actual.iff1!=sf.iff1||actual.iff2!=sf.iff2||actual.im!=sf.im||(!(mask&2u)&&actual.q!=sf.q)||(opcode!=0x76u&&actual.halted!=sf.halted)||actual.ei_delay!=sf.ei_delay)){fprintf(stderr,"opcode=%02" PRIx32 " extra=%u/%u/%u/%u/%u/%u/%u/%u expected=%u/%u/%u/%u/%u/%u/%u/%u\n",opcode,actual.i,actual.r,actual.iff1,actual.iff2,actual.im,actual.q,actual.halted,actual.ei_delay,sf.i,sf.r,sf.iff1,sf.iff2,sf.im,sf.q,sf.halted,sf.ei_delay);why="register mismatch";}
            for(size_t i=0;why[0]=='P'&&i<nf;i++){uint8_t gotbyte=0;int have=gw_test_z80_overlay_get(m,final[i].address,&gotbyte);if(!have||gotbyte!=final[i].value){fprintf(stderr,"opcode=%02" PRIx32 " mem[%04x]=%02x expected=%02x present=%d\n",opcode,final[i].address,gotbyte,final[i].value,have);why="memory mismatch";}}
            if(why[0]=='P'&&m->z80.next_cycle_tick-start_tick!=((uint64_t)tc*GW_Z80_DIVIDER)){fprintf(stderr,"opcode=%02" PRIx32 " ticks=%" PRIu64 " expected=%" PRIu32 " pc=%04x\n",opcode,m->z80.next_cycle_tick-start_tick,tc,(unsigned)actual.pc);why="tstate mismatch";}
            if(why[0]=='P'&&gw_test_z80_transaction_count(m)!=xc){fprintf(stderr,"opcode=%02" PRIx32 " transactions=%zu expected=%" PRIu32 "\n",opcode,gw_test_z80_transaction_count(m),xc);why="bus mismatch";}
            for(size_t i=0;why[0]=='P'&&i<xc;i++){gw_test_z80_transaction got_tx;if(!gw_test_z80_transaction_get(m,i,&got_tx)||got_tx.type!=expected[i].type||got_tx.address!=expected[i].address||got_tx.data!=expected[i].data||got_tx.t_states!=expected[i].t_states){fprintf(stderr,"opcode=%02" PRIx32 " tx[%zu]=%u/%04x/%02x/%u want=%u/%04x/%02x/%u\n",opcode,i,got_tx.type,got_tx.address,got_tx.data,got_tx.t_states,expected[i].type,expected[i].address,expected[i].data,expected[i].t_states);why="bus mismatch";}}
        }
        (void)opcode;printf("%s\n",why);
    }
    CHECK(feof(stdin),"input parse");gw_destroy(m);return 0;
}
