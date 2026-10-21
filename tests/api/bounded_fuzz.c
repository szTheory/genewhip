/* SPDX-License-Identifier: MIT
 * Fixed-seed malformed-load and bounded-execution property exercise.
 *
 * Usage: gw_bounded_fuzz            malformed-load / bounded-execution mode (default)
 *        gw_bounded_fuzz vdp-stream random VDP register, command, data and DMA streams
 *        gw_bounded_fuzz sprite-table random sprite tables, links and sizes, one field each
 *        gw_bounded_fuzz z80-stream random guest programs uploaded while BUSREQ is granted
 *        gw_bounded_fuzz audio-calls randomized bounded public audio calls
 * Each mode prints one JSON summary line and exits non-zero on any failure.
 */
#include <genewhip/genewhip.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef GW_TEST_HOOKS
extern uint64_t gw_test_allocation_count(const gw_machine *machine);
#endif
static uint32_t state=0x47573105u;
static uint32_t next(void) { state^=state<<13; state^=state>>17; state^=state<<5; return state; }
static int load_mode(void)
{
    unsigned char rom[1024]; unsigned accepted=0,rejected=0;
    for(unsigned i=0;i<4096;++i) {
        gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0};
        gw_machine *a=NULL,*b=NULL; gw_run_result x={0},y={0};
        x.struct_size=sizeof(x); y.struct_size=sizeof(y); x.version=y.version=GW_API_VERSION;
        for(unsigned j=0;j<sizeof(rom);++j) rom[j]=(unsigned char)next();
        /* Half the cases have admissible reset vectors, with random opcodes. */
        if(i%2==0) { const unsigned char vectors[]={0,0xff,0xff,0,0,0,2,0}; memcpy(rom,vectors,8); }
        if(gw_create(&c,&a)!=GW_OK || gw_create(&c,&b)!=GW_OK) return 1;
        size_t size=i%2 ? next()%sizeof(rom) : sizeof(rom);
        gw_status sa=gw_load_rom(a,rom,size),sb=gw_load_rom(b,rom,size);
        if(sa!=sb) return 1;
        if(sa==GW_OK) {
            ++accepted;
            if(gw_run_until(a,128,&x)!=gw_run_until(b,128,&y) || x.actual_tick!=y.actual_tick ||
               x.stop_reason!=y.stop_reason || x.instruction_address!=y.instruction_address || x.opcode!=y.opcode) return 1;
        } else ++rejected;
        gw_destroy(a); gw_destroy(b);
    }
    if(!accepted || !rejected || accepted+rejected!=4096) return 1;
    printf("{\"seed\":\"47573105\",\"denominator\":4096,\"pass\":4096,\"fail\":0,\"unknown\":0,\"skipped\":0,\"accepted_loads\":%u,\"rejected_loads\":%u,\"tick_budget\":128}\n",accepted,rejected);
    return 0;
}

/* ---- vdp-stream mode (plan GW-02-08) ----------------------------------------------
 * 4096 random 1 KiB ROMs, each a straight-line stream of VDP register writes, control
 * commands (including DMA, fill and copy forms), data writes and port reads, run for one
 * field. The machine must not fault under ASan/UBSan and may stop only for documented
 * reasons: target, field complete, or an unsupported address/state. Every 64th ROM also
 * runs on a second machine to check determinism. */
#define VDP_CTRL 0x00c00004u
#define VDP_DATA 0x00c00000u
typedef struct { unsigned char *rom; size_t pos; } emitter;
static void em16(emitter *e, uint32_t v) { e->rom[e->pos++]=(unsigned char)(v>>8); e->rom[e->pos++]=(unsigned char)v; }
static void em32(emitter *e, uint32_t v) { em16(e,v>>16); em16(e,v&0xffffu); }
static void em_move_w(emitter *e, uint32_t imm, uint32_t address) { em16(e,0x33fc); em16(e,imm); em32(e,address); }
static void em_move_l(emitter *e, uint32_t imm, uint32_t address) { em16(e,0x23fc); em32(e,imm); em32(e,address); }
static void em_read_w(emitter *e, uint32_t address) { em16(e,0x33f9); em32(e,address); em32(e,0x00ff0000u); } /* move.w (address).l,(0xFF0000).l */

static void em_reg(emitter *e, unsigned reg, unsigned value) { em_move_w(e,0x8000u|reg<<8|(value&0xffu),VDP_CTRL); }
/* Two-word command from CD5..CD0 and a 16-bit address (word-aligned most of the time). */
static void em_cmd(emitter *e, unsigned cd, uint32_t address)
{
    uint32_t first=((uint32_t)(cd&3u)<<14)|(address&0x3fffu), second=(((uint32_t)cd>>2)<<4)|((address>>14)&3u);
    em_move_l(e,first<<16|second,VDP_CTRL);
}

/* One random block. Most blocks are well formed so the DMA, fill, copy and FIFO paths
 * run to completion; a minority are malformed and must stop with a documented reason. */
static void em_vdp_block(emitter *e)
{
    unsigned raw=next()%34u, kind=raw==33u?11u:raw%11u, i, count; /* one malformed block in 34 */
    uint32_t address=(next()&0xfffeu);
    switch (kind) {
    case 0: em_reg(e,15,(next()%32u)?2u:next()%5u); break;
    case 1: em_reg(e,1,0x14u|((next()&1u)?0x40u:0u)); break;
    case 2: em_reg(e,12,(next()&1u)?0x81u:0u); break;
    case 3: case 4: /* FIFO: write command, then a burst of data words */
        em_cmd(e,((const unsigned[]){1,3,5})[next()%3u],address);
        for (count=1u+next()%8u,i=0;i<count;++i) em_move_w(e,next()&0xffffu,VDP_DATA);
        break;
    case 5: /* read command, then data reads and a status read */
        em_cmd(e,((const unsigned[]){0,8,4})[next()%3u],address);
        for (count=1u+next()%3u,i=0;i<count;++i) em_read_w(e,VDP_DATA);
        em_read_w(e,VDP_CTRL);
        break;
    case 6: case 7: case 8: { /* 68000 transfer: source in ROM, work RAM or anywhere */
        unsigned len=1u+next()%48u, src=next()%8u;
        src=src<4u?0u:src<7u?1u:2u;
        em_reg(e,19,len); em_reg(e,20,(next()%16u)?0u:next()%2u);
        if (src==0) { em_reg(e,21,next()%0x80u); em_reg(e,22,0); em_reg(e,23,0); }
        else if (src==1) { em_reg(e,21,next()); em_reg(e,22,next()|0xf0u); em_reg(e,23,0x70u|(next()&0xfu)); }
        else { em_reg(e,21,next()); em_reg(e,22,next()); em_reg(e,23,next()&0x7fu); }
        em_cmd(e,0x20u|((const unsigned[]){1,3,5})[next()%3u],address);
        break; }
    case 9: /* fill: arm, trigger, then immediate contention */
        em_reg(e,19,1u+next()%64u); em_reg(e,20,0); em_reg(e,23,0x80u);
        em_cmd(e,0x21u,address);
        em_move_w(e,next()&0xffffu,VDP_DATA);
        if (next()&1u) em_read_w(e,VDP_CTRL);
        if (next()&1u) { em_cmd(e,1u,address); em_move_w(e,next()&0xffffu,VDP_DATA); }
        break;
    case 10: /* copy */
        em_reg(e,19,1u+next()%64u); em_reg(e,20,0); em_reg(e,21,next()); em_reg(e,22,next()); em_reg(e,23,0xc0u);
        em_cmd(e,0x30u,address);
        if (next()&1u) em_read_w(e,VDP_CTRL);
        break;
    default: /* malformed: arbitrary command and register values */
        if (next()&1u) em_move_l(e,next(),VDP_CTRL); else em_reg(e,next()%26u,next());
        break;
    }
}

static int vdp_stream_mode(void)
{
    enum { ITERATIONS = 4096 };
    unsigned i, pass=0, fail=0, stops_target=0, stops_field=0, stops_address=0, stops_state=0;
    state=0x56445053u;
    for (i=0;i<ITERATIONS;++i) {
        unsigned char rom[1024];
        emitter e={rom,0x200};
        gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0};
        gw_machine *m=NULL;
        gw_run_result r={0};
        unsigned n=6u+next()%20u, k;
        int ok=1;
        r.struct_size=sizeof(r); r.version=GW_API_VERSION;
        memset(rom,0,sizeof(rom));
        { const unsigned char vectors[]={0,0xff,0xff,0,0,0,2,0}; memcpy(rom,vectors,8); }
        em_reg(&e,15,2); em_reg(&e,1,0x14u|((next()&1u)?0x40u:0u)); /* DMA enabled, Mode 5 */
        for (k=0;k<n && e.pos<0x360;++k) em_vdp_block(&e);
        em16(&e,0x60fe); /* bra.s self */
        if (gw_create(&c,&m)!=GW_OK) return 1;
        if (gw_load_rom(m,rom,sizeof(rom))!=GW_OK) { gw_destroy(m); ++fail; continue; }
        if (gw_run_until(m,GW_FIELD_TICKS+4096u,&r)!=GW_OK) ok=0;
        switch (r.stop_reason) { /* documented reasons only */
        case GW_STOP_TARGET: ++stops_target; break;
        case GW_STOP_FIELD_COMPLETE: ++stops_field; break;
        case GW_STOP_UNSUPPORTED_ADDRESS: ++stops_address; break;
        case GW_STOP_UNSUPPORTED_STATE: ++stops_state; break;
        default: ok=0; break;
        }
        if (ok && i%64u==0) { /* determinism on a sample */
            gw_machine *b=NULL; gw_run_result y={0};
            y.struct_size=sizeof(y); y.version=GW_API_VERSION;
            if (gw_create(&c,&b)!=GW_OK || gw_load_rom(b,rom,sizeof(rom))!=GW_OK ||
                gw_run_until(b,GW_FIELD_TICKS+4096u,&y)!=GW_OK || y.actual_tick!=r.actual_tick ||
                y.stop_reason!=r.stop_reason || y.fault_address!=r.fault_address) ok=0;
            gw_destroy(b);
        }
        gw_destroy(m);
        if (ok) ++pass; else ++fail;
    }
    if (stops_field<ITERATIONS/4u) ++fail; /* The generator must keep reaching the end of a field. */
    printf("{\"mode\":\"vdp-stream\",\"seed\":\"56445053\",\"denominator\":%u,\"pass\":%u,\"fail\":%u,\"unknown\":0,\"skipped\":0,"
           "\"stops\":{\"target\":%u,\"field_complete\":%u,\"unsupported_address\":%u,\"unsupported_state\":%u}}\n",
           (unsigned)ITERATIONS,pass,fail,stops_target,stops_field,stops_address,stops_state);
    return fail?1:0;
}

/* ---- sprite-table mode (plan GW-02-19) ---------------------------------------------
 * 4096 random 4 KiB ROMs. Each DMAs a random tile block to VRAM 0 and a random sprite table
 * (128 entries: Y mostly on screen, any size, links to any entry including itself and
 * cycles, arbitrary pattern and X) to the table address chosen by register 5, in H32 or H40,
 * with and without shadow/highlight (register 12), then renders one field. The field must
 * complete with a documented stop reason (a well formed program never faults), publish a
 * field of the latched width, and every 64th ROM must reproduce the same pixel checksum on a
 * second machine. Run under ASan/UBSan this exercises the traversal and clipping bounds. */
static void put_be16(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }

static uint64_t field_checksum(gw_machine *m, unsigned *width_out, int *ok)
{
    gw_video_field f={0};
    const uint32_t *pixels=NULL;
    uint64_t sum=1469598103934665603ull;
    unsigned x,y;
    f.struct_size=sizeof(f); f.version=GW_API_VERSION;
    if (gw_get_video_field(m,&f,&pixels)!=GW_OK || !pixels || f.height!=224 || (f.width!=256 && f.width!=320) ||
        f.pitch_bytes<f.width*4u) { *ok=0; return 0; }
    for (y=0;y<f.height;++y)
        for (x=0;x<f.width;++x) sum=(sum^pixels[(size_t)y*(f.pitch_bytes/4u)+x])*1099511628211ull;
    *width_out=f.width;
    return sum;
}

static int sprite_table_mode(void)
{
    enum { ITERATIONS = 4096 };
    unsigned i, j, pass=0, fail=0, h40_fields=0, h32_fields=0, sh_fields=0, cyclic_tables=0, maximal_sprites=0;
    state=0x53505254u;
    for (i=0;i<ITERATIONS;++i) {
        static unsigned char rom[4096];
        emitter e={rom,0x200};
        gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0};
        gw_machine *m=NULL;
        gw_run_result r={0};
        unsigned reg5=next()&0x7fu, h40=next()&1u, sh=next()&1u, width=0;
        uint32_t base=((uint32_t)reg5<<9)&0xfe00u;
        uint64_t sum;
        int ok=1;
        r.struct_size=sizeof(r); r.version=GW_API_VERSION;
        memset(rom,0,sizeof(rom));
        { const unsigned char vectors[]={0,0xff,0xff,0,0,0,2,0}; memcpy(rom,vectors,8); }
        for (j=0;j<128u;++j) { /* sprite table at ROM 0x800 */
            unsigned char *q=rom+0x800+j*8u;
            unsigned size=next()&0xfu, link=next()%128u;
            if (j==0) link=1u+next()%127u;       /* the traversal always leaves entry 0 */
            else if (j%8u==0) link=j;            /* self cycle */
            else if (j%8u==1) link=j-1u;           /* back edge: a two-cycle with the previous entry */
            if (next()%5u==0) size=0xfu;         /* maximal 4x4 cells */
            if (size==0xfu) ++maximal_sprites;
            put_be16(q,128u+next()%240u-8u);
            q[2]=(unsigned char)size; q[3]=(unsigned char)link;
            put_be16(q+4,next()&0xffffu);
            put_be16(q+6,next()%512u);
        }
        for (j=1;j<128u;++j) if (rom[0x800+j*8u+3]==j) { ++cyclic_tables; break; }
        for (j=0;j<1024u;++j) rom[0xc00+j]=(unsigned char)next(); /* tiles at ROM 0xC00 */
        em_reg(&e,15,2); em_reg(&e,1,0x54u);                      /* display on, DMA on */
        em_reg(&e,12,(h40?0x81u:0u)|(sh?8u:0u)); em_reg(&e,5,reg5);
        em_reg(&e,19,0); em_reg(&e,20,2); em_reg(&e,21,0); em_reg(&e,22,0x06); em_reg(&e,23,0); /* 512 words from 0xC00 */
        em_cmd(&e,0x21u,0);
        em_reg(&e,19,0); em_reg(&e,20,2); em_reg(&e,21,0); em_reg(&e,22,0x04); em_reg(&e,23,0); /* 512 words from 0x800 */
        em_cmd(&e,0x21u,base);
        em16(&e,0x60fe);
        if (gw_create(&c,&m)!=GW_OK) return 1;
        if (gw_load_rom(m,rom,sizeof(rom))!=GW_OK) { gw_destroy(m); ++fail; continue; }
        /* Two fields: the table is in place and rendered by the second. */
        for (j=0;j<2u && ok;++j) {
            r.flags=0;
            if (gw_run_until(m,3u*(uint64_t)GW_FIELD_TICKS,&r)!=GW_OK || r.stop_reason!=GW_STOP_FIELD_COMPLETE) ok=0;
        }
        sum=ok?field_checksum(m,&width,&ok):0;
        if (ok && width!=(h40?320u:256u)) ok=0;
        if (ok && i%64u==0) {
            gw_machine *b=NULL; gw_run_result y={0}; unsigned w2=0; int ok2=1;
            y.struct_size=sizeof(y); y.version=GW_API_VERSION;
            if (gw_create(&c,&b)!=GW_OK || gw_load_rom(b,rom,sizeof(rom))!=GW_OK) ok=0;
            else {
                for (j=0;j<2u;++j) { y.flags=0; if (gw_run_until(b,3u*(uint64_t)GW_FIELD_TICKS,&y)!=GW_OK) ok=0; }
                if (field_checksum(b,&w2,&ok2)!=sum || !ok2 || w2!=width) ok=0;
            }
            gw_destroy(b);
        }
        if (ok) { if (h40) ++h40_fields; else ++h32_fields; if (sh) ++sh_fields; }
        gw_destroy(m);
        if (ok) ++pass; else ++fail;
    }
    if (!h40_fields || !h32_fields || !sh_fields) ++fail;
    printf("{\"mode\":\"sprite-table\",\"seed\":\"53505254\",\"denominator\":%u,\"pass\":%u,\"fail\":%u,\"unknown\":0,\"skipped\":0,"
           "\"h40_fields\":%u,\"h32_fields\":%u,\"shadow_highlight_fields\":%u,\"tables_with_self_cycles\":%u,\"maximal_size_sprites\":%u}\n",
           (unsigned)ITERATIONS,pass,fail,h40_fields,h32_fields,sh_fields,cyclic_tables,maximal_sprites);
    return fail?1:0;
}

/* Z80 program delivery uses the 68000's RESET/BUSREQ and Z80 RAM window. */
#define Z80_RESET 0x00a11200u
#define Z80_BUSREQ 0x00a11100u
#define Z80_WINDOW 0x00a00000u
static uint64_t pcm_hash(gw_machine *m, int *ok)
{
    int16_t samples[GW_AUDIO_QUEUE_FRAMES*2u];
    gw_audio_read_result result={0};
    uint64_t hash=1469598103934665603ull;
    result.struct_size=sizeof(result); result.version=GW_API_VERSION;
    if(gw_audio_read(m,samples,GW_AUDIO_QUEUE_FRAMES,&result)!=GW_OK) { *ok=0; return 0; }
    for(uint32_t i=0;i<result.produced*2u;++i) {
        uint16_t v=(uint16_t)samples[i]; hash=(hash^(uint8_t)v)*1099511628211ull;
        hash=(hash^(uint8_t)(v>>8))*1099511628211ull;
    }
    return hash ^ result.first_index ^ ((uint64_t)result.produced<<32);
}

static int run_z80_case(const unsigned char *program, uint64_t *tick, uint32_t *stop,
                        uint8_t *ram, uint64_t *audio)
{
    unsigned char rom[0x2000];
    emitter e={rom,0x200};
    gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0,{0,0},22050};
    gw_machine *m=NULL; gw_run_result r={0}; int ok=1;
    memset(rom,0,sizeof(rom));
    { const unsigned char vectors[]={0,0xff,0xff,0,0,0,2,0}; memcpy(rom,vectors,8); }
    /* Keep the seed program at 0x1000; emitter uses the same 68000 path as a
     * cartridge upload, then the caller runs four deterministic fields. */
    em_move_w(&e,0,Z80_RESET); em_move_w(&e,0x0100,Z80_BUSREQ);
    for(unsigned i=0;i<256u;++i) { em16(&e,0x13f9); em32(&e,0x1000u+i); em32(&e,Z80_WINDOW+i); }
    em_move_w(&e,0x0100,Z80_RESET); em_move_w(&e,0,Z80_BUSREQ); em16(&e,0x60fe);
    memcpy(rom+0x1000,program,256u);
    if(gw_create(&c,&m)!=GW_OK || gw_load_rom(m,rom,sizeof(rom))!=GW_OK) { gw_destroy(m); return 0; }
    r.struct_size=sizeof(r); r.version=GW_API_VERSION; r.flags=GW_RUN_CONTINUE_PAST_FIELD;
    if(gw_run_until(m,4u*(uint64_t)GW_FIELD_TICKS,&r)!=GW_OK) ok=0;
    if(r.stop_reason!=GW_STOP_TARGET && r.stop_reason!=GW_STOP_FIELD_COMPLETE &&
       r.stop_reason!=GW_STOP_UNSUPPORTED_ADDRESS && r.stop_reason!=GW_STOP_UNSUPPORTED_STATE &&
       r.stop_reason!=GW_STOP_UNSUPPORTED_INSTRUCTION) ok=0;
    if(gw_peek_memory(m,0xff0000,ram,GW_RAM_SIZE)!=GW_OK) ok=0;
    *audio=pcm_hash(m,&ok); *tick=r.actual_tick; *stop=r.stop_reason;
    gw_destroy(m); return ok;
}

static int z80_stream_mode(void)
{
    enum { ITERATIONS=128 };
    unsigned pass=0,fail=0,unknown=0,skipped=0,target=0,field=0,address=0,state_stop=0,instruction=0;
    state=0x5a383053u;
    for(unsigned i=0;i<ITERATIONS;++i) {
        unsigned char program[256], ram_a[GW_RAM_SIZE], ram_b[GW_RAM_SIZE];
        uint64_t tick_a=0,tick_b=0,audio_a=0,audio_b=0; uint32_t stop_a=0,stop_b=0;
        for(unsigned j=0;j<sizeof(program);++j) program[j]=(unsigned char)next();
        int ok=run_z80_case(program,&tick_a,&stop_a,ram_a,&audio_a) &&
               run_z80_case(program,&tick_b,&stop_b,ram_b,&audio_b);
        if(ok && (tick_a!=tick_b || stop_a!=stop_b || audio_a!=audio_b ||
                  memcmp(ram_a,ram_b,sizeof(ram_a))!=0)) ok=0;
        if(stop_a==GW_STOP_TARGET) ++target; else if(stop_a==GW_STOP_FIELD_COMPLETE) ++field;
        else if(stop_a==GW_STOP_UNSUPPORTED_ADDRESS) ++address; else if(stop_a==GW_STOP_UNSUPPORTED_STATE) ++state_stop;
        else if(stop_a==GW_STOP_UNSUPPORTED_INSTRUCTION) ++instruction;
        if(ok) ++pass; else ++fail;
    }
    printf("{\"mode\":\"z80-stream\",\"seed\":\"5a383053\",\"denominator\":%u,\"pass\":%u,\"fail\":%u,\"unknown\":%u,\"skipped\":%u,\"stops\":{\"target\":%u,\"field_complete\":%u,\"unsupported_address\":%u,\"unsupported_state\":%u,\"unsupported_instruction\":%u}}\n",
           ITERATIONS,pass,fail,unknown,skipped,target,field,address,state_stop,instruction);
    return fail?1:0;
}

static int audio_calls_mode(void)
{
    enum { ITERATIONS=256 };
    unsigned pass=0,fail=0,unknown=0,skipped=0;
    state=0x41554443u;
    for(unsigned i=0;i<ITERATIONS;++i) {
        uint32_t rate=(i%10u==0u)?0u:(i%10u==1u)?GW_AUDIO_MIN_RATE_HZ-1u:
            (i%10u==2u)?GW_AUDIO_MIN_RATE_HZ:(i%10u==3u)?GW_AUDIO_MAX_RATE_HZ:
            (i%10u==4u)?GW_AUDIO_MAX_RATE_HZ+1u:(i%10u==5u)?UINT32_MAX:
            GW_AUDIO_MIN_RATE_HZ+next()%(GW_AUDIO_MAX_RATE_HZ-GW_AUDIO_MIN_RATE_HZ+1u);
        gw_config c={sizeof(c),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,GW_RESET_DETERMINISTIC_ZERO,0,{0,0},rate};
        gw_machine *m=NULL; unsigned char rom[1024]; int ok=1;
        memset(rom,0,sizeof(rom)); { const unsigned char vectors[]={0,0xff,0xff,0,0,0,2,0}; memcpy(rom,vectors,8); rom[512]=0x60; rom[513]=0xfe; }
        gw_status created=gw_create(&c,&m);
        int valid_rate=rate==0 || (rate>=GW_AUDIO_MIN_RATE_HZ && rate<=GW_AUDIO_MAX_RATE_HZ);
        if((created==GW_OK)!=valid_rate) ok=0;
        if(created==GW_OK) {
            if(gw_load_rom(m,rom,sizeof(rom))!=GW_OK) ok=0;
            gw_status trace_config=gw_configure_audio_trace(m,1u+next()%GW_AUDIO_TRACE_CAPACITY);
            if(trace_config!=GW_OK) ok=0;
            {
                int16_t sentinel[2]={123,-456}; gw_audio_read_result invalid={0}, before;
                invalid.struct_size=sizeof(invalid); invalid.version=GW_API_VERSION+1u; before=invalid;
                if(gw_audio_read(m,sentinel,1,&invalid)!=GW_ERROR_VERSION || sentinel[0]!=123 ||
                   sentinel[1]!=-456 || memcmp(&before,&invalid,sizeof(invalid))!=0) ok=0;
            }
            uint64_t target=0, next_audio_index=0, previous_lost=0;
            for(unsigned call=0;call<6u && ok;++call) {
                gw_run_result run_result={0}; run_result.struct_size=sizeof(run_result); run_result.version=GW_API_VERSION;
                target+=(uint64_t)(1u+next()%2u)*GW_FIELD_TICKS;
                if(gw_run_until(m,target,&run_result)!=GW_OK) { ok=0; break; }
                gw_audio_write writes[GW_AUDIO_TRACE_CAPACITY]; size_t count=0; uint64_t dropped=0;
                size_t cap=(call==0u)?UINT32_MAX:(size_t)(next()%(GW_AUDIO_TRACE_CAPACITY+1u));
                gw_status trace;
                /* Capacity is stereo frames: reserve two samples per frame. */
                int16_t samples[2u * 128u]; gw_audio_read_result audio={0};
                audio.struct_size=sizeof(audio); audio.version=GW_API_VERSION;
                uint32_t capacity=(call==1u)?0u:(call==2u)?UINT32_MAX:1u+next()%128u;
                if(next()&1u) {
                    trace=gw_get_audio_writes(m,writes,cap,&count,&dropped);
                    if(capacity==UINT32_MAX) {
                        if(gw_audio_read(m,NULL,capacity,&audio)!=GW_ERROR_ARGUMENT) ok=0;
                    } else if(capacity==0u) {
                        int16_t sentinel[2]={123,-456}; gw_audio_read_result before=audio;
                        if(gw_audio_read(m,sentinel,capacity,&audio)!=GW_ERROR_ARGUMENT || sentinel[0]!=123 || sentinel[1]!=-456 || memcmp(&before,&audio,sizeof(audio))!=0) ok=0;
                    } else if(gw_audio_read(m,samples,capacity,&audio)!=GW_OK || audio.produced>capacity) ok=0;
                } else {
                    if(capacity==UINT32_MAX) {
                        if(gw_audio_read(m,NULL,capacity,&audio)!=GW_ERROR_ARGUMENT) ok=0;
                    } else if(capacity==0u) {
                        int16_t sentinel[2]={123,-456}; gw_audio_read_result before=audio;
                        if(gw_audio_read(m,sentinel,capacity,&audio)!=GW_ERROR_ARGUMENT || sentinel[0]!=123 || sentinel[1]!=-456 || memcmp(&before,&audio,sizeof(audio))!=0) ok=0;
                    } else if(gw_audio_read(m,samples,capacity,&audio)!=GW_OK || audio.produced>capacity) ok=0;
                    trace=gw_get_audio_writes(m,writes,cap,&count,&dropped);
                }
                if(trace!=GW_OK && trace!=GW_ERROR_CAPACITY) ok=0;
                if(trace==GW_OK && (count>cap || (cap && count && writes[0].tick>run_result.actual_tick))) ok=0;
                if(capacity && capacity!=UINT32_MAX && audio.struct_size==sizeof(audio)) {
                    if(audio.lost<previous_lost ||
                       audio.first_index!=next_audio_index+(audio.lost-previous_lost) ||
                       audio.mix_id!=GW_AUDIO_MIX_V1) ok=0;
                    next_audio_index=audio.first_index+audio.produced;
                    previous_lost=audio.lost;
                }
            }
            gw_destroy(m);
        }
        if(ok) ++pass; else { ++fail; fprintf(stderr,"audio-calls: case %u rate %u failed\n",i,rate); }
    }
    printf("{\"mode\":\"audio-calls\",\"seed\":\"41554443\",\"denominator\":%u,\"pass\":%u,\"fail\":%u,\"unknown\":%u,\"skipped\":%u}\n",
           ITERATIONS,pass,fail,unknown,skipped);
    return fail?1:0;
}

typedef struct safety_options {
    uint32_t seed, cases, output_cap;
    uint64_t step_budget, tick_budget;
} safety_options;

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;
    if (!text || !*text || *text == '-') return 0;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno || !end || *end) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

static int safety_mode(int argc, char **argv)
{
    safety_options options = { UINT32_C(0x47573105), 16u, 128u, 8u, 180000u };
    unsigned pass = 0, fail = 0, guards = 0, returned = 0, steps = 0;
    uint64_t max_tick = 0, alloc_peak = 0, steady_allocations = 0;
    int instrumented = 0;
    for (int i = 2; i < argc; ++i) {
        uint64_t value;
        if (i + 1 >= argc || !parse_u64(argv[++i], &value)) return 2;
        if (!strcmp(argv[i - 1], "--seed") && value <= UINT32_MAX) options.seed = (uint32_t)value;
        else if (!strcmp(argv[i - 1], "--cases") && value > 0 && value <= 4096) options.cases = (uint32_t)value;
        else if (!strcmp(argv[i - 1], "--step-budget") && value > 0 && value <= 64) options.step_budget = value;
        else if (!strcmp(argv[i - 1], "--tick-budget") && value > 0 && value <= GW_MAX_TARGET_TICK) options.tick_budget = value;
        else if (!strcmp(argv[i - 1], "--output-cap") && value > 0 && value <= 256) options.output_cap = (uint32_t)value;
        else return 2;
    }
    state = options.seed ? options.seed : UINT32_C(0x9e3779b9);
    for (uint32_t i = 0; i < options.cases; ++i) {
        uint8_t rom[1024], control_ram[GW_RAM_SIZE], candidate_ram[GW_RAM_SIZE];
        int16_t guarded[2u * 256u + 2u];
        gw_config config = { sizeof(config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
            GW_RESET_DETERMINISTIC_ZERO, 0, { GW_DEVICE_PAD3, GW_DEVICE_PAD3 }, GW_AUDIO_MIN_RATE_HZ };
        gw_machine *candidate = NULL, *control = NULL;
        int ok = 1;
        uint64_t alloc_before = 0, alloc_after = 0;
        memset(rom, 0, sizeof(rom));
        { const uint8_t vectors[] = { 0,0xff,0xff,0,0,0,2,0 };
          memcpy(rom, vectors, sizeof(vectors)); rom[512] = 0x60; rom[513] = 0xfe; }
        if (gw_create(&config, &candidate) != GW_OK || gw_create(&config, &control) != GW_OK ||
            gw_load_rom(candidate, rom, sizeof(rom)) != GW_OK || gw_load_rom(control, rom, sizeof(rom)) != GW_OK) {
            gw_destroy(candidate); gw_destroy(control); ++fail; continue;
        }
#ifdef GW_TEST_HOOKS
        instrumented = 1;
        alloc_before = gw_test_allocation_count(candidate);
        if (alloc_before > 2u) ok = 0;
#endif
        for (uint64_t step = 0; step < options.step_budget && ok; ++step) {
            const size_t bad_sizes[] = { 0u, 1u, GW_MIN_ROM_SIZE - 1u, GW_MAX_ROM_SIZE + 1u, SIZE_MAX };
            const size_t bad_size = bad_sizes[next() % (sizeof(bad_sizes) / sizeof(bad_sizes[0]))];
            if (gw_load_rom(candidate, rom, bad_size) != GW_ERROR_ROM) ok = 0;
            ++steps;
            /* A rejected load promises no mutation; compare future public observations. */
            {
                gw_run_result a = {0}, b = {0};
                const uint64_t usable_ticks = options.tick_budget > 1024u ? options.tick_budget - 1024u : options.tick_budget;
                const uint64_t target = (step + 1u) * (usable_ticks / options.step_budget);
                a.struct_size = b.struct_size = sizeof(a); a.version = b.version = GW_API_VERSION;
                a.flags = b.flags = GW_RUN_CONTINUE_PAST_FIELD;
                if (gw_run_until(candidate, target, &a) != GW_OK || gw_run_until(control, target, &b) != GW_OK ||
                    a.actual_tick != b.actual_tick || a.stop_reason != b.stop_reason ||
                    a.instruction_address != b.instruction_address || a.opcode != b.opcode) ok = 0;
                if (a.actual_tick > max_tick) max_tick = a.actual_tick;
            }
        }
        if (gw_peek_memory(candidate, 0xff0000u, candidate_ram, sizeof(candidate_ram)) != GW_OK ||
            gw_peek_memory(control, 0xff0000u, control_ram, sizeof(control_ram)) != GW_OK ||
            memcmp(candidate_ram, control_ram, sizeof(candidate_ram)) != 0) ok = 0;
        memset(guarded, 0x5a, sizeof(guarded));
        {
            int16_t control_samples[2u * 256u];
            gw_audio_read_result result = {0}, control_result = {0};
            result.struct_size = control_result.struct_size = sizeof(result);
            result.version = control_result.version = GW_API_VERSION;
            memset(control_samples, 0x5a, sizeof(control_samples));
            if (gw_audio_read(candidate, &guarded[1], options.output_cap, &result) != GW_OK ||
                gw_audio_read(control, control_samples, options.output_cap, &control_result) != GW_OK ||
                result.produced > options.output_cap || result.produced > GW_AUDIO_QUEUE_FRAMES ||
                result.produced != control_result.produced || result.first_index != control_result.first_index ||
                result.lost != control_result.lost ||
                memcmp(&guarded[1], control_samples, (size_t)result.produced * 2u * sizeof(int16_t)) != 0) ok = 0;
            ++guards;
            if (guarded[0] != (int16_t)0x5a5a || guarded[2u * 256u + 1u] != (int16_t)0x5a5a) ok = 0;
            returned += result.produced;
        }
#ifdef GW_TEST_HOOKS
        alloc_after = gw_test_allocation_count(candidate);
        if (alloc_after > 2u) ok = 0;
        if (alloc_after != alloc_before) ++steady_allocations;
        if (alloc_after > alloc_peak) alloc_peak = alloc_after;
#else
        (void)alloc_before; (void)alloc_after;
#endif
        gw_destroy(candidate); gw_destroy(control);
        if (ok) ++pass; else { ++fail; fprintf(stderr, "safety: case %" PRIu32 " failed\n", i); }
    }
    printf("{\"mode\":\"safety\",\"seed\":\"%08" PRIx32 "\",\"denominator\":%" PRIu32
           ",\"pass\":%u,\"fail\":%u,\"unknown\":0,\"skipped\":0,\"step_budget\":%" PRIu64
           ",\"steps\":%u,\"tick_budget\":%" PRIu64 ",\"max_tick\":%" PRIu64
           ",\"output_cap\":%" PRIu32 ",\"returned_frames\":%u,\"guards_checked\":%u,"
           "\"continuation_match\":%s,\"allocation_instrumented\":%s,\"allocation_count_peak\":%" PRIu64
           ",\"steady_allocations\":%" PRIu64 "}\n",
           options.seed, options.cases, pass, fail, options.step_budget, steps, options.tick_budget,
           max_tick, options.output_cap, returned, guards, fail ? "false" : "true",
           instrumented ? "true" : "false", alloc_peak, steady_allocations);
    return fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc==1) return load_mode();
    if (argc>=2 && strcmp(argv[1],"safety")==0) return safety_mode(argc,argv);
    if (argc==2 && strcmp(argv[1],"vdp-stream")==0) return vdp_stream_mode();
    if (argc==2 && strcmp(argv[1],"sprite-table")==0) return sprite_table_mode();
    if (argc==2 && strcmp(argv[1],"z80-stream")==0) return z80_stream_mode();
    if (argc==2 && strcmp(argv[1],"audio-calls")==0) return audio_calls_mode();
    fputs("usage: gw_bounded_fuzz [safety --seed N --cases N --step-budget N --tick-budget N --output-cap N|vdp-stream|sprite-table|z80-stream|audio-calls]\n",stderr);
    return 2;
}
