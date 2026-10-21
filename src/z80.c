/* SPDX-License-Identifier: MIT
 * Original, deliberately small Z80 implementation. State transitions follow
 * Zilog UM0080; vector data is separately licensed and never supplies code.
 */
#include "internal.h"
#include "z80.h"

enum { Z80_M1 = 0, Z80_MEM_READ = 1, Z80_MEM_WRITE = 2, Z80_IO_READ = 3, Z80_IO_WRITE = 4, Z80_INTERNAL = 5, Z80_REFRESH = 6 };

static uint8_t hi(uint16_t v) { return (uint8_t)(v >> 8); }
static uint8_t lo(uint16_t v) { return (uint8_t)v; }
static uint16_t *pair(gw_z80 *z, unsigned n)
{
    switch (n & 3u) { case 0: return &z->bc; case 1: return &z->de; case 2: return &z->hl; default: return &z->sp; }
}
static void retire(gw_z80 *z)
{ if(z->index_active==1u){uint16_t *index=z->prefix==0xddu?&z->ix:&z->iy;uint16_t t=z->hl;z->hl=*index;*index=t;}else if(z->index_active==2u)z->hl=z->temporary_pc;z->index_active=0;z->q = 0; if(z->ei_delay) --z->ei_delay; z->instruction_active = 0; z->retired = 1; z->cycle_kind = 0; z->stage = 0; z->pending_cycles=0; z->prefix=0;z->prefix_count=0; }
static uint8_t get_reg(const gw_z80 *z, unsigned n)
{
    if (z->index_active==2u && (n&7u)==4u) return (uint8_t)(z->temporary_pc>>8);
    if (z->index_active==2u && (n&7u)==5u) return (uint8_t)z->temporary_pc;
    switch (n & 7u) {
    case 0: return hi(z->bc); case 1: return lo(z->bc);
    case 2: return hi(z->de); case 3: return lo(z->de);
    case 4: return hi(z->hl); case 5: return lo(z->hl);
    case 7: return hi(z->af); default: return 0;
    }
}
static void set_reg(gw_z80 *z, unsigned n, uint8_t v)
{
    if (z->index_active==2u && (n&7u)==4u) { z->temporary_pc=(uint16_t)(((uint32_t)v<<8)|((uint32_t)z->temporary_pc&0xffu)); return; }
    if (z->index_active==2u && (n&7u)==5u) { z->temporary_pc=(uint16_t)((z->temporary_pc&0xff00u)|v); return; }
    if ((n & 7u) == 7u) { z->af = (uint16_t)(((uint32_t)v << 8) | ((uint32_t)z->af & 0xffu)); return; }
    uint16_t *pair = NULL;
    switch (n & 7u) {
    case 0: pair = &z->bc; break; case 1: pair = &z->bc; break;
    case 2: pair = &z->de; break; case 3: pair = &z->de; break;
    case 4: pair = &z->hl; break; case 5: pair = &z->hl; break;
    case 7: pair = &z->af; break; default: return;
    }
    *pair = (uint16_t)((n & 1u) ? (((uint32_t)*pair & 0xff00u) | v) : (((uint32_t)v << 8) | ((uint32_t)*pair & 0xffu)));
}
enum { F_C=1u,F_N=2u,F_PV=4u,F_X=8u,F_H=16u,F_Y=32u,F_Z=64u,F_S=128u };
static unsigned parity(uint8_t v)
{ v^=(uint8_t)(v>>4);v&=15u;return (unsigned)((UINT16_C(0x6996)>>v)&1u)^1u; }
static uint8_t szp(uint8_t v)
{ return (uint8_t)((v&(F_S|F_Y|F_X))|(v==0?F_Z:0)|(parity(v)?F_PV:0)); }
static void alu(gw_z80 *z,unsigned kind,uint8_t value)
{
    uint8_t a=hi(z->af),oldf=lo(z->af),result=0,f=0;unsigned carry=oldf&F_C;
    switch(kind&7u){
    case 0: case 1:{unsigned c=(kind&1u)?carry:0u;unsigned sum=(unsigned)a+value+c;result=(uint8_t)sum;f=(uint8_t)(result&(F_S|F_Y|F_X));if(!result)f|=F_Z;if(((a^value^result)&0x10u)!=0)f|=F_H;if(((~(a^value)&(a^result))&0x80u)!=0)f|=F_PV;if(sum>255u)f|=F_C;break;}
    case 2: case 3: case 7:{unsigned c=(kind==3u)?carry:0u;unsigned sub=(unsigned)value+c;result=(uint8_t)(a-sub);f=(uint8_t)((result&(F_S|F_Y|F_X))|F_N);if(!result)f|=F_Z;if(((a^value^result)&0x10u)!=0)f|=F_H;if((((a^value)&(a^result))&0x80u)!=0)f|=F_PV;if((unsigned)a<sub)f|=F_C;if(kind==7u)result=a;break;}
    case 4: result=(uint8_t)(a&value);f=(uint8_t)(szp(result)|F_H);break;
    case 5: result=(uint8_t)(a^value);f=szp(result);break;
    default: result=(uint8_t)(a|value);f=szp(result);break;
    }
    if((kind&7u)!=7u)z->af=(uint16_t)(((uint16_t)result<<8)|f);else z->af=(uint16_t)(((uint16_t)a<<8)|f);
}
static int condition(const gw_z80 *z,unsigned c)
{
    uint8_t f=lo(z->af);switch(c&7u){case 0:return !(f&F_Z);case 1:return (f&F_Z)!=0;case 2:return !(f&F_C);case 3:return (f&F_C)!=0;case 4:return !(f&F_PV);case 5:return (f&F_PV)!=0;case 6:return !(f&F_S);default:return (f&F_S)!=0;}
}

#ifdef GW_TEST_HOOKS
static int overlay_find(const gw_machine *m, uint16_t a)
{
    for (size_t i = 0; i < m->z80_overlay_count; ++i)
        if (m->z80_overlay[i].address == a) return (int)i;
    return -1;
}
static int port_find(const gw_machine *m, uint16_t a)
{
    for (size_t i = 0; i < m->z80_port_count; ++i)
        if (m->z80_ports[i].address == a) return (int)i;
    return -1;
}
static void transaction(gw_machine *m, uint8_t type, uint16_t address, uint8_t data, uint8_t t)
{
    /* The bounded cycle log is a vector-adapter oracle only. Real guest
     * execution must never stop merely because diagnostic observations filled. */
    if (!m->z80_overlay_active) return;
    if (m->z80_transaction_count < sizeof(m->z80_transactions) / sizeof(m->z80_transactions[0])) {
        gw_test_z80_transaction *row = &m->z80_transactions[m->z80_transaction_count++];
        row->type = type; row->address = address; row->data = data; row->t_states = t;
    } else {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_STATE;
    }
}
#else
static void transaction(gw_machine *m, uint8_t type, uint16_t address, uint8_t data, uint8_t t)
{ (void)m; (void)type; (void)address; (void)data; (void)t; }
#endif

static int z80_fault(gw_machine *m, uint32_t reason, uint16_t address, uint16_t opcode)
{
    m->cpu.stop_reason = reason;
    m->cpu.fault_address = UINT32_C(0x40000000) | address;
    m->cpu.opcode = opcode;
    return 0;
}

static int mem_read(gw_machine *m, uint16_t address, uint8_t *value, uint8_t cycle, uint8_t t)
{
#ifdef GW_TEST_HOOKS
    if (m->z80_overlay_active) {
        int at = overlay_find(m, address);
        if (at < 0) { m->z80_overlay_miss = 1; m->z80_overlay_miss_address = address;
            return z80_fault(m, GW_STOP_UNSUPPORTED_ADDRESS, address, m->z80.opcode); }
        *value = m->z80_overlay[at].value;
        transaction(m, cycle, address, *value, t);
        return 1;
    }
#endif
    if (address < UINT16_C(0x4000)) {
        *value = m->z80.ram[address & UINT16_C(0x1fff)];
        transaction(m, cycle, address, *value, t);
        return 1;
    }
    if (!gw_z80_mem_read(m, address, value, cycle, t)) return 0;
    transaction(m, cycle, address, *value, t);
    return 1;
}

static int mem_write(gw_machine *m, uint16_t address, uint8_t value, uint8_t t)
{
#ifdef GW_TEST_HOOKS
    if (m->z80_overlay_active) {
        int at = overlay_find(m, address);
        if (at < 0) {
            if (m->z80_overlay_count == GW_TEST_MEMORY_CAPACITY) {
                m->z80_overlay_miss = 1; m->z80_overlay_miss_address = address;
                return z80_fault(m, GW_STOP_UNSUPPORTED_ADDRESS, address, m->z80.opcode);
            }
            at = (int)m->z80_overlay_count++;
            m->z80_overlay[at].address = address;
        }
        m->z80_overlay[at].value = value;
        transaction(m, Z80_MEM_WRITE, address, value, t);
        return 1;
    }
#endif
    if (address < UINT16_C(0x4000)) {
        m->z80.ram[address & UINT16_C(0x1fff)] = value;
        transaction(m, Z80_MEM_WRITE, address, value, t);
        return 1;
    }
    if (!gw_z80_mem_write(m, address, value, t)) return 0;
    transaction(m, Z80_MEM_WRITE, address, value, t);
    return 1;
}
static int stack_read(gw_machine *m, uint8_t *v)
{
    gw_z80 *z=&m->z80;if(!mem_read(m,z->sp,v,Z80_MEM_READ,3))return 0;
    z->sp=(uint16_t)(z->sp+1u);z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;return 1;
}
static int stack_write(gw_machine *m, uint8_t v)
{
    gw_z80 *z=&m->z80;z->sp=(uint16_t)(z->sp-1u);
    if(!mem_write(m,z->sp,v,3)){z->sp=(uint16_t)(z->sp+1u);return 0;}
    z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;return 1;
}
static int io_read(gw_machine *m,uint16_t address,uint8_t *v)
{
#ifndef GW_TEST_HOOKS
    (void)v;
#endif
#ifdef GW_TEST_HOOKS
    if(m->z80_overlay_active){int i=port_find(m,address);if(i<0)return z80_fault(m,GW_STOP_UNSUPPORTED_ADDRESS,address,m->z80.opcode);*v=m->z80_ports[i].value;transaction(m,Z80_IO_READ,address,*v,4);return 1;}
#endif
    return gw_z80_io_read(m, address, v);
}
static int io_write(gw_machine *m,uint16_t address,uint8_t v)
{
#ifndef GW_TEST_HOOKS
    (void)v;
#endif
#ifdef GW_TEST_HOOKS
    if(m->z80_overlay_active){int i=port_find(m,address);if(i<0){if(m->z80_port_count==GW_TEST_MEMORY_CAPACITY)return z80_fault(m,GW_STOP_UNSUPPORTED_ADDRESS,address,m->z80.opcode);i=(int)m->z80_port_count++;m->z80_ports[i].address=address;}m->z80_ports[i].value=v;transaction(m,Z80_IO_WRITE,address,v,4);return 1;}
#endif
    return gw_z80_io_write(m, address, v);
}

static int read_pc(gw_machine *m, uint8_t *v)
{
    gw_z80 *z = &m->z80;
    if (!mem_read(m, z->pc, v, Z80_MEM_READ, 3)) return 0;
    ++z->pc; z->next_cycle_tick += UINT64_C(3) * GW_Z80_DIVIDER; return 1;
}

void gw_z80_cold_init(gw_z80 *z)
{
    memset(z, 0, sizeof(*z));
    z->af = z->bc = z->de = z->hl = UINT16_C(0xffff);
    z->af_alt = z->bc_alt = z->de_alt = z->hl_alt = UINT16_C(0xffff);
    z->ix = z->iy = z->sp = z->wz = UINT16_C(0xffff);
    z->reset_asserted = 1;
}

void gw_z80_console_reset(gw_z80 *z)
{
    uint8_t ram[GW_Z80_RAM_SIZE];
    memcpy(ram, z->ram, sizeof(ram));
    gw_z80_cold_init(z);
    memcpy(z->ram, ram, sizeof(ram));
}

int gw_z80_at_boundary(const gw_z80 *z) { return z && !z->instruction_active; }

int gw_z80_cycle(gw_machine *m)
{
    gw_z80 *z = &m->z80;
    uint8_t op;
    if (z->reset_asserted || z->busreq) return 1;
    if (m->cpu.stop_reason != GW_STOP_TARGET) return 0;
    /* Secondary opcode fetches are independent M1 cycles. Keep all decoder
     * state in gw_z80 so arbitration can pause safely between prefix bytes. */
    if (z->instruction_active && z->stage == 60u) {
        uint16_t fetch = z->pc;
        uint8_t prior_r = z->r;
        if (!mem_read(m, fetch, &op, Z80_M1, 4)) return 0;
        ++z->pc;
        transaction(m, Z80_REFRESH, (uint16_t)(((uint16_t)z->i << 8) | prior_r), 0, 0);
        z->r = (uint8_t)((z->r & 0x80u) | ((z->r + 1u) & 0x7fu));
        z->next_cycle_tick += UINT64_C(4) * GW_Z80_DIVIDER;
        z->subopcode = op;
        if (z->prefix == 0xcbu) {
            unsigned r = op & 7u;
            if ((op >> 6) == 1u && r != 6u) {
                uint8_t value=get_reg(z,r),f=(uint8_t)((lo(z->af)&F_C)|F_H);
                if (!(value&(1u<<((op>>3)&7u)))) f|=F_Z|F_PV;
                if (((op>>3)&7u)==7u && (value&0x80u)) f|=F_S;
                f|=(uint8_t)(value&(F_X|F_Y));
                z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f); retire(z); return 1;
            }
            if (r == 6u) { z->stage=61u; z->cycle_kind=Z80_MEM_READ; return 1; }
            uint8_t value=get_reg(z,r),result=value,carry=0,f=0;
            unsigned group=op>>6,bit=(op>>3)&7u;
            if (group==0u) {
                switch(bit) {
                case 0: carry=(uint8_t)(value>>7);result=(uint8_t)((value<<1)|carry);break;
                case 1: carry=(uint8_t)(value&1u);result=(uint8_t)((value>>1)|(carry<<7));break;
                case 2: carry=(uint8_t)(value>>7);result=(uint8_t)((value<<1)|(lo(z->af)&F_C));break;
                case 3: carry=(uint8_t)(value&1u);result=(uint8_t)((value>>1)|((lo(z->af)&F_C)<<7));break;
                case 4: carry=(uint8_t)(value>>7);result=(uint8_t)(value<<1);break;
                case 5: carry=(uint8_t)(value&1u);result=(uint8_t)((value>>1)|(value&0x80u));break;
                case 6: carry=(uint8_t)(value>>7);result=(uint8_t)(((unsigned)value<<1)|1u);break;
                default: carry=(uint8_t)(value&1u);result=(uint8_t)(value>>1);break;
                }
                f=(uint8_t)(szp(result)&~(F_Y|F_X));if(carry)f|=F_C;
                set_reg(z,r,result);z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);
            } else if (group==2u) set_reg(z,r,(uint8_t)(value&~(1u<<bit)));
            else set_reg(z,r,(uint8_t)(value|(1u<<bit)));
            retire(z); return 1;
        }
        if (z->prefix == 0xedu) {
            unsigned edop=op;
            if ((edop&0xc7u)==0x40u || (edop&0xc7u)==0x41u) {
                if ((edop&0xc7u)==0x41u && ((edop>>3)&7u)==6u)
                    return z80_fault(m,GW_STOP_UNSUPPORTED_INSTRUCTION,(uint16_t)(fetch-1u),0xed00u|op);
                z->stage=68u;return 1;
            }
            if ((edop&0xcfu)==0x43u || (edop&0xcfu)==0x4bu) { z->stage=78u;return 1; }
            if ((edop&0xcfu)==0x42u || (edop&0xcfu)==0x4au) { z->stage=69u;return 1; }
            if (edop==0x44u) { uint8_t a=hi(z->af),r=(uint8_t)(0u-a),f=(uint8_t)(F_N|(r&(F_S|F_Y|F_X)));if(!r)f|=F_Z;if(a&15u)f|=F_H;if(a==0x80u)f|=F_PV;if(a)f|=F_C;z->af=(uint16_t)(((uint16_t)r<<8)|f);retire(z);return 1; }
            if (edop==0x45u || edop==0x4du) { z->stage=70u;return 1; }
            if (edop==0x46u || edop==0x56u || edop==0x5eu) { z->im=edop==0x46u?0u:edop==0x56u?1u:2u;retire(z);return 1; }
            if (edop==0x47u || edop==0x4fu) { if(edop==0x47u)z->i=hi(z->af);else z->r=hi(z->af);z->next_cycle_tick+=GW_Z80_DIVIDER;retire(z);return 1; }
            if (edop==0x57u || edop==0x5fu) { uint8_t v=edop==0x57u?z->i:z->r;uint8_t f=(uint8_t)((lo(z->af)&F_C)|(v&(F_S|F_Y|F_X))|(v?0:F_Z)|(z->iff2?F_PV:0));z->af=(uint16_t)(((uint16_t)v<<8)|f);z->next_cycle_tick+=GW_Z80_DIVIDER;retire(z);return 1; }
            if (edop==0x67u || edop==0x6fu) { z->stage=71u;return 1; }
            /* Block instructions retire one iteration at a time. Repeating
             * forms rewind PC after the documented extra machine cycle. */
            if (edop==0xa0u||edop==0xa8u||edop==0xb0u||edop==0xb8u||
                edop==0xa1u||edop==0xa9u||edop==0xb1u||edop==0xb9u||
                edop==0xa2u||edop==0xaau||edop==0xb2u||edop==0xbau||
                edop==0xa3u||edop==0xabu||edop==0xb3u||edop==0xbbu) {
                z->stage=74u;return 1;
            }
            z->instruction_active=0;
            return z80_fault(m,GW_STOP_UNSUPPORTED_INSTRUCTION,(uint16_t)(fetch-1u),0xed00u|op);
        }
        if (z->prefix==0xddu || z->prefix==0xfdu) {
            if(op==0xddu || op==0xfdu){z->prefix=op;++z->prefix_count;return 1;}
            /* DD/FD before ED is ignored. Restore the previous index state
             * before entering the ED decoder on its own prefetched opcode. */
            if(op==0xedu){z->prefix=0xedu;z->prefix_count=1;z->stage=60u;return 1;}
            if(op==0xcbu){z->stage=83u;return 1;}
            if(op==0x34u||op==0x35u||op==0x36u||((op>=0x40u&&op<=0x7fu)&&(((op&7u)==6u)||(((op>>3)&7u)==6u)))||(op>=0x80u&&op<=0xbfu&&(op&7u)==6u)) {z->stage=82u;return 1;}
            uint16_t *index=z->prefix==0xddu?&z->ix:&z->iy;uint16_t t=z->hl;z->hl=*index;*index=t;
            z->index_active=1;z->prefetched=1;z->instruction_active=0;return 1;
        }
        z->instruction_active=0;
        return z80_fault(m,GW_STOP_UNSUPPORTED_INSTRUCTION,(uint16_t)(fetch-1u),
                         (uint16_t)(((uint16_t)z->prefix<<8)|op));
    }
    if (!z->instruction_active) {
        uint16_t fetch;
        if(z->prefetched){fetch=(uint16_t)(z->pc-1u);op=z->subopcode;z->prefetched=0;z->stage=0;}
        else {fetch = z->halted?(uint16_t)(z->pc-1u):z->pc;uint8_t prior_r = z->r;
            if (!mem_read(m, fetch, &op, Z80_M1, 4)) return 0;
            if(!z->halted)++z->pc;
            transaction(m, Z80_REFRESH, (uint16_t)(((uint16_t)z->i << 8) | prior_r), 0, 0);
            z->r = (uint8_t)((z->r & 0x80u) | ((z->r + 1u) & 0x7fu));
            z->next_cycle_tick += UINT64_C(4) * GW_Z80_DIVIDER;
        }
        z->opcode = op; z->instruction_active = 1; z->micro_op = 1; z->retired = 0;
        if(z->halted){retire(z);return 1;}
        if (op==0xcbu || op==0xedu || op==0xddu || op==0xfdu) {
            z->prefix=op;z->prefix_count=1;z->effective_address=fetch;z->stage=60u;return 1;
        }
        z->source_reg = (uint8_t)(op & 7u); z->destination_reg = (uint8_t)((op >> 3) & 7u);
        if (op == 0x00u) { retire(z); return 1; }
        if (op >= 0x40u && op <= 0x7fu && op != 0x76u && z->source_reg != 6u && z->destination_reg != 6u) {
            set_reg(z, z->destination_reg, get_reg(z, z->source_reg));
            retire(z); return 1;
        }
        if (op >= 0x40u && op <= 0x7fu && op != 0x76u && z->source_reg == 6u) {
            z->cycle_kind = Z80_MEM_READ;
            return 1;
        }
        if (op >= 0x40u && op <= 0x7fu && op != 0x76u && z->destination_reg == 6u) {
            z->cycle_kind = Z80_MEM_WRITE;
            return 1;
        }
        if (op>=0x80u && op<=0xbfu) {
            if((op&7u)==6u){z->stage=31;z->cycle_kind=Z80_MEM_READ;return 1;}
            alu(z,(op>>3)&7u,get_reg(z,op&7u));retire(z);return 1;
        }
        if((op&0xc7u)==0xc6u){z->stage=30;z->cycle_kind=Z80_MEM_READ;return 1;}
        if(op==0x10u || op==0x18u || (op>=0x20u&&op<=0x38u&&(op&0xe7u)==0x20u)) {z->stage=40;z->cycle_kind=Z80_MEM_READ;return 1;}
        if(op==0xc3u || op==0xcdu || (op>=0xc2u&&op<=0xfau&&(op&0xc7u)==0xc2u) || (op>=0xc4u&&op<=0xfcu&&(op&0xc7u)==0xc4u)) {z->stage=41;z->cycle_kind=Z80_MEM_READ;return 1;}
        if(op==0xc9u || (op>=0xc0u&&op<=0xf8u&&(op&0xc7u)==0xc0u)) {if(op!=0xc9u&&!condition(z,(op>>3)&7u)){z->stage=42;z->cycle_kind=Z80_INTERNAL;return 1;}if(op!=0xc9u){z->stage=53;z->cycle_kind=Z80_INTERNAL;return 1;}z->stage=43;z->cycle_kind=Z80_MEM_READ;return 1;}
        if((op&0xc7u)==0xc7u){z->temporary_pc=z->pc;z->stage=44;z->cycle_kind=Z80_INTERNAL;return 1;}
        if((op&0xc7u)==0x04u || (op&0xc7u)==0x05u){
            unsigned r=(op>>3)&7u;uint8_t old=(r==6u)?0:get_reg(z,r);
            if(r==6u){z->stage=32;z->cycle_kind=Z80_MEM_READ;return 1;}
            unsigned dec=op&1u;uint8_t result=(uint8_t)(old+(dec?255u:1u));uint8_t f=(uint8_t)(lo(z->af)&F_C);
            f|=(uint8_t)(result&(F_S|F_Y|F_X));if(!result)f|=F_Z;
            if(dec){f|=F_N;if((old&15u)==0)f|=F_H;if(old==0x80u)f|=F_PV;}else{if((old&15u)==15u)f|=F_H;if(old==0x7fu)f|=F_PV;}
            set_reg(z,r,result);z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);retire(z);return 1;
        }
        if((op&0xcfu)==0x03u || (op&0xcfu)==0x0bu){uint16_t *p=pair(z,op>>4);*p=(uint16_t)(*p+((op&8u)?UINT16_MAX:1u));z->stage=33;z->cycle_kind=Z80_INTERNAL;return 1;}
        if(op==0x07u||op==0x0fu||op==0x17u||op==0x1fu){uint8_t a=hi(z->af),f=lo(z->af),c=0;switch(op){case 0x07:c=(uint8_t)(a>>7);a=(uint8_t)((a<<1)|c);break;case 0x0f:c=a&1u;a=(uint8_t)((a>>1)|(c<<7));break;case 0x17:c=(uint8_t)(a>>7);a=(uint8_t)((a<<1)|(f&F_C));break;default:c=a&1u;a=(uint8_t)((a>>1)|((f&F_C)<<7));break;}f=(uint8_t)((f&(F_S|F_Z|F_PV))|(a&(F_Y|F_X))|c);z->af=(uint16_t)(((uint16_t)a<<8)|f);retire(z);return 1;}
        if(op==0x2fu){uint8_t a=(uint8_t)~hi(z->af),f=(uint8_t)((lo(z->af)&(F_S|F_Z|F_PV|F_C))|F_H|F_N|(a&(F_Y|F_X)));z->af=(uint16_t)(((uint16_t)a<<8)|f);retire(z);return 1;}
        if(op==0x37u||op==0x3fu){uint8_t f=lo(z->af),oldc=(uint8_t)(f&F_C);f=(uint8_t)((f&(F_S|F_Z|F_PV))|(hi(z->af)&(F_Y|F_X)));if(op==0x37u)f|=F_C;else {if(oldc)f|=F_H;else f|=F_C;}z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);retire(z);return 1;}
        if(op==0x27u){uint8_t olda=hi(z->af),a=olda,f=lo(z->af),adjust=0;int sub=(f&F_N)!=0,carry=(f&F_C)!=0,half=(f&F_H)!=0;if(half||(a&15u)>9u)adjust|=6;if(carry||a>0x99u){adjust|=0x60;carry=1;}a=(uint8_t)(sub?a-adjust:a+adjust);f=(uint8_t)((f&F_N)|(carry?F_C:0)|(((olda^a^adjust)&0x10u)?F_H:0)|szp(a));z->af=(uint16_t)(((uint16_t)a<<8)|f);retire(z);return 1;}
        if((op&0xcfu)==0x09u){uint32_t sum=(uint32_t)z->hl+*pair(z,op>>4);uint16_t result=(uint16_t)sum;uint8_t f=(uint8_t)((lo(z->af)&(F_S|F_Z|F_PV))|(hi(result)&(F_Y|F_X)));if(((z->hl^*pair(z,op>>4)^result)&0x1000u)!=0)f|=F_H;if(sum>0xffffu)f|=F_C;z->hl=result;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);z->stage=33;z->cycle_kind=Z80_INTERNAL;return 1;}
        if(op==0xf3u){z->iff1=0;z->iff2=0;z->ei_delay=0;retire(z);return 1;}
        if(op==0xfbu){z->iff1=1;z->iff2=1;z->ei_delay=2;retire(z);return 1;}
        if(op==0xe9u){z->pc=z->hl;z->wz=z->hl;retire(z);return 1;}
        if(op==0xd3u||op==0xdbu){z->stage=51;z->cycle_kind=Z80_MEM_READ;return 1;}
        if(op==0xf9u){z->sp=z->hl;z->stage=33;z->cycle_kind=Z80_INTERNAL;return 1;}
        if(op==0x76u){z->halted=1;retire(z);return 1;}
        /* Decode the unprefixed forms described by ZiLOG UM0080, Chapter 4,
         * Table 4-1 and the instruction entries; HALT repetition follows
         * Figure 7 (PDF p. 36). This is an original implementation. */
        if ((op & 0xc7u) == 0x06u || (op & 0xcfu) == 0x01u ||
            op == 0x02u || op == 0x0au || op == 0x12u || op == 0x1au ||
            op == 0x22u || op == 0x2au || op == 0x32u || op == 0x3au) {
            z->stage = 1; z->cycle_kind = Z80_MEM_READ; return 1;
        }
        if (op == 0x08u) { uint16_t t=z->af; z->af=z->af_alt; z->af_alt=t; retire(z); return 1; }
        if (op == 0xd9u) { uint16_t t=z->bc;z->bc=z->bc_alt;z->bc_alt=t;t=z->de;z->de=z->de_alt;z->de_alt=t;t=z->hl;z->hl=z->hl_alt;z->hl_alt=t;retire(z);return 1; }
        if (op == 0xebu) { uint16_t t=z->de;z->de=z->hl;z->hl=t;retire(z);return 1; }
        if ((op & 0xcfu)==0xc1u) { z->stage=10;z->cycle_kind=Z80_MEM_READ;return 1; }
        if ((op & 0xcfu)==0xc5u) { z->stage=12;z->cycle_kind=Z80_INTERNAL;return 1; }
        if (op==0xe3u) { z->effective_address=z->sp;z->stage=14;z->cycle_kind=Z80_MEM_READ;return 1; }
        z->instruction_active = 0;
        return z80_fault(m, GW_STOP_UNSUPPORTED_INSTRUCTION, fetch, op);
    }
    if (z->stage==61u) {
        uint8_t value; if(!mem_read(m,z->hl,&value,Z80_MEM_READ,3))return 0;
        z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->temp=value;
        unsigned cbop=z->subopcode,group=cbop>>6,bit=(cbop>>3)&7u;
        if(group==1u){uint8_t f=(uint8_t)((lo(z->af)&F_C)|F_H);if(!(value&(1u<<bit)))f|=F_Z|F_PV;if(bit==7u&&(value&0x80u))f|=F_S;f|=(uint8_t)(hi(z->hl)&(F_X|F_Y));z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);z->stage=63u;return 1;}
        uint8_t carry=0,result=value;
        if(group==0u){switch(bit){case 0:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|carry);break;case 1:carry=value&1u;result=(uint8_t)((value>>1)|(carry<<7));break;case 2:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|(lo(z->af)&F_C));break;case 3:carry=value&1u;result=(uint8_t)((value>>1)|((lo(z->af)&F_C)<<7));break;case 4:carry=value>>7;result=(uint8_t)((unsigned)value<<1);break;case 5:carry=value&1u;result=(uint8_t)((value>>1)|(value&0x80u));break;case 6:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|1u);break;default:carry=value&1u;result=(uint8_t)(value>>1);break;}uint8_t f=(uint8_t)(szp(result)&~(F_Y|F_X));if(carry)f|=F_C;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);}
        else if(group==2u)result=(uint8_t)(value&~(1u<<bit));else result=(uint8_t)(value|(1u<<bit));
        z->temp=result;z->stage=62u;return 1;
    }
    if (z->stage==62u) {if(!mem_write(m,z->hl,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(4)*GW_Z80_DIVIDER;retire(z);return 1;}
    if (z->stage==63u) {z->next_cycle_tick+=GW_Z80_DIVIDER;retire(z);return 1;}
    if (z->stage==68u) {
        unsigned reg=(z->subopcode>>3)&7u;uint16_t port=z->bc;uint8_t value;
        if ((z->subopcode&7u)==0u) {
            if(!io_read(m,port,&value))return 0;
            if(reg!=6u)set_reg(z,reg,value);
            uint8_t f=(uint8_t)((lo(z->af)&F_C)|(value&(F_S|F_Y|F_X))|(value?0:F_Z)|(parity(value)?F_PV:0));
            z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);
        } else {
            value=reg==6u?0:get_reg(z,reg);
            if(!io_write(m,port,value))return 0;
        }
        z->next_cycle_tick+=UINT64_C(4)*GW_Z80_DIVIDER;retire(z);return 1;
    }
    if (z->stage==69u) {
        uint16_t rhs=*pair(z,(z->subopcode>>4)&3u),lhs=z->hl;unsigned sub=(z->subopcode&0x0fu)==2u;
        uint32_t wide=sub?(uint32_t)lhs-(uint32_t)rhs-(uint32_t)(lo(z->af)&F_C):(uint32_t)lhs+(uint32_t)rhs+(uint32_t)(lo(z->af)&F_C);
        uint16_t result=(uint16_t)wide;uint8_t f=(uint8_t)((hi(result)&F_S)|(result?0:F_Z)|(hi(result)&(F_X|F_Y))|(sub?F_N:0));
        if(((lhs^rhs^result)&0x1000u)!=0)f|=F_H;
        if(sub){if((uint32_t)lhs<(uint32_t)rhs+(uint32_t)(lo(z->af)&F_C))f|=F_C;if((((lhs^rhs)&(lhs^result))&0x8000u)!=0)f|=F_PV;}
        else {if(wide>0xffffu)f|=F_C;if((~(lhs^rhs)&(lhs^result)&0x8000u)!=0)f|=F_PV;}
        z->hl=result;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);z->next_cycle_tick+=UINT64_C(7)*GW_Z80_DIVIDER;retire(z);return 1;
    }
    if (z->stage==70u) {uint8_t value;if(!stack_read(m,&value))return 0;z->operand_lo=value;z->stage=72u;return 1;}
    if (z->stage==72u && (z->subopcode==0x45u||z->subopcode==0x4du)) {uint8_t value;if(!stack_read(m,&value))return 0;z->pc=(uint16_t)(((uint16_t)value<<8)|z->operand_lo);z->wz=z->pc;z->iff1=z->iff2;retire(z);return 1;}
    if (z->stage==71u) {
        uint8_t old;if(!mem_read(m,z->hl,&old,Z80_MEM_READ,3))return 0;
        z->next_cycle_tick+=UINT64_C(7)*GW_Z80_DIVIDER;
        uint8_t a=hi(z->af),al=(uint8_t)(a&15u),new_a,new_m;
        if(z->subopcode==0x67u){new_m=(uint8_t)((al<<4)|(old>>4));new_a=(uint8_t)((a&0xf0u)|(old&15u));}
        else {new_m=(uint8_t)((old<<4)|al);new_a=(uint8_t)((a&0xf0u)|(old>>4));}
        z->temp=new_m;z->operand_hi=new_a;z->stage=73u;return 1;
    }
    if (z->stage==73u) {
        if(z->subopcode==0x45u||z->subopcode==0x4du) { /* second RETN/RETI stack read */
            uint8_t value;if(!stack_read(m,&value))return 0;z->pc=(uint16_t)(((uint16_t)value<<8)|z->operand_lo);z->wz=z->pc;z->iff1=z->iff2;retire(z);return 1;
        }
        if(z->subopcode==0x67u||z->subopcode==0x6fu) {
            if(!mem_write(m,z->hl,z->temp,3))return 0;
            uint8_t a=z->operand_hi,f=(uint8_t)((lo(z->af)&F_C)|(a&(F_S|F_Y|F_X))|(a?0:F_Z)|(parity(a)?F_PV:0));
            z->af=(uint16_t)(((uint16_t)a<<8)|f);z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;retire(z);return 1;
        }
    }
    if (z->stage==74u) {z->stage=75u;return 1;}
    /* ED block transfer/search/I/O forms (LDI/LDD/LDIR/LDDR,
     * CPI/CPD/CPIR/CPDR, and INI/IND/INIR/INDR/OUTI/OUTD/OTIR/OTDR)
     * share the bus steps below; each repeat retires at its own boundary. */
    if (z->stage==75u) {
        unsigned kind=z->subopcode&3u;uint8_t value;
        if(kind==2u) {if(!io_read(m,z->bc,&value))return 0;z->next_cycle_tick+=UINT64_C(4)*GW_Z80_DIVIDER;z->temp=value;z->stage=76u;return 1;}
        if(!mem_read(m,z->hl,&value,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->temp=value;z->stage=76u;return 1;
    }
    if (z->stage==76u) {
        unsigned kind=z->subopcode&3u;int dec=(z->subopcode&8u)!=0;
        if(kind==0u) {if(!mem_write(m,z->de,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;}
        else if(kind==2u) {if(!mem_write(m,z->hl,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;}
        else if(kind==3u) {if(!io_write(m,z->bc,z->temp))return 0;z->next_cycle_tick+=UINT64_C(4)*GW_Z80_DIVIDER;}
        z->stage=77u;(void)dec;return 1;
    }
    if (z->stage==77u) {
        unsigned kind=z->subopcode&3u;int dec=(z->subopcode&8u)!=0,repeat=(z->subopcode&0x10u)!=0;
        uint16_t step=dec?UINT16_MAX:1u;int again=0;
        if(kind==0u) {z->hl=(uint16_t)(z->hl+step);z->de=(uint16_t)(z->de+step);z->bc=(uint16_t)(z->bc-1u);uint8_t f=(uint8_t)(lo(z->af)&(F_S|F_Z|F_C));if(z->bc)f|=F_PV;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);again=repeat&&z->bc!=0;}
        else if(kind==1u) {uint8_t a=hi(z->af),r=(uint8_t)(a-z->temp);z->hl=(uint16_t)(z->hl+step);z->bc=(uint16_t)(z->bc-1u);uint8_t f=(uint8_t)((lo(z->af)&F_C)|F_N|(r&(F_S|F_X|F_Y))|(r?0:F_Z));if((a^z->temp^r)&0x10u)f|=F_H;if(z->bc)f|=F_PV;z->af=(uint16_t)(((uint16_t)a<<8)|f);again=repeat&&z->bc!=0&&r!=0;}
        else {uint8_t b=(uint8_t)(hi(z->bc)-1u);z->bc=(uint16_t)(((uint16_t)b<<8)|lo(z->bc));z->hl=(uint16_t)(z->hl+step);uint8_t f=(uint8_t)((b&(F_S|F_Y|F_X))|(b?0:F_Z));unsigned k;
            if(kind==2u){uint8_t c=(uint8_t)(lo(z->bc)+(dec?255u:1u));k=(unsigned)z->temp+c;if(k>255u)f|=F_C;if(((z->temp&15u)+(c&15u))>15u)f|=F_H;if(z->temp&0x80u)f|=F_N;if(parity((uint8_t)((k&7u)^b)))f|=F_PV;}
            else{k=(unsigned)z->temp+lo(z->hl);if(k>255u)f|=F_C;if(((z->temp&15u)+(lo(z->hl)&15u))>15u)f|=F_H;if(z->temp&0x80u)f|=F_N;if(parity((uint8_t)((k&7u)^b)))f|=F_PV;}
            z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);again=repeat&&b!=0;}
        uint64_t extra=kind==1u?UINT64_C(5):kind==2u?UINT64_C(1):kind==3u?UINT64_C(1):UINT64_C(2);
        if(again)extra+=UINT64_C(5);
        z->next_cycle_tick+=extra*GW_Z80_DIVIDER;
        if(again)z->pc=(uint16_t)(z->effective_address);
        retire(z);return 1;
    }
    if (z->stage==78u) {uint8_t v;if(!read_pc(m,&v))return 0;z->operand_lo=v;z->stage=79u;return 1;}
    if (z->stage==79u) {uint8_t v;if(!read_pc(m,&v))return 0;z->effective_address=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);z->stage=80u;return 1;}
    if (z->stage==80u) {
        uint16_t *p=pair(z,(z->subopcode>>4)&3u);
        if((z->subopcode&0x0fu)==3u){if(!mem_write(m,z->effective_address,lo(*p),3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->stage=81u;return 1;}
        uint8_t v;if(!mem_read(m,z->effective_address,&v,Z80_MEM_READ,3))return 0;z->operand_lo=v;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->stage=81u;return 1;
    }
    if (z->stage==81u) {
        uint16_t *p=pair(z,(z->subopcode>>4)&3u);uint16_t address=(uint16_t)(z->effective_address+1u);
        if((z->subopcode&0x0fu)==3u){if(!mem_write(m,address,hi(*p),3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;}
        else {uint8_t v;if(!mem_read(m,address,&v,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;*p=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);}
        retire(z);return 1;
    }
    if (z->stage==82u) {
        uint8_t d;if(!read_pc(m,&d))return 0;z->displacement=d;z->temporary_pc=z->hl;
        uint16_t index=z->prefix==0xddu?z->ix:z->iy;z->effective_address=(uint16_t)(index+(int8_t)d);z->hl=z->effective_address;z->index_active=2u;
        z->next_cycle_tick+=((z->subopcode==0x36u)?UINT64_C(2):UINT64_C(5))*GW_Z80_DIVIDER;
        z->prefetched=1;z->instruction_active=0;return 1;
    }
    if (z->stage==83u) {uint8_t d;if(!read_pc(m,&d))return 0;z->displacement=d;z->effective_address=(uint16_t)((z->prefix==0xddu?z->ix:z->iy)+(int8_t)d);z->stage=84u;return 1;}
    if (z->stage==84u) {uint8_t cbop;if(!read_pc(m,&cbop))return 0;z->subopcode=cbop;z->stage=85u;return 1;}
    if (z->stage==85u) {
        uint8_t value;if(!mem_read(m,z->effective_address,&value,Z80_MEM_READ,3))return 0;z->temp=value;
        unsigned cbop=z->subopcode,group=cbop>>6,bit=(cbop>>3)&7u;
        if(group==1u){uint8_t f=(uint8_t)((lo(z->af)&F_C)|F_H);if(!(value&(1u<<bit)))f|=F_Z|F_PV;if(bit==7u&&(value&0x80u))f|=F_S;f|=(uint8_t)(hi(z->effective_address)&(F_X|F_Y));z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);z->stage=87u;z->next_cycle_tick+=UINT64_C(6)*GW_Z80_DIVIDER;return 1;}
        uint8_t carry=0,result=value;
        if(group==0u){switch(bit){case 0:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|carry);break;case 1:carry=value&1u;result=(uint8_t)((value>>1)|(carry<<7));break;case 2:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|(lo(z->af)&F_C));break;case 3:carry=value&1u;result=(uint8_t)((value>>1)|((lo(z->af)&F_C)<<7));break;case 4:carry=value>>7;result=(uint8_t)((unsigned)value<<1);break;case 5:carry=value&1u;result=(uint8_t)((value>>1)|(value&0x80u));break;case 6:carry=value>>7;result=(uint8_t)(((unsigned)value<<1)|1u);break;default:carry=value&1u;result=(uint8_t)(value>>1);break;}uint8_t f=(uint8_t)(szp(result)&~(F_X|F_Y));if(carry)f|=F_C;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|f);}
        else if(group==2u)result=(uint8_t)(value&~(1u<<bit));else result=(uint8_t)(value|(1u<<bit));
        z->temp=result;z->stage=86u;z->next_cycle_tick+=UINT64_C(6)*GW_Z80_DIVIDER;return 1;
    }
    if (z->stage==86u) {if(!mem_write(m,z->effective_address,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;retire(z);return 1;}
    if (z->stage==87u) {retire(z);return 1;}
    if (z->stage == 1u) {
        uint8_t v;
        if (z->opcode == 0x02u || z->opcode == 0x12u) {
            uint16_t a=z->opcode==0x02u?z->bc:z->de;
            if (!mem_write(m,a,hi(z->af),3)) return 0;
            z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER; retire(z); return 1;
        }
        if (z->opcode == 0x0au || z->opcode == 0x1au) {
            uint16_t a=z->opcode==0x0au?z->bc:z->de;
            if (!mem_read(m,a,&v,Z80_MEM_READ,3)) return 0;
            z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER; set_reg(z,7,v); retire(z); return 1;
        }
        if (!read_pc(m, &v)) return 0;
        if ((z->opcode & 0xc7u) == 0x06u) {
            if (((z->opcode>>3)&7u)==6u) { z->temp=v;z->stage=19;return 1; }
            set_reg(z,z->opcode>>3,v); retire(z); return 1;
        }
        if ((z->opcode & 0xcfu) == 0x01u) { z->operand_lo=v; z->stage=2; return 1; }
        z->operand_lo=v;z->stage=2;return 1;
    }
    if(z->stage==30u){uint8_t v;if(!read_pc(m,&v))return 0;alu(z,(z->opcode>>3)&7u,v);retire(z);return 1;}
    if(z->stage==31u){uint8_t v;if(!mem_read(m,z->hl,&v,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;alu(z,(z->opcode>>3)&7u,v);retire(z);return 1;}
    if(z->stage==32u){uint8_t old;if(!mem_read(m,z->hl,&old,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;unsigned dec=z->opcode&1u;uint8_t result=(uint8_t)(old+(dec?255u:1u));uint8_t f=(uint8_t)(lo(z->af)&F_C);f|=(uint8_t)(result&(F_S|F_Y|F_X));if(!result)f|=F_Z;if(dec){f|=F_N;if((old&15u)==0)f|=F_H;if(old==0x80u)f|=F_PV;}else{if((old&15u)==15u)f|=F_H;if(old==0x7fu)f|=F_PV;}z->temp=result;z->operand_hi=f;z->stage=35;return 1;}
    if(z->stage==35u){z->next_cycle_tick+=GW_Z80_DIVIDER;z->stage=34;return 1;}
    if(z->stage==34u){if(!mem_write(m,z->hl,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->af=(uint16_t)(((uint16_t)hi(z->af)<<8)|z->operand_hi);retire(z);return 1;}
    if(z->stage==33u){z->next_cycle_tick+=((z->opcode&0xcfu)==0x09u?UINT64_C(7):UINT64_C(2))*GW_Z80_DIVIDER;retire(z);return 1;}
    if(z->stage==40u){uint8_t d;if(!read_pc(m,&d))return 0;z->temp=d;
        if(z->opcode==0x10u){uint8_t b=(uint8_t)(hi(z->bc)-1u);z->bc=(uint16_t)(((uint16_t)b<<8)|lo(z->bc));z->pending_cycles=(uint8_t)(b?6u:1u);if(b!=0)z->pc=(uint16_t)(z->pc+(int8_t)d);z->stage=45;return 1;}
        if(z->opcode==0x18u || condition(z,(z->opcode>>3)&3u)){z->pc=(uint16_t)(z->pc+(int8_t)d);z->pending_cycles=5;z->stage=45;return 1;}retire(z);return 1;}
    if(z->stage==45u){z->next_cycle_tick+=(uint64_t)z->pending_cycles*GW_Z80_DIVIDER;retire(z);return 1;}
    if(z->stage==41u){uint8_t v;if(!read_pc(m,&v))return 0;z->operand_lo=v;z->stage=46;return 1;}
    if(z->stage==46u){uint8_t v;if(!read_pc(m,&v))return 0;z->effective_address=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);z->wz=z->effective_address;
        if(z->opcode==0xc3u || ((z->opcode&0xc7u)==0xc2u&&condition(z,(z->opcode>>3)&7u))){z->pc=z->effective_address;retire(z);return 1;}
        if(z->opcode==0xcdu || ((z->opcode&0xc7u)==0xc4u&&condition(z,(z->opcode>>3)&7u))){z->temporary_pc=z->pc;z->stage=47;return 1;}retire(z);return 1;}
    if(z->stage==47u){z->next_cycle_tick+=GW_Z80_DIVIDER;if(!stack_write(m,hi(z->temporary_pc)))return 0;z->stage=48;return 1;}
    if(z->stage==48u){if(!stack_write(m,lo(z->temporary_pc)))return 0;z->pc=z->effective_address;retire(z);return 1;}
    if(z->stage==42u){z->next_cycle_tick+=GW_Z80_DIVIDER;retire(z);return 1;}
    if(z->stage==53u){z->next_cycle_tick+=GW_Z80_DIVIDER;z->stage=43;return 1;}
    if(z->stage==43u){uint8_t v;if(!stack_read(m,&v))return 0;z->operand_lo=v;z->stage=49;return 1;}
    if(z->stage==49u){uint8_t v;if(!stack_read(m,&v))return 0;z->pc=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);z->wz=z->pc;retire(z);return 1;}
    if(z->stage==44u){z->next_cycle_tick+=GW_Z80_DIVIDER;if(!stack_write(m,hi(z->temporary_pc)))return 0;z->stage=50;return 1;}
    if(z->stage==50u){if(!stack_write(m,lo(z->temporary_pc)))return 0;z->pc=(uint16_t)(z->opcode&0x38u);z->wz=z->pc;retire(z);return 1;}
    if(z->stage==51u){uint8_t n;if(!read_pc(m,&n))return 0;z->effective_address=(uint16_t)(((uint16_t)hi(z->af)<<8)|n);z->stage=52;return 1;}
    if(z->stage==52u){uint8_t a=hi(z->af);if(z->opcode==0xdbu){uint8_t v;if(!io_read(m,z->effective_address,&v))return 0;set_reg(z,7,v);}else if(!io_write(m,z->effective_address,a))return 0;z->next_cycle_tick+=UINT64_C(4)*GW_Z80_DIVIDER;retire(z);return 1;}
    if (z->stage == 10u) {
        uint8_t v;if(!stack_read(m,&v))return 0;z->operand_lo=v;z->stage=11;return 1;
    }
    if (z->stage == 11u) {
        uint8_t v;if(!stack_read(m,&v))return 0;
        uint16_t value=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);unsigned n=(z->opcode>>4)&3u;
        if(n==3u)z->af=value;else *pair(z,n)=value;retire(z);return 1;
    }
    if (z->stage == 12u) {
        z->next_cycle_tick+=GW_Z80_DIVIDER;z->stage=20;return 1;
    }
    if (z->stage == 20u) {
        uint16_t value=(z->opcode==0xf5u)?z->af:*pair(z,(z->opcode>>4)&3u);
        z->operand_lo=lo(value);z->operand_hi=hi(value);
        if(!stack_write(m,z->operand_hi))return 0;z->stage=13;return 1;
    }
    if (z->stage == 13u) { if(!stack_write(m,z->operand_lo))return 0;retire(z);return 1; }
    if (z->stage == 14u) { uint8_t v;if(!mem_read(m,z->effective_address,&v,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->operand_lo=v;z->stage=15;return 1; }
    if (z->stage == 15u) { uint8_t v;if(!mem_read(m,(uint16_t)(z->effective_address+1u),&v,Z80_MEM_READ,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->operand_hi=v;z->stage=16;return 1; }
    if (z->stage == 16u) { if(!mem_write(m,z->effective_address,lo(z->hl),3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->stage=17;return 1; }
    if (z->stage == 17u) { if(!mem_write(m,(uint16_t)(z->effective_address+1u),hi(z->hl),3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->stage=18;return 1; }
    if (z->stage == 18u) { z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;z->hl=(uint16_t)(((uint16_t)z->operand_hi<<8)|z->operand_lo);retire(z);return 1; }
    if (z->stage == 19u) { if(!mem_write(m,z->hl,z->temp,3))return 0;z->next_cycle_tick+=UINT64_C(3)*GW_Z80_DIVIDER;retire(z);return 1; }
    if (z->stage == 2u) {
        uint8_t v;
        if (z->opcode == 0x01u || z->opcode == 0x11u || z->opcode == 0x21u || z->opcode == 0x31u) {
            if (!read_pc(m,&v)) return 0;
            *pair(z,z->opcode>>4)=(uint16_t)(((uint16_t)v<<8)|z->operand_lo); retire(z); return 1;
        }
        if (!read_pc(m,&v)) return 0;
        z->operand_hi=v;z->effective_address=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);
        if (z->opcode==0x32u) {
            if (!mem_write(m,z->effective_address,hi(z->af),3)) return 0;
            z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER; retire(z); return 1;
        }
        if (z->opcode==0x3au) {
            if (!mem_read(m,z->effective_address,&v,Z80_MEM_READ,3)) return 0;
            z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER;set_reg(z,7,v);retire(z);return 1;
        }
        z->stage=3;return 1;
    }
    if (z->stage == 3u && (z->opcode==0x22u || z->opcode==0x2au)) {
        if (z->opcode==0x22u) {
            if (!mem_write(m,z->effective_address,lo(z->hl),3)) return 0;
            z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER; z->stage=4; return 1;
        }
        uint8_t v;if(!mem_read(m,z->effective_address,&v,Z80_MEM_READ,3))return 0;
        z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER;z->operand_lo=v;z->stage=4;return 1;
    }
    if (z->stage == 4u && (z->opcode==0x22u || z->opcode==0x2au)) {
        uint16_t a=(uint16_t)(z->effective_address+1u);
        if (z->opcode==0x22u) {
            if(!mem_write(m,a,hi(z->hl),3))return 0;z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER;
        } else {
            uint8_t v;if(!mem_read(m,a,&v,Z80_MEM_READ,3))return 0;z->next_cycle_tick += UINT64_C(3)*GW_Z80_DIVIDER;z->hl=(uint16_t)(((uint16_t)v<<8)|z->operand_lo);
        }
        retire(z);return 1;
    }
    if (z->micro_op == 1u && z->cycle_kind == Z80_MEM_READ) {
        uint8_t value;
        if (!mem_read(m, z->hl, &value, Z80_MEM_READ, 3)) return 0;
        z->next_cycle_tick += UINT64_C(3) * GW_Z80_DIVIDER;
        set_reg(z, z->destination_reg, value);
        retire(z);
        return 1;
    }
    if (z->micro_op == 1u && z->cycle_kind == Z80_MEM_WRITE) {
        uint8_t value = get_reg(z, z->source_reg);
        if (!mem_write(m, z->hl, value, 3)) return 0;
        z->next_cycle_tick += UINT64_C(3) * GW_Z80_DIVIDER;
        retire(z);
        return 1;
    }
    z->instruction_active = 0;
    return z80_fault(m, GW_STOP_UNSUPPORTED_STATE, z->pc, z->opcode);
}

/* IM0/IM2 need the byte returned during INT acknowledge. That Genesis bus
 * value is not established, so the live VDP seam currently accepts IM1 only;
 * hooks inject a byte to validate the CPU's documented mode behavior. */
static int accept_int(gw_machine *m, int data_known, uint8_t data)
{
    gw_z80 *z = &m->z80;
    if (z->instruction_active || !z->retired || !z->iff1 || z->ei_delay) return 0;
    if ((z->im == 0u && (!data_known || (data & 0xc7u) != 0xc7u)) ||
        (z->im == 2u && !data_known) || z->im > 2u) return 0;
    z->halted = 0;
    z->retired = 0;
    z->iff1 = 0;
    z->iff2 = 0;
    if (!stack_write(m, hi(z->pc)) || !stack_write(m, lo(z->pc))) return 0;
    if (z->im == 0u) {
        z->pc = (uint16_t)(data & 0x38u);
        z->next_cycle_tick += UINT64_C(7) * GW_Z80_DIVIDER;
    } else if (z->im == 1u) {
        z->pc = UINT16_C(0x0038);
        /* Stack writes contribute six of the documented 13 T states. */
        z->next_cycle_tick += UINT64_C(7) * GW_Z80_DIVIDER;
    } else {
        uint16_t table = (uint16_t)(((uint16_t)z->i << 8) | data);
        uint8_t low = 0, high = 0;
        if (!mem_read(m, table, &low, Z80_MEM_READ, 3) ||
            !mem_read(m, (uint16_t)(table + 1u), &high, Z80_MEM_READ, 3)) return 0;
        z->pc = (uint16_t)(((uint16_t)high << 8) | low);
        z->wz = z->pc;
        /* UM0080: 7 acknowledge + 6 stack + 6 vector-fetch T states. */
        z->next_cycle_tick += UINT64_C(13) * GW_Z80_DIVIDER;
    }
    return 1;
}

void gw_z80_sample_interrupt(gw_machine *m, uint64_t tick)
{
    gw_z80 *z = &m->z80;
    if (!gw_z80_int_asserted(m, tick)) return;
    /* Acknowledge data is unknown for this console seam. */
    if (z->im == 1u) (void)accept_int(m, 0, 0);
}

uint64_t gw_z80_digest(const gw_z80 *z, uint64_t h)
{
    const uint16_t pairs[] = { z->af,z->bc,z->de,z->hl,z->af_alt,z->bc_alt,z->de_alt,z->hl_alt,z->ix,z->iy,z->sp,z->pc,z->wz,z->effective_address,z->temporary_pc,z->bank };
    for (size_t i = 0; i < sizeof(pairs)/sizeof(pairs[0]); ++i) { h = (h ^ (uint8_t)pairs[i]) * UINT64_C(1099511628211); h = (h ^ (uint8_t)(pairs[i] >> 8)) * UINT64_C(1099511628211); }
    const uint8_t bytes[] = { z->i,z->r,z->iff1,z->iff2,z->im,z->q,z->halted,z->ei_delay,z->reset_asserted,z->busreq,z->micro_op,z->opcode,z->instruction_active,z->source_reg,z->destination_reg,z->cycle_kind,z->retired,z->operand_lo,z->operand_hi,z->temp,z->stage,z->pending_cycles,z->prefix,z->subopcode,z->displacement,z->prefix_count,z->prefetched,z->index_active,z->bank_shift_count };
    const uint8_t arbitration[] = { z->busreq_pending,z->reset_pending };
    for (size_t i = 0; i < sizeof(bytes); ++i) h = (h ^ bytes[i]) * UINT64_C(1099511628211);
    for (size_t i = 0; i < sizeof(arbitration); ++i) h = (h ^ arbitration[i]) * UINT64_C(1099511628211);
    for (unsigned i = 0; i < 8; ++i) h = (h ^ (uint8_t)(z->next_cycle_tick >> (i*8u))) * UINT64_C(1099511628211);
    for (unsigned i = 0; i < 8; ++i) h = (h ^ (uint8_t)(z->busreq_tick >> (i*8u))) * UINT64_C(1099511628211);
    for (unsigned i = 0; i < 8; ++i) h = (h ^ (uint8_t)(z->reset_tick >> (i*8u))) * UINT64_C(1099511628211);
    for (size_t i = 0; i < sizeof(z->ram); ++i) h = (h ^ z->ram[i]) * UINT64_C(1099511628211);
    return h;
}

#ifdef GW_TEST_HOOKS
int gw_test_z80_set_state(gw_machine *m, const gw_test_z80_state *s)
{
    if (!m || !s) return 0;
    gw_z80 *z=&m->z80; z->af=s->af; z->bc=s->bc; z->de=s->de; z->hl=s->hl;
    z->af_alt=s->af_alt; z->bc_alt=s->bc_alt; z->de_alt=s->de_alt; z->hl_alt=s->hl_alt;
    z->ix=s->ix; z->iy=s->iy; z->sp=s->sp; z->pc=s->pc; z->wz=s->wz;
    z->i=s->i; z->r=s->r; z->iff1=s->iff1; z->iff2=s->iff2; z->im=s->im; z->q=s->q; z->halted=s->halted;z->ei_delay=s->ei_delay;
    z->reset_asserted=0; z->busreq=0; z->busreq_pending=0; z->reset_pending=0;
    z->bank=0; z->bank_shift_count=0;
    z->busreq_tick=0; z->reset_tick=0; z->instruction_active=0; z->cycle_kind=0; z->retired=0;
    z->prefix=0;z->subopcode=0;z->displacement=0;z->prefix_count=0;z->prefetched=0;z->index_active=0;z->stage=0;z->pending_cycles=0;
    z->next_cycle_tick=m->tick; m->cpu.stop_reason=GW_STOP_TARGET; m->cpu.fault_address=0; m->cpu.opcode=0;
    m->z80_transaction_count=0; m->z80_overlay_miss=0;
    return 1;
}
int gw_test_z80_get_state(const gw_machine *m, gw_test_z80_state *s)
{
    if (!m || !s) return 0; const gw_z80 *z=&m->z80;
    s->af=z->af;s->bc=z->bc;s->de=z->de;s->hl=z->hl;s->af_alt=z->af_alt;s->bc_alt=z->bc_alt;s->de_alt=z->de_alt;s->hl_alt=z->hl_alt;
    s->ix=z->ix;s->iy=z->iy;s->sp=z->sp;s->pc=z->pc;s->wz=z->wz;s->i=z->i;s->r=z->r;s->iff1=z->iff1;s->iff2=z->iff2;s->im=z->im;s->q=z->q;s->halted=z->halted;s->ei_delay=z->ei_delay; return 1;
}
int gw_test_z80_step_instruction(gw_machine *m)
{
    if (!m) return 0;
    for (unsigned cycles=0; cycles<16; ++cycles) {
        if (!gw_z80_cycle(m)) return 0;
        if (m->z80.retired) return 1;
    }
    return 0;
}
int gw_test_z80_nmi(gw_machine *m)
{
    if (!m) return 0;
    gw_z80 *z = &m->z80;
    if (z->reset_asserted || z->busreq || z->instruction_active) return 0;
    z->halted = 0;
    z->retired = 0;
    z->instruction_active = 0;
    z->iff2 = z->iff1;
    z->iff1 = 0;
    if (!stack_write(m, hi(z->pc)) || !stack_write(m, lo(z->pc))) return 0;
    z->pc = UINT16_C(0x0066);
    z->wz = z->pc;
    /* Two stack writes account for six T states; NMI acknowledge adds five. */
    z->next_cycle_tick += UINT64_C(5) * GW_Z80_DIVIDER;
    return 1;
}
int gw_test_z80_accept_int(gw_machine *m, uint8_t data)
{
    if (!m) return 0;
    m->z80.retired = 1;
    return accept_int(m, 1, data);
}
void gw_test_z80_overlay_reset(gw_machine *m)
{ if (m) { m->z80_overlay_count=0; m->z80_port_count=0; m->z80_transaction_count=0; m->z80_overlay_active=1; m->z80_overlay_miss=0; } }
int gw_test_z80_overlay_set(gw_machine *m,uint16_t a,uint8_t v)
{ if(!m)return 0; int i=overlay_find(m,a); if(i<0){if(m->z80_overlay_count==GW_TEST_MEMORY_CAPACITY)return 0;i=(int)m->z80_overlay_count++;m->z80_overlay[i].address=a;}m->z80_overlay[i].value=v;return 1; }
int gw_test_z80_overlay_get(const gw_machine *m,uint16_t a,uint8_t *v)
{ if(!m||!v)return 0;int i=overlay_find(m,a);if(i<0)return 0;*v=m->z80_overlay[i].value;return 1; }
int gw_test_z80_overlay_port_set(gw_machine *m,uint16_t a,uint8_t v)
{ if(!m)return 0;int i=port_find(m,a);if(i<0){if(m->z80_port_count==GW_TEST_MEMORY_CAPACITY)return 0;i=(int)m->z80_port_count++;m->z80_ports[i].address=a;}m->z80_ports[i].value=v;return 1; }
int gw_test_z80_overlay_port_get(const gw_machine *m,uint16_t a,uint8_t *v)
{ if(!m||!v)return 0;int i=port_find(m,a);if(i<0)return 0;*v=m->z80_ports[i].value;return 1; }
size_t gw_test_z80_transaction_count(const gw_machine *m) { return m ? m->z80_transaction_count : 0; }
int gw_test_z80_transaction_get(const gw_machine *m,size_t i,gw_test_z80_transaction *t)
{ if(!m||!t||i>=m->z80_transaction_count)return 0;*t=m->z80_transactions[i];return 1; }
#endif
