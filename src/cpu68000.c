/* SPDX-License-Identifier: MIT
 * Original bounded interpreter; semantics informed by Motorola M68000PRM and
 * MC68000UM. No third-party CPU code. See docs/cpu.md for supported forms and
 * timing limits (in particular, no instruction prefetch or address-error frame).
 */
#include "internal.h"

static int fetch(gw_machine *m, unsigned size, uint32_t *value)
{
    if (!gw_bus_read(m, m->cpu.pc, size, value)) return 0;
    m->cpu.pc += size;
    return 1;
}

static uint32_t sign16(uint32_t value)
{
    return (value & 0x8000u) ? value | UINT32_C(0xffff0000) : value;
}

static void move_flags(gw_cpu *cpu, uint32_t value, unsigned size)
{
    uint32_t sign = size == 1 ? 0x80u : size == 2 ? 0x8000u : UINT32_C(0x80000000);
    cpu->sr = (uint16_t)((cpu->sr & 0xfff0u) | (value == 0 ? 4u : 0u) |
                        ((value & sign) ? 8u : 0u));
}

/* Effective addresses. The twelve 68000 modes are numbered 0-6 for mode fields
 * 0-6, then 7 abs.w, 8 abs.l, 9 d16(PC), 10 d8(PC,Xn), 11 immediate. */
enum { EA_DN, EA_AN, EA_MEM, EA_IMM };
typedef struct { int kind; unsigned reg; uint32_t address, value; } ea_t;

#define EA_BIT(i) (1u << (i))
#define EA_ALL 0x0fffu
#define EA_DATA (EA_ALL & ~EA_BIT(1))
#define EA_DATA_ALT (EA_BIT(0) | EA_BIT(2) | EA_BIT(3) | EA_BIT(4) | EA_BIT(5) | EA_BIT(6) | EA_BIT(7) | EA_BIT(8))
#define EA_ALT (EA_DATA_ALT | EA_BIT(1))
#define EA_MEM_ALT (EA_DATA_ALT & ~EA_BIT(0))
#define EA_CONTROL (EA_BIT(2) | EA_BIT(5) | EA_BIT(6) | EA_BIT(7) | EA_BIT(8) | EA_BIT(9) | EA_BIT(10))

static uint32_t size_mask(unsigned size)
{
    return size == 1 ? 0xffu : size == 2 ? 0xffffu : UINT32_MAX;
}

static uint32_t size_sign(unsigned size)
{
    return size == 1 ? 0x80u : size == 2 ? 0x8000u : UINT32_C(0x80000000);
}

static int unsupported_instruction(gw_machine *m)
{
    m->cpu.stop_reason = GW_STOP_UNSUPPORTED_INSTRUCTION;
    return 0;
}

static int ea_legal(unsigned mode, unsigned reg, unsigned allowed)
{
    unsigned index = mode < 7 ? mode : 7u + reg;
    return index < 12u && (allowed & EA_BIT(index));
}

static uint32_t ea_index(const gw_cpu *cpu, uint32_t ext)
{
    uint32_t index = (ext & 0x8000u) ? cpu->a[(ext >> 12) & 7u] : cpu->d[(ext >> 12) & 7u];
    uint32_t disp = ext & 0xffu;
    if (!(ext & 0x800u)) index = sign16(index & 0xffffu);
    if (disp & 0x80u) disp |= UINT32_C(0xffffff00);
    return index + disp;
}

/* Resolve an operand: consume extension words and apply (An)+/-(An) updates in
 * instruction-stream order. The caller has already checked legality. */
static int ea_address(gw_machine *m, unsigned mode, unsigned reg, unsigned size, ea_t *ea)
{
    uint32_t ext, base, step = (size == 1 && reg == 7) ? 2u : size;
    ea->reg = reg;
    ea->kind = EA_MEM;
    switch (mode) {
    case 0: ea->kind = EA_DN; return 1;
    case 1: ea->kind = EA_AN; return 1;
    case 2: ea->address = m->cpu.a[reg]; return 1;
    case 3: ea->address = m->cpu.a[reg]; m->cpu.a[reg] += step; return 1;
    case 4: m->cpu.a[reg] -= step; ea->address = m->cpu.a[reg]; return 1;
    case 5:
        if (!fetch(m, 2, &ext)) return 0;
        ea->address = m->cpu.a[reg] + sign16(ext);
        return 1;
    case 6:
        if (!fetch(m, 2, &ext)) return 0;
        ea->address = m->cpu.a[reg] + ea_index(&m->cpu, ext);
        return 1;
    default:
        break;
    }
    switch (reg) {
    case 0:
        if (!fetch(m, 2, &ext)) return 0;
        ea->address = sign16(ext);
        return 1;
    case 1: return fetch(m, 4, &ea->address);
    case 2:
        base = m->cpu.pc;
        if (!fetch(m, 2, &ext)) return 0;
        ea->address = base + sign16(ext);
        return 1;
    case 3:
        base = m->cpu.pc;
        if (!fetch(m, 2, &ext)) return 0;
        ea->address = base + ea_index(&m->cpu, ext);
        return 1;
    default:
        ea->kind = EA_IMM;
        if (!fetch(m, size == 4 ? 4u : 2u, &ea->value)) return 0;
        ea->value &= size_mask(size);
        return 1;
    }
}

static int ea_read(gw_machine *m, const ea_t *ea, unsigned size, uint32_t *value)
{
    switch (ea->kind) {
    case EA_DN: *value = m->cpu.d[ea->reg] & size_mask(size); return 1;
    case EA_AN: *value = m->cpu.a[ea->reg] & size_mask(size); return 1;
    case EA_IMM: *value = ea->value; return 1;
    default: return gw_bus_read(m, ea->address, size, value);
    }
}

static int ea_write(gw_machine *m, const ea_t *ea, unsigned size, uint32_t value)
{
    uint32_t mask = size_mask(size);
    if (ea->kind == EA_DN) {
        m->cpu.d[ea->reg] = (m->cpu.d[ea->reg] & ~mask) | (value & mask);
        return 1;
    }
    if (ea->kind == EA_AN) { m->cpu.a[ea->reg] = value; return 1; }
    return gw_bus_write(m, ea->address, size, value & mask);
}

enum { ALU_ADD, ALU_SUB, ALU_CMP };

static void set_ccr(gw_cpu *cpu, int x, int n, int z, int v, int c, int keep_x)
{
    uint16_t sr = (uint16_t)(cpu->sr & (keep_x ? 0xfff0u : 0xffe0u));
    if (!keep_x && x) sr |= 0x10u;
    if (n) sr |= 8u;
    if (z) sr |= 4u;
    if (v) sr |= 2u;
    if (c) sr |= 1u;
    cpu->sr = sr;
}

/* add_flags / sub_flags / cmp_flags in one place: operands are pre-masked, the
 * result is masked, and CMP leaves X unchanged. */
static uint32_t alu(gw_cpu *cpu, int kind, uint32_t src, uint32_t dst, unsigned size)
{
    uint32_t mask = size_mask(size), sign = size_sign(size), res;
    int v, c;
    if (kind == ALU_ADD) {
        res = (dst + src) & mask;
        v = ((src ^ res) & (dst ^ res) & sign) != 0;
        c = (((src & dst) | (~res & (src | dst))) & sign) != 0;
    } else {
        res = (dst - src) & mask;
        v = ((src ^ dst) & (res ^ dst) & sign) != 0;
        c = (((~dst & src) | (res & (~dst | src))) & sign) != 0;
    }
    set_ccr(cpu, c, (res & sign) != 0, res == 0, v, c, kind == ALU_CMP);
    return res;
}

static unsigned op_size(uint32_t bits)
{
    return bits == 0 ? 1u : bits == 1 ? 2u : 4u;
}

static int execute_move(gw_machine *m, uint32_t op)
{
    unsigned sm = (op >> 3) & 7u, sr = op & 7u;
    unsigned dm = (op >> 6) & 7u, dr = (op >> 9) & 7u;
    unsigned code = op >> 12;
    unsigned size = code == 1 ? 1 : code == 2 ? 4 : 2;
    uint32_t value;
    ea_t src, dst;
    if (!ea_legal(sm, sr, EA_ALL) || (sm == 1 && size == 1)) return unsupported_instruction(m);
    if (dm == 1) {
        /* MOVEA: word or long only; word sources sign-extend; CCR unchanged. */
        if (size == 1) return unsupported_instruction(m);
        if (!ea_address(m, sm, sr, size, &src) || !ea_read(m, &src, size, &value)) return 0;
        if (size == 2) value = sign16(value);
        m->cpu.a[dr] = value;
        return 1;
    }
    if (!ea_legal(dm, dr, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, sm, sr, size, &src) || !ea_read(m, &src, size, &value)) return 0;
    if (!ea_address(m, dm, dr, size, &dst) || !ea_write(m, &dst, size, value)) return 0;
    move_flags(&m->cpu, value, size);
    return 1;
}

static int execute_lea(gw_machine *m, uint32_t op)
{
    ea_t ea;
    unsigned mode = (op >> 3) & 7u, reg = op & 7u;
    if (!ea_legal(mode, reg, EA_CONTROL)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, 4, &ea)) return 0;
    m->cpu.a[(op >> 9) & 7u] = ea.address;
    return 1;
}

/* PEA computes a control effective address; it does not fetch the operand at
 * that address. NXP M68000PRM p. 4-159, with the 68000 EA subset only. */
static int execute_pea(gw_machine *m, uint32_t op)
{
    ea_t ea;
    unsigned mode = (op >> 3) & 7u, reg = op & 7u;
    unsigned ea_index = mode < 7u ? mode : 7u + reg;
    static const uint8_t clocks_by_control_ea[12] = {
        0, 0, 12, 0, 0, 16, 20, 16, 20, 16, 20, 0
    };
    uint64_t start_tick = m->tick;
    if (!ea_legal(mode, reg, EA_CONTROL)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, 4, &ea)) return 0;
    m->cpu.a[7] -= 4u;
    if (!gw_bus_write(m, m->cpu.a[7], 4, ea.address)) return 0;
    /* Fill the internal clocks not represented by the simplified bus model to
     * the MC68000UM §8.9 Table 8-10 (16-bit bus) total.
     * Bus ordering remains approximate. */
    uint64_t target_ticks = (uint64_t)clocks_by_control_ea[ea_index] * GW_CPU_DIVIDER;
    /* The dispatcher has already charged the four-clock opcode fetch. */
    uint64_t elapsed_ticks = m->tick - start_tick + 4u * GW_CPU_DIVIDER;
    if (elapsed_ticks < target_ticks) m->tick += target_ticks - elapsed_ticks;
    return 1;
}

/* CLR does not model the 68000's read-before-write bus cycle. */
static int execute_clr(gw_machine *m, uint32_t op)
{
    ea_t ea;
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, size, &ea) || !ea_write(m, &ea, size, 0)) return 0;
    move_flags(&m->cpu, 0, size);
    return 1;
}

static int execute_tst(gw_machine *m, uint32_t op)
{
    ea_t ea;
    uint32_t value;
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &value)) return 0;
    move_flags(&m->cpu, value, size);
    return 1;
}

/* Groups 0x9 (SUB/SUBA), 0xB (CMP/CMPA) and 0xD (ADD/ADDA). */
static int execute_arith(gw_machine *m, uint32_t op, int kind)
{
    unsigned reg = (op >> 9) & 7u, opmode = (op >> 6) & 7u;
    unsigned mode = (op >> 3) & 7u, ereg = op & 7u, size;
    uint32_t src, dst, res, mask;
    ea_t ea;
    if (opmode == 3 || opmode == 7) { /* ADDA, SUBA, CMPA: no flags except CMPA */
        size = opmode == 3 ? 2u : 4u;
        if (!ea_legal(mode, ereg, EA_ALL)) return unsupported_instruction(m);
        if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &src)) return 0;
        if (size == 2) src = sign16(src);
        if (kind == ALU_CMP) (void)alu(&m->cpu, ALU_CMP, src, m->cpu.a[reg], 4);
        else m->cpu.a[reg] = kind == ALU_ADD ? m->cpu.a[reg] + src : m->cpu.a[reg] - src;
        return 1;
    }
    size = op_size(opmode & 3u);
    mask = size_mask(size);
    if (opmode < 3) { /* <ea> op Dn */
        if (!ea_legal(mode, ereg, EA_ALL) || (mode == 1 && size == 1)) return unsupported_instruction(m);
        if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &src)) return 0;
        dst = m->cpu.d[reg] & mask;
        res = alu(&m->cpu, kind, src, dst, size);
        if (kind != ALU_CMP) m->cpu.d[reg] = (m->cpu.d[reg] & ~mask) | res;
        return 1;
    }
    /* Dn op <ea>: CMP encodings here are EOR/CMPM; ADDX/SUBX use modes 0-1. */
    if (kind == ALU_CMP || !ea_legal(mode, ereg, EA_MEM_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &dst)) return 0;
    res = alu(&m->cpu, kind, m->cpu.d[reg] & mask, dst, size);
    return ea_write(m, &ea, size, res);
}

/* ADDX Dn,Dn: M68000PRM4-13/14. Read both old operands before writing
 * (source may equal destination); Z is cumulative, unlike ordinary ADD. */
static int execute_addx_dn(gw_machine *m, uint32_t op)
{
    unsigned src = op & 7u, dst = (op >> 9) & 7u;
    unsigned size = op_size((op >> 6) & 3u);
    uint32_t mask = size_mask(size), sign = size_sign(size);
    uint32_t a = m->cpu.d[src] & mask, b = m->cpu.d[dst] & mask;
    uint64_t sum = (uint64_t)a + b + ((m->cpu.sr & 0x10u) != 0);
    uint32_t result = (uint32_t)sum & mask;
    int carry = sum > mask;
    int overflow = ((a ^ result) & (b ^ result) & sign) != 0;
    int zero = (m->cpu.sr & 4u) && result == 0;
    m->cpu.d[dst] = (m->cpu.d[dst] & ~mask) | result;
    set_ccr(&m->cpu, carry, (result & sign) != 0, zero, overflow, carry, 0);
    /* Original MC68000 register totals4BW/8L, including opcode fetch. */
    if (size == 4) m->tick += 4u * GW_CPU_DIVIDER;
    return 1;
}

/* ADDQ / SUBQ (group 0x5 with a size field). */
static int execute_quick(gw_machine *m, uint32_t op)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    uint32_t data = (op >> 9) & 7u, value;
    int kind = (op & 0x100u) ? ALU_SUB : ALU_ADD;
    ea_t ea;
    if (data == 0) data = 8;
    if (!ea_legal(mode, reg, EA_ALT) || (mode == 1 && size == 1)) return unsupported_instruction(m);
    if (mode == 1) { /* full address register, no flags */
        m->cpu.a[reg] = kind == ALU_ADD ? m->cpu.a[reg] + data : m->cpu.a[reg] - data;
        return 1;
    }
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &value)) return 0;
    return ea_write(m, &ea, size, alu(&m->cpu, kind, data, value, size));
}

/* ADDI (0x06), SUBI (0x04), CMPI (0x0C): immediate precedes destination words. */
static int execute_immediate(gw_machine *m, uint32_t op, int kind)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    uint32_t src, dst;
    ea_t imm, ea;
    if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, 7, 4, size, &imm)) return 0;
    src = imm.value;
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &dst)) return 0;
    dst = alu(&m->cpu, kind, src, dst, size);
    return kind == ALU_CMP ? 1 : ea_write(m, &ea, size, dst);
}

static void logic_flags(gw_cpu *cpu, uint32_t value, unsigned size)
{
    move_flags(cpu, value & size_mask(size), size);
}

/* Condition codes 0-15 per the M68000PRM table; codes 0 and 1 (T, F) are
 * BRA/BSR and DBF in their instructions but are evaluated here for DBcc and Bcc. */
static int condition_true(uint16_t sr, unsigned cc)
{
    int c = (sr & 1u) != 0, v = (sr & 2u) != 0, z = (sr & 4u) != 0, n = (sr & 8u) != 0;
    switch (cc & 15u) {
    case 0: return 1;
    case 1: return 0;
    case 2: return !c && !z;
    case 3: return c || z;
    case 4: return !c;
    case 5: return c;
    case 6: return !z;
    case 7: return z;
    case 8: return !v;
    case 9: return v;
    case 10: return !n;
    case 11: return n;
    case 12: return n == v;
    case 13: return n != v;
    case 14: return !z && n == v;
    default: return z || n != v;
    }
}

/* Branch and jump targets that are odd would raise an address error on the next
 * instruction fetch; that frame is not modeled, so they stop visibly instead. */
static int jump_to(gw_machine *m, uint32_t target)
{
    if (target & 1u) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
        m->cpu.fault_address = target;
        return 0;
    }
    m->cpu.pc = target;
    return 1;
}

static int push32(gw_machine *m, uint32_t value)
{
    uint32_t sp = m->cpu.a[7] - 4u;
    if (!gw_bus_write(m, sp, 4, value)) return 0;
    m->cpu.a[7] = sp;
    return 1;
}

static int pop32(gw_machine *m, uint32_t *value)
{
    if (!gw_bus_read(m, m->cpu.a[7], 4, value)) return 0;
    m->cpu.a[7] += 4u;
    return 1;
}

/* M68000PRM4-111/4-194; MC68000UM table8-12: LINK.W16 clocks,
 * UNLK12. A7 alias forms are deliberately unsupported pending an independent
 * alias-order oracle. Failed transfers expose this model's partial state;
 * physical exception sequencing is not implemented. */
static int execute_frame(gw_machine *m, uint32_t op)
{
    unsigned reg = op & 7u;
    uint32_t value;
    if (reg == 7u) return unsupported_instruction(m);
    if (!(op & 8u)) {
        if (!fetch(m, 2, &value)) return 0;
        m->cpu.a[7] -= 4u;
        if (!gw_bus_write(m, m->cpu.a[7], 4, m->cpu.a[reg])) return 0;
        m->cpu.a[reg] = m->cpu.a[7];
        m->cpu.a[7] += sign16(value);
    } else {
        m->cpu.a[7] = m->cpu.a[reg];
        if (!pop32(m, &value)) return 0;
        m->cpu.a[reg] = value;
    }
    return 1;
}

/* Bcc / BRA / BSR (group 6). The displacement is relative to the address after
 * the opcode word. Idle ticks follow the BRA precedent: taken branches reach
 * ten cycles in total, not-taken branches eight (byte) or twelve (word). */
static int execute_branch(gw_machine *m, uint32_t op)
{
    unsigned cc = (op >> 8) & 15u;
    uint32_t base = m->cpu.pc, disp = op & 0xffu;
    int word = disp == 0;
    if (word) {
        if (!fetch(m, 2, &disp)) return 0;
        disp = sign16(disp);
    } else if (disp & 0x80u) {
        disp |= UINT32_C(0xffffff00);
    }
    if (cc == 1) { /* BSR */
        if (!push32(m, m->cpu.pc)) return 0;
        m->tick += (word ? 6u : 2u) * GW_CPU_DIVIDER;
        return jump_to(m, base + disp);
    }
    if (!condition_true(m->cpu.sr, cc)) {
        m->tick += 4u * GW_CPU_DIVIDER;
        return 1;
    }
    m->tick += (word ? 2u : 6u) * GW_CPU_DIVIDER;
    return jump_to(m, base + disp);
}

static int execute_dbcc(gw_machine *m, uint32_t op)
{
    uint32_t base = m->cpu.pc, disp, counter;
    unsigned reg = op & 7u;
    if (!fetch(m, 2, &disp)) return 0;
    if (condition_true(m->cpu.sr, (op >> 8) & 15u)) {
        m->tick += 4u * GW_CPU_DIVIDER;
        return 1;
    }
    counter = (m->cpu.d[reg] - 1u) & 0xffffu;
    m->cpu.d[reg] = (m->cpu.d[reg] & UINT32_C(0xffff0000)) | counter;
    if (counter == 0xffffu) {
        m->tick += 6u * GW_CPU_DIVIDER;
        return 1;
    }
    m->tick += 2u * GW_CPU_DIVIDER;
    return jump_to(m, base + sign16(disp));
}

/* JMP (0x4EC0) and JSR (0x4E80) on control addressing modes. */
static int execute_jump(gw_machine *m, uint32_t op, int subroutine)
{
    ea_t ea;
    unsigned mode = (op >> 3) & 7u, reg = op & 7u;
    if (!ea_legal(mode, reg, EA_CONTROL)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, 4, &ea)) return 0;
    if (subroutine && !push32(m, m->cpu.pc)) return 0;
    return jump_to(m, ea.address);
}

/* BTST/BCHG/BCLR/BSET. Data registers use the bit number modulo 32 as a long
 * operand; memory uses modulo 8 on a byte. Only Z changes. */
static int execute_bit(gw_machine *m, uint32_t op, int is_static)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, type = (op >> 6) & 3u;
    unsigned size = mode == 0 ? 4u : 1u;
    unsigned allowed = type == 0 ? (is_static ? EA_DATA & ~EA_BIT(11) : EA_DATA) : EA_DATA_ALT;
    uint32_t number, value, bit;
    ea_t ea;
    if (!ea_legal(mode, reg, allowed)) return unsupported_instruction(m);
    if (is_static) {
        if (!fetch(m, 2, &number)) return 0;
    } else {
        number = m->cpu.d[(op >> 9) & 7u];
    }
    bit = UINT32_C(1) << (number & (size == 4 ? 31u : 7u));
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &value)) return 0;
    m->cpu.sr = (uint16_t)((m->cpu.sr & ~4u) | ((value & bit) ? 0u : 4u));
    if (type == 0) return 1;
    value = type == 1 ? value ^ bit : type == 2 ? value & ~bit : value | bit;
    return ea_write(m, &ea, size, value);
}

enum { LOGIC_AND, LOGIC_OR, LOGIC_EOR };

/* Original MC68000 word multiply: unsigned low words, full32 result.
 * MC68000UM8.3: 38+2*popcount(source) clocks, plus word EA time.
 * Opcode/read/extension bus cycles already charge four clocks each. */
static int execute_mulu(gw_machine *m, uint32_t op)
{
    unsigned mode=(op>>3)&7u, reg=op&7u, dst=(op>>9)&7u, n=0;
    uint32_t source,product;
    ea_t ea;
    if(!ea_legal(mode,reg,EA_DATA)) return unsupported_instruction(m);
    if(!ea_address(m,mode,reg,2,&ea) || !ea_read(m,&ea,2,&source)) return 0;
    for(unsigned bit=0;bit<16;bit++) n+=(source>>bit)&1u;
    product=(m->cpu.d[dst]&0xffffu)*source;
    m->cpu.d[dst]=product;
    logic_flags(&m->cpu,product,4);
    m->tick+=(34u+2u*n+((mode==4 || mode==6 || (mode==7 && reg==3))?2u:0u))*GW_CPU_DIVIDER;
    return 1;
}

/* Original68000 signed word product, M68000PRM4-135/136.
 * MC68000UM8.3 counts01/10 transitions after appending a zero LSB.
 * Operand conversion uses representable positive pieces, never a narrowing
 * unsigned-to-signed cast; every signed16 product fits int32_t. */
static int execute_muls(gw_machine *m, uint32_t op)
{
    unsigned mode=(op>>3)&7u, reg=op&7u, dst=(op>>9)&7u, n=0;
    uint32_t source,low,transitions,product;
    int32_t multiplier,multiplicand;
    ea_t ea;
    if(!ea_legal(mode,reg,EA_DATA)) return unsupported_instruction(m);
    if(!ea_address(m,mode,reg,2,&ea) || !ea_read(m,&ea,2,&source)) return 0;
    low=m->cpu.d[dst]&0xffffu;
    multiplier=(int32_t)(source&0x7fffu)-(int32_t)(source&0x8000u);
    multiplicand=(int32_t)(low&0x7fffu)-(int32_t)(low&0x8000u);
    transitions=source^(source<<1);
    for(unsigned bit=0;bit<16;bit++) n+=(transitions>>bit)&1u;
    product=(uint32_t)(multiplier*multiplicand);
    m->cpu.d[dst]=product;
    logic_flags(&m->cpu,product,4);
    m->tick+=(34u+2u*n+((mode==4 || mode==6 || (mode==7 && reg==3))?2u:0u))*GW_CPU_DIVIDER;
    return 1;
}

/* NXP M68000PRM4-96..97. Nonzero word divisor only; divide-by-zero
 * exception frames remain outside this subset and stop explicitly.
 * MC68000UM8.3 gives a140-clock maximum and operand variability, not
 * its algorithm. Charge that maximum plus EA time as a stated approximation. */
static int execute_divu(gw_machine *m, uint32_t op)
{
    unsigned mode=(op>>3)&7u,reg=op&7u,dst=(op>>9)&7u;
    uint32_t source,dividend=m->cpu.d[dst],quotient,remainder;
    ea_t ea;
    if(!ea_legal(mode,reg,EA_DATA)) return unsupported_instruction(m);
    if(!ea_address(m,mode,reg,2,&ea) || !ea_read(m,&ea,2,&source)) return 0;
    if(!source) {m->cpu.stop_reason=GW_STOP_UNSUPPORTED_STATE;return 0;}
    quotient=dividend/source;remainder=dividend%source;
    if(quotient>0xffffu) {
        /* N/Z undefined on overflow: preserve them by explicit model policy. */
        m->cpu.sr=(uint16_t)((m->cpu.sr&~3u)|2u);
    } else {
        m->cpu.d[dst]=(remainder<<16)|quotient;
        logic_flags(&m->cpu,quotient,2);
    }
    m->tick+=(136u+((mode==4 || mode==6 || (mode==7&&reg==3))?2u:0u))*GW_CPU_DIVIDER;
    return 1;
}

static uint32_t logic_op(int kind, uint32_t a, uint32_t b)
{
    return kind == LOGIC_AND ? a & b : kind == LOGIC_OR ? a | b : a ^ b;
}

/* AND (group 0xC) and OR (group 0x8). */
static int execute_logic(gw_machine *m, uint32_t op, int kind)
{
    unsigned reg = (op >> 9) & 7u, opmode = (op >> 6) & 7u;
    unsigned mode = (op >> 3) & 7u, ereg = op & 7u, size = op_size(opmode & 3u);
    uint32_t mask = size_mask(size), src, res;
    ea_t ea;
    if (opmode == 3 || opmode == 7) return unsupported_instruction(m); /* MUL/DIV */
    if (opmode < 3) { /* <ea>,Dn */
        if (!ea_legal(mode, ereg, EA_DATA)) return unsupported_instruction(m);
        if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &src)) return 0;
        res = logic_op(kind, src, m->cpu.d[reg] & mask) & mask;
        logic_flags(&m->cpu, res, size);
        m->cpu.d[reg] = (m->cpu.d[reg] & ~mask) | res;
        return 1;
    }
    /* Dn,<ea>: modes 0-1 here encode ABCD/SBCD/EXG/CMPM and stay unsupported. */
    if (opmode < 4 || !ea_legal(mode, ereg, EA_MEM_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &src)) return 0;
    res = logic_op(kind, src, m->cpu.d[reg] & mask) & mask;
    logic_flags(&m->cpu, res, size);
    return ea_write(m, &ea, size, res);
}

/* EOR Dn,Dn is also legal (mode 0), unlike AND/OR Dn,<ea>. */
static int execute_eor(gw_machine *m, uint32_t op)
{
    unsigned mode = (op >> 3) & 7u, ereg = op & 7u, size = op_size(((op >> 6) & 7u) - 4u);
    uint32_t src, res, mask = size_mask(size);
    ea_t ea;
    if (!ea_legal(mode, ereg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, ereg, size, &ea) || !ea_read(m, &ea, size, &src)) return 0;
    res = (src ^ m->cpu.d[(op >> 9) & 7u]) & mask;
    logic_flags(&m->cpu, res, size);
    return ea_write(m, &ea, size, res);
}

/* ANDI (0x02), ORI (0x00) and EORI (0x0A) to a data-alterable destination. */
static int execute_logic_immediate(gw_machine *m, uint32_t op, int kind)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    uint32_t value, res;
    ea_t imm, ea;
    if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, 7, 4, size, &imm)) return 0;
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &value)) return 0;
    res = logic_op(kind, value, imm.value) & size_mask(size);
    logic_flags(&m->cpu, res, size);
    return ea_write(m, &ea, size, res);
}

/* NEG (0x44), NOT (0x46). */
static int execute_unary(gw_machine *m, uint32_t op, int negate)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, size = op_size((op >> 6) & 3u);
    uint32_t value, res;
    ea_t ea;
    if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, size, &ea) || !ea_read(m, &ea, size, &value)) return 0;
    if (negate) {
        res = alu(&m->cpu, ALU_SUB, value, 0, size);
    } else {
        res = ~value & size_mask(size);
        logic_flags(&m->cpu, res, size);
    }
    return ea_write(m, &ea, size, res);
}

/* Shift and rotate engine: one bit per step, count already masked to 0..63.
 * type 0 arithmetic, 1 logical, 3 rotate (ROXL/ROXR are not implemented). X
 * follows C for shifts with a nonzero count and is unchanged for rotates. */
static uint32_t shift_execute(gw_cpu *cpu, unsigned type, int left, uint32_t value,
                              unsigned count, unsigned size)
{
    uint32_t mask = size_mask(size), sign = size_sign(size), result = value & mask;
    int carry = 0, overflow = 0;
    unsigned i;
    for (i = 0; i < count; ++i) {
        uint32_t before = result;
        if (left) {
            carry = (result & sign) != 0;
            result = (result << 1) & mask;
            if (type == 3 && carry) result |= 1u;
            if (type == 0 && ((before ^ result) & sign)) overflow = 1;
        } else {
            carry = (int)(result & 1u);
            result >>= 1;
            if (type == 0) result |= before & sign;
            else if (type == 3 && carry) result |= sign;
        }
    }
    set_ccr(cpu, carry, (result & sign) != 0, result == 0, overflow, carry,
            count == 0 || type == 3);
    return result;
}

/* Group 0xE: register forms (all sizes) and word memory forms (count 1). */
static int execute_shift(gw_machine *m, uint32_t op)
{
    unsigned size = (op >> 6) & 3u, left = (op >> 8) & 1u, reg = op & 7u;
    unsigned type, count;
    uint32_t value;
    ea_t ea;
    if (size == 3) {
        unsigned mode = (op >> 3) & 7u;
        if ((op & 0x0800u) || ((op >> 9) & 3u) == 2u || !ea_legal(mode, reg, EA_MEM_ALT))
            return unsupported_instruction(m);
        type = (op >> 9) & 3u;
        if (!ea_address(m, mode, reg, 2, &ea) || !ea_read(m, &ea, 2, &value)) return 0;
        return ea_write(m, &ea, 2, shift_execute(&m->cpu, type, (int)left, value, 1, 2));
    }
    type = (op >> 3) & 3u;
    if (type == 2) return unsupported_instruction(m);
    size = op_size(size);
    if (op & 0x20u) {
        count = m->cpu.d[(op >> 9) & 7u] & 63u;
    } else {
        count = (op >> 9) & 7u;
        if (count == 0) count = 8;
    }
    m->tick += (size == 4 ? 4u + 2u * count : 2u + 2u * count) * GW_CPU_DIVIDER;
    value = shift_execute(&m->cpu, type, (int)left, m->cpu.d[reg], count, size);
    m->cpu.d[reg] = (m->cpu.d[reg] & ~size_mask(size)) | value;
    return 1;
}

/* EXT.w (0x4880) and EXT.l (0x48C0) on a data register. */
static int execute_ext(gw_machine *m, uint32_t op)
{
    unsigned reg = op & 7u;
    uint32_t value = m->cpu.d[reg];
    if (op & 0x40u) {
        value = sign16(value & 0xffffu);
        m->cpu.d[reg] = value;
        logic_flags(&m->cpu, value, 4);
    } else {
        value &= 0xffu;
        if (value & 0x80u) value |= 0xff00u;
        m->cpu.d[reg] = (m->cpu.d[reg] & UINT32_C(0xffff0000)) | value;
        logic_flags(&m->cpu, value, 2);
    }
    return 1;
}

/* M68000PRM 4-128..130; MC68000UM table8-10. MOVEM owns the
 * repeated EA updates: the generic single-operand helper must not apply an
 * extra decrement/increment. All transfers use the existing ordered bus.
 * Completed registers/words survive a fault; a failing predecrement is visible,
 * while postincrement commits only after a complete operand transfer. */
static int execute_movem(gw_machine *m, uint32_t op)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u;
    unsigned size = (op & 0x40u) ? 4u : 2u, bit;
    int load = (op & 0x400u) != 0;
    unsigned allowed = load ? EA_CONTROL | EA_BIT(3) :
                               (EA_CONTROL & ~(EA_BIT(9) | EA_BIT(10))) | EA_BIT(4);
    uint32_t mask, address, value, initial_base = m->cpu.a[reg];
    ea_t ea;
    if (!ea_legal(mode, reg, allowed)) return unsupported_instruction(m);
    if (!fetch(m, 2, &mask)) return 0;
    if (mode == 3 || mode == 4) address = initial_base;
    else {
        if (!ea_address(m, mode, reg, size, &ea)) return 0;
        address = ea.address;
    }
    /* Opcode/mask/EA fetches and data bus cycles already charge their clocks.
     * Indexed EAs add two idle clocks; loads add four. Prefetch is not modeled. */
    m->tick += ((load ? 4u : 0u) + ((mode == 6 || (mode == 7 && reg == 3)) ? 2u : 0u)) * GW_CPU_DIVIDER;
    for (bit = 0; bit < 16; ++bit) {
        unsigned r;
        if (!(mask & (1u << bit))) continue;
        r = mode == 4 ? 15u - bit : bit;
        if (mode == 4) {
            address -= size;
            m->cpu.a[reg] = address;
        }
        if (load) {
            if (!gw_bus_read(m, address, size, &value)) return 0;
            if (size == 2) value = sign16(value);
            if (r < 8) m->cpu.d[r] = value;
            else if (!(mode == 3 && r == reg + 8u)) m->cpu.a[r - 8u] = value;
        } else {
            value = r < 8 ? m->cpu.d[r] :
                    mode == 4 && r == reg + 8u ? initial_base : m->cpu.a[r - 8u];
            if (!gw_bus_write(m, address, size, value & size_mask(size))) return 0;
        }
        if (mode != 4) address += size;
        if (mode == 3) m->cpu.a[reg] = address;
    }
    return 1;
}

void gw_cpu_reset(gw_machine *m)
{
    memset(&m->cpu, 0, sizeof(m->cpu));
    m->cpu.sr = 0x2700;
    /* Load validation guarantees that these vector fetches are mapped. */
    (void)gw_bus_read(m, 0, 4, &m->initial_ssp);
    (void)gw_bus_read(m, 4, 4, &m->initial_pc);
    m->cpu.a[7] = m->initial_ssp;
    m->cpu.pc = m->initial_pc;
}

static int supervisor_state(gw_machine *m, uint32_t sr)
{
    /* User/trace execution requires stack switching/trace exceptions, not a
     * silent approximation. Leave the attempted instruction visible. */
    if (!(sr & 0x2000u) || (sr & 0x8000u)) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_STATE;
        return 0;
    }
    return 1;
}

/* Write the implemented SR bits (T, S, interrupt mask, XNZVC). Clearing S or
 * setting T would need user-stack switching or trace exceptions, so it stops. */
static int sr_write(gw_machine *m, uint32_t value)
{
    value &= 0xa71fu;
    if (!supervisor_state(m, value)) return 0;
    m->cpu.sr = (uint16_t)value;
    return 1;
}

static void ccr_write(gw_cpu *cpu, uint32_t value)
{
    cpu->sr = (uint16_t)((cpu->sr & 0xffe0u) | (value & 0x1fu));
}

/* ANDI/ORI/EORI to CCR (byte immediate) or SR (word immediate). */
static int execute_logic_to_sr(gw_machine *m, uint32_t op, int kind)
{
    uint32_t imm;
    int to_sr = (op & 0x40u) != 0;
    if (!fetch(m, 2, &imm)) return 0;
    if (to_sr) return sr_write(m, logic_op(kind, m->cpu.sr, imm));
    ccr_write(&m->cpu, logic_op(kind, m->cpu.sr, imm));
    return 1;
}

/* MOVE from SR (0x40C0), MOVE to CCR (0x44C0), MOVE to SR (0x46C0). */
static int execute_move_sr(gw_machine *m, uint32_t op)
{
    unsigned mode = (op >> 3) & 7u, reg = op & 7u, group = (op >> 8) & 7u;
    uint32_t value;
    ea_t ea;
    if (group == 0) { /* MOVE from SR; the 68000 read-before-write cycle is not modeled */
        if (!ea_legal(mode, reg, EA_DATA_ALT)) return unsupported_instruction(m);
        return ea_address(m, mode, reg, 2, &ea) && ea_write(m, &ea, 2, m->cpu.sr);
    }
    if (!ea_legal(mode, reg, EA_DATA)) return unsupported_instruction(m);
    if (!ea_address(m, mode, reg, 2, &ea) || !ea_read(m, &ea, 2, &value)) return 0;
    if (group == 4) {
        ccr_write(&m->cpu, value);
        return 1;
    }
    return sr_write(m, value);
}

static int trap(gw_machine *m, uint32_t number)
{
    uint32_t handler, sp = m->cpu.a[7];
    uint32_t saved_sr = m->cpu.sr;
    m->cpu.a[7] = sp - 6u;
    if (!gw_bus_write(m, sp - 4u, 4, m->cpu.pc) ||
        !gw_bus_write(m, sp - 6u, 2, saved_sr) ||
        !gw_bus_read(m, (32u + number) * 4u, 4, &handler)) return 0;
    m->cpu.sr = (uint16_t)((saved_sr | 0x2000u) & 0x7fffu);
    m->cpu.pc = handler;
    m->tick += 10 * GW_CPU_DIVIDER;
    gw_count(m, &m->exceptions);
    return 1;
}

/* Autovectored interrupt acceptance (MC68000UM exception processing; vectors 25..31 at
 * 0x64..0x7C, so level 4 reads 0x70 and level 6 reads 0x78). Ordering mirrors trap(): the
 * PC long and then the SR word go to the supervisor stack through the bus, the vector is
 * read, S is set, T cleared and the mask raised to `level`, and the source is acknowledged.
 * Idle ticks bring the whole entry, bus ticks included, to GW_INTERRUPT_TICKS. */
int gw_cpu_accept_interrupt(gw_machine *m, int level)
{
    uint32_t handler, sp = m->cpu.a[7];
    uint32_t saved_sr = m->cpu.sr;
    uint64_t start = m->tick, elapsed;
    m->cpu.instruction_address = m->cpu.pc;
    m->cpu.opcode = 0;
    if (!gw_bus_write(m, sp - 4u, 4, m->cpu.pc) ||
        !gw_bus_write(m, sp - 6u, 2, saved_sr) ||
        !gw_bus_read(m, (24u + (uint32_t)level) * 4u, 4, &handler)) return 0;
    m->cpu.a[7] = sp - 6u;
    m->cpu.sr = (uint16_t)(0x2000u | ((uint32_t)level << 8) | (saved_sr & 0x1fu));
    if (!jump_to(m, handler)) return 0;
    elapsed = m->tick - start;
    if (elapsed < GW_INTERRUPT_TICKS) m->tick += GW_INTERRUPT_TICKS - elapsed;
    gw_vdp_irq_ack(m, level);
    gw_count(m, &m->exceptions);
    return 1;
}

static int return_exception(gw_machine *m)
{
    uint32_t sr, pc, sp = m->cpu.a[7];
    if (!gw_bus_read(m, sp, 2, &sr) || !gw_bus_read(m, sp + 2u, 4, &pc)) return 0;
    if (!supervisor_state(m, sr)) return 0;
    m->cpu.a[7] = sp + 6u;
    m->cpu.sr = (uint16_t)(sr & 0xa71fu);
    m->cpu.pc = pc;
    m->tick += 4 * GW_CPU_DIVIDER;
    gw_count(m, &m->exception_returns);
    return 1;
}

void gw_cpu_step(gw_machine *m)
{
    uint32_t op, value;
    int retired = 1;
    m->cpu.instruction_address = m->cpu.pc;
    m->cpu.opcode = 0;
    if (!supervisor_state(m, m->cpu.sr) || !fetch(m, 2, &op)) return;
    m->cpu.opcode = op;
    if ((op >> 12) >= 1 && (op >> 12) <= 3) {
        retired = execute_move(m, op);
    } else if ((op & 0xf1c0u) == 0x41c0u) {
        retired = execute_lea(m, op);
    } else if ((op & 0xffc0u) == 0x4840u && (op & 0x0038u) != 0) {
        retired = execute_pea(m, op);
    } else if ((op & 0xff00u) == 0x4200u && (op & 0xc0u) != 0xc0u) {
        retired = execute_clr(m, op);
    } else if ((op & 0xff00u) == 0x4a00u && (op & 0xc0u) != 0xc0u) {
        retired = execute_tst(m, op);
    } else if (((op & 0xff00u) == 0x4400u || (op & 0xff00u) == 0x4600u) && (op & 0xc0u) != 0xc0u) {
        retired = execute_unary(m, op, (op & 0xff00u) == 0x4400u);
    } else if ((op & 0xffc0u) == 0x40c0u || (op & 0xffc0u) == 0x44c0u || (op & 0xffc0u) == 0x46c0u) {
        retired = execute_move_sr(m, op);
    } else if ((op & 0xfff8u) == 0x4880u || (op & 0xfff8u) == 0x48c0u) {
        retired = execute_ext(m, op);
    } else if ((op & 0xfb80u) == 0x4880u) {
        retired = execute_movem(m, op);
    } else if ((op & 0xfff8u) == 0x4840u) {
        m->cpu.d[op & 7u] = (m->cpu.d[op & 7u] << 16) | (m->cpu.d[op & 7u] >> 16);
        logic_flags(&m->cpu, m->cpu.d[op & 7u], 4);
    } else if ((op & 0xfff0u) == 0x4e50u) {
        retired = execute_frame(m, op);
    } else if ((op & 0xffc0u) == 0x4e80u || (op & 0xffc0u) == 0x4ec0u) {
        retired = execute_jump(m, op, (op & 0x40u) == 0);
    } else if (op == 0x4e75u) {
        retired = pop32(m, &value) && jump_to(m, value);
        if (retired) m->tick += 4 * GW_CPU_DIVIDER;
    } else if ((op & 0xf138u) == 0xd100u && (op & 0xc0u) != 0xc0u) {
        retired = execute_addx_dn(m, op);
    } else if ((op >> 12) == 0xdu) {
        retired = execute_arith(m, op, ALU_ADD);
    } else if ((op >> 12) == 0x9u) {
        retired = execute_arith(m, op, ALU_SUB);
    } else if ((op >> 12) == 0xbu) {
        unsigned opmode = (op >> 6) & 7u;
        if (opmode >= 4 && opmode <= 6 && ((op >> 3) & 7u) != 1u) retired = execute_eor(m, op);
        else retired = execute_arith(m, op, ALU_CMP);
    } else if ((op & 0xf1c0u) == 0xc0c0u) {
        retired = execute_mulu(m,op);
    } else if ((op & 0xf1c0u) == 0xc1c0u) {
        retired = execute_muls(m,op);
    } else if ((op >> 12) == 0xcu) {
        retired = execute_logic(m, op, LOGIC_AND);
    } else if ((op & 0xf1c0u) == 0x80c0u) {
        retired = execute_divu(m,op);
    } else if ((op >> 12) == 0x8u) {
        retired = execute_logic(m, op, LOGIC_OR);
    } else if ((op >> 12) == 0xeu) {
        retired = execute_shift(m, op);
    } else if ((op & 0xf0f8u) == 0x50c8u) {
        retired = execute_dbcc(m, op);
    } else if ((op & 0xf0f8u) == 0x50c0u) {
        /* Scc Dn: M68000PRM4-172/173, byte destination, CCR unchanged.
         * MC68000UM8.5 table8-6: false4/true6 clocks, including opcode fetch.
         * Memory forms remain unsupported; their read-before-write cycle is
         * not introduced by this register-only repair. */
        value = condition_true(m->cpu.sr, (op >> 8) & 15u) ? 0xffu : 0u;
        m->cpu.d[op & 7u] = (m->cpu.d[op & 7u] & UINT32_C(0xffffff00)) | value;
        if (value) m->tick += 2u * GW_CPU_DIVIDER;
    } else if ((op & 0xf000u) == 0x5000u && (op & 0xc0u) != 0xc0u) {
        retired = execute_quick(m, op);
    } else if (op == 0x003cu || op == 0x007cu || op == 0x023cu || op == 0x027cu ||
               op == 0x0a3cu || op == 0x0a7cu) {
        retired = execute_logic_to_sr(m, op, (op & 0xff00u) == 0x0200u ? LOGIC_AND :
                                             (op & 0xff00u) == 0x0000u ? LOGIC_OR : LOGIC_EOR);
    } else if ((op & 0xf100u) == 0x0100u && ((op >> 3) & 7u) != 1u) {
        retired = execute_bit(m, op, 0);
    } else if ((op & 0xff00u) == 0x0800u) {
        retired = execute_bit(m, op, 1);
    } else if (((op & 0xff00u) == 0x0600u || (op & 0xff00u) == 0x0400u ||
                (op & 0xff00u) == 0x0c00u) && (op & 0xc0u) != 0xc0u) {
        retired = execute_immediate(m, op, (op & 0xff00u) == 0x0600u ? ALU_ADD :
                                           (op & 0xff00u) == 0x0400u ? ALU_SUB : ALU_CMP);
    } else if (((op & 0xff00u) == 0x0200u || (op & 0xff00u) == 0x0000u ||
                (op & 0xff00u) == 0x0a00u) && (op & 0xc0u) != 0xc0u) {
        retired = execute_logic_immediate(m, op, (op & 0xff00u) == 0x0200u ? LOGIC_AND :
                                                 (op & 0xff00u) == 0x0000u ? LOGIC_OR : LOGIC_EOR);
    } else if ((op & 0xf100u) == 0x7000u) {
        value = op & 0xffu;
        if (value & 0x80u) value |= UINT32_C(0xffffff00);
        m->cpu.d[(op >> 9) & 7u] = value;
        move_flags(&m->cpu, value, 4);
    } else if ((op >> 12) == 0x6u) {
        retired = execute_branch(m, op);
    } else if ((op & 0xfff0u) == 0x4e40u) {
        retired = trap(m, op & 15u);
    } else if ((op & 0xfff0u) == 0x4e60u) {
        /* Supervisor check already precedes fetch. A7 remains SSP: these
         * explicit transfers do not enable user-mode stack switching. */
        if(op & 8u) m->cpu.a[op&7u]=m->cpu.usp;
        else m->cpu.usp=m->cpu.a[op&7u];
    } else if (op == 0x4e73u) {
        retired = return_exception(m);
    } else if (op == 0x4e70u) {
        m->tick += 128 * GW_CPU_DIVIDER;
        gw_count(m, &m->external_resets);
    } else if (op == 0x4e72u) {
        if (!fetch(m, 2, &value) || !supervisor_state(m, value)) return;
        m->cpu.sr = (uint16_t)(value & 0xa71fu);
        m->cpu.stop_reason = GW_STOP_CPU_STOPPED;
    } else if (op != 0x4e71u) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_INSTRUCTION;
        retired = 0;
    }
    if (retired) gw_count(m, &m->instructions);
}
