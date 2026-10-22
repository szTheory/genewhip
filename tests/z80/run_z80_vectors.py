#!/usr/bin/env python3
"""Reproducible pinned Z80 corpus selector and hooks adapter (stdlib only)."""
import argparse
import collections
import copy
import contextlib
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import urllib.request
from urllib.parse import quote

ROOT = pathlib.Path(__file__).resolve().parent
REV = "ebe1875d48f374bcfd4b505d8eb8ee751568b5f7"
RAW = f"https://raw.githubusercontent.com/SingleStepTests/z80/{REV}/"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def fetch(url):
    url = quote(url, safe=":/?=&")
    req = urllib.request.Request(url, headers={"User-Agent": "Genewhip-vector-evidence"})
    with urllib.request.urlopen(req, timeout=40) as response:
        return response.read()


def selected_paths():
    # One record for each instruction encoding whose family is admitted by
    # the current PR slice. Prefix opcodes remain for Plan 03-11.
    ops = {0x00, 0x08, 0xD9, 0xEB, 0xE3}
    ops.update(range(0x40, 0x80))
    ops.discard(0x76)
    ops.update(op for op in range(256) if (op & 0xC7) == 0x06 or (op & 0xCF) == 0x01)
    ops.update((0x02, 0x0A, 0x12, 0x1A, 0x22, 0x2A, 0x32, 0x3A))
    ops.update(op for op in range(256) if (op & 0xCF) in (0xC1, 0xC5))
    ops.update(op for op in range(0x80,0xc0))
    ops.update(op for op in range(256) if (op&0xc7)==0xc6)
    ops.update(op for op in range(256) if (op&0xc7) in (0x04,0x05))
    ops.update(op for op in range(256) if (op&0xcf) in (0x03,0x0b,0x09))
    ops.update((0x07,0x0f,0x17,0x1f,0x27,0x2f,0x37,0x3f,0xf3,0xfb,0x76,0xf9))
    ops.update((0x10,0x18,0x20,0x28,0x30,0x38,0xc3,0xc9,0xcd,0xd3,0xdb,0xe9))
    ops.update(op for op in range(256) if (op&0xc7) in (0xc0,0xc2,0xc4,0xc7))
    paths = [f"v1/{op:02x}.json" for op in sorted(ops)]
    # CB SLL (30..37) is intentionally excluded; all other CB encodings have
    # a documented instruction-table definition in UM0080 Chapter 4.
    paths.extend(f"v1/cb {op:02x}.json" for op in range(256) if not 0x30 <= op <= 0x37)
    ed_ops = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4d,0x4f,
              0x50,0x51,0x52,0x53,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5e,0x5f,
              0x60,0x61,0x62,0x63,0x67,0x68,0x69,0x6a,0x6b,0x6f,0x72,0x73,0x78,0x79,0x7a,0x7b,
              0xa0,0xa1,0xa2,0xa3,0xa8,0xa9,0xaa,0xab,0xb0,0xb1,0xb2,0xb3,0xb8,0xb9,0xba,0xbb}
    paths.extend(f"v1/ed {op:02x}.json" for op in sorted(ed_ops))
    indexed_ops={0x21,0x22,0x23,0x29,0x2a,0x2b,0xe1,0xe3,0xe5,0xe9,0xf9,
                 0x34,0x35,0x36}
    indexed_ops.update(op for op in range(0x40,0x80) if op!=0x76 and ((op&7)==6 or ((op>>3)&7)==6))
    indexed_ops.update(op for op in range(0x80,0xc0) if (op&7)==6)
    for prefix in ("dd","fd"):
        paths.extend(f"v1/{prefix} {op:02x}.json" for op in sorted(indexed_ops))
        paths.extend(f"v1/{prefix} cb __ {op:02x}.json" for op in range(256) if (op&7)==6 and op!=0x36)
    return paths


def branch_taken(op, test):
    state=test["initial"];f=state["f"]
    if op==0x10:return ((state["b"]-1)&0xff)!=0
    if op==0x18:return True
    if 0x20<=op<=0x38:return condition((op>>3)&3,f)
    if op==0xc9:return True
    if op in (0xc3,0xcd):return True
    if (op&0xc7) in (0xc0,0xc2,0xc4):return condition((op>>3)&7,f)
    return False


def condition(code, f):
    return (not bool(f&0x40),bool(f&0x40),not bool(f&1),bool(f&1),
            not bool(f&4),bool(f&4),not bool(f&0x80),bool(f&0x80))[code&7]


def tree_inventory():
    url = f"https://api.github.com/repos/SingleStepTests/z80/git/trees/{REV}?recursive=1"
    data = json.loads(fetch(url))
    if data.get("truncated"):
        raise ValueError("pinned repository tree is truncated")
    rows = [{"path": e["path"], "git_blob_sha1": e["sha"], "bytes": e.get("size", 0)}
            for e in data["tree"] if e["type"] == "blob" and e["path"].startswith("v1/")]
    return rows


ED_DOCUMENTED = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4d,0x4f,
                 0x50,0x51,0x52,0x53,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5e,0x5f,
                 0x60,0x61,0x62,0x63,0x67,0x68,0x69,0x6a,0x6b,0x6f,0x72,0x73,0x78,0x79,0x7a,0x7b,
                 0xa0,0xa1,0xa2,0xa3,0xa8,0xa9,0xaa,0xab,0xb0,0xb1,0xb2,0xb3,0xb8,0xb9,0xba,0xbb}


def indexed_opcode_roster():
    ops={0x21,0x22,0x23,0x29,0x2a,0x2b,0xe1,0xe3,0xe5,0xe9,0xf9,0x34,0x35,0x36}
    ops.update(op for op in range(0x40,0x80) if op!=0x76 and ((op&7)==6 or ((op>>3)&7)==6))
    ops.update(op for op in range(0x80,0xc0) if (op&7)==6)
    return ops


def classify(op, source=None):
    if source and source.startswith("v1/cb "):
        sub=int(source.rsplit(" ",1)[1].split(".",1)[0],16)
        if 0x30<=sub<=0x37:return "gated:undocumented-opcode"
        return "CB"
    if source and source.startswith("v1/ed "):
        sub=int(source.rsplit(" ",1)[1].split(".",1)[0],16)
        if sub not in ED_DOCUMENTED:return "gated:undocumented-opcode"
        return "ED"
    if source and (source.startswith("v1/dd cb ") or source.startswith("v1/fd cb ")):
        sub=int(source.rsplit(" ",1)[1].split(".",1)[0],16)
        if (sub&7)!=6 or sub==0x36:return "gated:unlisted-indexed-CB-encoding"
        return "DD/FD"
    if source and (source.startswith("v1/dd ") or source.startswith("v1/fd ")):
        sub=int(source.rsplit(" ",1)[1].split(".",1)[0],16)
        if sub not in indexed_opcode_roster():return "gated:unlisted-index-prefix"
        return "DD/FD"
    if op == 0: return "NOP"
    if 0x40 <= op <= 0x7F and op != 0x76: return "LD r,r'"
    if (op & 0xC7) == 0x06 or (op & 0xCF) == 0x01 or op in (2,10,18,26,34,42,50,58): return "load"
    if (op & 0xCF) in (0xC1,0xC5) or op in (0x08,0xD9,0xEB,0xE3): return "stack/exchange"
    if 0x80<=op<=0xbf or (op&0xc7)==0xc6 or (op&0xc7) in (4,5) or (op&0xcf) in (3,0xb,9) or op in (7,15,23,31,39,47,55,63): return "ALU/rotate"
    if op in (0xd3, 0xdb): return "I/O"
    if op in (0xf3, 0xfb, 0x76, 0xf9): return "interrupt-control"
    if op in (0x10,0x18,0x20,0x28,0x30,0x38,0xc3,0xc9,0xcd,0xe9) or (op&0xc7) in (0xc0,0xc2,0xc4,0xc7): return "control-flow"
    return "gated:unimplemented-family"


STATE_WIDTHS = {
    "a": 8, "b": 8, "c": 8, "d": 8, "e": 8, "f": 8, "h": 8, "l": 8,
    "i": 8, "r": 8, "q": 8, "af_": 16, "bc_": 16, "de_": 16, "hl_": 16,
    "ix": 16, "iy": 16, "pc": 16, "sp": 16, "wz": 16,
}
STATE_DOMAINS = {"ei": range(2), "iff1": range(2), "iff2": range(2),
                 "im": range(3), "p": range(2)}
STATE_FIELDS = frozenset((*STATE_WIDTHS, *STATE_DOMAINS, "ram"))


def validate_state(state, label="state"):
    if not isinstance(state, dict):
        raise ValueError(f"{label} must be an object")
    missing, extra = STATE_FIELDS - state.keys(), state.keys() - STATE_FIELDS
    if missing or extra:
        details = []
        if missing: details.append("missing " + ", ".join(sorted(missing)))
        if extra: details.append("unexpected " + ", ".join(sorted(extra)))
        raise ValueError(f"{label} schema: {'; '.join(details)}")
    for name, width in STATE_WIDTHS.items():
        value = state[name]
        if type(value) is not int or not 0 <= value < (1 << width):
            raise ValueError(f"{label}.{name} must be an integer in [0, {(1 << width) - 1}]")
    for name, allowed in STATE_DOMAINS.items():
        value = state[name]
        if type(value) is not int or value not in allowed:
            raise ValueError(f"{label}.{name} must be an integer in {list(allowed)}")
    if not isinstance(state["ram"], list):
        raise ValueError(f"{label}.ram must be a list")


def pack_state(state):
    validate_state(state)
    return [((state["a"] << 8) | state["f"]), ((state["b"] << 8) | state["c"]),
            ((state["d"] << 8) | state["e"]), ((state["h"] << 8) | state["l"]),
            state["af_"], state["bc_"], state["de_"], state["hl_"], state["ix"], state["iy"],
            state["sp"], state["pc"], state["wz"], state["i"], state["r"], state["iff1"],
            state["iff2"], state["im"], state["q"], 0, state.get("ei",0)]


def expected_transactions(test):
    pc = test["initial"]["pc"]
    opcode = test["initial"]["ram"]
    op = next((value for address, value in opcode if address == pc), None)
    if op is None:
        raise ValueError("instruction byte absent at initial PC")
    cycles = test["cycles"]
    if len(cycles) < 3:
        raise ValueError("M1 cycle sequence is incomplete")
    # Upstream records one memory-read status sample and the subsequent refresh
    # address/data pins. The adapter represents those as one M1 and one refresh.
    transactions = [[0, pc, op, 4], [6, cycles[2][0], 0, 0]]
    def memory_byte(rows, address):
        return next((v for a, v in rows if a == (address & 0xffff)), None)
    if op in (0xdd,0xfd):
        prefix=op;sub=memory_byte(test["initial"]["ram"],pc+1)
        if sub is None: raise ValueError("index secondary opcode absent")
        transactions.extend([[0,(pc+1)&0xffff,sub,4],[6,cycles[6][0],0,0]])
        state=test["initial"]; index=state["ix"] if prefix==0xdd else state["iy"]
        if sub==0xcb:
            d=memory_byte(state["ram"],pc+2);cbop=memory_byte(state["ram"],pc+3)
            if d is None or cbop is None: raise ValueError("index-CB operands absent")
            address=(index+(d if d<128 else d-256))&0xffff
            value=memory_byte(state["ram"],address)
            if value is None: raise ValueError("index-CB source absent")
            transactions.extend([[1,(pc+2)&0xffff,d,3],[1,(pc+3)&0xffff,cbop,3],[1,address,value,3]])
            group=cbop>>6;bit=(cbop>>3)&7
            if group!=1:
                if group==0:
                    carry=value>>7 if bit in (0,2,4,6) else value&1
                    result=(((value<<1)|carry)&255 if bit==0 else (value>>1)|(carry<<7) if bit==1 else
                            ((value<<1)|(state["f"]&1))&255 if bit==2 else (value>>1)|((state["f"]&1)<<7) if bit==3 else
                            (value<<1)&255 if bit==4 else (value>>1)|(value&0x80) if bit==5 else
                            ((value<<1)|1)&255 if bit==6 else value>>1)
                elif group==2: result=value&~(1<<bit)
                else: result=value|(1<<bit)
                transactions.append([2,address,result&255,3])
            return transactions
        displacement_ops=(sub in (0x34,0x35,0x36) or
                          (0x40<=sub<=0x7f and sub!=0x76 and ((sub&7)==6 or ((sub>>3)&7)==6)) or
                          (0x80<=sub<=0xbf and (sub&7)==6))
        if displacement_ops:
            d=memory_byte(state["ram"],pc+2)
            if d is None: raise ValueError("index displacement absent")
            address=(index+(d if d<128 else d-256))&0xffff
            transactions.append([1,(pc+2)&0xffff,d,3])
            if sub==0x36:
                immediate=memory_byte(state["ram"],pc+3)
                if immediate is None: raise ValueError("index immediate absent")
                transactions.append([1,(pc+3)&0xffff,immediate,3])
                transactions.append([2,address,immediate,3])
            elif sub in (0x34,0x35):
                old=memory_byte(state["ram"],address);new=memory_byte(test["final"]["ram"],address)
                if old is None or new is None: raise ValueError("index INC/DEC memory absent")
                transactions.extend([[1,address,old,3],[2,address,new,3]])
            elif (sub&7)==6:
                old=memory_byte(state["ram"],address)
                if old is None: raise ValueError("index memory source absent")
                transactions.append([1,address,old,3])
            else:
                new=memory_byte(test["final"]["ram"],address)
                if new is None: raise ValueError("index memory destination absent")
                transactions.append([2,address,new,3])
            return transactions
        if sub in (0x21,):
            for off in (2,3):
                v=memory_byte(state["ram"],pc+off)
                if v is None: raise ValueError("index immediate word absent")
                transactions.append([1,(pc+off)&0xffff,v,3])
        elif sub in (0x22,0x2a):
            lo_byte=memory_byte(state["ram"],pc+2);hi_byte=memory_byte(state["ram"],pc+3)
            if lo_byte is None or hi_byte is None: raise ValueError("index address bytes absent")
            address=lo_byte|(hi_byte<<8)
            transactions.extend([[1,(pc+2)&0xffff,lo_byte,3],[1,(pc+3)&0xffff,hi_byte,3]])
            if sub==0x22:
                transactions.extend([[2,address,index&255,3],[2,(address+1)&0xffff,index>>8,3]])
            else:
                lo_value=memory_byte(state["ram"],address);hi_value=memory_byte(state["ram"],address+1)
                if lo_value is None or hi_value is None: raise ValueError("index pair memory source absent")
                transactions.extend([[1,address,lo_value,3],[1,(address+1)&0xffff,hi_value,3]])
        elif sub in (0xe1,0xe3):
            sp=state["sp"]
            values=[memory_byte(state["ram"],sp),memory_byte(state["ram"],sp+1)]
            if None in values: raise ValueError("index stack source absent")
            transactions.extend([[1,sp,values[0],3],[1,(sp+1)&0xffff,values[1],3]])
            if sub==0xe3: transactions.extend([[2,sp,index&255,3],[2,(sp+1)&0xffff,index>>8,3]])
        elif sub==0xe5:
            sp=state["sp"]
            transactions.extend([[2,(sp-1)&0xffff,index>>8,3],[2,(sp-2)&0xffff,index&255,3]])
        return transactions
    if op == 0xcb:
        sub = memory_byte(test["initial"]["ram"], pc + 1)
        if sub is None: raise ValueError("CB secondary opcode absent")
        transactions.extend([[0, (pc + 1) & 0xffff, sub, 4],
                             [6, cycles[6][0], 0, 0]])
        r = sub & 7
        if r == 6:
            address=(test["initial"]["h"]<<8)|test["initial"]["l"]
            value=memory_byte(test["initial"]["ram"],address)
            if value is None: raise ValueError("CB (HL) source absent")
            transactions.append([1,address,value,3])
            if sub >> 6 != 1:
                value=memory_byte(test["final"]["ram"],address)
                if value is None: raise ValueError("CB (HL) final byte absent")
                transactions.append([2,address,value,3])
        return transactions
    if op == 0xed:
        sub=memory_byte(test["initial"]["ram"],pc+1)
        if sub is None: raise ValueError("ED secondary opcode absent")
        transactions.extend([[0,(pc+1)&0xffff,sub,4],[6,cycles[6][0],0,0]])
        if (sub&0xc7)==0x40 or (sub&0xc7)==0x41:
            port=(test["initial"]["b"]<<8)|test["initial"]["c"]
            rows=test.get("ports",[])
            row=next((p for p in rows if p[0]==port),None)
            if row is None: raise ValueError("ED port record absent")
            direction=3 if (sub&7)==0 else 4
            transactions.append([direction,port,row[1],4])
        elif sub in (0x43,0x4b,0x53,0x5b,0x63,0x6b,0x73,0x7b):
            lo_pc=memory_byte(test["initial"]["ram"],pc+2);hi_pc=memory_byte(test["initial"]["ram"],pc+3)
            if lo_pc is None or hi_pc is None: raise ValueError("ED address operand absent")
            address=lo_pc|(hi_pc<<8);transactions.extend([[1,(pc+2)&0xffff,lo_pc,3],[1,(pc+3)&0xffff,hi_pc,3]])
            pair=(test["initial"]["b"],test["initial"]["c"]) if sub in (0x43,0x4b) else (test["initial"]["d"],test["initial"]["e"]) if sub in (0x53,0x5b) else (test["initial"]["h"],test["initial"]["l"]) if sub in (0x63,0x6b) else (test["initial"]["sp"]>>8,test["initial"]["sp"]&255)
            if sub&0x0f==3: transactions.extend([[2,address,pair[1],3],[2,(address+1)&0xffff,pair[0],3]])
            else:
                a=memory_byte(test["initial"]["ram"],address);b=memory_byte(test["initial"]["ram"],address+1)
                if a is None or b is None: raise ValueError("ED pair source absent")
                transactions.extend([[1,address,a,3],[1,(address+1)&0xffff,b,3]])
        elif sub in (0x45,0x4d):
            sp=test["initial"]["sp"]
            for address in (sp,(sp+1)&0xffff):
                value=memory_byte(test["initial"]["ram"],address)
                if value is None: raise ValueError("ED return source absent")
                transactions.append([1,address,value,3])
        elif sub in (0x67,0x6f) or sub in (0xa0,0xa8,0xb0,0xb8,0xa1,0xa9,0xb1,0xb9,0xa2,0xaa,0xb2,0xba,0xa3,0xab,0xb3,0xbb):
            address=(test["initial"]["h"]<<8)|test["initial"]["l"]
            kind=sub&3
            if kind==2:
                port=(test["initial"]["b"]<<8)|test["initial"]["c"]
                row=next((p for p in test.get("ports",[]) if p[0]==port),None)
                if row is None: raise ValueError("ED input port record absent")
                value=row[1];transactions.append([3,port,value,4])
                result=memory_byte(test["final"]["ram"],address)
                if result is None: raise ValueError("ED input memory result absent")
                transactions.append([2,address,result,3])
            else:
                value=memory_byte(test["initial"]["ram"],address)
                if value is None: raise ValueError("ED block source absent")
                transactions.append([1,address,value,3])
            if sub in (0x67,0x6f):
                value=memory_byte(test["final"]["ram"],address)
                if value is None: raise ValueError("ED nibble result absent")
                transactions.append([2,address,value,3])
            elif kind==0:
                address=(test["initial"]["d"]<<8)|test["initial"]["e"]
                value=memory_byte(test["final"]["ram"],address)
                if value is None: raise ValueError("ED transfer result absent")
                transactions.append([2,address,value,3])
            elif kind==3:
                port=(test["initial"]["b"]<<8)|test["initial"]["c"]
                transactions.append([4,port,value,4])
        return transactions
    pc = test["initial"]["pc"]
    if (op & 0xC7) == 0x06:
        v = memory_byte(test["initial"]["ram"], pc + 1)
        if v is None: raise ValueError("LD r,n operand absent")
        transactions.append([1, (pc + 1) & 0xffff, v, 3])
        if ((op >> 3) & 7) == 6:
            hl=(test["initial"]["h"]<<8)|test["initial"]["l"]
            transactions.append([2,hl,v,3])
    elif (op & 0xCF) == 0x01:
        for offset in (1, 2):
            v = memory_byte(test["initial"]["ram"], pc + offset)
            if v is None: raise ValueError("LD rr,nn operand absent")
            transactions.append([1, (pc + offset) & 0xffff, v, 3])
    elif op in (0x02,0x12,0x0a,0x1a):
        state=test["initial"]; address=((state["b"]<<8)|state["c"]) if op in (2,10) else ((state["d"]<<8)|state["e"])
        if op in (2,0x12): v=state["a"]; kind=2
        else:
            v=memory_byte(state["ram"],address); kind=1
            if v is None: raise ValueError("LD (BC/DE) source absent")
        transactions.append([kind,address,v,3])
    elif op in (0x22,0x2a,0x32,0x3a):
        lo_pc=memory_byte(test["initial"]["ram"],pc+1); hi_pc=memory_byte(test["initial"]["ram"],pc+2)
        if lo_pc is None or hi_pc is None: raise ValueError("LD (nn) address absent")
        address=lo_pc|(hi_pc<<8)
        transactions.extend([[1,(pc+1)&0xffff,lo_pc,3],[1,(pc+2)&0xffff,hi_pc,3]])
        if op in (0x22,0x32):
            values=(test["initial"]["l"],test["initial"]["h"]) if op==0x22 else (test["initial"]["a"],)
            for i,v in enumerate(values): transactions.append([2,(address+i)&0xffff,v,3])
        else:
            values=[]
            for i in range(2 if op==0x2a else 1):
                v=memory_byte(test["initial"]["ram"],address+i)
                if v is None: raise ValueError("LD (nn) source absent")
                transactions.append([1,(address+i)&0xffff,v,3]);values.append(v)
    elif op in (0xd3, 0xdb):
        immediate = memory_byte(test["initial"]["ram"], pc + 1)
        if immediate is None: raise ValueError("I/O port operand absent")
        port_address, port_value, direction = test["ports"][0]
        transactions.append([1, (pc + 1) & 0xffff, immediate, 3])
        transactions.append([4 if op == 0xd3 else 3, port_address, port_value, 4])
    elif (op & 0xCF) == 0xC1:
        sp=test["initial"]["sp"]
        for address in (sp,(sp+1)&0xffff):
            v=memory_byte(test["initial"]["ram"],address)
            if v is None: raise ValueError("POP source absent")
            transactions.append([1,address,v,3])
    elif (op & 0xCF) == 0xC5:
        state=test["initial"];n=(op>>4)&3
        value=((state["a"]<<8)|state["f"]) if n==3 else (((state["b"]<<8)|state["c"]) if n==0 else (((state["d"]<<8)|state["e"]) if n==1 else (((state["h"]<<8)|state["l"]) if n==2 else state["sp"])))
        sp=state["sp"]
        transactions.extend([[2,(sp-1)&0xffff,(value>>8)&255,3],[2,(sp-2)&0xffff,value&255,3]])
    elif op==0xe3:
        state=test["initial"];sp=state["sp"]
        values=[memory_byte(state["ram"],sp),memory_byte(state["ram"],sp+1)]
        if None in values: raise ValueError("EX (SP),HL source absent")
        transactions.extend([[1,sp,values[0],3],[1,(sp+1)&0xffff,values[1],3],
                             [2,sp,state["l"],3],[2,(sp+1)&0xffff,state["h"],3]])
    elif 0x80<=op<=0xbf and (op&7)==6:
        state=test["initial"];address=(state["h"]<<8)|state["l"];v=memory_byte(state["ram"],address)
        if v is None: raise ValueError("ALU (HL) source absent")
        transactions.append([1,address,v,3])
    elif (op&0xc7)==0xc6:
        v=memory_byte(test["initial"]["ram"],pc+1)
        if v is None: raise ValueError("ALU immediate absent")
        transactions.append([1,(pc+1)&0xffff,v,3])
    elif (op&0xc7) in (4,5) and ((op>>3)&7)==6:
        state=test["initial"];address=(state["h"]<<8)|state["l"];v=memory_byte(state["ram"],address)
        if v is None: raise ValueError("INC/DEC (HL) source absent")
        transactions.extend([[1,address,v,3],[2,address,memory_byte(test["final"]["ram"],address),3]])
    elif op in (0x10,0x18,0x20,0x28,0x30,0x38):
        v=memory_byte(test["initial"]["ram"],pc+1)
        if v is None: raise ValueError("relative branch displacement absent")
        transactions.append([1,(pc+1)&0xffff,v,3])
    elif op==0xc3 or op==0xcd or (op&0xc7) in (0xc2,0xc4):
        for offset in (1,2):
            v=memory_byte(test["initial"]["ram"],pc+offset)
            if v is None: raise ValueError("control-flow address absent")
            transactions.append([1,(pc+offset)&0xffff,v,3])
        if op==0xcd or ((op&0xc7)==0xc4 and branch_taken(op,test)):
            state=test["initial"];sp=state["sp"];ret=(pc+3)&0xffff
            transactions.extend([[2,(sp-1)&0xffff,(ret>>8)&255,3],[2,(sp-2)&0xffff,ret&255,3]])
    elif op==0xc9 or ((op&0xc7)==0xc0 and branch_taken(op,test)):
        state=test["initial"];sp=state["sp"]
        for address in (sp,(sp+1)&0xffff):
            v=memory_byte(state["ram"],address)
            if v is None: raise ValueError("RET target absent")
            transactions.append([1,address,v,3])
    elif (op&0xc7)==0xc7:
        state=test["initial"];sp=state["sp"];ret=pc+1
        transactions.extend([[2,(sp-1)&0xffff,(ret>>8)&255,3],[2,(sp-2)&0xffff,ret&255,3]])
    if 0x40 <= op <= 0x7F and op != 0x76:
        src, dst = op & 7, (op >> 3) & 7
        hl = (test["initial"]["h"] << 8) | test["initial"]["l"]
        if src == 6:
            value = next((v for a, v in test["initial"]["ram"] if a == hl), None)
            if value is None:
                raise ValueError("LD r,(HL) source byte absent")
            transactions.append([1, hl, value, 3])
        elif dst == 6:
            value = next((v for a, v in test["final"]["ram"] if a == hl), None)
            if value is None:
                raise ValueError("LD (HL),r destination byte absent")
            transactions.append([2, hl, value, 3])
    return transactions


def normalize_entry(source, index, test):
    op = test["initial"]["ram"]
    opcode = next((v for a, v in op if a == test["initial"]["pc"]), None)
    if opcode is None:
        raise ValueError(f"opcode missing: {source} record {index}")
    return {"source": source, "index": index, "opcode": opcode, "test": test}


def documented_subopcode(entry, prefix):
    if not entry["source"].startswith(f"v1/{prefix} "):
        return None
    return int(entry["source"].rsplit(" ", 1)[1].split(".", 1)[0], 16)


def select(args):
    args.corpus_dir.mkdir(parents=True, exist_ok=True)
    inventory = tree_inventory()
    blob_by_path = {row["path"]: row["git_blob_sha1"] for row in inventory}
    entries, sources = [], []
    for path in selected_paths():
        rel = path
        local = args.corpus_dir / pathlib.PurePosixPath(path).name
        if not local.exists():
            if not args.fetch:
                raise ValueError("cached corpus file missing; rerun --select --fetch: " + path)
            data = fetch(RAW + path)
            local.write_bytes(data)
        else:
            data = local.read_bytes()
        parsed = json.loads(data)
        if not isinstance(parsed, list) or not parsed:
            raise ValueError("invalid upstream JSON file: " + path)
        indices={0,min(len(parsed)-1,999)}
        op=int(path.rsplit("/", 1)[1][:2], 16)
        conditional=(0x20<=op<=0x38 and op!=0x18) or (op&0xc7) in (0xc0,0xc2,0xc4) and op not in (0xc3,0xc9,0xcd)
        if conditional:
            seen=set()
            for index,test in enumerate(parsed):
                taken=branch_taken(op,test)
                if taken not in seen:
                    indices.add(index);seen.add(taken)
                if len(seen)==2:break
        entries.extend(normalize_entry(path,index,parsed[index]) for index in sorted(indices))
        blob = blob_by_path.get(rel)
        if not blob or git_blob_sha(data) != blob:
            raise ValueError("Git blob identity mismatch: " + rel)
        sources.append({"path": rel, "git_blob_sha1": blob, "bytes": len(data),
                        "sha256": sha(data), "tests": len(parsed)})
    license_path = args.corpus_dir / "LICENSE"
    if not license_path.exists():
        if not args.fetch:
            raise ValueError("cached pinned LICENSE missing; rerun --select --fetch")
        license_data = fetch(RAW + "LICENSE")
        (args.corpus_dir / "LICENSE").write_bytes(license_data)
    else:
        license_data = license_path.read_bytes()
    manifest = {
        "schema_version": 1, "repository": "https://github.com/SingleStepTests/z80",
        "revision": REV, "raw_base": RAW, "license": "MIT",
        "license_review": "2026-10-20; exact pinned repository LICENSE reviewed; data only, no upstream CPU code used",
        "generator_options": {"cpu": "NMOS Z80", "simplified_memory_t_states": True,
                              "refresh_values_on_address_pins": True, "null_during_waits_checked": False},
        "oracle": "SingleStepTests/z80 data; upstream describes Ares-derived generation; oracle revision not stated",
        "selection_rule": "indices 0 and 999 where available from every selected documented opcode file; conditional branch encodings also include first pinned taken and untaken records when present",
        "implemented": ["NOP", "LD r,r'", "load", "stack/exchange", "ALU/rotate", "control-flow", "interrupt-control", "I/O", "CB", "ED", "DD/FD"],
        "tree_inventory": inventory, "sources": sources,
        "retained_files": [{"path": "upstream/LICENSE", "git_blob_sha1": "f4c25cc255d8e13a17140a0904db9f47ad30380c",
                            "sha256": sha(license_data), "bytes": len(license_data)}],
        "selected": {"path": "selected.json", "denominator": len(entries), "bytes": 0, "sha256": ""},
        "scheduled": {"command": "python3 tests/z80/run_z80_vectors.py --runner build/extended/tests/z80/z80_vector_runner --full --corpus-dir build/z80-vector-corpus --fetch --report build/extended/reports/z80-vectors.json",
                      "inventory_sources": len(inventory),
                      "inventory_bytes": sum(row["bytes"] for row in inventory),
                      "record_denominator": 1604000,
                      "class_denominators": {"documented_compared": 692000,
                                              "partial_match": 692000,
                                              "unconditional_pass": 0,
                                              "failed": 0,
                                              "unsupported": 0,
                                              "gated:undocumented-opcode": 30000,
                                              "gated:unlisted-index-prefix": 432000,
                                              "gated:unlisted-indexed-CB-encoding": 450000},
                      "overlapping_field_gates": {"xy-flags": 232347, "memptr": 220925,
                                                  "q": 496865,
                                                  "um0080-unspecified-block-io-flags": 8000},
                      "selected_slice_sources": len(sources),
                      "selected_slice_records": sum(s["tests"] for s in sources)}
    }
    data = (json.dumps(entries, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    manifest["selected"].update(bytes=len(data), sha256=sha(data))
    (ROOT / "selected.json").write_bytes(data)
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (ROOT / "upstream").mkdir(exist_ok=True)
    (ROOT / "upstream/LICENSE").write_bytes(license_data)
    print(f"selected {len(entries)} records ({len(data)} bytes) from {len(sources)} pinned files")


def load_inputs(manifest, full, corpus_dir, fetch_missing, source_filter=None):
    selected = json.loads((ROOT / "selected.json").read_bytes())
    expected = manifest["selected"]
    if sha((ROOT / "selected.json").read_bytes()) != expected["sha256"]:
        raise ValueError("SHA256 mismatch: selected.json")
    entries = selected
    if full:
        entries = []
        sources = manifest["tree_inventory"]
        if source_filter:
            sources = [source for source in sources if source["path"] == source_filter]
            if not sources:
                raise ValueError("source is not present in pinned tree inventory: " + source_filter)
        for source in sources:
            path = corpus_dir / pathlib.PurePosixPath(source["path"]).name
            if fetch_missing and not path.exists():
                path.write_bytes(fetch(manifest["raw_base"] + source["path"]))
            data = path.read_bytes()
            if (len(data) != source["bytes"] or git_blob_sha(data) != source["git_blob_sha1"]):
                raise ValueError("source identity mismatch: " + source["path"])
            for index, test in enumerate(json.loads(data)):
                entries.append(normalize_entry(source["path"], index, test))
        if not source_filter:
            by_id = {(e["source"], e["index"]): e for e in entries}
            for pinned in selected:
                actual = by_id.get((pinned["source"], pinned["index"]))
                if actual != pinned:
                    raise ValueError("selected records differ from pinned source data")
    elif len(entries) != expected["denominator"]:
        raise ValueError("denominator mismatch")
    return entries


def run(args):
    manifest = json.loads((ROOT / "manifest.json").read_text())
    implemented_families = set(manifest["implemented"])
    seen_families = set()
    for item in manifest["retained_files"]:
        data = (ROOT / item["path"]).read_bytes()
        if (len(data) != item["bytes"] or sha(data) != item["sha256"] or
                git_blob_sha(data) != item["git_blob_sha1"]):
            raise ValueError("retained file identity mismatch: " + item["path"])
    entries = load_inputs(manifest, args.full, args.corpus_dir, args.fetch, args.source)
    if args.source:
        entries=[entry for entry in entries if entry["source"]==args.source]
    outcomes = collections.Counter()
    outcomes["records_selected"] = len(entries)
    outcomes["records_fully_comparable"] = 0
    outcomes["records_partial_gated"] = 0
    outcomes_by_record = []
    outcomes["conditional_taken_selected"] = 0
    outcomes["conditional_untaken_selected"] = 0
    for category in ("gated:xy-flags", "gated:memptr", "gated:q",
                     "gated:undocumented-opcode", "gated:um0080-unspecified-block-io-flags", "unsupported"):
        outcomes[category] = 0
    lines = []
    for entry in entries:
        test, opcode = entry["test"], entry["opcode"]
        if ((0x20 <= opcode <= 0x38 and opcode != 0x18) or
                ((opcode & 0xc7) in (0xc0, 0xc2, 0xc4) and opcode not in (0xc3, 0xc9, 0xcd))):
            outcomes["conditional_taken_selected" if branch_taken(opcode, test) else "conditional_untaken_selected"] += 1
        category = classify(opcode, entry["source"])
        if category.startswith("gated:"):
            outcomes[category] += 1
            continue
        if category not in implemented_families:
            outcomes["unsupported"] += 1
            continue
        seen_families.add(category)
        before, after = test["initial"], test["final"]
        mask = 0
        gated_fields = []
        index_jump = entry["source"].startswith(("v1/dd e9.", "v1/fd e9."))
        if before["wz"] != after["wz"] or opcode == 0xe9 or index_jump:
            outcomes["gated:memptr"] += 1; mask |= 1; gated_fields.append("memptr")
        if before["q"] != after["q"] or before["q"] or after["q"]:
            outcomes["gated:q"] += 1; gated_fields.append("q")
        ed_subopcode = documented_subopcode(entry, "ed")
        if ed_subopcode in (0xa2,0xa3,0xaa,0xab,0xb2,0xb3,0xba,0xbb):
            # Zilog UM0080 (2016), instruction descriptions pp. 298-303 and
            # 309-315: S, H, and P/V are explicitly unknown for block I/O.
            # Keep these fields out of equality comparison while preserving
            # the records as partial matches, never unconditional passes.
            mask |= 8
            gated_fields.append("um0080-unspecified-block-io-flags")
            outcomes["gated:um0080-unspecified-block-io-flags"] += 1
        if (before["f"] ^ after["f"]) & 0x28: outcomes["gated:xy-flags"] += 1
        # The adapter masks X/Y unconditionally because this phase has not
        # promoted those flag bits; every such record is therefore partial.
        gated_fields.append("xy-flags")
        # X/Y bits are kept visible in the report but masked from this oracle
        # comparison until the phase explicitly promotes them.
        # Q is unresolved for every instruction, including records whose
        # reference happens to leave its initial value unchanged.
        mask |= 2 | 4
        init, final = pack_state(before), pack_state(after)
        expected = expected_transactions(test)
        mem0, mem1 = before["ram"], test["final"]["ram"]
        line = [str(opcode), str(mask)] + list(map(str, init)) + list(map(str, final))
        line += [str(len(mem0))] + [str(x) for pair in mem0 for x in pair]
        line += [str(len(mem1))] + [str(x) for pair in mem1 for x in pair]
        ports = test.get("ports", [])
        port_inputs = [[address, value] for address, value, direction in ports if direction == "r"]
        line += [str(len(port_inputs))] + [str(x) for pair in port_inputs for x in pair]
        line += [str(len(test["cycles"])), str(len(expected))]
        line += [str(x) for tx in expected for x in tx]
        lines.append(" ".join(line))
        outcomes["documented"] += 1
        outcomes["family:" + category] += 1
        if gated_fields:
            outcomes["records_partial_gated"] += 1
            outcomes_by_record.append((category, True))
        else:
            outcomes["records_fully_comparable"] += 1
            outcomes_by_record.append((category, False))
    if lines:
        input_text = "\n".join(lines) + "\n"
        if args.negative_control:
            cases = []
            fields = [row.split() for row in lines]
            first = fields[0].copy()
            # Corrupt expected AF while preserving the selected instruction/input.
            first[2 + 21] = str(int(first[2 + 21]) ^ 1)
            cases.append((fields[0], first, "register mismatch"))
            block_io_index = next((i for i,e in enumerate(entries)
                                   if documented_subopcode(e, "ed") in
                                   (0xa2,0xa3,0xaa,0xab,0xb2,0xb3,0xba,0xbb)), None)
            if block_io_index is None: raise ValueError("block-I/O documented-flag negative-control row missing")
            block_io = fields[block_io_index].copy()
            block_io[2 + 21] = str(int(block_io[2 + 21]) ^ 1)  # C is documented unaffected.
            cases.append((fields[block_io_index], block_io, "register mismatch"))
            for row in fields:
                cursor = 44
                ni = int(row[cursor]); cursor += 1 + 2 * ni
                nf = int(row[cursor]); cursor += 1 + 2 * nf
                np = int(row[cursor]); cursor += 1 + 2 * np
                cursor += 1  # T-state count
                nx = int(row[cursor]); cursor += 1
                if nx:
                    corrupt = row.copy()
                    corrupt[cursor + 2] = str(int(corrupt[cursor + 2]) ^ 1)
                    cases.append((row, corrupt, "bus mismatch"))
                    break
            if len(cases) != 3: raise ValueError("negative-control transaction candidate missing")
            for original, corrupted, expected_failure in cases:
                batch = [" ".join(corrupted if row is original else row) for row in fields]
                proc = subprocess.run([args.runner], input="\n".join(batch) + "\n", text=True,
                                      capture_output=True, timeout=60)
                if proc.returncode: raise ValueError("negative-control adapter failed: " + proc.stderr.strip())
                verdicts = proc.stdout.splitlines()
                if len(verdicts) != len(batch) or not any(expected_failure in v for v in verdicts):
                    raise ValueError("negative control did not detect " + expected_failure)
            print("z80_vectors_negative_control: PASS (register, documented block-I/O C flag, and ordered-transaction mutations detected)")
            return
        proc = subprocess.run([args.runner], input=input_text, text=True, capture_output=True, timeout=60)
        if proc.returncode:
            raise ValueError("adapter failed: " + proc.stderr.strip())
        verdicts = proc.stdout.splitlines()
        if len(verdicts) != len(lines):
            raise ValueError("runner dropped outcomes")
        failures = [v for v in verdicts if v != "PASS"]
        counts = collections.Counter(verdicts)
        # A masked-field match is evidence only for the fields actually compared;
        # never fold gated records into the unconditional passing denominator.
        outcomes["records_partial_match"] = sum(
            1 for (_, gated), verdict in zip(outcomes_by_record, verdicts)
            if gated and verdict == "PASS")
        outcomes["records_unconditional_pass"] = sum(
            1 for (_, gated), verdict in zip(outcomes_by_record, verdicts)
            if not gated and verdict == "PASS")
        outcomes["records_failed"] = len(failures)
        outcomes["pass"] = outcomes["records_unconditional_pass"]
        for category in ("NOP", "LD r,r'", "load", "stack/exchange", "ALU/rotate", "control-flow", "interrupt-control", "I/O", "CB", "ED"):
            outcomes["family_unconditional_pass:" + category] = sum(
                1 for (row_category, gated), verdict in zip(outcomes_by_record, verdicts)
                if row_category == category and not gated and verdict == "PASS")
            outcomes["family_partial_match:" + category] = sum(
                1 for (row_category, gated), verdict in zip(outcomes_by_record, verdicts)
                if row_category == category and gated and verdict == "PASS")
        missing_families = set() if args.source else implemented_families - seen_families
        if missing_families:
            raise ValueError("implemented family has no selected vectors: " + ", ".join(sorted(missing_families)))
        if outcomes["unsupported"]:
            raise ValueError("selected opcodes outside implemented families: " + str(outcomes["unsupported"]))
        for failure in failures:
            outcomes["fail:" + failure] += 1
        print("z80_vectors: " + ", ".join(f"{k}={v}" for k, v in sorted(outcomes.items())))
        failed_ids = [f"{entry['source']}[{entry['index']}] {entry['test'].get('name','')} => {verdict}"
                      for entry, verdict in zip(entries, verdicts) if verdict != "PASS"]
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({"revision": REV, "counts": dict(outcomes),
                                               "failed_records": failed_ids}, indent=2) + "\n")
        if failures and not (args.full and args.source):
            raise ValueError(proc.stderr + "vector failures: " + ", ".join(f"{k}={v}" for k,v in counts.items() if k!="PASS") +
                             "\nfailed records: " + "; ".join(failed_ids))
    if args.report and not (args.full and args.source):
        args.report.write_text(json.dumps({"revision": REV, "counts": dict(outcomes)}, indent=2) + "\n")
    return outcomes


def run_full(args):
    manifest = json.loads((ROOT / "manifest.json").read_text())
    total = collections.Counter()
    inventory = manifest["tree_inventory"]
    source_failures = []
    for index, source in enumerate(inventory, 1):
        args.source = source["path"]
        per_source_report = args.corpus_dir / ".gw0311-last-report.json"
        original_report = args.report
        args.report = per_source_report
        with contextlib.redirect_stdout(io.StringIO()):
            per_source = run(args)
        source_report = json.loads(per_source_report.read_text())
        if source_report.get("failed_records"):
            source_failures.extend(source_report["failed_records"])
        args.report = original_report
        if per_source:
            total.update(per_source)
        if index % 25 == 0 or index == len(inventory):
            print(f"z80_full_progress: verified_sources={index}/{len(inventory)} records={total['records_selected']}")
    args.source = None
    args.report.parent.mkdir(parents=True, exist_ok=True)
    tested_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT.parent.parent,
                                              text=True).strip()
    args.report.write_text(json.dumps({"revision": REV, "git_revision": tested_revision,
                                       "tree_sources": len(inventory),
                                       "tree_bytes": sum(row["bytes"] for row in inventory),
                                       "integrity": {"algorithm": "Git blob SHA-1 and exact pinned byte size",
                                                     "verified_sources": len(inventory),
                                                     "verified_bytes": sum(row["bytes"] for row in inventory)},
                                       "counts": dict(total), "failed_records": source_failures}, indent=2) + "\n")
    if total["records_failed"] or total["unsupported"]:
        raise ValueError(f"full lane has {total['records_failed']} documented failures and {total['unsupported']} unsupported records")
    print("z80_full: " + ", ".join(f"{key}={value}" for key, value in sorted(total.items())))


def check_integrity(root):
    raw = (root / "selected.json").read_bytes()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if sha(raw) != manifest["selected"]["sha256"]:
        raise ValueError("SHA256 mismatch: selected.json")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid selected JSON") from exc
    if len(entries) != manifest["selected"]["denominator"]:
        raise ValueError("denominator mismatch")
    # Provenance metadata must cover all v1 JSON files and every selected source.
    inventory = {row["path"] for row in manifest["tree_inventory"]}
    for source in manifest["sources"]:
        if source["path"] not in inventory or len(source["sha256"]) != 64:
            raise ValueError("source inventory mismatch")


def integrity(args):
    check_integrity(ROOT)
    # Exercise the real integrity entry point in isolated copies. Mutations are
    # detected for the intended reason and cannot alter the committed corpus.
    import shutil
    import tempfile
    base_manifest = json.loads((ROOT / "manifest.json").read_text())
    base_selected = (ROOT / "selected.json").read_bytes()
    for mutation, expected in (("corrupt", "SHA256 mismatch: selected.json"),
                               ("drop", "denominator mismatch")):
        with tempfile.TemporaryDirectory(prefix="z80-integrity-") as temporary:
            copied = pathlib.Path(temporary) / "z80"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("__pycache__"))
            selected_path = copied / "selected.json"
            manifest_path = copied / "manifest.json"
            manifest = copy.deepcopy(base_manifest)
            if mutation == "corrupt":
                selected_path.write_bytes(base_selected + b" ")
            else:
                records = json.loads(base_selected)
                selected_path.write_text(json.dumps(records[:-1], separators=(",", ":")) + "\n")
                manifest["selected"]["sha256"] = sha(selected_path.read_bytes())
                manifest_path.write_text(json.dumps(manifest))
            proc = subprocess.run([sys.executable, str(copied / "run_z80_vectors.py"), "--integrity"],
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode != 2 or expected not in proc.stderr:
                raise ValueError("integrity negative control failed: " + mutation + ": " + proc.stderr)
    print("z80_vectors_integrity: PASS (selected digest, denominator, corpus inventory)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--runner")
    p.add_argument("--select", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--corpus-dir", type=pathlib.Path, default=pathlib.Path("build/z80-vector-corpus"))
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--report", type=pathlib.Path)
    p.add_argument("--source", help="run only one exact pinned source path (diagnostic use)")
    p.add_argument("--negative-control", action="store_true")
    p.add_argument("--integrity", action="store_true")
    args = p.parse_args()
    if args.select:
        select(args)
    elif args.integrity:
        integrity(args)
    elif args.runner and args.full and args.source:
        run(args)
    elif args.runner and args.full:
        if not args.report:
            p.error("--full requires --report so the complete outcome inventory is retained")
        run_full(args)
    elif args.runner:
        run(args)
    else:
        p.error("--runner, --select, or --integrity is required")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("z80_vectors: FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
