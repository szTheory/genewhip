#!/usr/bin/env python3
"""Fail-closed source route audit for the pinned MAME 0.289 Genesis build."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
# Local MAME checkout: GENEWHIP_MAME_SOURCE_DIR, else the ignored in-repo cache filled by
# GENEWHIP_MAME_WORK_ROOT=build/tool-cache/mame0289 fixtures/independent-game/mame_build.sh --build.
DEFAULT_SOURCE = Path(os.environ.get("GENEWHIP_MAME_SOURCE_DIR")
                      or ROOT / "build/tool-cache/mame0289/source")
REQUIRED_LOCK = {
    "version": "0.289",
    "source_archive_sha256": "0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84",
}

FILES = {
    "cpu": "src/devices/cpu/m68000/m68000.cpp",
    "cpu_access": "src/devices/cpu/m68000/m68kcpu.cpp",
    "cpu_direct": "src/devices/cpu/m68000/m68000-sdp.cpp",
    "cpu_header": "src/devices/cpu/m68000/m68000.h",
    "common": "src/devices/cpu/m68000/m68kcommon.h",
    "map": "src/mame/sega/megadriv.cpp",
    "machine": "src/mame/sega/mdconsole.cpp",
    "space": "src/emu/emumem_aspace.cpp",
    "space_header": "src/emu/emumem.h",
    "handler": "src/emu/emumem_het.cpp",
    "handler_header": "src/emu/emumem_het.h",
    "generic": "src/emu/emumem.cpp",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-toolchain-lock", required=True, type=Path)
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--output", type=Path, default=ROOT / "fixtures/independent-game/route_audit.json")
    args = ap.parse_args()
    errors: list[str] = []
    lock = json.loads(args.verify_toolchain_lock.read_text())
    mame = lock.get("mame", {})
    for key, value in REQUIRED_LOCK.items():
        if mame.get(key) != value:
            errors.append(f"toolchain lock {key} mismatch")
    if mame.get("status") != "pass" or mame.get("source_signature", {}).get("status") != "pass":
        errors.append("MAME source/signature/build status is not pass")
    patch = (ROOT / "fixtures/independent-game/mame.patch").read_bytes()
    script = (ROOT / "fixtures/independent-game/mame_build.sh").read_bytes()
    if sha(patch) != mame.get("patch_sha256"):
        errors.append("instrumentation patch hash differs from locked build")
    if sha(script) != mame.get("build_script_sha256"):
        errors.append("build script hash differs from locked build")
    source = args.source.resolve()
    if not (source / ".git").exists() and not (source / ".git").is_file():
        errors.append(f"pinned MAME git checkout unavailable: {source}")
    try:
        rev = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        tag = subprocess.check_output(["git", "-C", str(source), "describe", "--exact-match", "--tags", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        if rev != "f34f02505e32c1993c6a782b6814232cbfc74e36" or tag != "mame0289":
            errors.append("source checkout is not exact signed mame0289 revision")
        dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True)
        dirty_paths = sorted(line[3:] for line in dirty.splitlines())
        if dirty_paths != ["src/mame/sega/mdconsole.cpp", "src/mame/sega/megadriv.h"]:
            errors.append(f"source patch working-tree path set mismatch: {dirty_paths}")
        reverse = subprocess.run(["git", "-C", str(source), "apply", "--reverse", "--check", str(ROOT / "fixtures/independent-game/mame.patch")], capture_output=True, text=True)
        if reverse.returncode:
            errors.append("instrumentation patch is not exactly present in source checkout")
        validator = subprocess.run(["bash", str(ROOT / "fixtures/independent-game/mame_build.sh"), "--verify-toolchain-lock"], capture_output=True, text=True, env={**os.environ, "GENEWHIP_MAME_SOURCE_DIR": str(source)})
        if validator.returncode:
            errors.append("MAME build lock validator failed: " + (validator.stdout + validator.stderr).strip())
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"cannot inspect source revision: {exc}")
    texts: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    for key, rel in FILES.items():
        path = source / rel
        if not path.is_file():
            errors.append(f"missing pinned source file: {rel}")
            continue
        raw = path.read_bytes()
        texts[key] = raw.decode("utf-8", errors="replace")
        file_hashes[rel] = sha(raw)

    def require(file_key: str, needle: str, label: str) -> None:
        if needle not in texts.get(file_key, ""):
            errors.append(f"source route proof missing {label}: {FILES[file_key]}")

    # Device and logical-space configuration, aliases, 24-bit mask, CPU routes.
    for needle, label in [
        ("m_program_config(\"program\", ENDIANNESS_BIG, 16, 24)", "24-bit program space"),
        ("m_cpu_space_config(\"cpu_space\", ENDIANNESS_BIG, 16, 24", "24-bit CPU space"),
        ("scv.push_back(std::make_pair(AS_PROGRAM, &m_program_config))", "program space enumeration"),
        ("if(has_configured_map(AS_OPCODES))", "conditional opcode space enumeration"),
        ("if(has_configured_map(AS_USER_PROGRAM))", "conditional user program enumeration"),
        ("if(has_configured_map(AS_USER_OPCODES))", "conditional user opcode enumeration"),
        ("if(m_cpu_space_id == AS_CPU_SPACE)", "CPU space enumeration"),
        ("m_s_opcodes = has_space(AS_OPCODES) ? &space(AS_OPCODES) : m_s_program", "opcode alias to program"),
        ("m_s_uprogram = has_space(AS_USER_PROGRAM) ? &space(AS_USER_PROGRAM) : m_s_program", "user program alias"),
        ("m_s_uopcodes = has_space(AS_USER_OPCODES) ? &space(AS_USER_OPCODES) : has_space(AS_USER_PROGRAM) ? m_s_uprogram : m_s_opcodes", "user opcode alias"),
        ("m_s_program->specific(m_r_program)", "program space specific dispatch binding"),
        ("m_s_opcodes->specific(m_r_opcodes)", "opcode space specific dispatch binding"),
        ("m_s_cpu_space->specific(m_cpu_space)", "CPU-space specific dispatch binding"),
        ("m_handlers_p = s_handlers_dp", "standard non-MMU generated-handler selection"),
        ("m_mmu(nullptr)", "standard Genesis M68000 has no MMU configured"),
        ("m_maincpu->set_addrmap(m68000_base_device::AS_CPU_SPACE, &md_core_state::cpu_space_map)", "Genesis CPU-space map"),
        ("m_maincpu->set_addrmap(AS_PROGRAM, &md_base_state::megadriv_68k_map)", "Genesis program map"),
        ("CONS( 1989, genesis,", "Genesis USA NTSC driver selection"),
        ("SOFTWARE_LIST(config, \"cart_list\").set_original(\"megadriv\").set_filter(\"NTSC-U\")", "NTSC-U cartridge software list"),
        ("m_maincpu->space(AS_PROGRAM).install_read_handler(0x000000, 0x7fffff", "cartridge read overlay"),
        ("m_maincpu->space(AS_PROGRAM).install_write_handler(0x000000, 0x7fffff", "cartridge write overlay"),
        ("m_maincpu->space(AS_PROGRAM).install_readwrite_handler(0xa13000, 0xa130ff", "cartridge A13 overlay"),
        ("m_maincpu->space(AS_PROGRAM).install_readwrite_handler(0xa15000, 0xa150ff", "cartridge A15 overlay"),
        ("M68000(config, m_maincpu, MASTER_CLOCK_NTSC / 7)", "NTSC M68000 device"),
    ]:
        require("cpu" if label in {"24-bit program space", "24-bit CPU space", "program space enumeration", "conditional opcode space enumeration", "conditional user program enumeration", "conditional user opcode enumeration", "CPU space enumeration", "opcode alias to program", "user program alias", "user opcode alias", "program space specific dispatch binding", "opcode space specific dispatch binding", "CPU-space specific dispatch binding", "standard non-MMU generated-handler selection", "standard Genesis M68000 has no MMU configured"} else "machine" if "cartridge" in label or "Genesis USA" in label or "NTSC-U" in label else "map", needle, label)
    require("map", "void md_base_state::megadriv_68k_base_map(address_map &map)", "Genesis base address map")
    require("map", "void md_base_state::megadriv_68k_map(address_map &map)", "Genesis cartridge address map")
    require("map", "map(0xe00000, 0xe0ffff).ram().mirror(0x1f0000).share(\"megadrive_ram\")", "mirrored Genesis 64K RAM")
    require("map", "void md_core_state::cpu_space_map(address_map &map)", "Genesis interrupt acknowledge map")
    for vector in range(1, 8):
        address = 0xFFFFF0 + 2 * vector + 1
        require("map", f"map(0x{address:06x}, 0x{address:06x})", f"autovector level {vector}")
    require("cpu_access", "/* Acknowledge the interrupt by reading the cpu space. */", "interrupt acknowledge read route")
    require("cpu_access", "m_cpu_space->read_word(0xfffffff0 | (int_level << 1))", "68000 CPU-space word read")
    require("cpu_direct", "m_opcodes.read_interruptible", "standard M68000 opcode-fetch route")
    require("cpu_direct", "m_program.read_interruptible", "standard M68000 program data read route")
    require("cpu_direct", "m_program.write_interruptible", "standard M68000 program data write route")
    require("cpu_direct", "m_cpu_space.read_interruptible", "standard M68000 interrupt-acknowledge route")
    require("cpu_access", "m_cpu_space->read_word(0xfffffff0 | (int_level << 1))", "base M68000 interrupt-acknowledge route")
    require("cpu_header", "memory_access<24, 1, 0, ENDIANNESS_BIG>::specific m_r_program, m_r_opcodes", "24-bit specific accessor types")
    require("common", "AS_CPU_SPACE = 4", "M68000 CPU-space identifier")
    require("common", "AS_USER_PROGRAM = 5", "M68000 user-program identifier")
    require("common", "AS_USER_OPCODES = 6", "M68000 user-opcode identifier")

    # Route-to-hook proof: the applied patch taps the complete mask; MAME installs
    # taps into root dispatch, calls them around the next handler, and disables
    # cached direct reads for the tap node. Program/opcode aliases share that bus.
    for key, needle, label in [
        ("space", "m_root_read->populate_passthrough(nstart, nend, nmirror, handler)", "read tap root insertion"),
        ("space", "m_root_write->populate_passthrough(nstart, nend, nmirror, handler)", "write tap root insertion"),
        ("space", "invalidate_caches(read_or_write::READ)", "read cache invalidation"),
        ("space", "invalidate_caches(read_or_write::WRITE)", "write cache invalidation"),
        ("handler", "uX data = this->m_next->read(offset, mem_mask);", "read callback delegates through tap"),
        ("handler", "m_tap(offset, data, mem_mask);", "read callback logger invocation"),
        ("handler", "m_tap(offset, data, mem_mask);\n\tthis->m_next->write(offset, data, mem_mask);", "write callback/logger and delegation"),
        ("generic", "return nullptr;", "no direct pointer from handler node"),
        ("handler_header", "class handler_entry_read_tap : public handler_entry_read_passthrough", "tap inherits non-pointer handler"),
        ("space_header", "install_read_tap(offs_t addrstart, offs_t addrend", "address-space read tap API"),
        ("space_header", "install_write_tap(offs_t addrstart, offs_t addrend", "address-space write tap API"),
    ]:
        require(key, needle, label)
    if "install_trace(AS_PROGRAM, \"AS_PROGRAM\")" not in patch.decode() or "space.addrmask()" not in patch.decode():
        errors.append("hook does not install the complete address_space.addrmask() range on AS_PROGRAM")
    if "install_trace(m68000_base_device::AS_CPU_SPACE, \"AS_CPU_SPACE\")" not in patch.decode():
        errors.append("hook does not cover the configured M68000 CPU-space bus")
    console_text = texts.get("machine", "")
    slot_start = console_text.find("void md_cons_slot_state::machine_start()")
    slot_end = console_text.find("void md_cons_state::machine_reset()", slot_start)
    slot_startup = console_text[slot_start:slot_end] if slot_start >= 0 and slot_end > slot_start else ""
    if not slot_startup or "md_cons_state::machine_start();" not in slot_startup or "install_cartslot();" not in slot_startup:
        errors.append("configured Genesis slot startup does not initialize console and cartridge maps")
    cart_start = console_text.find("void md_cons_state::install_cartslot()")
    cart_end = console_text.find("uint16_t md_cons_state::", cart_start)
    cart_setup = console_text[cart_start:cart_end] if cart_start >= 0 and cart_end > cart_start else ""
    cart_trace = cart_setup.find("install_trace(AS_PROGRAM, \"AS_PROGRAM\")")
    if not cart_setup or cart_trace < 0 or "install_trace(m68000_base_device::AS_CPU_SPACE, \"AS_CPU_SPACE\")" not in cart_setup:
        errors.append("active Genesis cartridge map setup does not invoke both hooked address spaces")
    elif any(cart_setup.find(needle) >= 0 and cart_trace < cart_setup.find(needle) for needle in ["install_read_handler(0x000000", "install_write_handler(0x000000", "install_readwrite_handler(0xa13000", "install_readwrite_handler(0xa15000"]):
        errors.append("Genesis taps are installed before cartridge ROM or mapper overlays")

    map_text = texts.get("map", "")
    map_functions = [
        ("megadriv_68k_base_map", "void md_base_state::megadriv_68k_base_map(address_map &map)"),
        ("megadriv_68k_map", "void md_base_state::megadriv_68k_map(address_map &map)"),
        ("cpu_space_map", "void md_core_state::cpu_space_map(address_map &map)"),
    ]
    map_rows = []
    lines = map_text.splitlines()
    for function_name, signature in map_functions:
        start = map_text.find(signature)
        if start < 0:
            errors.append(f"missing source map function {function_name}")
            continue
        end = map_text.find("\n}", start)
        if end < 0:
            errors.append(f"unterminated source map function {function_name}")
            continue
        first_line = map_text.count("\n", 0, start) + 1
        body = map_text[start:end]
        body_lines = body.splitlines()
        offset = 0
        while offset < len(body_lines):
            line = body_lines[offset]
            if not re.search(r"\bmap\(0x", line) or line.strip().startswith("//"):
                offset += 1
                continue
            statement = [line]
            if "NAME([this]" in line and "}));" not in line:
                offset += 1
                while offset < len(body_lines):
                    statement.append(body_lines[offset])
                    if "}));" in body_lines[offset]:
                        break
                    offset += 1
            combined = " ".join(part.strip() for part in statement)
            m = re.search(r"\bmap\((0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)(.*)", combined)
            if not m:
                errors.append(f"cannot parse address-map statement in {function_name}:{first_line + offset}")
                offset += 1
                continue
            lo, hi, tail = int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()
            modes = []
            if ".r(" in tail or ".rw(" in tail or ".rom()" in tail or ".ram()" in tail or ".lr" in tail:
                modes.append("read")
            if ".w(" in tail or ".rw(" in tail or ".rom()" in tail or ".ram()" in tail:
                modes.append("write")
            map_rows.append({"function": function_name, "line": first_line + offset, "start": f"0x{lo:06X}", "end": f"0x{hi:06X}", "access": modes, "mapping": tail})
            offset += 1
    if not map_rows:
        errors.append("could not derive configured Genesis map rows from pinned source")
    cpu_map_addresses = {row["start"] for row in map_rows if row["function"] == "cpu_space_map"}
    expected_cpu_map = {f"0x{0xFFFFF0 + 2 * vector + 1:06X}" for vector in range(1, 8)}
    if cpu_map_addresses != expected_cpu_map:
        errors.append(f"Genesis interrupt map inventory incomplete: found {sorted(cpu_map_addresses)}")

    ranges = {
        "AS_PROGRAM": {"start": "0x000000", "end": "0xFFFFFF", "bits": 24, "hook": "genewhip_trace", "transactions": ["opcode_fetch", "data_read", "data_write", "memory_mapped_io_read", "memory_mapped_io_write"]},
        "AS_CPU_SPACE": {"start": "0x000000", "end": "0xFFFFFF", "bits": 24, "hook": "genewhip_trace", "transactions": ["interrupt_acknowledge_read"]},
    }
    dispositions = [
        {"space": "AS_PROGRAM", "status": "configured", "source_disposition": "Genesis map + cartridge overlays; handles 68000 supervisor/program data and instruction fetches across the full 24-bit mask", "hooked_alias": None},
        {"space": "AS_OPCODES", "status": "alias", "source_disposition": "no opcode map configured; m68000 device aliases opcode accesses to AS_PROGRAM", "hooked_alias": "AS_PROGRAM"},
        {"space": "AS_DATA", "status": "inapplicable", "source_disposition": "generic MAME enum exists but M68000 logical-space configuration does not enumerate AS_DATA; CPU data helpers use program space", "hooked_alias": "AS_PROGRAM"},
        {"space": "AS_IO", "status": "inapplicable", "source_disposition": "generic MAME enum exists but M68000 logical-space configuration does not enumerate AS_IO; Genesis 68000 I/O devices are mapped on AS_PROGRAM", "hooked_alias": "AS_PROGRAM"},
        {"space": "AS_USER_PROGRAM", "status": "alias", "source_disposition": "no user-program map configured; m68000 device aliases it to AS_PROGRAM", "hooked_alias": "AS_PROGRAM"},
        {"space": "AS_USER_OPCODES", "status": "alias", "source_disposition": "no user-opcode map configured; m68000 device aliases it to AS_PROGRAM through user-program fallback", "hooked_alias": "AS_PROGRAM"},
        {"space": "AS_CPU_SPACE", "status": "configured", "source_disposition": "Genesis config sets explicit CPU-space map; M68000 16-bit, 24-bit mask", "hooked_alias": None},
    ]
    route_rows = [
        {"route": "opcode fetch", "helper": "m68000-sdp.cpp: m_opcodes.read_interruptible", "space": "AS_OPCODES alias AS_PROGRAM", "hook": "AS_PROGRAM read tap", "proof": "m68000_device::device_start binds m_r_opcodes from the configured or aliased opcode space; root tap prevents direct handler bypass"},
        {"route": "normal data read", "helper": "m68000-sdp.cpp: m_program.read_interruptible", "space": "AS_PROGRAM", "hook": "AS_PROGRAM read tap", "proof": "standard non-MMU handler selected by m68000_device::device_start; specific accessor is bound to AS_PROGRAM"},
        {"route": "normal data write", "helper": "m68000-sdp.cpp: m_program.write_interruptible", "space": "AS_PROGRAM", "hook": "AS_PROGRAM write tap", "proof": "standard non-MMU handler selected by m68000_device::device_start; specific accessor is bound to AS_PROGRAM"},
        {"route": "memory-mapped I/O read/write", "helper": "same m_program32 specific read/write methods against Genesis device map callbacks", "space": "AS_PROGRAM", "hook": "AS_PROGRAM read/write tap", "proof": "Genesis controllers, YM, VDP, Z80 control and cartridge registers are mapped in AS_PROGRAM; there is no separate M68000 AS_IO"},
        {"route": "user data read/write", "helper": "m_s_uprogram aliases m_s_program absent map", "space": "AS_USER_PROGRAM alias AS_PROGRAM", "hook": "AS_PROGRAM read/write tap", "proof": "space fallback uses same hooked program space"},
        {"route": "user opcode fetch", "helper": "m_s_uopcodes aliases opcode/program absent maps", "space": "AS_USER_OPCODES alias AS_PROGRAM", "hook": "AS_PROGRAM read tap", "proof": "space fallback uses same hooked program space"},
        {"route": "interrupt acknowledge", "helper": "m68000-sdp.cpp: m_cpu_space.read_interruptible; base implementation: m_cpu_space->read_word(0xfffffff0 | (int_level << 1))", "space": "AS_CPU_SPACE", "hook": "AS_CPU_SPACE read tap", "proof": "CPU-space specific accessor is bound to configured CPU-space; 24-bit mask is 0xfffff0-0xfffffe"},
    ]
    anchor_specs = [
        ("m68000 logical spaces", "cpu", "device_memory_interface::space_config_vector m68000_device::memory_logical_space_config() const"),
        ("standard M68000 generated handlers", "cpu_direct", "m68000_device::state_reset_dp"),
        ("instruction and CPU bus", "cpu_access", "/* Acknowledge the interrupt by reading the cpu space. */"),
        ("Genesis base map", "map", "void md_base_state::megadriv_68k_base_map(address_map &map)"),
        ("Genesis program map", "map", "void md_base_state::megadriv_68k_map(address_map &map)"),
        ("Genesis CPU map", "map", "void md_core_state::cpu_space_map(address_map &map)"),
        ("Genesis NTSC-U machine", "machine", "void md_cons_slot_state::ms_megadriv(machine_config &config)"),
        ("cart overlays", "machine", "void md_cons_state::install_cartslot()"),
        ("interrupt acknowledge", "cpu_access", "/* Acknowledge the interrupt by reading the cpu space. */"),
    ]
    source_anchors = {}
    for label, key, symbol in anchor_specs:
        source_lines = texts.get(key, "").splitlines()
        line_index = next((i for i, source_line in enumerate(source_lines, 1) if symbol in source_line), None)
        if line_index is None:
            errors.append(f"source anchor not found: {label} ({symbol})")
        source_anchors[label] = {"file": FILES[key], "symbol": symbol, "line": line_index}
    cart_specs = [
        ("cartridge read delegate", "0x000000", "0x7FFFFF", ["read"], "install_read_handler(0x000000"),
        ("cartridge write delegate", "0x000000", "0x7FFFFF", ["write"], "install_write_handler(0x000000"),
        ("cartridge A13 read/write registers", "0xA13000", "0xA130FF", ["read", "write"], "install_readwrite_handler(0xa13000"),
        ("cartridge A15 read/write registers", "0xA15000", "0xA150FF", ["read", "write"], "install_readwrite_handler(0xa15000"),
    ]
    cart_rows = []
    for label, start, end, access, needle in cart_specs:
        line_index = next((i for i, source_line in enumerate(texts.get("machine", "").splitlines(), 1) if needle in source_line), None)
        if line_index is None:
            errors.append(f"missing Genesis cartridge overlay: {label}")
        else:
            cart_rows.append({"function": "install_cartslot", "line": line_index, "start": start, "end": end, "access": access, "mapping": label})
    audit = {
        "schema_version": 1,
        "status": "blocked" if errors else "pass",
        "source": {"tag": "mame0289", "commit": "f34f02505e32c1993c6a782b6814232cbfc74e36", "archive_sha256": REQUIRED_LOCK["source_archive_sha256"], "files_sha256": file_hashes, "source_anchors": source_anchors},
        "build": {"source_configuration_identity": mame.get("source_configuration_identity"), "executable_build_sha256": mame.get("executable_build_sha256"), "patch_sha256": mame.get("patch_sha256"), "hook": "md_cons_state::install_cartslot/genewhip_trace", "hook_range": "after cartridge overlays, each configured address_space [0, addrmask] for R/W"},
        "machine": {"driver": "genesis (Genesis USA, NTSC); machine ms_megadriv; software-list filter NTSC-U", "cpu": "M68000, 16-bit data, 24-bit program and cpu-space address masks", "program_range": "0x000000-0xFFFFFF", "map_source": "src/mame/sega/megadriv.cpp::megadriv_68k_base_map + megadriv_68k_map + cpu_space_map; src/mame/sega/mdconsole.cpp::ms_megadriv + install_cartslot", "map_entries": map_rows + cart_rows},
        "spaces": dispositions,
        "applicable_transactions": ranges,
        "routes": route_rows,
        "hook_proof": {"root_passthrough_taps": True, "read_and_write_cache_invalidation": True, "tap_callbacks_delegate_to_original_handler": True, "tap_node_direct_read_pointer": "nullptr", "sentinels_required_in_runtime": ["AS_PROGRAM opcode fetch", "AS_PROGRAM data read", "AS_PROGRAM data write", "AS_CPU_SPACE interrupt acknowledge"]},
        "errors": errors,
    }
    args.output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    print(f"{audit['status'].upper()}: {len(map_rows)} source map rows; {len(route_rows)} access routes; {len(errors)} audit errors")
    for error in errors:
        print(f"BLOCKED: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
