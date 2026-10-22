#!/usr/bin/env python3
"""Capture fresh, bounded MAME observations for every frozen successor case."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game-v2"
LOCK = FIXTURE / "toolchain.lock"
SCENARIO = FIXTURE / "scenario.json"
ORACLE = FIXTURE / "oracle.json"
SOURCE = FIXTURE / "src/game.s"
ROM = FIXTURE / "game.bin"
SCRIPT = FIXTURE / "mame.lua"
OUT = ROOT / "build/phase4/game-successor-reference.json"
MAX_BYTES = 2_250_000_000
MAX_ROWS = 36_000_000
TIMEOUT = 600


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def check_case(case: dict, observed: dict) -> dict:
    if observed.get("observation") is None:
        raise ValueError(f"reference-observation:{case['id']}")
    frame, state, position = observed["observation"]
    expected = case["expect"]
    if frame != case["frames"] or state != expected["play_state"]:
        raise ValueError(f"reference-state:{case['id']}")
    if not expected["position_min"] <= position <= expected["position_max"]:
        raise ValueError(f"reference-position:{case['id']}")
    if observed["controller_reads"] <= 0:
        raise ValueError(f"reference-controller-route:{case['id']}")
    if observed["vdp_control_writes"] <= 0:
        raise ValueError(f"reference-vdp-route:{case['id']}")
    if observed["storage_accesses"]:
        raise ValueError(f"reference-cartridge-storage-access:{case['id']}")
    geometry = expected["geometry"]
    vram = observed["vram"]
    title = [vram.get(f"{0xc000 + index * 2:04X}") for index in range(geometry["title_row"]["cells"])]
    if title != [geometry["title_row"]["tile"]] * geometry["title_row"]["cells"]:
        raise ValueError(f"reference-title-geometry:{case['id']}")
    marker = geometry["marker"]
    if marker.get("present") is False:
        if vram.get(f"{marker['address']:04X}", 0) == marker.get("tile", 2):
            raise ValueError(f"reference-marker-geometry:{case['id']}")
        marker_position = None
    else:
        marker_position = position if marker["column"] == "RAM:0xFF0002" else marker["column"]
        marker_address = marker["address"] + marker_position * 2
        if vram.get(f"{marker_address:04X}") != marker["tile"]:
            raise ValueError(f"reference-marker-geometry:{case['id']}:address={marker_address:04X}:observed={[(k,v) for k,v in sorted(vram.items()) if k.startswith('C2')][-12:]}")
    # MAME's 16-bit tap records the PSG byte lane in data and mem_mask.
    psg = observed["psg_writes"]
    expected_psg = expected["psg_writes"]
    if psg != expected_psg:
        raise ValueError(f"reference-psg-sequence:{case['id']}:expected={expected_psg}:observed={psg}")
    if case["id"] == "sustained-play" and frame < 720:
        raise ValueError("reference-sustained-denominator")
    return {"id":case["id"],"status":"pass","outcome":"pass","frames":frame,
            "observed":{"play_state":state,"position":position,"psg_writes":psg,
                        "controller_reads":observed["controller_reads"],
                        "vdp_control_writes":observed["vdp_control_writes"],
                        "geometry":{"title_row":title,"marker_position":marker_position,"marker_tile":marker.get("tile")}},
            "trace":observed["trace"]}


def parse_trace(path: Path, stdout_path: Path, scenario_id: str) -> dict:
    pattern = re.compile(rb"^(?:\[:[^\]]*\]\s*)?GWTRACE,(\d+),(AS_PROGRAM|AS_CPU_SPACE),([RW]),([0-9A-F]{6}),16,([0-9A-F]{4}),([0-9A-F]{4}),([0-9A-F]{6})$")
    hasher = hashlib.sha256()
    rows = 0
    trace_bytes = 0
    first = last = None
    controller_reads = vdp_control_writes = storage_accesses = 0
    vdp_high = None
    vram_address = None
    vram = {}
    psg = []
    for line in path.open("rb"):
        if b"GWTRACE," not in line:
            continue
        trace_bytes += len(line)
        if trace_bytes > MAX_BYTES:
            raise ValueError("reference-trace-byte-budget")
        hasher.update(line)
        match = pattern.fullmatch(line.rstrip(b"\r\n"))
        if not match:
            raise ValueError("reference-trace-malformed-row")
        seq_b, space_b, op_b, address_b, value_b, mask_b, _pc = match.groups()
        seq, address, value, mask = int(seq_b), int(address_b,16), int(value_b,16), int(mask_b,16)
        space, op = space_b.decode(), op_b.decode()
        if first is None:
            first = seq
        if last is not None and seq != last + 1:
            raise ValueError("reference-trace-order")
        last = seq
        rows += 1
        if rows > MAX_ROWS:
            raise ValueError("reference-trace-row-budget")
        if space == "AS_PROGRAM" and op == "R" and address == 0xa10002:
            controller_reads += 1
        if space == "AS_PROGRAM" and op == "W" and address == 0xc00004:
            vdp_control_writes += 1
            vdp_high = value
        if space == "AS_PROGRAM" and op == "W" and address == 0xc00006 and vdp_high is not None:
            command_address = (vdp_high & 0x3fff) | ((value & 0x3) << 14)
            command_code = ((vdp_high & 0xc000) >> 14) | ((value & 0x00f0) >> 2)
            vram_address = command_address if command_code == 1 else None
            vdp_high = None
        if space == "AS_PROGRAM" and op == "W" and address in (0xc00000, 0xc00002) and vram_address is not None:
            if 0xc000 <= vram_address <= 0xc2ce:
                vram[f"{vram_address:04X}"] = value
            vram_address += 2
        if space == "AS_PROGRAM" and op in ("R","W") and (0x200000 <= address <= 0x20ffff or 0xa13000 <= address <= 0xa130ff):
            storage_accesses += 1
        if space == "AS_PROGRAM" and op == "W" and address in (0xc00010,0xc00011):
            if mask & 0x00ff: psg.append(value & 0xff)
            elif mask & 0xff00: psg.append((value >> 8) & 0xff)
    if not rows:
        raise ValueError("reference-trace-missing")
    observation = None
    pattern_observation = re.compile(rf"GWOBS,scenario={re.escape(scenario_id)},frame=(\d+),play_state=(\d+),position=(\d+)")
    for output_path in (stdout_path,path):
        for line in output_path.open("rb"):
            decoded = line.decode("utf-8",errors="replace")
            match = pattern_observation.search(decoded)
            if match:
                observation = tuple(map(int,match.groups()))
    if path.stat().st_size + stdout_path.stat().st_size > MAX_BYTES:
        raise ValueError("reference-output-byte-budget")
    return {"observation":observation,"controller_reads":controller_reads,"vdp_control_writes":vdp_control_writes,"vram":vram,
            "storage_accesses":storage_accesses,"psg_writes":psg,
            "trace":{"rows":rows,"bytes":trace_bytes,"sha256":hasher.hexdigest(),"first_sequence":first,"last_sequence":last}}


def run_case(executable: Path, case: dict, lua_body: str) -> dict:
    lua_value = {"id":case["id"],"frames":case["frames"],"input_schedule":case["input_schedule"]}
    prelude = "GW_SCENARIO = " + lua_literal(lua_value) + "\n"
    with tempfile.TemporaryDirectory(prefix="gw-successor-mame-") as td:
        work = Path(td)
        lua = work / "scenario.lua"
        stdout_path = work / "stdout.log"
        error_path = work / "error.log"
        lua.write_text(prelude + lua_body)
        command = [str(executable),"genesis","-cart",str(ROM),"-noreadconfig","-video","none",
                   "-sound","none","-skip_gameinfo","-seconds_to_run","15","-log",
                   "-autoboot_script",str(lua),"-autoboot_delay","0"]
        env = {**os.environ,"SDL_VIDEODRIVER":"dummy","SDL_AUDIODRIVER":"dummy"}
        started = time.monotonic()
        try:
            with stdout_path.open("wb") as stdout:
                process = subprocess.Popen(command,cwd=work,env=env,stdout=stdout,stderr=subprocess.STDOUT)
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    if elapsed > TIMEOUT:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                        raise ValueError(f"reference-mame-timeout:{case['id']}")
                    output_bytes = (error_path.stat().st_size if error_path.exists() else 0) + stdout_path.stat().st_size
                    if output_bytes > MAX_BYTES:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                        tail = stdout_path.read_text(errors="replace")[-300:].replace("\n", " | ")
                        raise ValueError(f"reference-output-byte-budget:{case['id']}:{output_bytes}:stdout={tail}")
                    time.sleep(0.2)
                returncode = process.returncode
        except OSError as exc:
            raise ValueError(f"reference-mame-start:{case['id']}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"reference-mame-timeout:{case['id']}") from exc
        if returncode:
            raise ValueError(f"reference-mame-exit:{case['id']}:{returncode}")
        if not error_path.is_file():
            raise ValueError("reference-trace-file-missing:" + case["id"])
        observed = parse_trace(error_path,stdout_path,case["id"])
        if observed.get("observation") is None:
            tail = stdout_path.read_text(errors="replace")[-500:].replace("\n", " | ")
            raise ValueError(f"reference-observation:{case['id']}:rows={observed['trace']['rows']}:stdout={tail}")
        return check_case(case,observed)


def lua_literal(value) -> str:
    if isinstance(value, bool): return "true" if value else "false"
    if isinstance(value, int): return str(value)
    if isinstance(value, str): return json.dumps(value)
    if isinstance(value, list): return "{" + ",".join(lua_literal(v) for v in value) + "}"
    if isinstance(value, dict): return "{" + ",".join("[" + lua_literal(k) + "]=" + lua_literal(v) for k,v in value.items()) + "}"
    raise TypeError(type(value).__name__)


def notifier_self_test() -> None:
    executable = ROOT / "build/tool-cache/mame0289/source/genewhip"
    expected = load_json(LOCK)["mame"]["executable_build_sha256"]
    if not executable.is_file() or sha(executable) != expected:
        raise ValueError("mame-executable-identity")

    def run(*, retain: bool) -> str:
        at_119 = "collectgarbage('collect')" if retain else "GW_FRAME_SUBSCRIPTION = nil; collectgarbage('collect')"
        script = ("local machine = manager.machine\nlocal frame = 0\n"
                  "local callback\ncallback = function()\n"
                  "  frame = frame + 1\n"
                  f"  if frame == 119 then {at_119} end\n"
                  "  if frame == 130 then print('GWNOTIFIER,frame=130'); machine:exit() end\n"
                  "end\nGW_FRAME_SUBSCRIPTION = emu.add_machine_frame_notifier(callback)\n")
        with tempfile.TemporaryDirectory(prefix="gw-notifier-regression-") as td:
            work = Path(td)
            lua, stdout = work / "notifier.lua", work / "stdout.log"
            lua.write_text(script)
            command = [str(executable), "genesis", "-cart", str(ROM), "-noreadconfig", "-video", "none",
                       "-sound", "none", "-skip_gameinfo", "-seconds_to_run", "5",
                       "-autoboot_script", str(lua), "-autoboot_delay", "0"]
            try:
                with stdout.open("wb") as output:
                    result = subprocess.run(command, cwd=work,
                                            env={**os.environ, "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"},
                                            stdout=output, stderr=subprocess.STDOUT, timeout=60, check=False)
            except subprocess.TimeoutExpired as exc:
                raise ValueError("reference-notifier-timeout") from exc
            if result.returncode:
                raise ValueError("reference-notifier-exit:" + str(result.returncode))
            return stdout.read_text(errors="replace")

    def require_observation(output: str) -> None:
        if "GWNOTIFIER,frame=130" not in output:
            raise ValueError("reference-notifier-observation")

    require_observation(run(retain=True))
    try:
        require_observation(run(retain=False))
    except ValueError as exc:
        if str(exc) != "reference-notifier-observation":
            raise
    else:
        raise ValueError("reference-notifier-negative-control-accepted")


def capture() -> dict:
    scenario = load_json(SCENARIO)
    lock = load_json(LOCK)
    executable = ROOT / "build/tool-cache/mame0289/source/genewhip"
    expected = lock["mame"]["executable_build_sha256"]
    if not executable.is_file() or sha(executable) != expected:
        raise ValueError("mame-executable-identity")
    # Re-run signed-source, route-hook and eight-sentinel verification before
    # collecting case-specific reference observations.
    verify = subprocess.run([sys.executable,"-I",str(ROOT/"scripts/evidence/prepare_game_reference.py"),"--verify"],
                            cwd=ROOT,capture_output=True,text=True,timeout=1800,check=False)
    if verify.returncode:
        raise ValueError("mame-route-runtime-capability:" + (verify.stdout + verify.stderr)[-1000:])
    cases = [run_case(executable,case,SCRIPT.read_text()) for case in scenario["cases"]]
    counts = {"pass":len(cases),"fail":0,"unknown":0,"unsupported":0,"skipped":0,"infrastructure_error":0}
    try:
        source_revision = subprocess.run(["git","-C",str(ROOT),"log","--follow","--format=%H","-1","--","fixtures/independent-game-v2/src/game.s"],
                                         check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    except (OSError,subprocess.SubprocessError) as exc:
        raise ValueError("source-revision") from exc
    return {"schema_version":1,"fixture_id":"genewhip-independent-game-v2","purpose":"fresh bounded source-derived MAME reference evidence",
            "status":"pass","outcome":"pass","candidate_disposition":"candidate",
            "outcome_counts":counts,"identities":{"source_revision":source_revision,"source_sha256":sha(SOURCE),
            "build_sha256":sha(FIXTURE/"build.sh"),"notices_sha256":sha(FIXTURE/"NOTICES.md"),
            "capture_script_sha256":sha(Path(__file__).resolve()),
            "admission_script_sha256":sha(ROOT/"tests/evidence/game_successor_admission.py"),
            "manifest_validator_sha256":sha(ROOT/"tools/evidence/fixture_manifest.py"),
            "mame_script_sha256":sha(SCRIPT),"rom_sha256":sha(ROM),
            "scenario_sha256":sha(SCENARIO),"oracle_sha256":sha(ORACLE),"mame_lock_sha256":sha(LOCK),
            "mame_executable_sha256":expected,"mame_patch_sha256":lock["mame"]["patch_sha256"],
            "mame_configuration_sha256":lock["mame"]["source_configuration_identity"],
            "mame_source_archive_sha256":lock["mame"]["source_archive_sha256"],"profile":scenario["profile"]},
            "reference_capability":{"status":"pass","route_status":"pass","runtime_sentinels":lock["reference_capability"]["sentinels"]},
            "sustained_policy":scenario["sustained_policy"],"cases":cases}


def validate_evidence(evidence: dict, *, require_admitted: bool = False) -> str:
    scenario = load_json(SCENARIO)
    identities = evidence.get("identities", {})
    try:
        source_revision = subprocess.run(["git","-C",str(ROOT),"log","--follow","--format=%H","-1","--","fixtures/independent-game-v2/src/game.s"],
                                         check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    except (OSError,subprocess.SubprocessError):
        return "source-revision"
    expected = {"source_revision":source_revision,"source_sha256":sha(SOURCE),
                "build_sha256":sha(FIXTURE/"build.sh"),"notices_sha256":sha(FIXTURE/"NOTICES.md"),
                "capture_script_sha256":sha(Path(__file__).resolve()),
                "admission_script_sha256":sha(ROOT/"tests/evidence/game_successor_admission.py"),
                "manifest_validator_sha256":sha(ROOT/"tools/evidence/fixture_manifest.py"),
                "mame_script_sha256":sha(SCRIPT),"rom_sha256":sha(ROM),
                "scenario_sha256":sha(SCENARIO),"oracle_sha256":sha(ORACLE),"mame_lock_sha256":sha(LOCK)}
    if any(identities.get(k) != v for k,v in expected.items()): return "identity"
    if evidence.get("fixture_id") != "genewhip-independent-game-v2": return "fixture-id"
    if evidence.get("status") != "pass" or evidence.get("outcome") != "pass": return "reference-status"
    if evidence.get("outcome_counts") != {"pass":6,"fail":0,"unknown":0,"unsupported":0,"skipped":0,"infrastructure_error":0}: return "outcome-denominator"
    if evidence.get("reference_capability",{}).get("status") != "pass" or evidence["reference_capability"].get("route_status") != "pass": return "reference-route"
    if [c.get("id") for c in evidence.get("cases",[])] != [c["id"] for c in scenario["cases"]]: return "case-roster"
    for result, contract in zip(evidence["cases"],scenario["cases"]):
        if result.get("outcome") != "pass" or result.get("status") != "pass": return "case-status:" + str(result.get("id"))
        if result.get("frames") != contract["frames"]: return "case-denominator:" + contract["id"]
        if result.get("observed",{}).get("play_state") != contract["expect"]["play_state"]: return "case-play-state:" + contract["id"]
        if result.get("observed",{}).get("psg_writes") != contract["expect"]["psg_writes"]: return "case-sound:" + contract["id"]
        if result.get("observed",{}).get("position",-1) not in range(contract["expect"]["position_min"],contract["expect"]["position_max"]+1): return "case-position:" + contract["id"]
        geometry = contract["expect"]["geometry"]
        observed_geometry = result.get("observed",{}).get("geometry",{})
        title_row = [geometry["title_row"]["tile"]] * geometry["title_row"]["cells"]
        if observed_geometry.get("title_row") != title_row: return "case-title-geometry:" + contract["id"]
        marker = geometry["marker"]
        expected_marker_position = None if marker.get("present") is False else (
            result["observed"]["position"] if marker["column"] == "RAM:0xFF0002" else marker["column"])
        if observed_geometry.get("marker_position") != expected_marker_position: return "case-marker-position:" + contract["id"]
        if observed_geometry.get("marker_tile") != marker.get("tile"): return "case-marker-tile:" + contract["id"]
        trace = result.get("trace",{})
        if not (0 < trace.get("rows",0) <= MAX_ROWS and 0 < trace.get("bytes",0) <= MAX_BYTES
                and re.fullmatch(r"[0-9a-f]{64}",trace.get("sha256",""))): return "case-trace:" + contract["id"]
    sustained = evidence.get("sustained_policy",{})
    if sustained != scenario["sustained_policy"] or evidence["cases"][-1]["frames"] < 720: return "sustained-protocol"
    if require_admitted and evidence.get("candidate_disposition") != "admitted": return "admission"
    return "ok"


def main() -> int:
    if sys.argv[1:] == ["--notifier-self-test"]:
        notifier_self_test()
        print("PASS: real MAME notifier survives forced GC; discarded handle triggers named missing-observation failure")
        return 0
    if sys.argv[1:] == ["--capture"]:
        evidence = capture()
        status = validate_evidence(evidence)
        if status != "ok": raise ValueError("captured evidence validation:" + status)
        OUT.parent.mkdir(parents=True,exist_ok=True)
        OUT.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
        print(f"PASS: fresh MAME reference observations 6/6; stored at {OUT.relative_to(ROOT)}; candidate remains unadmitted")
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--verify-evidence":
        evidence = load_json(OUT)
        status = validate_evidence(evidence)
        if status != "ok": raise ValueError("reference evidence:" + status)
        print("PASS: current committed source, six fresh MAME cases, route identity and sustained denominator validate")
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        case = {"id":"title-no-start","frames":12,"expect":{"play_state":0,"position_min":0,"position_max":0,"geometry":{"title_row":{"start":0xc000,"cells":10,"tile":1},"marker":{"address":0xc280,"present":False}},"psg_writes":[]}}
        good = {"observation":(12,0,0),"controller_reads":1,"vdp_control_writes":1,
                "storage_accesses":0,"psg_writes":[],"vram":{**{f"{0xc000+i*2:04X}":1 for i in range(10)}},
                "trace":{"rows":2,"bytes":100,"sha256":"0"*64}}
        check_case(case,good)
        mutations = [("missing VDP route",{**good,"vdp_control_writes":0},"reference-vdp-route:title-no-start"),
                     ("storage access",{**good,"storage_accesses":1},"reference-cartridge-storage-access:title-no-start"),
                     ("unexpected PSG write",{**good,"psg_writes":[132]},"reference-psg-sequence:title-no-start"),
                     ("missing title cell",{**good,"vram":{**good["vram"],"C000":0}},"reference-title-geometry:title-no-start")]
        for name,changed,expected in mutations:
            try: check_case(case,changed)
            except ValueError as exc:
                if not str(exc).startswith(expected): raise ValueError(f"{name}: expected {expected}, got {exc}") from exc
            else: raise ValueError(name+" mutation accepted")
        play_case = {"id":"start-idle","frames":20,"expect":{"play_state":1,"position_min":0,"position_max":0,
                     "geometry":{"title_row":{"start":0xc000,"cells":10,"tile":0},
                                 "marker":{"address":0xc280,"column":0,"tile":2}},"psg_writes":[]}}
        play_good = {"observation":(20,1,0),"controller_reads":1,"vdp_control_writes":1,"storage_accesses":0,
                     "psg_writes":[],"vram":{**{f"{0xc000+i*2:04X}":0 for i in range(10)},"C280":2},
                     "trace":{"rows":2,"bytes":100,"sha256":"0"*64}}
        check_case(play_case,play_good)
        try: check_case(play_case,{**play_good,"vram":{**play_good["vram"],"C280":0}})
        except ValueError as exc:
            if not str(exc).startswith("reference-marker-geometry:start-idle"):
                raise ValueError("missing marker: expected reference-marker-geometry:start-idle, got " + str(exc)) from exc
        else: raise ValueError("missing marker mutation accepted")
        with tempfile.TemporaryDirectory(prefix="gw-reference-self-test-") as td:
            trace=Path(td)/"trace.log"; stdout=Path(td)/"stdout.log"
            stdout.write_bytes(b"GWOBS,scenario=title-no-start,frame=12,play_state=0,position=0\n")
            trace.write_bytes(b"GWTRACE,2,AS_PROGRAM,W,000000,16,0000,FFFF,000200\nGWTRACE,4,AS_PROGRAM,R,000000,16,0000,FFFF,000200\n")
            try: parse_trace(trace,stdout,"title-no-start")
            except ValueError as exc:
                if str(exc) != "reference-trace-order": raise
            else: raise ValueError("trace sequence gap mutation accepted")
        print("PASS: production route/storage/PSG/geometry/sequence validators reject six named reference mutations")
        return 0
    raise ValueError("usage: --self-test | --capture | --verify-evidence | --notifier-self-test")


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"BLOCKED: {exc}",file=sys.stderr)
        raise SystemExit(1)
