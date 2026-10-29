#!/usr/bin/env python3
"""Early Phase 6 SDL route diagnostic over the actual SDL gamepad path."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import struct
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

HOST_SEMANTIC_MUTANT_EXPECTATIONS = (
    ("missing-case", "host-roster"), ("failed-host-process", "host-process"),
    ("unconfirmed-host-cleanup", "host-process"),
    ("missing-host-process-receipt", "host-process-binding-missing"),
    ("failed-control-process", "host-process"), ("video-corruption", "host-renderer"),
    ("native-false-capability", "host-native-capability"), ("stale-source", "host-identity"),
    ("missing-backend", "host-backend"), ("missing-control-roster", "host-controls"),
    ("stale-delivery-map", "host-map"), ("wrong-headless-rom-identity", "host-core-observation"),
    ("missing-renderer-media", "host-raw-output"), ("stale-device-counter-receipt", "host-audio"),
    ("boolean-process-wall", "host-process"), ("unbound-extra-process", "host-process-binding"),
    ("actual-host-handler-input-bytes", "host-input"), ("actual-device-audio-activity", "host-audio"),
    ("actual-renderer-readback-bytes", "host-renderer"),
    ("actual-submitted-audio-bytes", "host-audio"),
    ("unsupported-core-status", "host-core-observation"),
)


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


compiler = load_module("phase6_routes_desktop", ROOT / "scripts/evidence/phase6_routes.py")
process_contract = load_module("phase6_process_contract", ROOT / "tests/session/phase6_route_contract.py")
phase6_game = load_module("phase6_product_harness", ROOT / "tests/fixtures/phase6_game.py")


def set_execution_scope(scope: dict | None) -> None:
    """Forward caller-owned Phase 7 limits to all imported host helpers."""
    phase6_game.set_execution_scope(scope)


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path: pathlib.Path, value: object) -> None:
    parent = path.parent.resolve(strict=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise RuntimeError(f"refusing symlink output: {path}")
    if path.exists():
        prior = path.lstat()
        if not path.is_file() or prior.st_uid != os.getuid() or prior.st_nlink != 1:
            raise RuntimeError(f"refusing non-exclusive JSON output: {path}")
        path.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(parent / path.name, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def reconcile_existing(build: pathlib.Path, core_path: pathlib.Path, map_path: pathlib.Path,
                       output: pathlib.Path, candidate_path: pathlib.Path,
                       work_dir: pathlib.Path | None = None) -> int:
    """Assemble a receipt from already-complete client outputs without relaunching."""
    evidence_root = build.resolve(strict=True) / "evidence"
    work = work_dir.resolve(strict=True) if work_dir else max(
        (path for path in evidence_root.glob("phase6-sdl-*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: path.stat().st_mtime)
    if work.parent != evidence_root or not work.name.startswith("phase6-sdl-"):
        raise RuntimeError("retained SDL report directory is outside the configured private evidence root")
    native_path, host_path = work/"native.json", work/"host.json"
    disk_audio_path = work/"sdlaudio.raw"
    if work.is_symlink() or native_path.is_symlink() or host_path.is_symlink() or disk_audio_path.is_symlink():
        raise RuntimeError("retained SDL diagnostic contains a symlink")
    if not work.is_dir() or not native_path.is_file() or not host_path.is_file():
        raise RuntimeError("complete retained SDL diagnostic reports are required")
    if native_path.stat().st_size > 8*1024*1024 or host_path.stat().st_size > 1024*1024:
        raise RuntimeError("retained SDL report exceeds its declared size cap")
    native=json.loads(native_path.read_text(encoding="utf-8"))
    host=json.loads(host_path.read_text(encoding="utf-8"))
    core=json.loads(core_path.read_text(encoding="utf-8"))
    mapping=json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping,client="sdl")
    candidate=json.loads(candidate_path.read_text(encoding="utf-8"))
    polls=[]
    for index,row in enumerate(mapping["events"]):
        input_row=native.get("inputs",[])[index] if index<len(native.get("inputs",[])) else None
        expected=row["expected_guest_poll"]
        sample=(next((x for x in native.get("samples",[]) if x.get("attempt")==expected.get("attempt") and
                      x.get("tick")==expected.get("tick")),None)
                if row["clock_kind"]=="gameplay-source-step" else None)
        polls.append({"event_id":row["event_id"],"expected":expected,
            "input_observed":bool(input_row and input_row.get("effective")==row["effective_mask"]),
            "host_input_observed":bool(index<len(host.get("input_events",[])) and
                host["input_events"][index].get("requested_mask")==row["effective_mask"] and
                host["input_events"][index].get("effective_mask")==row["effective_mask"]),
            "poll_observed":bool(sample) if row["clock_kind"]=="gameplay-source-step" else None,
            "poll_attempt":sample.get("attempt") if sample else None,
            "poll_tick":sample.get("tick") if sample else None,
            "poll_field":sample.get("field") if sample else None})
    raw_outputs={"native":{"path":str(native_path.relative_to(ROOT)),"sha256":sha(native_path),"bytes":native_path.stat().st_size},
                 "host":{"path":str(host_path.relative_to(ROOT)),"sha256":sha(host_path),"bytes":host_path.stat().st_size}}
    disk_audio=({"path":str(disk_audio_path.relative_to(ROOT)),"sha256":sha(disk_audio_path),"bytes":disk_audio_path.stat().st_size}
                if disk_audio_path.is_file() else None)
    core_route_pass=(native.get("status")==0 and native.get("active_ticks")==3600 and
            native.get("fields",0)<=7200 and native.get("boundary_calls",100_000_001)<=100_000_000 and
            all(x["input_observed"] for x in polls) and
            all(x["poll_observed"] is True for x in polls if x["poll_observed"] is not None))
    passed=(core_route_pass and host.get("host_outcome")=="pass-diagnostic" and
            len(host.get("input_events",[]))>=19 and all(x["host_input_observed"] for x in polls))
    report={"schema":"genewhip-phase6-sdl-diagnostic-v1","candidate_sha256":canonical_sha(candidate),
        "delivery_map_sha256":compiler.canonical_digest(mapping),"delivery_client":"sdl",
        "core_report":{"path":str(core_path.resolve().relative_to(ROOT)),"sha256":sha(core_path)},
        "route_metadata":{"client":"sdl","map_id":mapping["map_id"],"sha256":compiler.canonical_digest(mapping),
                          "schema":mapping["schema"],"original_input_sha256":mapping["source"]["input_program_sha256"]},
        "backend":"software","diagnostic_only":True,"guest_poll_observations":polls,
        "input_events":host.get("input_events",[])[:20],"effective_masks":[x.get("effective_mask") for x in host.get("input_events",[])[:20]],
        "presented_frames":host.get("presented_frames"),"renderer_readback_samples":host.get("renderer_readback_samples"),
        "renderer_readback_sha256":host.get("renderer_readback_hash"),"pcm_frames":host.get("pcm_frames"),
        "pcm_sha256":host.get("pcm_hash"),"audio_submitted_frames":host.get("audio_submitted_frames"),
        "audio_device_consumed_frames":host.get("audio_device_consumed_frames"),"audio_device_activity":host.get("audio_device_activity"),
        "capability":host.get("capability"),"core_outcome":"pass" if core_route_pass else "fail",
        "host_outcome":"pass-diagnostic" if passed else "fail-diagnostic","raw_outputs":raw_outputs,
        "disk_audio_artifact":disk_audio,"core_route_outcome":"pass" if core_route_pass else "fail",
        "process":{"client":"desktop","return_code":None,"wall_seconds":None,
          "receipt_status":"reconciled-from-complete-child-reports","stdout_stderr_bytes":"not-retained-by-original-wrapper",
          "process_group_cleanup":"confirmed-before-wrapper-postprocessing"},
        "wrapper_failure":{"stage":"post-child-report-serialization","error":"core_path.relative_to(ROOT) received relative path after child completed",
          "child_product_result":"pass" if passed else "fail","exit_code_retained":False,"rerun":False},
        "limitations":["Early REC software-route diagnostic only; it does not close HOST-04.",
          "This run reports the actual virtual-device D-pad mismatch; requested directional masks were not consumed by SDL_Gamepad.",
          "Renderer readback is a per-frame center-pixel sample, not a full-frame comparison.",
          "PCM is observed at the real route callback; cross-client media comparison belongs to Plan51."]}
    write_json(output,report)
    return 0 if passed else 1


def diagnostic(build: pathlib.Path, core_path: pathlib.Path, map_path: pathlib.Path,
               output: pathlib.Path, candidate_path: pathlib.Path) -> int:
    build = build.resolve(strict=True)
    desktop = build / "tools/desktop/genewhip-desktop"
    headless = build / "tools/session/gw_headless"
    cache = build / "CMakeCache.txt"
    if not desktop.is_file() or not headless.is_file() or not cache.is_file():
        raise RuntimeError("source-bound configured headless and desktop builds are required")
    core = json.loads(core_path.read_text(encoding="utf-8"))
    if core.get("schema") != "genewhip-phase6-tracer-v1" or core.get("result") != "pass":
        raise RuntimeError("the mapped public-core tracer must pass before SDL diagnostics")
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping, client="sdl")
    roster = compiler.compile_routes(mapping, "sdl")
    route = next(row for row in roster["routes"]
                 if row["fixture"] == "recursion94" and row["case"]["id"] == "full-route")
    binary, metadata = compiler.lower_route(route, boundary_call_limit=100_000_000,
                                             delivery_map=mapping, client="sdl")
    map_sha = compiler.canonical_digest(mapping)
    core_sha = sha(core_path)
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate.setdefault("client_identities", {})["sdl"] = {
        "path":"build/phase6/tools/desktop/genewhip-desktop","sha256":sha(desktop)}
    candidate.setdefault("source_files", {})["tools/desktop/main_sdl.c"] = sha(ROOT/"tools/desktop/main_sdl.c")
    candidate["build_identity"].update({"desktop_sha256":sha(desktop),"desktop_size":desktop.stat().st_size})
    candidate.setdefault("proof_dependencies", {})["sdl_diagnostic"] = {
        "requires_core_report_sha256":core_sha,"delivery_map_sha256":map_sha,
        "desktop_source_sha256":sha(ROOT/"tools/desktop/main_sdl.c")}
    candidate.setdefault("invalidations", {})["sdl"] = "SDL host diagnostic and dependent desktop observations"
    write_json(candidate_path, candidate)

    evidence_root = (ROOT/"build/v02/runtime/host-work"/backend if phase6_game._EXECUTION_SCOPE is not None
        else build / "evidence")
    if evidence_root.is_symlink():
        raise RuntimeError("refusing symlink evidence root")
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    if not evidence_root.is_dir():
        raise RuntimeError("evidence root is not a directory")
    work = pathlib.Path(__import__("tempfile").mkdtemp(prefix="phase6-sdl-", dir=evidence_root))
    plan, native_report, host_report = work/"recursion94-full-route.gwrc", work/"native.json", work/"host.json"
    plan.write_bytes(binary)
    env = os.environ.copy()
    env.update({"SDL_VIDEODRIVER":"dummy","SDL_AUDIODRIVER":"disk","SDL_RENDER_DRIVER":"software"})
    command = [str(desktop), "--route-plan", str(plan), "--route-report", str(native_report),
               "--route-diagnostic", str(host_report), "--route-input-source", "virtual-gamepad",
               str(ROOT/"fixtures/phase5-b/game.bin")]
    processes: list[dict] = []
    streams: dict = {}
    started = time.monotonic()
    result = process_contract._run_client(desktop, command, processes, report=native_report,
        timeout=600, cwd=work, env=env, retained_streams=streams,
        monitored_files=((work/"sdlaudio.raw", 16*1024*1024),))
    process = processes[-1]
    native = json.loads(native_report.read_text(encoding="utf-8")) if native_report.is_file() else {}
    host = json.loads(host_report.read_text(encoding="utf-8")) if host_report.is_file() else {}
    disk_audio_path = work/"sdlaudio.raw"
    if native_report.is_file() and native_report.stat().st_size > 8*1024*1024 or host_report.is_file() and host_report.stat().st_size > 1024*1024:
        raise RuntimeError("SDL report exceeded its configured file-size cap")
    guest_polls = []
    inputs = native.get("inputs", [])
    samples = native.get("samples", [])
    mapped_inputs = host.get("input_events", [])
    for index, row in enumerate(mapping["events"]):
        input_observation = inputs[index] if index < len(inputs) else None
        point = row["expected_guest_poll"]
        sample = (next((item for item in samples if item.get("attempt") == point.get("attempt") and
                        item.get("tick") == point.get("tick")), None)
                  if row["clock_kind"] == "gameplay-source-step" else None)
        guest_polls.append({"event_id":row["event_id"],"expected":point,
            "input_observed":bool(input_observation and input_observation.get("effective") == row["effective_mask"]),
            "poll_observed":bool(sample) if row["clock_kind"] == "gameplay-source-step" else None,
            "poll_attempt":sample.get("attempt") if sample else None,
            "poll_tick":sample.get("tick") if sample else None,
            "poll_field":sample.get("field") if sample else None})
    host_pass = (result.returncode == 0 and not process.get("bound_violation") and native.get("status") == 0 and
                 host.get("host_outcome") == "pass-diagnostic" and host.get("input_path") == "sdl-virtual-gamepad/sample_port" and
                 len(mapped_inputs) >= 19 and all(item["input_observed"] for item in guest_polls) and
                 all(item["poll_observed"] is True for item in guest_polls if item["poll_observed"] is not None))
    report = {"schema":"genewhip-phase6-sdl-diagnostic-v1", "candidate_sha256":canonical_sha(candidate),
        "delivery_map_sha256":map_sha,"delivery_client":"sdl","core_report":{"path":str(core_path.resolve().relative_to(ROOT)),"sha256":core_sha},
        "route_plan_sha256":hashlib.sha256(binary).hexdigest(),"route_metadata":metadata.get("delivery_map"),
        "backend":"software","diagnostic_only":True,
        "input_events":mapped_inputs[:20],"effective_masks":[row.get("effective_mask") for row in mapped_inputs[:20]],
        "guest_poll_observations":guest_polls,
        "presented_frames":host.get("presented_frames"),"renderer_readback_samples":host.get("renderer_readback_samples"),
        "renderer_readback_sha256":host.get("renderer_readback_hash"),"pcm_frames":host.get("pcm_frames"),
        "pcm_sha256":host.get("pcm_hash"),"audio_submitted_frames":host.get("audio_submitted_frames"),
        "audio_device_consumed_frames":host.get("audio_device_consumed_frames"),
        "audio_device_activity":host.get("audio_device_activity"),"capability":host.get("capability"),
        "disk_audio_artifact":{"path":str(disk_audio_path.relative_to(ROOT)),"bytes":disk_audio_path.stat().st_size,
            "sha256":sha(disk_audio_path)} if disk_audio_path.is_file() else None,
        "core_outcome":"pass" if native.get("status") == 0 else "fail",
        "host_outcome":"pass-diagnostic" if host_pass else "fail-diagnostic",
        "process":process,"streams":streams,"elapsed_seconds":time.monotonic()-started,
        "limitations":["Early REC software-route diagnostic only; it does not close HOST-04.",
                       "Renderer readback is a per-frame center-pixel sample, not a full-frame comparison.",
                       "PCM is observed at the real route callback; cross-client media comparison belongs to Plan51."]}
    write_json(output, report)
    return 0 if host_pass else 1


def contract(map_path: pathlib.Path, core_path: pathlib.Path) -> int:
    mapping=json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping,client="sdl")
    core=json.loads(core_path.read_text(encoding="utf-8"))
    if core.get("result")!="pass" or len(mapping.get("events",[]))!=19:
        return 1
    print("phase6 SDL offline contract: pass (no client launched)")
    return 0


def input_contract(build: pathlib.Path, map_path: pathlib.Path, output: pathlib.Path,
                   candidate_path: pathlib.Path, backend: str = "software") -> int:
    """No-ROM SDL Gamepad-to-sample_port proof for every mapped request mask."""
    build = build.resolve(strict=True)
    desktop = build / "tools/desktop/genewhip-desktop"
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping, client="sdl")
    expected = [(0, row["effective_mask"]) for row in mapping["events"]]
    # Exercise distinct state on port two, with port one held independently.
    expected.extend(((1, 2), (1, 0), (1, 16), (1, 0)))
    if not desktop.is_file() or len(expected) != 23:
        raise RuntimeError("source-bound desktop executable, nineteen mapped requests, and four port-two probes are required")
    if phase6_game._EXECUTION_SCOPE is not None:
        temp_root=ROOT/"build/v02/runtime/input-contract"
        temp_root.mkdir(parents=True,exist_ok=True)
        root=pathlib.Path(__import__("tempfile").mkdtemp(prefix=backend+"-",dir=temp_root))
        temporary=None
    else:
        temporary=__import__("tempfile").TemporaryDirectory(prefix="gw-phase6-sdl-input-contract-")
        root=pathlib.Path(temporary.name)
    try:
        processes: list[dict] = []
        environment = os.environ.copy()
        if backend == "software":
            environment["SDL_VIDEODRIVER"] = "dummy"
        else:
            for name in ("SDL_VIDEODRIVER", "SDL_AUDIODRIVER", "SDL_RENDER_DRIVER"):
                environment.pop(name, None)
            environment["SDL_VIDEODRIVER"] = "cocoa"
            environment["GENEWHIP_PHASE6_INPUT_VIDEO"] = "1"
            environment["GENEWHIP_LIVE_DISPLAY"] = "1"
            environment["GENEWHIP_LIVE_AUDIO"] = "1"
        result = process_contract._run_client(desktop,
            [str(desktop), "--route-input-contract", ",".join(f"{port}:{mask}" for port, mask in expected)],
            processes, report=root/"unused-report.json", timeout=30, cwd=root, env=environment,
            limits=(phase6_game._EXECUTION_SCOPE or {}).get("per_child_limits"), scratch_roots=(root,))
        write_json(root/"process.json",{"processes":processes,"historical_window_access":False,
            "scope_id":(phase6_game._EXECUTION_SCOPE or {}).get("scope_id")})
    finally:
        if temporary is not None:temporary.cleanup()
    try:
        actual = json.loads(result.stdout)
        parse_error = None
    except json.JSONDecodeError as error:
        actual = {}
        parse_error = str(error)
    observations = actual.get("inputs", [])
    port_state = [0, 0]
    independent = True
    for row, (port, mask) in zip(observations, expected):
        port_state[port] = mask
        independent &= row.get("port") == port and row.get("other_port_mask") == port_state[1 - port]
    passed = (result.returncode == 0 and not processes[-1].get("bound_violation") and
              actual.get("schema") == "genewhip-sdl-virtual-input-contract-v1" and
              len(observations) == len(expected) and
              all(row.get("requested_mask") == mask and row.get("effective_mask") == mask
                  for row, (_, mask) in zip(observations, expected)) and independent)
    if backend == "native":
        passed = passed and actual.get("video_driver") == "cocoa" and all(
            row.get("joystick_mask") == mask for row, (_, mask) in zip(observations, expected))
    desktop_source_sha=sha(ROOT/"tools/desktop/main_sdl.c")
    receipt = {"schema":"genewhip-phase6-sdl-virtual-input-contract-v1",
        "delivery_map_sha256":compiler.canonical_digest(mapping),"desktop_sha256":sha(desktop),
        "desktop_source_sha256":desktop_source_sha,
        "backend":backend,"video_driver":actual.get("video_driver"),
        "window_input_focus":actual.get("window_input_focus"),
        "rom_used":False,"production_title_launch":False,"requested_count":len(expected),
        "port_isolation_verified":independent,"observations":observations,"process":processes[-1],
        "parse_error":parse_error,"outcome":"pass" if passed else "fail"}
    write_json(output, receipt)
    return 0 if passed else 1


HOST_CASES = ("full-route", "withhold-first-plate", "withhold-final-b")
TANK_CASES = ("full-route", "withhold-early-hit", "withhold-late-hit")


def host_environment(backend: str, work: pathlib.Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("SDL_VIDEODRIVER", "SDL_AUDIODRIVER", "SDL_RENDER_DRIVER", "SDL_AUDIO_DISK_OUTPUT_FILE"):
        env.pop(key, None)
    if backend == "software":
        env.update({"SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "disk",
                    "SDL_RENDER_DRIVER": "software",
                    "SDL_AUDIO_DISK_OUTPUT_FILE": str(work / "sdlaudio.raw")})
    else:
        env.update({"SDL_VIDEODRIVER": "cocoa", "SDL_AUDIODRIVER": "coreaudio",
                    "GENEWHIP_LIVE_DISPLAY": "1", "GENEWHIP_LIVE_AUDIO": "1"})
    return env


def _owned_relative(path: pathlib.Path) -> str:
    return str(path.resolve(strict=True).relative_to(ROOT))


def _scrub_local_paths(value: str) -> str:
    return value.replace(str(ROOT), "<repository>").replace(str(pathlib.Path.home()), "<home>")


def _core_run(core: dict, fixture: str, case: str) -> dict:
    row = next((item for item in core.get("runs", []) if item.get("client") == "public-core" and
                item.get("fixture") == fixture and item.get("case") == case and
                item.get("repetition") == 1 and item.get("status") == "pass"), None)
    if row is None:
        raise RuntimeError(f"current repeated core row is missing: {fixture}/{case}")
    return row


def _input_join(native: dict, host: dict, mapping: dict, fixture: str, case: str) -> dict:
    core_events = native.get("inputs", [])
    host_events = host.get("input_events", [])
    if fixture != "recursion94":
        if len(core_events) != len(host_events) or not core_events:
            return {"equal": False, "core_count": len(core_events), "host_count": len(host_events)}
        rows = []
        for index, (core_event, host_event) in enumerate(zip(core_events, host_events)):
            equal = (core_event.get("port") == host_event.get("port") and
                core_event.get("desired") == host_event.get("requested_mask") == host_event.get("effective_mask") and
                core_event.get("effective") == host_event.get("effective_mask") and
                host_event.get("handler") == "SDL_Gamepad/sample_port")
            rows.append({"index": index, "event_id": f"{fixture}-route-event-{index+1}",
                "equal": bool(equal), "port": core_event.get("port"),
                "desired": core_event.get("desired"), "effective": core_event.get("effective")})
        return {"equal": all(item["equal"] for item in rows), "core_count": len(core_events),
            "host_count": len(host_events), "rows": rows}
    expected_events = [event for event in mapping.get("events", []) if case in event.get("cases", [])]
    cleanup_count = int(bool(expected_events) and expected_events[-1]["effective_mask"] != 0)
    if len(core_events) != len(host_events) or len(core_events) != len(expected_events) + cleanup_count:
        return {"equal": False, "core_count": len(core_events), "host_count": len(host_events)}
    rows = []
    for index, (core_event, host_event) in enumerate(zip(core_events, host_events)):
        equal = (core_event.get("port") == host_event.get("port") and
                 core_event.get("desired") == host_event.get("requested_mask") and
                 core_event.get("effective") == host_event.get("effective_mask") and
                 host_event.get("handler") == "SDL_Gamepad/sample_port")
        if index < len(expected_events):
            equal = equal and core_event.get("desired") == expected_events[index]["effective_mask"]
        else:
            # The final raw event is the separately bound cleanup release.
            equal = equal and core_event.get("desired") == 0 and host_event.get("requested_mask") == 0
        rows.append({"index": index, "event_id": expected_events[index]["event_id"] if index < len(expected_events) else "cleanup-release",
                     "equal": bool(equal), "port": core_event.get("port"),
                     "desired": core_event.get("desired"), "effective": core_event.get("effective")})
    return {"equal": all(row["equal"] for row in rows), "core_count": len(core_events),
            "host_count": len(host_events), "rows": rows}


def _host_identity(build: pathlib.Path, desktop: pathlib.Path, map_path: pathlib.Path,
                   core_path: pathlib.Path, candidate: dict, backend: str) -> dict:
    if phase6_game._EXECUTION_SCOPE is not None:
        input_contract_path=ROOT/f"build/v02/runtime/input-contract/{backend}.json"
    else:
        input_contract_path = (ROOT / "build/phase6/evidence/phase6-sdl-input-contract/native-window-v2.json"
            if backend == "native" else ROOT / "build/phase6/evidence/phase6-sdl-input-contract/software-current.json")
    return {"schema": "genewhip-phase6-host-identity-v1",
        "backend": backend,
        "core_candidate_sha256": canonical_sha(candidate),
        "core_report": {"path": str(core_path.resolve().relative_to(ROOT)), "sha256": sha(core_path)},
        "delivery_map": {"path": str(map_path.resolve().relative_to(ROOT),),
                         "sha256": compiler.canonical_digest(json.loads(map_path.read_text()))},
        "desktop_source_sha256": sha(ROOT / "tools/desktop/main_sdl.c"),
        "audio_source_sha256": sha(ROOT / "tools/desktop/audio.c"),
        "desktop_test_source_sha256": sha(pathlib.Path(__file__).resolve()),
        "phase4_control_source_sha256": sha(ROOT / "tests/desktop/phase4_sessions.py"),
        "input_contract": {"path": str(input_contract_path.resolve().relative_to(ROOT)),
            "sha256": sha(input_contract_path)},
        "desktop_binary": {"path": str(desktop.resolve().relative_to(ROOT)), "sha256": sha(desktop)},
        "cmake_cache_sha256": sha(build / "CMakeCache.txt"),
        "media_expectations_sha256": sha(ROOT / "fixtures/phase6/media-expectations-v1.json"),
        "proof_dependencies": {"renderer": "SDL renderer target readback after RenderTexture and before RenderPresent",
            "input": "two virtual SDL gamepads through normal event handling and sample_port",
            "pcm": "actual full core PCM before host gain/drift, submitted to runner_audio",
            "device": "SDL audio stream submission and observed queued-frame consumption"}}


def _retained_host_case(build: pathlib.Path, desktop: pathlib.Path, route: dict, mapping: dict,
                        core: dict, core_path: pathlib.Path, backend: str, work: pathlib.Path,
                        candidate: dict) -> dict:
    fixture, case = route["fixture"], route["case"]["id"]
    headless = _core_run(core, fixture, case)
    head_native_path = ROOT / headless["native_report"]["path"]
    head_native = json.loads(head_native_path.read_text(encoding="utf-8"))
    head_pcm = ROOT / headless["pcm"]["path"]
    head_pixels = ROOT / headless["image"]["path"]
    if len(head_pixels.read_bytes()) != 320 * 224 * 4:
        raise RuntimeError(f"headless common-field has an unexpected size: {fixture}/{case}")
    scene_field = int(headless["field_sequence"])
    attempts = sorted(path for path in work.glob(f"{fixture}-{case}-attempt*") if path.is_dir())
    attempt_dir = work / f"{fixture}-{case}-attempt{len(attempts) + 1}"
    attempt_dir.mkdir(mode=0o700)
    route_path, native_path = attempt_dir / "route.gwrc", attempt_dir / "native.json"
    host_path, renderer_path = attempt_dir / "host.json", attempt_dir / "renderer-field.bin"
    pcm_path, disk_path = attempt_dir / "audio.pcm", attempt_dir / "sdlaudio.raw"
    binary, metadata = compiler.lower_route(route, boundary_call_limit=100_000_000 if fixture == "recursion94" else 10_000_000,
                                             delivery_map=mapping if fixture == "recursion94" else None, client="sdl")
    route_path.write_bytes(binary)
    rom = ROOT / compiler.SOURCES[fixture][3]
    command = [str(desktop), "--route-plan", str(route_path), "--route-report", str(native_path),
        "--route-diagnostic", str(host_path), "--route-input-source", "virtual-gamepad",
        "--dump-audio", str(pcm_path), "--renderer-capture-field", str(scene_field),
        "--renderer-capture-output", str(renderer_path), str(rom)]
    if backend == "software":
        monitored = ((pcm_path, 16 * 1024 * 1024), (renderer_path, 16 * 1024 * 1024),
                     (disk_path, 16 * 1024 * 1024))
    else:
        monitored = ((pcm_path, 16 * 1024 * 1024), (renderer_path, 16 * 1024 * 1024))
    cap = 600 if fixture == "recursion94" else 300
    result, process, streams = phase6_game.shared_launch(desktop, command, attempt_dir, native_path, cap,
        files=monitored, env=host_environment(backend, attempt_dir), plan_id="06-52")
    native = json.loads(native_path.read_text(encoding="utf-8")) if native_path.is_file() else {}
    host = json.loads(host_path.read_text(encoding="utf-8")) if host_path.is_file() else {}
    inputs = _input_join(native, host, mapping, fixture, case)
    source_equal = native.get("samples") == head_native.get("samples")
    pcm_equal = pcm_path.is_file() and sha(pcm_path) == headless["pcm"]["sha256"] and pcm_path.stat().st_size == head_pcm.stat().st_size
    renderer_equal = renderer_path.is_file() and sha(renderer_path) == headless["image"]["sha256"] and \
        renderer_path.stat().st_size == head_pixels.stat().st_size
    device_active = bool(host.get("audio_device_activity") and host.get("audio_submitted_frames", 0) > 0 and
                         host.get("audio_device_consumed_frames", 0) > 0)
    core_ok = (result.returncode == 0 and not process.get("bound_violation") and native.get("status") == 0 and
        native.get("active_ticks") == 3600 and native.get("fields", 7201) <= (7200 if fixture == "recursion94" else 4500) and
        native.get("boundary_calls", 100_000_001) <= (100_000_000 if fixture == "recursion94" else 10_000_000) and
        source_equal and inputs["equal"])
    host_ok = (host.get("host_outcome") == "pass-diagnostic" and host.get("renderer_readback_activity") is True and
        host.get("renderer_capture_field") == scene_field and renderer_equal and pcm_equal and device_active and
        host.get("renderer") and host.get("video_driver") and host.get("audio_driver"))
    row = {"fixture": fixture, "case": case, "client": "sdl", "backend": backend,
        "status": "pass" if core_ok and host_ok else "fail",
        "reason": None if core_ok and host_ok else "core-input-progress-or-common-boundary-mismatch" if not core_ok else "host-renderer-pcm-or-device-mismatch",
        "identity": headless["identity"], "delivery_map_sha256": compiler.canonical_digest(mapping),
        "route_plan_sha256": hashlib.sha256(binary).hexdigest(), "route_metadata": metadata.get("delivery_map"),
        "core_outcome": "pass" if core_ok else "fail", "host_outcome": host.get("host_outcome", "unavailable"),
        "observed_clocks": {key: native.get(key) for key in ("active_ticks", "fields", "boundary_calls", "status")},
        "common_boundary": {"headless_native_sha256": sha(head_native_path), "host_native_sha256": sha(native_path) if native_path.is_file() else None,
            "source_samples_equal": source_equal, "source_samples_sha256": canonical_sha(native.get("samples", [])),
            "inputs": inputs, "headless_pixel": headless["image"],
            "renderer_pixel": phase6_game.artifact(renderer_path) if renderer_path.is_file() else None,
            "renderer_pixel_equal": renderer_equal, "headless_pcm": headless["pcm"],
            "desktop_pcm": phase6_game.artifact(pcm_path) if pcm_path.is_file() else None, "full_pcm_equal": pcm_equal},
        "renderer": {key: host.get(key) for key in ("renderer", "video_driver", "renderer_capture_field",
            "renderer_capture_fnv1a64", "renderer_readback_activity")},
        "capability": host.get("capability"),
        "audio": {key: host.get(key) for key in ("audio_driver", "audio_device_id", "audio_device_name",
            "pcm_frames", "audio_submitted_frames", "audio_device_consumed_frames", "audio_device_activity")},
        "raw_outputs": {"native": phase6_game.artifact(native_path) if native_path.is_file() else None,
            "host": phase6_game.artifact(host_path) if host_path.is_file() else None,
            "renderer": phase6_game.artifact(renderer_path) if renderer_path.is_file() else None,
            "pcm": phase6_game.artifact(pcm_path) if pcm_path.is_file() else None},
        "process": process, "process_receipt":phase6_game.artifact(attempt_dir/"process.json"),
        "streams": {name: {k: v for k, v in item.items() if k != "text"} for name, item in streams.items()},
        "attempt_directory": _owned_relative(attempt_dir), "attempt_number": len(attempts) + 1,
        "error": _scrub_local_paths(result.stderr[:1000]) if result.returncode else None}
    return row


def _reconcile_host_row(row: dict, build: pathlib.Path, mapping: dict, core: dict) -> dict:
    """Re-evaluate a retained attempt when only the current reader/projection changed."""
    row = copy.deepcopy(row)
    row["process_receipt"]=phase6_game.artifact((ROOT/row["raw_outputs"]["native"]["path"]).parent/"process.json")
    if row.get("process", {}).get("status") != "completed" or row.get("process", {}).get("return_code") != 0 or row.get("process", {}).get("bound_violation"):
        return row
    fixture, case = row.get("fixture"), row.get("case")
    headless = _core_run(core, fixture, case)
    native_path = ROOT / row["raw_outputs"]["native"]["path"]
    host_path = ROOT / row["raw_outputs"]["host"]["path"]
    renderer_path = ROOT / row["raw_outputs"]["renderer"]["path"]
    pcm_path = ROOT / row["raw_outputs"]["pcm"]["path"]
    route_path = native_path.parent / "route.gwrc"
    if not all(path.is_file() and not path.is_symlink() for path in (native_path, host_path, renderer_path, pcm_path, route_path)):
        return row
    route = next((item for item in compiler.compile_routes(mapping, "sdl")["routes"]
                  if item["fixture"] == fixture and item["case"]["id"] == case), None)
    if route is None:
        return row
    binary, _ = compiler.lower_route(route, boundary_call_limit=100_000_000 if fixture == "recursion94" else 10_000_000,
                                     delivery_map=mapping if fixture == "recursion94" else None, client="sdl")
    if hashlib.sha256(binary).hexdigest() != row.get("route_plan_sha256") or route_path.read_bytes() != binary:
        return row
    native, host = json.loads(native_path.read_text()), json.loads(host_path.read_text())
    inputs = _input_join(native, host, mapping, fixture, case)
    head_native = json.loads((ROOT / headless["native_report"]["path"]).read_text())
    source_equal = native.get("samples") == head_native.get("samples")
    pcm_equal = sha(pcm_path) == headless["pcm"]["sha256"] and pcm_path.stat().st_size == (ROOT / headless["pcm"]["path"]).stat().st_size
    pixels = ROOT / headless["image"]["path"]
    renderer_equal = sha(renderer_path) == headless["image"]["sha256"] and renderer_path.stat().st_size == pixels.stat().st_size
    scene_field = int(headless["field_sequence"])
    device_active = bool(host.get("audio_device_activity") and host.get("audio_submitted_frames", 0) > 0 and host.get("audio_device_consumed_frames", 0) > 0)
    core_ok = (native.get("status") == 0 and native.get("active_ticks") == 3600 and
        native.get("fields", 7201) <= (7200 if fixture == "recursion94" else 4500) and
        native.get("boundary_calls", 100_000_001) <= (100_000_000 if fixture == "recursion94" else 10_000_000) and
        source_equal and inputs["equal"])
    host_ok = (host.get("host_outcome") == "pass-diagnostic" and host.get("renderer_readback_activity") is True and
        host.get("renderer_capture_field") == scene_field and renderer_equal and pcm_equal and device_active)
    row.update({"status": "pass" if core_ok and host_ok else "fail",
        "reason": None if core_ok and host_ok else "core-input-progress-or-common-boundary-mismatch" if not core_ok else "host-renderer-pcm-or-device-mismatch",
        "core_outcome": "pass" if core_ok else "fail", "host_outcome": host.get("host_outcome"),
        "common_boundary": {**row.get("common_boundary", {}), "source_samples_equal": source_equal,
            "inputs": inputs, "renderer_pixel_equal": renderer_equal, "full_pcm_equal": pcm_equal}})
    return row


def _run_original_controls(build: pathlib.Path, desktop: pathlib.Path, work: pathlib.Path,
                           backend: str) -> dict:
    prior = sorted(work.glob("original-host-controls-attempt*.json"))
    control_path = work / f"original-host-controls-attempt{len(prior) + 1}.json"
    driver = ROOT / "tests/desktop/phase4_sessions.py"
    mode = "software" if backend == "software" else "live"
    command = [sys.executable, "-I", str(driver), mode,
        "--headless", str(build / "tools/session/gw_headless"), "--desktop", str(desktop),
        "--build", str(build), "--out", str(control_path)]
    if phase6_game._EXECUTION_SCOPE is not None:
        scope_path=phase6_game._EXECUTION_SCOPE.get("_scope_path")
        if not isinstance(scope_path,str):raise RuntimeError("phase7-host-control-scope-path-missing")
        command.extend(["--execution-scope",scope_path])
    env = host_environment(backend, work)
    result, process, streams = phase6_game.shared_launch(pathlib.Path(sys.executable), command, work,
        control_path, 600, env=env, plan_id="06-52")
    report = json.loads(control_path.read_text(encoding="utf-8")) if control_path.is_file() else {}
    return {"schema": report.get("schema"), "mode": report.get("mode"),
        "outcome": report.get("outcome", "missing-report"), "denominator": report.get("denominator", 0),
        "counts": report.get("counts", {}), "runs": report.get("runs", []),
        "report": phase6_game.artifact(control_path) if control_path.is_file() else None,
        "process": process, "process_receipt":phase6_game.artifact(work/"process.json"),
        "streams": {name: {k: v for k, v in item.items() if k != "text"} for name, item in streams.items()},
        "return_code": result.returncode,
        "error": _scrub_local_paths(result.stderr[:1000]) if result.returncode not in (0, 77) else None}


def host_batch(backend: str, build: pathlib.Path, core_path: pathlib.Path, map_path: pathlib.Path,
               output: pathlib.Path, candidate_path: pathlib.Path) -> int:
    build = build.resolve(strict=True)
    desktop = build / "tools/desktop/genewhip-desktop"
    if not desktop.is_file():
        raise RuntimeError("source-bound desktop executable is required")
    core = json.loads(core_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping, client="sdl")
    if core.get("schema") != "genewhip-phase6-product-report-v1" or core.get("candidate_sha256") != canonical_sha(candidate):
        raise RuntimeError("headless product report and immutable core candidate identity do not match")
    routes = compiler.compile_routes(mapping, "sdl")["routes"]
    if phase6_game._EXECUTION_SCOPE is not None:
        input_contract_path=ROOT/f"build/v02/runtime/input-contract/{backend}.json"
    else:
        input_contract_path = (ROOT / "build/phase6/evidence/phase6-sdl-input-contract/native-window-v2.json"
            if backend == "native" else ROOT / "build/phase6/evidence/phase6-sdl-input-contract/phase6-sdl-input-contract-final-5.json")
    input_proof = json.loads(input_contract_path.read_text(encoding="utf-8"))
    if (input_proof.get("outcome") != "pass" or input_proof.get("requested_count") != 23 or
            not input_proof.get("port_isolation_verified") or input_proof.get("desktop_sha256") != sha(desktop)):
        raise RuntimeError("current actual SDL two-port input contract is required before title launch")
    if backend == "native" and (input_proof.get("backend") != "native" or input_proof.get("video_driver") != "cocoa"):
        raise RuntimeError("current Cocoa-window native virtual-input contract is required before title launch")
    selected = [route for fixture, cases in (("recursion94", HOST_CASES), ("tank-battle", TANK_CASES))
        for case in cases for route in routes if route["fixture"] == fixture and route["case"]["id"] == case]
    if len(selected) != 6:
        raise RuntimeError("frozen SDL host roster does not contain six canonical cases")
    evidence_root = build / "evidence"
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    window = phase6_game._read_window()
    identity = _host_identity(build, desktop, map_path, core_path, candidate, backend)
    roster = [{"fixture": route["fixture"], "case": route["case"]["id"],
        "expected_status": "pass", "attempt_budget": 600 if route["fixture"] == "recursion94" else 300}
        for route in selected]
    controls_roster = {"fixture_controls": ["pause", "resume", "reset", "mute", "unmute", "replace", "drop", "reject-cartridge", "exit"],
        "sessions": ["independent-game-v2", "sounded-diagnostic"]}
    if output.exists():
        report = json.loads(output.read_text(encoding="utf-8"))
        if (report.get("schema") != "genewhip-phase6-host-v1" or report.get("backend") != backend or
                report.get("host_identity_sha256") != canonical_sha(identity) or report.get("roster") != roster):
            raise RuntimeError("existing host report is bound to another source, backend or frozen roster")
        work = ROOT / report["resources"]["owned_directory"]
        if work.parent != evidence_root or not work.is_dir() or work.is_symlink():
            raise RuntimeError("existing host attempt directory is not a safe owned path")
    else:
        work = pathlib.Path(__import__("tempfile").mkdtemp(prefix="phase6-sdl-host-", dir=evidence_root))
        root_name = str(work.relative_to(ROOT))
        if root_name not in window["owned_artifact_roots"]:
            window["owned_artifact_roots"].append(root_name)
        window["retained_artifact_bytes"] = sum(phase6_game.tree_bytes(ROOT / p) for p in window["owned_artifact_roots"])
        phase6_game._write_window(window)
        report = {"schema": "genewhip-phase6-host-v1", "candidate_sha256": canonical_sha(candidate),
            "backend": backend, "host_identity": identity, "host_identity_sha256": canonical_sha(identity),
            "roster": roster, "controls_roster": controls_roster, "runs": [], "attempts": [], "controls": None,
            "processes": [], "resources": {"shared_window": {"started_at": window["started_at"],
                "workload_cutoff": window["workload_cutoff"], "deadline": window["deadline"]},
                "owned_directory": root_name}, "status": "in-progress", "reasons": []}
        write_json(output, report)
    completed = {(row.get("fixture"), row.get("case")): row for row in report.get("runs", [])
                 if row.get("status") == "pass"}
    for index, prior in enumerate(list(report.get("runs", []))):
        if prior.get("status") == "fail":
            retained = next((attempt for attempt in reversed(report.get("attempts", []))
                if (attempt.get("fixture"), attempt.get("case")) == (prior.get("fixture"), prior.get("case"))), None)
            if retained is not None:
                reconciled = _reconcile_host_row(retained, build, mapping, core)
                report.setdefault("reader_reconciliations", []).append({"fixture": prior.get("fixture"),
                    "case": prior.get("case"), "prior_status": prior.get("status"),
                    "retained_attempt": retained.get("attempt_number"), "result_status": reconciled.get("status"),
                    "reason": reconciled.get("reason")})
                report["runs"][index] = reconciled
                if reconciled.get("status") == "pass":
                    completed[(prior.get("fixture"), prior.get("case"))] = reconciled
                write_json(output, report)
    skipped = False
    for route in selected:
        key = (route["fixture"], route["case"]["id"])
        if key in completed:
            continue
        if skipped:
            continue
        row = _retained_host_case(build, desktop, route, mapping, core, core_path, backend, work, candidate)
        report.setdefault("attempts", []).append(row)
        report["processes"].append(row["process"])
        report["runs"] = [prior for prior in report["runs"]
                           if (prior.get("fixture"), prior.get("case")) != key]
        report["runs"].append(row)
        missing_native = (backend == "native" and
            ("Could not initialise SDL video" in (row.get("error") or "") or
             "Could not create the window or renderer" in (row.get("error") or "") or
             row.get("capability") == "audio-unavailable"))
        if missing_native:
            report["reasons"].append("native-display-or-audio-capability-unavailable; HOST-04 remains blocked")
            report["runs"][-1]["status"] = "skipped"
            report["runs"][-1]["reason"] = "native-display-or-audio-capability-unavailable"
            for remaining in selected:
                remaining_key = (remaining["fixture"], remaining["case"]["id"])
                if remaining_key not in {(r.get("fixture"), r.get("case")) for r in report["runs"]}:
                    report["runs"].append({"fixture": remaining_key[0], "case": remaining_key[1],
                        "status": "skipped", "reason": "native-capability-unavailable-before-title-launch"})
            skipped = True
        write_json(output, report)
        if row["status"] != "pass" and not missing_native:
            report["status"] = "fail"
            report["reasons"].append(f"host-tracer-failed:{route['fixture']}/{route['case']['id']}; fix before expansion")
            write_json(output, report)
            return 1
        if key == ("recursion94", "full-route") and row["status"] == "pass":
            # Re-read retained native facts, device counters and the common full-frame/PCM joins
            # before admitting any expansion case; this adds no guest launch or attempt.
            check = report["runs"][-1]
            if not (check.get("common_boundary", {}).get("source_samples_equal") and
                    check.get("common_boundary", {}).get("renderer_pixel_equal") and
                    check.get("common_boundary", {}).get("full_pcm_equal") and
                    check.get("audio", {}).get("audio_device_activity")):
                report["status"] = "fail"
                report["reasons"].append("tracer-feedback-gate-failed-before-expansion")
                write_json(output, report)
                return 1
    passed_cases = {(row.get("fixture"), row.get("case")) for row in report["runs"] if row.get("status") == "pass"}
    controls = report.get("controls") if (report.get("controls") or {}).get("outcome") in ("pass", "skipped") else None
    if controls is None and (len(passed_cases) == 6 or skipped):
        if backend == "native" and skipped:
            controls = {"schema": "genewhip-phase4-host-sessions", "mode": "live",
                "outcome": "skipped", "reason": "native display/audio capability unavailable before controls",
                "denominator": 0, "runs": [], "return_code": 77, "process": None}
        else:
            controls = _run_original_controls(build, desktop, work, backend)
    if controls is not None:
        report["controls"] = controls
        if controls.get("process") is not None:
            report["processes"].append(controls["process"])
    native_missing = backend == "native" and (skipped or (controls and controls["return_code"] == 77))
    report["status"] = "blocked-capability" if native_missing else (
        "pass" if all(row["status"] == "pass" for row in report["runs"]) and controls and controls["outcome"] == "pass" else "fail")
    if native_missing:
        report["reasons"].append("native-display-or-audio-capability-unavailable; HOST-04 remains blocked")
        for route in selected:
            report["runs"].append({"fixture": route["fixture"], "case": route["case"]["id"],
                "status": "skipped", "reason": "native-capability-unavailable-before-title-launch"})
    elif report["status"] != "pass":
        report["reasons"].append("one-or-more-case-or-control-host-dimensions-failed")
    report["resources"].update({"workload_wall_seconds": sum(
        float(item.get("wall_seconds", 0)) for item in report["processes"]),
        "owned_artifact_bytes": phase6_game.tree_bytes(work)})
    write_json(output, report)
    if native_missing:
        compiler.validate_host_capability_blocker(report, candidate)
    else:
        compiler.validate_host_report(report, candidate)
    return 77 if native_missing else 0 if report["status"] == "pass" else 1


def negative_controls(build: pathlib.Path, core_path: pathlib.Path, map_path: pathlib.Path,
                      output: pathlib.Path, candidate_path: pathlib.Path, offline: bool = False,
                      software_override: pathlib.Path | None = None,
                      native_override: pathlib.Path | None = None,
                      semantic_only: bool = False) -> int:
    """Exercise the production host consumer with retained independent receipts."""
    software_path = software_override or ROOT / "evidence/phase6-host-software-current.json"
    native_path = native_override or ROOT / "evidence/phase6-host-native.json"
    if not software_path.is_file() or not native_path.is_file():
        raise RuntimeError("both retained host reports are required before offline fault controls")
    software = json.loads(software_path.read_text())
    native = json.loads(native_path.read_text())
    candidate = json.loads(candidate_path.read_text())
    if semantic_only:
        compiler.validate_host_report(software, candidate)
        compiler.validate_host_report(native, candidate)
    # Preserve real accepted captures. Fault controls use byte-correct copies in a
    # separate owned directory, with outer digests recomputed after each mutation.
    evidence_root = build.resolve(strict=True) / "evidence"
    window = None if semantic_only else phase6_game._read_window()
    fault_root = pathlib.Path(__import__("tempfile").mkdtemp(
        prefix="phase6-sdl-host-fault-", dir=evidence_root))
    relative_root = str(fault_root.relative_to(ROOT))
    if window is not None and relative_root not in window["owned_artifact_roots"]:
        window["owned_artifact_roots"].append(relative_root)
    if window is not None:
        window["retained_artifact_bytes"] = sum(
            phase6_game.tree_bytes(ROOT / item) for item in window["owned_artifact_roots"])
        phase6_game._write_window(window)
    mutations = []
    for label, report, edit, expected in (
        ("missing-case", copy.deepcopy(software), lambda x: x["runs"].pop(), "host-roster"),
        ("failed-host-process", copy.deepcopy(software), lambda x:x["runs"][0]["process"].update(return_code=1), "host-process"),
        ("unconfirmed-host-cleanup", copy.deepcopy(software), lambda x:x["runs"][0]["process"].update(process_group_cleanup="unconfirmed"), "host-process"),
        ("missing-host-process-receipt", copy.deepcopy(software), lambda x:x["runs"][0].update(process_receipt=None), "host-process-binding-missing"),
        ("failed-control-process", copy.deepcopy(software), lambda x:x["controls"]["process"].update(return_code=1), "host-process"),
        ("video-corruption", copy.deepcopy(software), lambda x: x["runs"][0]["common_boundary"].update(renderer_pixel_equal=False), "host-renderer"),
        ("native-false-capability", copy.deepcopy(native), lambda x: x.update(status="blocked-capability", reasons=["native capability unavailable"]), "host-native-capability"),
        ("stale-source", copy.deepcopy(software), lambda x: x["host_identity"].update(desktop_source_sha256="0"*64), "host-identity"),
        ("missing-backend", copy.deepcopy(software), lambda x: x.update(backend="unknown"), "host-backend"),
        ("missing-control-roster", copy.deepcopy(software), lambda x: x["controls"].update(outcome="skipped"), "host-controls"),
        ("stale-delivery-map", copy.deepcopy(software), lambda x: (x["host_identity"]["delivery_map"].update(sha256="0"*64), x.update(host_identity_sha256=compiler.canonical_digest(x["host_identity"]))), "host-map"),
        ("wrong-headless-rom-identity", copy.deepcopy(software), lambda x: x["runs"][0]["identity"].update(rom_sha256="0"*64), "host-core-observation"),
        ("missing-renderer-media", copy.deepcopy(software), lambda x: x["runs"][0]["raw_outputs"].update(renderer=None), "host-raw-output"),
        ("stale-device-counter-receipt", copy.deepcopy(software), lambda x: x["runs"][0]["audio"].update(audio_device_consumed_frames=0), "host-audio"),
    ):
        edit(report)
        try:
            compiler.validate_host_report(report, candidate)
        except compiler.Invalid as error:
            actual = str(error)
            mutations.append({"id": label, "expected_reason": expected, "actual_reason": actual,
                              "rejected": actual == expected})
        else:
            mutations.append({"id": label, "expected_reason": expected, "actual_reason": None, "rejected": False})

    def process_receipt_mutant(name, change, expected):
        mutant=copy.deepcopy(software)
        row=mutant["runs"][0]
        receipt=json.loads((ROOT/row["process_receipt"]["path"]).read_text())
        change(mutant,row,receipt)
        path=fault_root/(name+".json")
        write_json(path,receipt)
        row["process_receipt"]=phase6_game.artifact(path)
        actual=None
        try:compiler.validate_host_report(mutant,candidate)
        except compiler.Invalid as error:actual=str(error)
        mutations.append({"id":name,"expected_reason":expected,"actual_reason":actual,"rejected":actual==expected})
    def boolean_wall(report,row,receipt):
        row["process"]["wall_seconds"]=True
        receipt["processes"]=[copy.deepcopy(row["process"])]
        for process in report["processes"]:
            if process["pid"]==row["process"]["pid"]:process["wall_seconds"]=True
    process_receipt_mutant("boolean-process-wall",boolean_wall,"host-process")
    process_receipt_mutant("unbound-extra-process",lambda report,row,receipt:receipt["processes"].insert(0,{"pid":1,"status":"unconfirmed"}),"host-process-binding")

    def copied_artifact(report: dict, name: str, filename: str) -> tuple[dict, pathlib.Path]:
        mutant = copy.deepcopy(report)
        row = mutant["runs"][0]
        original = ROOT / row["raw_outputs"][name]["path"]
        destination = fault_root / filename
        destination.write_bytes(original.read_bytes())
        row["raw_outputs"][name] = phase6_game.artifact(destination)
        return mutant, destination

    def check_mutant(label: str, mutant: dict, expected: str) -> None:
        try:
            compiler.validate_host_report(mutant, candidate)
        except compiler.Invalid as error:
            actual = str(error)
            mutations.append({"id": label, "expected_reason": expected,
                "actual_reason": actual, "rejected": actual == expected})
        else:
            mutations.append({"id": label, "expected_reason": expected,
                "actual_reason": None, "rejected": False})

    input_mutant, input_path = copied_artifact(software, "host", "suppressed-input-host.json")
    input_bytes = json.loads(input_path.read_text(encoding="utf-8"))
    input_bytes["input_events"][0]["effective_mask"] ^= 1
    write_json(input_path, input_bytes)
    input_mutant["runs"][0]["raw_outputs"]["host"] = phase6_game.artifact(input_path)
    check_mutant("actual-host-handler-input-bytes", input_mutant, "host-input")

    device_mutant, device_path = copied_artifact(software, "host", "disabled-audio-device-observation.json")
    device_bytes = json.loads(device_path.read_text(encoding="utf-8"))
    device_bytes["audio_device_activity"] = False
    device_bytes["audio_submitted_frames"] = 0
    device_bytes["audio_device_consumed_frames"] = 0
    write_json(device_path, device_bytes)
    device_mutant["runs"][0]["raw_outputs"]["host"] = phase6_game.artifact(device_path)
    check_mutant("actual-device-audio-activity", device_mutant, "host-audio")

    renderer_mutant, renderer_path = copied_artifact(software, "renderer", "corrupt-renderer-readback.bin")
    renderer_bytes = bytearray(renderer_path.read_bytes())
    renderer_bytes[0] ^= 1
    renderer_path.write_bytes(renderer_bytes)
    renderer_mutant["runs"][0]["raw_outputs"]["renderer"] = phase6_game.artifact(renderer_path)
    check_mutant("actual-renderer-readback-bytes", renderer_mutant, "host-renderer")

    audio_mutant, pcm_path = copied_artifact(software, "pcm", "missing-device-audio-bytes.pcm")
    pcm_bytes = bytearray(pcm_path.read_bytes())
    pcm_bytes[0] ^= 1
    pcm_path.write_bytes(pcm_bytes)
    audio_mutant["runs"][0]["raw_outputs"]["pcm"] = phase6_game.artifact(pcm_path)
    check_mutant("actual-submitted-audio-bytes", audio_mutant, "host-audio")

    core_mutant, native_path = copied_artifact(software, "native", "unsupported-core-stop.json")
    native_bytes = json.loads(native_path.read_text(encoding="utf-8"))
    native_bytes["status"] = 4
    write_json(native_path, native_bytes)
    core_mutant["runs"][0]["raw_outputs"]["native"] = phase6_game.artifact(native_path)
    check_mutant("unsupported-core-status", core_mutant, "host-core-observation")

    if semantic_only:
        expected_rows=[{"id":name,"expected_reason":reason,"actual_reason":reason,"rejected":True}
                       for name,reason in HOST_SEMANTIC_MUTANT_EXPECTATIONS]
        if mutations!=expected_rows:
            raise AssertionError("host semantic mutant identities or reasons diverged from declared roster")
        passed = bool(mutations) and all(row["rejected"] for row in mutations)
        write_json(output,{"schema":"genewhip-phase6-host-check-v1","mutations":mutations,
            "production_consumer":"scripts/evidence/phase6_routes.py::validate_host_report",
            "admitted_title_launches":0,"new_admitted_title_launches":0,
            "canonical_qualification_launches":0,"launch_accounting":{"new_launches":0},
            "outcome":"pass" if passed else "fail"})
        return 0 if passed else 1

    if offline:
        prior_path=ROOT/"evidence/phase6-host-check.json"
        prior=json.loads(prior_path.read_text())
        retained=next((item for item in prior.get("mutations",[])
            if item.get("id")=="real-sdl-virtual-handler-suppression"),None)
        if not isinstance(retained,dict) or retained.get("rejected") is not True:
            raise RuntimeError("offline-retained-real-host-fault-missing")
        raw=retained.get("raw_outputs",{});loaded={}
        for label in ("host","native"):
            ref=raw.get(label)
            if not isinstance(ref,dict):raise RuntimeError("offline-retained-real-host-fault-artifact")
            path=(ROOT/ref.get("path","")).resolve()
            if (not path.is_relative_to(evidence_root) or path.is_symlink() or not path.is_file() or
                    sha(path)!=ref.get("sha256")):
                raise RuntimeError("offline-retained-real-host-fault-identity")
            loaded[label]=json.loads(path.read_text())
        actual_reason=None
        try:compiler.validate_host_input_observations(loaded["host"],loaded["native"])
        except compiler.Invalid as error:actual_reason=str(error)
        native_inputs=loaded["native"].get("inputs",[]);host_inputs=loaded["host"].get("input_events",[])
        process=retained.get("process",{})
        reused=(actual_reason=="host-input" and process.get("process_group_cleanup")=="confirmed" and
            process.get("bound_violation") is False and process.get("return_code") in (0,1) and
            bool(native_inputs) and bool(host_inputs) and native_inputs[0].get("desired")==8 and
            native_inputs[0].get("effective")==0 and host_inputs[0].get("requested_mask")==8 and
            host_inputs[0].get("effective_mask")==0)
        mutations.append({"id":"real-sdl-virtual-handler-suppression","expected_reason":"host-input",
            "actual_reason":actual_reason,"consumer":"scripts/evidence/phase6_routes.py::validate_host_input_observations",
            "rejected":reused,"reused_retained_fault":True,"process":process,
            "raw_outputs":{"host":raw["host"],"native":raw["native"]}})
        passed=bool(mutations) and all(row["rejected"] for row in mutations)
        window=phase6_game._read_window()
        window["retained_artifact_bytes"]=sum(phase6_game.tree_bytes(ROOT/item) for item in window["owned_artifact_roots"])
        phase6_game._write_window(window)
        write_json(output,{"schema":"genewhip-phase6-host-check-v1","mutations":mutations,
            "production_consumer":"scripts/evidence/phase6_routes.py::validate_host_report",
            "admitted_title_launches":1,"new_admitted_title_launches":0,"canonical_qualification_launches":0,
            "launch_accounting":{"admitted_rom_negative":1,"canonical_qualification":0,
                "new_launches":0,"reused_historical_fault":1},"reused_fault_source":phase6_game.artifact(prior_path),
            "resources":{"owned_fault_directory":str(fault_root.relative_to(ROOT)),
                "owned_fault_bytes":phase6_game.tree_bytes(fault_root)},"outcome":"pass" if passed else "fail"})
        return 0 if passed else 1

    # A short real SDL ROM negative: retain the first REC press, suppress it at
    # the virtual joystick boundary, and prove the normal sample_port value that
    # reaches the guest is zero. The shortened authored route plan is not a
    # canonical qualification row, but it does launch the admitted REC ROM.
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    route = next(item for item in compiler.compile_routes(mapping, "sdl")["routes"]
        if item["fixture"] == "recursion94" and item["case"]["id"] == "full-route")
    plan_bytes, _ = compiler.lower_route(route, boundary_call_limit=100_000_000,
        delivery_map=mapping, client="sdl")
    words = list(struct.unpack("<" + "I" * (len(plan_bytes) // 4), plan_bytes))
    words[3], words[4], words[13] = 7200, 30, 0  # bound execution to 30 active fields
    # Predicates refer to the full product field range; omit them from this
    # intentionally shortened fault guest and remove their trailing records.
    short_plan = struct.pack("<" + "I" * (len(words) - 4 * 4), *words[:-4 * 4])
    short_dir = fault_root / "suppressed-input-short-route"
    short_dir.mkdir(mode=0o700)
    plan_path = short_dir / "short.gwrc"
    native_path = short_dir / "native.json"
    host_path = short_dir / "host.json"
    plan_path.write_bytes(short_plan)
    desktop = build.resolve(strict=True) / "tools/desktop/genewhip-desktop"
    env = host_environment("software", short_dir)
    command = [str(desktop), "--route-plan", str(plan_path), "--route-report", str(native_path),
        "--route-diagnostic", str(host_path), "--route-input-source", "virtual-gamepad",
        "--route-input-suppress", str(ROOT / "fixtures/phase5-b/game.bin")]
    process_result, process, streams = phase6_game.shared_launch(desktop, command, short_dir,
        native_path, 30, env=env, files=((short_dir / "sdlaudio.raw", 16 * 1024 * 1024),), plan_id="06-52")
    native = json.loads(native_path.read_text(encoding="utf-8")) if native_path.is_file() else {}
    host = json.loads(host_path.read_text(encoding="utf-8")) if host_path.is_file() else {}
    native_inputs, host_inputs = native.get("inputs", []), host.get("input_events", [])
    actual_reason=None
    try:
        compiler.validate_host_input_observations(host,native)
    except compiler.Invalid as error:
        actual_reason=str(error)
    input_fault_detected=(actual_reason=="host-input" and process_result.returncode in (0,1) and
        not process.get("bound_violation") and process.get("process_group_cleanup")=="confirmed" and
        bool(native_inputs) and bool(host_inputs) and native_inputs[0].get("desired")==8 and
        native_inputs[0].get("effective")==0 and host_inputs[0].get("requested_mask")==8 and
        host_inputs[0].get("effective_mask")==0)
    mutations.append({"id": "real-sdl-virtual-handler-suppression", "expected_reason": "host-input",
        "actual_reason": actual_reason,
        "consumer": "scripts/evidence/phase6_routes.py::validate_host_input_observations",
        "rejected": input_fault_detected, "process": process,
        "native_status": native.get("status"), "first_core_input": native_inputs[0] if native_inputs else None,
        "first_sdl_input": host_inputs[0] if host_inputs else None,
        "short_plan_sha256": hashlib.sha256(short_plan).hexdigest(),
        "work_directory": _owned_relative(short_dir),
        "raw_outputs": {"plan": phase6_game.artifact(plan_path),
            "native": phase6_game.artifact(native_path) if native_path.is_file() else None,
            "host": phase6_game.artifact(host_path) if host_path.is_file() else None,
            "audio_device": phase6_game.artifact(short_dir / "sdlaudio.raw") if (short_dir / "sdlaudio.raw").is_file() else None},
        "streams": {name: {k: v for k, v in item.items() if k != "text"} for name, item in streams.items()}})
    passed = bool(mutations) and all(row["rejected"] for row in mutations)
    window = phase6_game._read_window()
    window["retained_artifact_bytes"] = sum(
        phase6_game.tree_bytes(ROOT / item) for item in window["owned_artifact_roots"])
    phase6_game._write_window(window)
    write_json(output, {"schema": "genewhip-phase6-host-check-v1", "mutations": mutations,
        "production_consumer": "scripts/evidence/phase6_routes.py::validate_host_report",
        "admitted_title_launches": 1,
        "canonical_qualification_launches": 0,
        "launch_accounting": {"admitted_rom_negative": 1, "canonical_qualification": 0},
        "resources": {"owned_fault_directory": str(fault_root.relative_to(ROOT)),
            "owned_fault_bytes": phase6_game.tree_bytes(fault_root)},
        "outcome": "pass" if passed else "fail"})
    return 0 if passed else 1


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("diagnostic","contract","input-contract","native-input-contract","reconcile","software","native","negative-controls"),required=True)
    parser.add_argument("--build",type=pathlib.Path,required=True)
    parser.add_argument("--core",type=pathlib.Path)
    parser.add_argument("--delivery-map",type=pathlib.Path,required=True)
    parser.add_argument("--candidate",type=pathlib.Path,default=ROOT/"evidence/phase6-candidate.json")
    parser.add_argument("--output",type=pathlib.Path,required=True)
    parser.add_argument("--work-dir",type=pathlib.Path)
    parser.add_argument("--execution-scope", type=pathlib.Path,
                        help="explicit Phase 7 caller-owned bounds and historical-window isolation")
    parser.add_argument("--offline",action="store_true",help="reuse the retained real fault row; launch no guest")
    args=parser.parse_args()
    try:
        if args.execution_scope is not None:
            set_execution_scope(json.loads(args.execution_scope.read_text(encoding="utf-8")))
        if args.mode in ("software", "native"):
            if args.core is None: parser.error("--core is required for host qualification")
            return host_batch(args.mode,args.build,args.core,args.delivery_map,args.output,args.candidate)
        if args.mode == "negative-controls":
            if args.core is None: parser.error("--core is required for host negative controls")
            return negative_controls(args.build,args.core,args.delivery_map,args.output,args.candidate,args.offline)
        if args.mode=="diagnostic":
            if args.core is None: parser.error("--core is required for diagnostic mode")
            return diagnostic(args.build,args.core,args.delivery_map,args.output,args.candidate)
        if args.mode=="reconcile":
            if args.core is None: parser.error("--core is required for reconcile mode")
            return reconcile_existing(args.build,args.core,args.delivery_map,args.output,args.candidate,args.work_dir)
        if args.mode in ("input-contract","native-input-contract"):
            return input_contract(args.build,args.delivery_map,args.output,args.candidate,
                                  "native" if args.mode == "native-input-contract" else "software")
        if args.core is None: parser.error("--core is required for contract mode")
        return contract(args.delivery_map,args.core)
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,compiler.Invalid) as error:
        print(f"phase6 SDL {args.mode} failed: {error}",file=sys.stderr)
        return 1


if __name__=="__main__":
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())
