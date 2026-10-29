#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Required source-derived v2 gameplay contract through public clients."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_PATH = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE_PATH = ROOT / "fixtures/independent-game-v2/oracle.json"
SCENARIO_SHA = "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2"
ORACLE_SHA = "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"
SOURCE_SHA = "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe"
FIELD_TICKS = 896040
MASTER_HZ = 53693175
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2, "A": 64, "B": 16, "C": 32}
PROCESS_RECEIPT_PATH: Path | None = None
PROCESS_RECEIPTS: list[dict] = []
V02_EXECUTION_SCOPE: dict | None = None


def _save_process_receipts() -> None:
    if PROCESS_RECEIPT_PATH is not None:
        PROCESS_RECEIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
        PROCESS_RECEIPT_PATH.write_text(json.dumps({"processes": PROCESS_RECEIPTS}, sort_keys=True, indent=2) + "\n")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command_identity(args: list[str], *, temporary_root: Path) -> tuple[list[str], str]:
    normalized = []
    for item in args:
        path = Path(item)
        if path.is_absolute():
            try:
                item = path.resolve(strict=False).relative_to(ROOT.resolve(strict=True)).as_posix()
            except ValueError:
                try:
                    relative = path.resolve(strict=False).relative_to(temporary_root.resolve(strict=True))
                    item = "<case-run>/" + relative.as_posix()
                except ValueError as exc:
                    raise ValueError("process command contains an unapproved absolute path") from exc
        normalized.append(item)
    raw_identity = json.dumps(args, separators=(",", ":")).encode()
    return normalized, hashlib.sha256(raw_identity).hexdigest()


def input_log(case: dict) -> bytes:
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for event in sorted(case["input_schedule"], key=lambda row: row["frame"]):
        port_name, _, button = event["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in BUTTONS:
            raise ValueError("scenario contains an unknown controller event")
        port = int(port_name[1]) - 1
        held[port] = held[port] | BUTTONS[button] if event["asserted"] else held[port] & ~BUTTONS[button]
        lines.append(f"{event['frame'] * FIELD_TICKS} pad {port} {held[port]:x}")
    return ("\n".join(lines) + "\n").encode()


def _retain_streams(streams: dict[str, bytes], root: Path | None) -> dict:
    result = {}
    limit = 1048576
    for name, raw in streams.items():
        truncated = len(raw) > limit
        item = {"sha256": hashlib.sha256(raw).hexdigest(), "observed_bytes": len(raw),
                "retained_bytes": min(len(raw), limit), "truncated": truncated,
                "preview": raw[:limit].decode("utf-8", errors="replace")}
        if root is not None:
            root.mkdir(parents=True, exist_ok=True)
            real_root = root.resolve(strict=True)
            real_root.relative_to(ROOT.resolve(strict=True))
            path = root / f"child.{name}.raw"
            if path.is_symlink():
                raise ValueError("retained child stream symlink denied")
            path.write_bytes(raw[:limit])
            item["path"] = path.resolve(strict=True).relative_to(ROOT.resolve(strict=True)).as_posix()
        result[name] = item
    if any(item["truncated"] for item in result.values()):
        raise ValueError("child stdout or stderr exceeded 1 MiB retention bound")
    return result


class BoundedProcessError(RuntimeError):
    def __init__(self, reason: str, stdout: bytes, stderr: bytes):
        super().__init__(reason); self.stdout=stdout; self.stderr=stderr


class RetainedFailureDirectory:
    """Keep intermediate workload files only when a retained run fails."""
    def __init__(self, retain_root: Path):
        self.path = retain_root.parent / (retain_root.name + ".work")

    def __enter__(self):
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("retained-workspace-collision")
        self.path.mkdir(parents=True)
        return str(self.path)

    def __exit__(self, kind, value, traceback):
        if kind is None:
            shutil.rmtree(self.path)
        return False


def bounded_run(command: list[str], *, timeout: float, cap: int = 2097152,
                outer_process_group: bool = False):
    """Bound runtime and combined child output while killing the complete process group."""
    if V02_EXECUTION_SCOPE is not None:
        import importlib.util
        spec=importlib.util.spec_from_file_location("gw_phase7_nested_boundary",ROOT/"tests/session/phase6_route_contract.py")
        if spec is None or spec.loader is None:raise RuntimeError("phase7-nested-boundary-import")
        boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)
        if "--dump-fields" in command:
            work=Path(command[command.index("--dump-fields")+1]).parent.resolve()
        elif "--dump-audio" in command:
            work=Path(command[command.index("--dump-audio")+1]).parent.resolve()
        else:
            raise RuntimeError("phase7-nested-scratch-root-missing")
        receipts=[];streams={};report=work/"bounded-child-report.json"
        result=boundary._run_client(Path(command[0]),command,receipts,report=report,
            timeout=min(float(timeout),float(V02_EXECUTION_SCOPE["per_child_limits"]["wall_seconds"])),
            cwd=ROOT,retained_streams=streams,limits=V02_EXECUTION_SCOPE["per_child_limits"],
            scratch_roots=(work,))
        PROCESS_RECEIPTS.extend(receipts);_save_process_receipts()
        stdout=streams.get("stdout",{}).get("text","").encode()
        stderr=streams.get("stderr",{}).get("text","").encode()
        return subprocess.CompletedProcess(command,result.returncode,stdout,stderr)
    process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,start_new_session=not outer_process_group,bufsize=0)
    receipt={"pid":process.pid,"pgid":os.getpgid(process.pid),"driver_pgid":os.getpgrp(),
        "outer_process_group":outer_process_group,"status":"started"}
    PROCESS_RECEIPTS.append(receipt);_save_process_receipts()
    output={'stdout':bytearray(),'stderr':bytearray()};selector=selectors.DefaultSelector()
    for name in output:selector.register(getattr(process,name),selectors.EVENT_READ,name)
    deadline=time.monotonic()+timeout;failure=None
    try:
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:failure='bounded-process-timeout';break
            for key,_ in selector.select(min(remaining,.1)):
                block=os.read(key.fileobj.fileno(),65536)
                if not block:selector.unregister(key.fileobj);continue
                retained=sum(map(len,output.values()))
                if outer_process_group and len(output[key.data])+len(block)>1048576:
                    room=max(0,1048576-len(output[key.data]));output[key.data].extend(block[:room])
                    failure='bounded-process-stream-cap';break
                if retained+len(block)>cap:
                    room=max(0,cap-retained);output[key.data].extend(block[:room]);failure='bounded-process-output-cap';break
                output[key.data].extend(block)
            if failure:break
        if not failure:
            try:process.wait(timeout=max(0,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:failure='bounded-process-timeout'
    finally:
        if outer_process_group:
            if failure:
                process.kill()
        else:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        process.wait();selector.close();process.stdout.close();process.stderr.close()
        receipt["returncode"]=process.returncode;receipt["status"]="finished" if not failure else "interrupted"
        _save_process_receipts()
    out=bytes(output['stdout']);err=bytes(output['stderr'])
    if failure:raise BoundedProcessError(failure,out,err)
    return subprocess.CompletedProcess(command,process.returncode,out,err)


def execute(client: Path, rom: Path, case: dict, temp: Path, desktop: bool = False,
            retain_dir: Path | None = None, outer_process_group: bool = False,
            process_runner=None) -> dict:
    temp.mkdir(parents=True, exist_ok=True)
    log = temp / "input.log"
    log.write_bytes(input_log(case))
    audio = temp / ("desktop.pcm" if desktop else "headless.pcm")
    fields_dir = temp / "fields"
    fields_dir.mkdir(exist_ok=True)
    if desktop:
        args = [str(client), "--fields", str(case["frames"]), "--replay", str(log),
                "--print-field-hashes", "--dump-audio", str(audio), str(rom)]
    else:
        trace = temp / "audio-trace.jsonl"
        args = [str(client), str(rom), "--fields", str(case["frames"]), "--replay", str(log),
                "--port-device", "pad3", "pad3", "--peek", "0xff0000", "4",
                "--dump-fields", str(fields_dir), "--audio-rate", "48000",
                "--dump-audio", str(audio), "--dump-audio-trace", str(trace)]
    started=time.monotonic()
    try:
        result = (process_runner or bounded_run)(args,timeout=240,outer_process_group=outer_process_group)
    except BoundedProcessError as exc:
        _retain_streams({"stdout": exc.stdout, "stderr": exc.stderr}, retain_dir)
        raise ValueError(f"{case['id']}: child watchdog/output cap reached; raw prefix retained") from exc
    retained_streams = _retain_streams({"stdout": result.stdout, "stderr": result.stderr}, retain_dir)
    process_streams = {name: {key: value for key, value in item.items() if key != "preview"}
                       for name, item in retained_streams.items()}
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    normalized_command, exact_command_sha256 = command_identity(args, temporary_root=temp)
    process={"client":client.name,"return_code":result.returncode,
             "wall_seconds":round(time.monotonic()-started,6),
             "stdout_bytes":len(result.stdout),"stderr_bytes":len(result.stderr),
             "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),
             "stderr_sha256":hashlib.sha256(result.stderr).hexdigest(),
             "command":normalized_command,"command_sha256":exact_command_sha256,
             "executable_path":client.relative_to(ROOT).as_posix(),
             "executable_sha256":sha(client),"cwd":"."}
    if result.returncode:
        raise ValueError(f"{case['id']}: {('desktop' if desktop else 'headless')} exit {result.returncode}: {stderr.strip()}")
    rows = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    hashes = [row["fnv1a64"] for row in rows if "fnv1a64" in row and "sequence" in row]
    if desktop:
        if len(hashes) != case["frames"]:
            raise ValueError(f"{case['id']}: desktop rendered {len(hashes)} fields, expected {case['frames']}")
        final = next((dict(row) for row in reversed(rows) if "fields" in row), None)
        if final is None:
            raise ValueError(f"{case['id']}: desktop did not report final field count")
        if final.get("fields") != case["frames"] or not final.get("ram_fnv1a64"):
            raise ValueError(f"{case['id']}: desktop final machine observation is incomplete")
        return {"hashes": hashes, "audio": audio.read_bytes(), "final": final,"process":process,
                "process_streams":process_streams,
                "machine_digest": final["ram_fnv1a64"]}

    final = next((row for row in reversed(rows) if "unsupported" in row), None)
    if final is None or final["fields"] != case["frames"] or final["unsupported"] != 0 or final["stop_reason"] != 0 or final["fault_address"] != 0:
        raise ValueError(f"{case['id']}: incomplete/unsupported headless result {final}")
    if len(hashes) != case["frames"]:
        raise ValueError(f"{case['id']}: headless field denominator {len(hashes)} != {case['frames']}")
    state = bytes.fromhex(final["peek"])
    play_state, position = int.from_bytes(state[:2], "big"), int.from_bytes(state[2:4], "big")
    expected = dict(case["expect"])
    if temp.name == "negative-control":
        expected["play_state"] = 1 - expected["play_state"]
    if play_state != expected["play_state"] or not expected["position_min"] <= position <= expected["position_max"]:
        raise ValueError(f"{case['id']}: source state mismatch play={play_state} position={position}")
    trace_rows = [json.loads(line) for line in trace.read_text().splitlines()]
    dropped = trace_rows.pop()["dropped"]
    psg = [row["value"] for row in trace_rows if row["chip"] == 3]
    if dropped or psg != expected["psg_writes"]:
        raise ValueError(f"{case['id']}: causal PSG writes {psg}, expected {expected['psg_writes']} (dropped={dropped})")
    raw = audio.read_bytes()
    expected_frames = case["frames"] * FIELD_TICKS * 48000 // MASTER_HZ
    if len(raw) != expected_frames * 4:
        raise ValueError(f"{case['id']}: PCM frame denominator {len(raw)//4} != {expected_frames}")
    samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
    ac = max(samples) - min(samples) if samples else 0
    if expected["psg_writes"] and ac == 0:
        raise ValueError(f"{case['id']}: PSG action has no non-DC captured PCM")
    if not expected["psg_writes"] and psg:
        raise ValueError(f"{case['id']}: no-trigger case emitted PSG writes")
    geometry_paths = sorted(fields_dir.glob("field-*.bin"), key=lambda path: int(path.stem.split("-")[1]))
    if len(geometry_paths) != case["frames"]:
        raise ValueError(f"{case['id']}: raw rendered geometry denominator is incomplete")
    geometry = [sha(path) for path in geometry_paths]
    return {"hashes": hashes, "geometry": geometry, "audio": raw, "final": final,"process":process,
            "process_streams":process_streams,
            "input_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "play_state": play_state,
            "position": position, "psg": psg, "ac_range": ac,
            "machine_digest": final["ram_fnv1a64"]}


def main() -> int:
    global V02_EXECUTION_SCOPE
    args = sys.argv[1:]
    outer_process_group = "--outer-process-group" in args
    args = [arg for arg in args if arg != "--outer-process-group"]
    negative = "--negative-control" in args
    report_path = None
    retain_dir = None
    if "--report" in args:
        index = args.index("--report")
        if index + 1 >= len(args):
            print("--report requires a path", file=sys.stderr)
            return 2
        report_path = Path(args[index + 1]).resolve()
        del args[index:index + 2]
    if "--retain-artifacts" in args:
        index=args.index("--retain-artifacts")
        if index+1>=len(args):
            print("--retain-artifacts requires a path",file=sys.stderr);return 2
        retain_dir=Path(args[index+1]).resolve()
        del args[index:index+2]
    if "--process-receipt" in args:
        index=args.index("--process-receipt")
        if index+1>=len(args):
            print("--process-receipt requires a path",file=sys.stderr);return 2
        global PROCESS_RECEIPT_PATH, PROCESS_RECEIPTS
        PROCESS_RECEIPT_PATH=Path(args[index+1]).resolve();PROCESS_RECEIPTS=[]
        del args[index:index+2]
    if "--execution-scope" in args:
        index=args.index("--execution-scope")
        if index+1>=len(args):
            print("--execution-scope requires a path",file=sys.stderr);return 2
        scope_path=Path(args[index+1]).resolve()
        V02_EXECUTION_SCOPE=json.loads(scope_path.read_text())
        if (V02_EXECUTION_SCOPE.get("schema")!="genewhip-v02-execution-v1" or
                V02_EXECUTION_SCOPE.get("scope_id")!="phase7-serial-child-workloads"):
            print("invalid Phase 7 execution scope",file=sys.stderr);return 2
        del args[index:index+2]
    args = [arg for arg in args if arg != "--negative-control"]
    if len(args) not in (1, 2):
        print("usage: phase4_game.py HEADLESS [DESKTOP] [--negative-control] [--outer-process-group] [--report FILE] [--retain-artifacts DIR]", file=sys.stderr)
        return 2
    clients = [Path(arg).resolve() for arg in args]
    try:
        scenario = json.loads(SCENARIO_PATH.read_text())
        oracle = json.loads(ORACLE_PATH.read_text())
        rom = ROOT / scenario["rom"]["relative_path"]
        if sha(SCENARIO_PATH) != SCENARIO_SHA: raise ValueError("roster identity changed")
        if sha(ORACLE_PATH) != ORACLE_SHA: raise ValueError("source oracle identity changed")
        if sha(ROOT / scenario["source"]["relative_path"]) != SOURCE_SHA: raise ValueError("source identity changed")
        if sha(rom) != scenario["rom"]["sha256"]: raise ValueError("ROM identity changed")
        if scenario["cases"][-1]["id"] != oracle["case_ids"][-1]:
            raise ValueError("sustained scenario id changed")
        if scenario["cases"][-1]["frames"] != oracle["sustained_protocol"]["minimum_total_fields"]:
            raise ValueError("sustained workload denominator changed")
        build = clients[0].parents[2]
        cache = build / "CMakeCache.txt"
        if not cache.is_file(): raise ValueError("identified CMake build configuration is missing")
        results = []
        geometry_by_id = {}
        native_children=[]
        if retain_dir:
            try:retain_root=retain_dir.relative_to(ROOT)
            except ValueError as exc:raise ValueError("retained artifacts must stay inside the project") from exc
            retain_dir.mkdir(parents=True,exist_ok=True)
        workspace = RetainedFailureDirectory(retain_dir) if retain_dir else tempfile.TemporaryDirectory(prefix="gw-phase4-game-")
        with workspace as tmp:
            base = Path(tmp)
            for case in scenario["cases"]:
                if negative and len(clients) == 1:
                    try:
                        execute(clients[0], rom, case, base / "negative-control", outer_process_group=outer_process_group)
                    except ValueError as exc:
                        if "source state mismatch" not in str(exc):
                            raise ValueError("negative control missed intended source-play-state assertion") from exc
                        print("REJECT: source-play-state (negative control reached production semantic validator)")
                        return 0
                    raise ValueError("negative control mutant unexpectedly passed")
                case_retained = retain_dir / case["id"] if retain_dir else None
                headless = execute(clients[0], rom, case, base / case["id"],
                                   retain_dir=case_retained / "headless" if case_retained else None,
                                   outer_process_group=outer_process_group)
                native_children.append(dict(case=case["id"], **headless["process"],
                                            streams=headless["process_streams"]))
                retained_pcm=None
                if retain_dir:
                    pcm_path=retain_dir/f"{case['id']}.pcm"
                    pcm_path.write_bytes(headless["audio"])
                    retained_pcm={"path":pcm_path.relative_to(ROOT).as_posix(),
                                  "bytes":len(headless["audio"]),
                                  "sha256":hashlib.sha256(headless["audio"]).hexdigest()}
                geometry_by_id[case["id"]] = headless["geometry"]
                # comparison runs intentionally use the existing public runner field hashes and PCM capture
                desktop = None
                if len(clients) > 1:
                    desktop = execute(clients[1], rom, case, base / (case["id"] + "-desktop"), True,
                                      retain_dir=case_retained / "desktop" if case_retained else None,
                                      outer_process_group=outer_process_group)
                    if desktop["hashes"] != headless["hashes"]:
                        if negative:
                            print("REJECT: desktop-headless-rendered-fields (negative control)")
                            return 0
                        raise ValueError(f"{case['id']}: ordered desktop/headless rendered field hashes differ")
                    if negative and desktop["audio"]:
                        desktop["audio"] = bytes([desktop["audio"][0] ^ 1]) + desktop["audio"][1:]
                    if desktop["audio"] != headless["audio"]:
                        if negative:
                            print("REJECT: desktop-headless-raw-pcm (negative control reached production comparator)")
                            return 0
                        raise ValueError(f"{case['id']}: complete raw PCM differs between clients")
                    if desktop["machine_digest"] != headless["machine_digest"]:
                        if negative:
                            print("REJECT: desktop-headless-machine-state (negative control)")
                            return 0
                        raise ValueError(f"{case['id']}: complete final RAM observation differs between clients")
                result = {key: value for key, value in headless.items() if key not in ("audio", "hashes", "geometry", "final")}
                if retained_pcm:result["retained_pcm"]=retained_pcm
                result.update(id=case["id"], fields=case["frames"], pcm_frames=len(headless["audio"]) // 4,
                              outcome="pass", unsupported=0,
                              field_hashes_sha256=hashlib.sha256("\n".join(headless["hashes"]).encode()).hexdigest(),
                              raw_geometry_sha256=hashlib.sha256("\n".join(headless["geometry"]).encode()).hexdigest())
                if desktop:
                    result["desktop_equal"] = True
                results.append(result)
        if len(results) != len(oracle["case_ids"]) or [r["id"] for r in results] != oracle["case_ids"]:
            raise ValueError("required roster denominator/order mismatch")
        by_id = {row["id"]: row for row in results}
        title_to_play = geometry_by_id["title-no-start"][10] != geometry_by_id["start-idle"][10]
        moved_marker = geometry_by_id["start-idle"][19] != geometry_by_id["start-move"][19]
        if not title_to_play:
            raise ValueError("source title-to-play geometry did not transition")
        if not moved_marker:
            raise ValueError("source movement did not change rendered marker geometry")
        if by_id["action-sound"]["ac_range"] <= 0 or by_id["action-no-trigger"]["ac_range"] != 0:
            raise ValueError("action-sound/no-trigger matched waveform control failed")
        evidence = {"schema": "genewhip-phase4-gameplay-v1", "version": 1, "outcome": "pass",
                          "fixture_id": scenario["fixture_id"], "source_sha256": SOURCE_SHA,
                          "rom_sha256": scenario["rom"]["sha256"], "scenario_sha256": SCENARIO_SHA,
                          "oracle_sha256": ORACLE_SHA, "denominator": len(results), "fields": sum(r["fields"] for r in results),
                          "profile": scenario["profile"], "build_configuration_sha256": sha(cache),
                          "client_sha256": [sha(client) for client in clients],
                          "clients": ["headless", "desktop"] if len(clients) > 1 else ["headless"],
                          "native_child_processes":native_children,
                          "visual_observations": {"title_to_play_field_10_changed": title_to_play,
                                                   "start_idle_to_moved_marker_field_19_changed": moved_marker},
                          "results": results}
        rendered = json.dumps(evidence, sort_keys=True)
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(rendered + "\n")
        print(rendered)
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
