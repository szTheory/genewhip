#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare and verify an isolated MAME 0.289 successor reference capability."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import queue
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game"
SUCCESSOR = ROOT / "fixtures/independent-game-v2"
LOCK = SUCCESSOR / "toolchain.lock"
WORK = ROOT / "build/tool-cache/mame0289"
SOURCE = WORK / "source"
ROUTE = WORK / "route-audit.json"
RESULT = WORK / "reference-verification.json"
MAX_TRACE_BYTES = 134_217_728
MAX_TRACE_ROWS = 3_000_000
TIMEOUT = 4 * 60 * 60
MAX_BUILD_LOG_BYTES = 64 * 1024 * 1024
MIN_BUILD_FREE_BYTES = 8 * 1024 * 1024 * 1024
MAME_TIMEOUT = 90

spec = importlib.util.spec_from_file_location("gw_mame_trace", FIXTURE / "trace.py")
trace = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(trace)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha(path.read_bytes())


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def validate_lock(doc: dict) -> None:
    """Structural trust checks; real signature, source and binary are checked separately."""
    assembler = doc.get("assembler", {})
    if assembler.get("version") != "2.47":
        raise ValueError("assembler must retain verified Binutils 2.47")
    signature = assembler.get("signature", {})
    if signature.get("status") != "pass" and "GOODSIG and VALIDSIG" not in signature.get("outcome", ""):
        raise ValueError("Binutils 2.47 signature evidence is missing")
    if doc.get("mame", {}).get("status") != "pass":
        raise ValueError("MAME build status is not pass")
    mame = doc["mame"]
    if mame.get("version") != "0.289" or mame.get("source_signature", {}).get("status") != "pass":
        raise ValueError("MAME version/source signature is not verified")
    for key in ("patch_sha256", "build_script_sha256", "executable_build_sha256", "source_configuration_identity"):
        if not re.fullmatch(r"[0-9a-f]{64}", mame.get(key, "")):
            raise ValueError("MAME identity missing or malformed: " + key)
    capability = doc.get("reference_capability", {})
    if capability.get("status") != "pass" or capability.get("route_status") != "pass":
        raise ValueError("reference route capability is not pass")
    sentinels = capability.get("sentinels", {})
    required = {"sram_storage_read", "sram_storage_write", "sram_enable_read", "sram_enable_write",
                "cpu_space_ack", "program_fetch", "controller_read", "vdp_write"}
    if set(sentinels) != required or any(item.get("status") != "pass" for item in sentinels.values()):
        raise ValueError("required route sentinel roster is incomplete or non-pass")
    build = capability.get("build_process", {})
    if build.get("status") != "pass" or build.get("log_relative_path") != "build/tool-cache/mame0289/mame-build.log":
        raise ValueError("bounded MAME build-process record is missing")
    if not re.fullmatch(r"[0-9a-f]{64}", build.get("log_sha256", "")) or build.get("log_bytes", 0) > MAX_BUILD_LOG_BYTES:
        raise ValueError("MAME build log digest or size is invalid")
    if capability.get("preparer_sha256") != sha_file(Path(__file__)):
        raise ValueError("reference preparer source identity changed")


def validate_static_identity(doc: dict) -> None:
    mame = doc.get("mame", {})
    if mame.get("patch_sha256") != sha_file(FIXTURE / "mame.patch"):
        raise ValueError("MAME instrumentation patch digest mismatch")
    if mame.get("build_script_sha256") != sha_file(FIXTURE / "mame_build.sh"):
        raise ValueError("MAME build script digest mismatch")
    if mame.get("source_archive_sha256") != "0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84":
        raise ValueError("MAME source archive identity mismatch")


def environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update({"GENEWHIP_MAME_WORK_ROOT": str(WORK), "GENEWHIP_MAME_SOURCE_DIR": str(SOURCE),
                "GENEWHIP_SDL3_PREFIX": str(WORK / "sdl3prefix"),
                "GENEWHIP_TOOLCHAIN_LOCK": str(LOCK)})
    return env


def run(command: list[str], *, timeout: int, env: dict[str, str] | None = None,
        cwd: Path = ROOT) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)


def run_build() -> dict:
    """Run the reviewed builder with bounded disk log, output cap and deadline."""
    WORK.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(WORK).free < MIN_BUILD_FREE_BYTES:
        raise ValueError("MAME build requires at least 8 GiB free in its bounded work cache")
    log_path = WORK / "mame-build.log"
    command = ["bash", str(FIXTURE / "mame_build.sh"), "--build"]
    process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=32)

    def reader() -> None:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            messages.put(chunk)
        messages.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.monotonic()
    total = 0
    ended = False
    with log_path.open("wb") as log:
        while not ended or process.poll() is None:
            if time.monotonic() - started > TIMEOUT:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise ValueError(f"reviewed MAME build exceeded {TIMEOUT}s bounded runtime")
            try:
                chunk = messages.get(timeout=1)
            except queue.Empty:
                continue
            if chunk is None:
                ended = True
                continue
            total += len(chunk)
            if total > MAX_BUILD_LOG_BYTES:
                process.terminate()
                process.wait(timeout=10)
                raise ValueError(f"MAME build log exceeded {MAX_BUILD_LOG_BYTES} byte cap")
            log.write(chunk)
            if time.monotonic() - started > 30 and not (total % (4 * 1024 * 1024)):
                print(f"MAME build active: {int(time.monotonic() - started)}s, {total} log bytes", flush=True)
    returncode = process.wait()
    if returncode:
        raise ValueError(f"reviewed signed-source build script failed with exit {returncode}; bounded log retained")
    return {"status": "pass", "command": "fixtures/independent-game/mame_build.sh --build",
            "log_relative_path": "build/tool-cache/mame0289/mame-build.log",
            "log_bytes": total, "log_sha256": sha_file(log_path), "exit_code": 0,
            "timeout_seconds": TIMEOUT, "max_log_bytes": MAX_BUILD_LOG_BYTES,
            "parallel_jobs": 8, "cache_relative_path": "build/tool-cache/mame0289"}


def prepare() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    if not LOCK.exists():
        SUCCESSOR.mkdir(parents=True, exist_ok=True)
        LOCK.write_text(json.dumps(load_json(FIXTURE / "toolchain.lock"), indent=2) + "\n")
    build_process = run_build()
    verify(allow_write_lock=True, build_process=build_process)


def route_audit(lock_path: Path = LOCK) -> dict:
    command = [sys.executable, "-I", str(FIXTURE / "route_audit.py"),
               "--verify-toolchain-lock", str(lock_path), "--source", str(SOURCE),
               "--output", str(ROUTE)]
    result = run(command, timeout=1800, env=environment())
    if result.returncode:
        raise ValueError("MAME route source audit failed: " + result.stdout.decode(errors="replace")[-3000:])
    audit = load_json(ROUTE)
    if audit.get("status") != "pass":
        raise ValueError("MAME route audit did not pass")
    return audit


def mame_run(rom: Path, script: Path, name: str) -> tuple[bytes, list[dict], int]:
    with tempfile.TemporaryDirectory(prefix="gw-mame-reference-") as td:
        temp = Path(td)
        command = [str(SOURCE / "genewhip"), "genesis", "-cart", str(rom), "-noreadconfig",
                   "-video", "none", "-sound", "none", "-skip_gameinfo", "-seconds_to_run", "5",
                   "-log", "-autoboot_script", str(script), "-autoboot_delay", "0"]
        env = {**os.environ, "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"}
        try:
            result = subprocess.run(command, cwd=temp, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=MAME_TIMEOUT, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"MAME {name} sentinel timed out after {MAME_TIMEOUT}s") from exc
        error_log = temp / "error.log"
        log = error_log.read_bytes() if error_log.exists() else b""
        if len(result.stdout) + len(log) > MAX_TRACE_BYTES:
            raise ValueError(f"MAME {name} output exceeded {MAX_TRACE_BYTES} bytes")
        candidates = [blob for blob in (result.stdout, log) if b"GWTRACE," in blob]
        if not candidates:
            raise ValueError(f"MAME {name} emitted no route trace")
        raw = max(candidates, key=lambda blob: blob.count(b"GWTRACE,"))
        rows = trace.parse(raw, MAX_TRACE_BYTES, MAX_TRACE_ROWS)
        if result.returncode:
            raise ValueError(f"MAME {name} exited {result.returncode}")
        return result.stdout + b"\n" + log, rows, result.returncode


def sentinel_results() -> dict:
    with tempfile.TemporaryDirectory(prefix="gw-reference-roms-") as td:
        temp = Path(td)
        sram_rom = temp / "sram-sentinel.bin"
        built = run(["bash", str(FIXTURE / "build-sram-sentinel.sh"), "--output", str(sram_rom)],
                    timeout=1800, env=environment())
        if built.returncode:
            raise ValueError("SRAM route sentinel ROM build failed: " + built.stdout.decode(errors="replace")[-2000:])
        sram_text, sram_rows, _ = mame_run(sram_rom, FIXTURE / "sram-sentinel.lua", "SRAM/control")
        if b"GWSENTINEL,guest-68000-accesses-complete" not in sram_text:
            raise ValueError("SRAM/control sentinel guest did not finish")
        sram_specs = {
            "sram_storage_read": lambda r: r["address"] == 0x200000 and r["operation"] == "R",
            "sram_storage_write": lambda r: r["address"] == 0x200000 and r["operation"] == "W",
            "sram_enable_read": lambda r: 0xa130f0 <= r["address"] <= 0xa130f1 and r["operation"] == "R",
            "sram_enable_write": lambda r: 0xa130f0 <= r["address"] <= 0xa130f1 and r["operation"] == "W",
        }
        output = {}
        for name, predicate in sram_specs.items():
            matches = [row for row in sram_rows if row["space"] == "AS_PROGRAM" and predicate(row)]
            if not matches:
                raise ValueError("actual MAME route sentinel missed " + name)
            output[name] = {"status": "pass", "count": len(matches)}

        gameplay_text, gameplay_rows, _ = mame_run(FIXTURE / "game.bin", FIXTURE / "mame.lua", "program/controller/CPU-space")
        required = {
            "cpu_space_ack": lambda r: r["space"] == "AS_CPU_SPACE" and r["operation"] == "R",
            "program_fetch": lambda r: r["space"] == "AS_PROGRAM" and r["operation"] == "R" and r["pc"] >= 0x200,
            "controller_read": lambda r: r["space"] == "AS_PROGRAM" and r["operation"] == "R" and
                r["address"] == 0xa10002 and (r["mem_mask"] & 0x00ff) != 0,
            "vdp_write": lambda r: r["space"] == "AS_PROGRAM" and r["operation"] == "W" and r["address"] == 0xc00004,
        }
        if b"GWINPUT,frame=1" not in gameplay_text or b"GWOBS,scenario=genewhip-independent-game-start-right-ntscu-v1,frame=60," not in gameplay_text:
            raise ValueError("actual MAME gameplay route/input sentinels did not finish")
        for name, predicate in required.items():
            matches = [row for row in gameplay_rows if predicate(row)]
            if not matches:
                raise ValueError("actual MAME route sentinel missed " + name)
            output[name] = {"status": "pass", "count": len(matches)}
        return {"status": "pass", "route_status": "pass", "sentinels": output,
                "sram_trace_sha256": sha(trace_bytes(sram_rows)),
                "gameplay_trace_sha256": sha(trace_bytes(gameplay_rows)),
                "sram_rom_sha256": sha_file(sram_rom),
                "game_rom_sha256": sha_file(FIXTURE / "game.bin"),
                "scenario_sha256": sha_file(FIXTURE / "scenario.json"),
                "route_audit_sha256": sha_file(ROUTE)}


def trace_bytes(rows: list[dict]) -> bytes:
    return json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()


def verify(*, allow_write_lock: bool = False, build_process: dict | None = None) -> None:
    if not LOCK.is_file():
        raise ValueError("successor toolchain lock is missing; --verify never builds or creates it")
    original_lock_hash = sha_file(FIXTURE / "toolchain.lock")
    doc = load_json(LOCK)
    validate_static_identity(doc)
    if doc.get("mame", {}).get("status") != "pass":
        raise ValueError("successor MAME lock is not prepared")
    env = environment()
    result = run(["bash", str(FIXTURE / "mame_build.sh"), "--verify-toolchain-lock"], timeout=1800, env=env)
    if result.returncode:
        raise ValueError("actual MAME source/build lock verification failed: " + result.stdout.decode(errors="replace")[-3000:])
    audit = route_audit()
    if audit.get("build", {}).get("executable_build_sha256") != doc["mame"].get("executable_build_sha256"):
        raise ValueError("route audit executable identity differs from successor lock")
    actual_capability = sentinel_results()
    if allow_write_lock:
        doc["successor_schema"] = "genewhip-independent-game-v2-toolchain-v1"
        doc["reference_capability"] = actual_capability
        doc["reference_capability"]["build_process"] = build_process
        doc["reference_capability"]["preparer_sha256"] = sha_file(Path(__file__))
        LOCK.write_text(json.dumps(doc, indent=2) + "\n")
        doc = load_json(LOCK)
    else:
        expected = doc.get("reference_capability", {})
        if any(expected.get(key) != actual_capability.get(key)
               for key in actual_capability):
            raise ValueError("actual route/sentinel evidence differs from measured successor lock")
        build_record = expected.get("build_process", {})
        build_log = ROOT / build_record.get("log_relative_path", "")
        if not build_log.is_file() or sha_file(build_log) != build_record.get("log_sha256"):
            raise ValueError("bounded MAME build log is missing or changed")
    validate_lock(doc)
    if sha_file(FIXTURE / "toolchain.lock") != original_lock_hash:
        raise ValueError("historical v1 toolchain lock changed")
    sanitized = {"schema": "genewhip-mame-reference-verification-v1", "status": "pass",
                 "mame_executable_sha256": doc["mame"]["executable_build_sha256"],
                 "source_configuration_identity": doc["mame"]["source_configuration_identity"],
                 "route_audit_sha256": actual_capability["route_audit_sha256"],
                 "sentinels": actual_capability["sentinels"],
                 "historical_v1_lock_sha256": original_lock_hash}
    WORK.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(sanitized, indent=2, sort_keys=True) + "\n")
    print("PASS: actual signed MAME 0.289 executable, post-overlay route hooks and eight runtime sentinels verified")


def self_test() -> None:
    historical_lock_digest = sha_file(FIXTURE / "toolchain.lock")
    base = load_json(FIXTURE / "toolchain.lock")
    # Build a complete structural sample from reviewed, already measured v1 evidence. The v2
    # mode checks that these fields remain mandatory and that expired Binutils 2.46.1 is refused.
    sample = copy.deepcopy(base)
    sample["reference_capability"] = {"status": "pass", "route_status": "pass", "sentinels": {
        name: {"status": "pass", "count": 1} for name in
        ("sram_storage_read", "sram_storage_write", "sram_enable_read", "sram_enable_write",
         "cpu_space_ack", "program_fetch", "controller_read", "vdp_write")},
        "build_process": {"status": "pass", "log_relative_path": "build/tool-cache/mame0289/mame-build.log",
            "log_sha256": "a" * 64, "log_bytes": 1}, "preparer_sha256": sha_file(Path(__file__))}
    sample["mame"]["status"] = "pass"
    validate_static_identity(sample)
    validate_lock(sample)
    mutations = [
        ("MAME executable identity", lambda d: d["mame"].__setitem__("executable_build_sha256", "bad")),
        ("MAME patch identity", lambda d: d["mame"].__setitem__("patch_sha256", "0" * 64)),
        ("route hook status", lambda d: d["reference_capability"].__setitem__("route_status", "unknown")),
        ("missing controller sentinel", lambda d: d["reference_capability"]["sentinels"].pop("controller_read")),
        ("sentinel non-pass", lambda d: d["reference_capability"]["sentinels"]["vdp_write"].__setitem__("status", "skipped")),
        ("build log identity", lambda d: d["reference_capability"]["build_process"].__setitem__("log_sha256", "bad")),
        ("expired Binutils 2.46.1", lambda d: d["assembler"].__setitem__("version", "2.46.1")),
    ]
    for label, mutate in mutations:
        candidate = copy.deepcopy(sample)
        mutate(candidate)
        try:
            validate_lock(candidate)
            validate_static_identity(candidate)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("named trust mutation was accepted: " + label)
    if sha_file(FIXTURE / "toolchain.lock") != historical_lock_digest:
        raise ValueError("self-test mutated historical v1 lock")
    print("game_reference_contract: PASS (7 named trust/route/build mutations rejected; historical v1 lock unchanged)")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.prepare:
            prepare()
        elif args.verify:
            verify()
        else:
            self_test()
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
