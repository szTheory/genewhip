#!/usr/bin/env python3
"""Plan47's finite current Tank checkpoint; it never touches the legacy ledger."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import shutil
import selectors
import platform

ROOT = pathlib.Path(__file__).resolve().parents[2]
PLAN = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-47-PLAN.md"
SELECTION = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/selection.json"
EVIDENCE = SELECTION.parent
LEDGER = ROOT / "evidence/phase6-repairs.json"
PLAN_SHA = "bc83fe2b64b98b39b22389ad8a2291db20ec94700db4466cc1d0651fbdfad2cb"
LEDGER_SHA = "18fd6dbc2f892e4aa5c4c1847adf3b272e6cc71e31f91093d8a6fe1dd6281e5a"
DEADLINE = 583628.382862666  # Exact separately authorized two-hour continuation.
CONTINUATION = EVIDENCE / "continuation.json"
TERMINAL = 600.0
WORKLOAD_LIMITS = {"seconds": 600, "stdout_bytes": 1048576, "stderr_bytes": 1048576,
                   "trace_bytes": 16777216, "trace_rows": 100000, "report_bytes": 8388608,
                   "disk_bytes": 6442450944, "fields": 4500, "active_ticks": 3600,
                   "events": 64, "boundary_calls": 128}
CONTROL_IDS = ["title-no-start", "start-idle", "start-move", "action-sound", "action-no-trigger", "sustained-play"]
FIELD_TICKS = 896040
MASTER_HZ = 53693175
ATTEMPT_HOOK = None
OBSERVED_CREATIONS = 0


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: pathlib.Path) -> str:
    return digest_bytes(path.read_bytes())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def normalize_argv(argv: list[str]) -> list[str]:
    normalized = []
    root = ROOT.resolve(strict=True)
    for item in argv:
        path = pathlib.Path(item)
        if path.is_absolute():
            try:
                item = path.resolve(strict=False).relative_to(root).as_posix()
            except ValueError:
                item = "<local-tool>/" + path.name
        normalized.append(item)
    return normalized


def redact_stream(data: bytes) -> bytes:
    result = data.replace(str(ROOT).encode(), b"[workspace]")
    home = pathlib.Path.home().as_posix().encode()
    if home and home != b"/":
        result = result.replace(home, b"[local-home]")
    return result


def load(path: pathlib.Path):
    return json.loads(path.read_bytes())


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key:" + key)
        result[key] = value
    return result


def _load_review_record(path: pathlib.Path, label: str) -> dict:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(label + "-record-not-strict-json") from exc
    if not isinstance(value, dict):
        raise ValueError(label + "-record-not-object")
    return value


def check_identity(selection_path: pathlib.Path) -> dict:
    if digest(PLAN) != PLAN_SHA:
        raise ValueError("selected-plan-bytes-changed")
    selected = load(selection_path)
    if (selected.get("schema") != "genewhip-phase6-plan47-dispatch-v1" or
            selected.get("status") != "selected-and-dispatched" or
            selected.get("selection", {}).get("plan_sha256") != PLAN_SHA or
            selected.get("selection", {}).get("dispatch_commit") != "cfbde261a23ec1273cb141688b34de26eb2fbb6b"):
        raise ValueError("plan47-selection-mismatch")
    if digest(LEDGER) != LEDGER_SHA:
        raise ValueError("historical-ledger-changed")
    continuation = load(CONTINUATION)
    if (continuation.get("schema") != "genewhip-plan47-continuation-v1" or
            continuation.get("authorization", {}).get("user_response") != "Authorize two-hour continuation" or
            continuation.get("deadline_monotonic") != DEADLINE or continuation.get("seconds") != 7200 or
            continuation.get("protected_terminal_seconds") != TERMINAL or
            continuation.get("workload_slots") != ["47-tank", "47-control-1", "47-control-2"] or
            continuation.get("workload_retries") != 0 or continuation.get("selection_sha256") != digest(selection_path)):
        raise ValueError("plan47-continuation-mismatch")
    return selected


def safe_file(relative: str) -> pathlib.Path:
    p = pathlib.Path(relative)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("unsafe-relative-path")
    result = ROOT / p
    if result.is_symlink():
        raise ValueError("symlink-input-denied:" + relative)
    resolved = result.resolve(strict=True)
    resolved.relative_to(ROOT.resolve(strict=True))
    if not resolved.is_file():
        raise ValueError("non-file-input:" + relative)
    return resolved


def source_identity() -> dict:
    files = set()
    for folder in ("src", "include", "tools"):
        base = ROOT / folder
        if base.exists():
            files.update(p.relative_to(ROOT).as_posix() for p in base.rglob("*") if p.is_file())
    cmake_dir = ROOT / "cmake"
    if cmake_dir.exists():
        files.update(p.relative_to(ROOT).as_posix() for p in cmake_dir.rglob("*") if p.is_file())
    files.update(("CMakeLists.txt", "tests/fixtures/phase6_repairs.py", "tests/fixtures/phase4_game.py",
                  "scripts/evidence/phase6_routes.py", "scripts/evidence/phase6_tank_checkpoint.py",
                  "tests/evidence/phase6_tank_checkpoint_contract.py",
                  CONTINUATION.relative_to(ROOT).as_posix(), "fixtures/phase5-a/scenario.json",
                  "fixtures/phase5-a/oracle.json", "fixtures/phase5-a/input-program.json",
                  "fixtures/phase5-a/game.bin", "fixtures/phase5-a/reference-build-record.json",
                  "evidence/phase5-baseline.json", "evidence/phase5-baseline-roster.json",
                  "evidence/phase5-failure-inventory.json", "evidence/phase5-current-reference.json",
                  "evidence/phase5-reference-d118.json",
                  "tests/session/phase6_route_contract.py", "fixtures/independent-game-v2/scenario.json",
                  "fixtures/independent-game-v2/oracle.json", "fixtures/independent-game-v2/src/game.s",
                  "fixtures/independent-game-v2/game.bin"))
    files.update(("fixtures/phase5-b/scenario.json", "fixtures/phase5-b/oracle.json",
                  "fixtures/phase5-b/input-program.json", "fixtures/phase5-b/game.bin",
                  "fixtures/independent-game-v2/host-controls.json"))
    files.update("tests/api/" + name + ".c" for name in (
        "load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
        "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract"))
    out = {}
    for name in sorted(files):
        path = safe_file(name)
        out[name] = digest(path)
    return out


def check_guard_review() -> dict:
    path = EVIDENCE / "guard-review.md"
    if not path.is_file():
        raise ValueError("distinct-source-review-missing")
    record = _load_review_record(path, "source-review")
    findings = record.get("findings") if isinstance(record, dict) else None
    source_keys = {"schema", "reviewer_identity", "reviewer_role", "source_hashes", "findings",
                   "high_count", "critical_count", "verdict"}
    if (set(record) != source_keys or not isinstance(findings, list) or
            any(not isinstance(item, dict) or set(item) != {"finding", "severity", "blocking"} or
                not isinstance(item.get("finding"), str) or
                item.get("severity") not in ("critical", "high", "warning") or
                type(item.get("blocking")) is not bool for item in findings)):
        raise ValueError("source-review-not-approved")
    reviewed = ("tests/fixtures/phase6_repairs.py", "tests/fixtures/phase4_game.py",
                "scripts/evidence/phase6_tank_checkpoint.py", "tests/evidence/phase6_tank_checkpoint_contract.py")
    actual_hashes = {name: digest(ROOT / name) for name in reviewed}
    high = sum(item.get("severity") in ("high", "critical") for item in findings)
    critical = sum(item.get("blocking") is True for item in findings)
    if (high != 0 or critical != 0 or record.get("schema") != "genewhip-plan47-source-review-v1" or
            record.get("reviewer_identity") != "/root/continuation47_review" or
            record.get("reviewer_role") != "independent source guard and expectation reviewer" or
            record.get("source_hashes") != actual_hashes or record.get("high_count") != high or
            record.get("critical_count") != critical or
            record.get("verdict") != ("APPROVE" if high == 0 and critical == 0 else "REJECT")):
        raise ValueError("source-review-record-invalid-or-not-approved")
    for name in reviewed:
        if name not in record["source_hashes"]:
            raise ValueError("source-review-hash-mismatch:" + name)
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)}


def _tree_bytes(path: pathlib.Path) -> int:
    total = 0
    if not path.exists():
        return total
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except FileNotFoundError:
            pass
    return total


def _workspace_size(build: pathlib.Path) -> int:
    sanitize = build.parent / (build.name + "-sanitize")
    if sanitize.resolve() == build.resolve() or build.resolve() not in sanitize.resolve().parents:
        # Sibling build roots are expected; reject aliases or an escaped tree.
        if sanitize.resolve().parent != build.resolve().parent:
            raise ValueError("sanitize-build-outside-workspace")
    return _tree_bytes(build) + _tree_bytes(sanitize) + _tree_bytes(EVIDENCE)


def _remaining() -> float:
    value = DEADLINE - time.monotonic() - TERMINAL
    if value <= 0:
        raise TimeoutError("engineering-terminal-reserve-reached")
    return value


def _run_bounded(command: list[str], *, timeout: float, cwd: pathlib.Path, cap: int,
                 process_group: bool = True, build: pathlib.Path | None = None,
                 env: dict | None = None,
                 bounded_file: pathlib.Path | None = None, file_cap: int = 8388608,
                 receipt_path: pathlib.Path | None = None) -> dict:
    if ATTEMPT_HOOK:
        ATTEMPT_HOOK("process", command)
    started = time.monotonic()
    global OBSERVED_CREATIONS
    if timeout <= 0:
        raise TimeoutError("bounded-process-deadline-before-launch")
    if receipt_path is not None:
        _save_json(receipt_path, {**load(receipt_path), "launch_attempt": {
            "monotonic": started, "status": "attempted", "command": normalize_argv(command)}})
    try:
        proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=process_group, bufsize=0, env=env)
    except BaseException as exc:
        if receipt_path is not None:
            record = load(receipt_path)
            record["launch_attempt"].update(status="not-created", failure=type(exc).__name__)
            _save_json(receipt_path, record)
        raise
    OBSERVED_CREATIONS += 1
    out, err = bytearray(), bytearray()
    observed_pgid = None
    try:
        observed_pgid = os.getpgid(proc.pid)
        if receipt_path is not None:
            _save_json(receipt_path, {**load(receipt_path), "observed_start": {
                "pid": proc.pid, "pgid": observed_pgid, "monotonic": time.monotonic(), "process_creations": 1}})
        if process_group and observed_pgid != proc.pid:
            raise RuntimeError("new-process-group-not-observed")
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, ("stdout", out))
        selector.register(proc.stderr, selectors.EVENT_READ, ("stderr", err))
        while selector.get_map():
            if time.monotonic() - started > timeout:
                raise TimeoutError("bounded-process-timeout")
            if build is not None and _workspace_size(build) > WORKLOAD_LIMITS["disk_bytes"]:
                raise RuntimeError("workspace-disk-bound")
            if bounded_file is not None and bounded_file.exists() and bounded_file.stat().st_size > file_cap:
                raise RuntimeError("bounded-report-file-cap")
            for key, _ in selector.select(0.05):
                dest = key.data[1]
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                dest.extend(chunk)
                if len(dest) > cap:
                    raise RuntimeError("bounded-stream-cap")
        proc.wait(timeout=max(0.01, timeout-(time.monotonic()-started)))
        if process_group:
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                pass
            else:
                os.killpg(proc.pid, signal.SIGKILL)
                raise RuntimeError("process-group-descendants-remained-after-parent-exit")
    except BaseException as exc:
        if process_group and observed_pgid == proc.pid:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        proc.wait()
        if receipt_path is not None:
            _save_json(receipt_path, {**load(receipt_path), "observed_failure": {
                "pid": proc.pid, "pgid": observed_pgid, "returncode": proc.returncode,
                "wall_seconds": round(time.monotonic()-started, 6),
                "stdout_bytes": len(out), "stderr_bytes": len(err),
                "process_creations": 1, "reason": type(exc).__name__}})
        failure_dir = EVIDENCE / "raw" / "failures"
        failure_dir.mkdir(parents=True, exist_ok=True)
        key = digest_bytes(canonical(command))[:16]
        for suffix, content in (("stdout", bytes(out)), ("stderr", bytes(err))):
            path = failure_dir / f"{key}.{suffix}.prefix.raw"
            if not path.exists():
                path.write_bytes(redact_stream(content[:1048576]))
        raise
    finally:
        if 'selector' in locals():
            selector.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
    return {"argv": command, "pid": proc.pid, "pgid": observed_pgid,
            "returncode": proc.returncode, "wall_seconds": round(time.monotonic()-started, 6),
            "stdout": bytes(out), "stderr": bytes(err), "stdout_sha256": digest_bytes(bytes(out)),
            "stderr_sha256": digest_bytes(bytes(err)), "process_creations": 1}


def _save_json(path: pathlib.Path, value, *, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    if exclusive:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def validate_ctest_seven(stdout: bytes, stderr: bytes) -> None:
    """Require every named contract row; accept the two observed CTest summaries."""
    import re
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    rows = re.findall(r"(?m)^\s*([1-7])/7 Test\s+#\d+:\s+(\w+)\s+\.+\s+Passed\s", text)
    expected = ["load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
                "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract"]
    if (rows != [(str(index),name) for index,name in enumerate(expected,1)] or
            re.search(r"(?m)^100% tests passed(?:, 0 tests failed)? out of 7\s*$", text) is None):
        raise ValueError("ctest-seven-contract-denominator-invalid")


def check_contract_tests() -> dict:
    path = EVIDENCE / "tests.json"
    report = load(path)
    reviewed = ("tests/fixtures/phase6_repairs.py", "tests/fixtures/phase4_game.py",
                "scripts/evidence/phase6_tank_checkpoint.py", "tests/evidence/phase6_tank_checkpoint_contract.py")
    checks = report.get("checks", [])
    names = [item.get("name") for item in checks if isinstance(item, dict)]
    required = {"positive-pea-split-instruction", "bad-a7", "bad-opcode", "spent-slot",
                "helper-process-group-timeout-cleanup", "phase4-outer-group-child-cleanup",
                "positive-synthetic-control-bundle-six-complete-pcm", "stale-control-source",
                "stale-control-build", "stale-control-rom", "stale-control-contract", "stale-control-case",
                "skipped-control-case", "wrong-control-case", "duplicate-control-case", "extra-control-case",
                "missing-control-pcm", "changed-control-terminal", "malformed-child-json", "truncated-child-stream",
                "historical-ledger-write-detected", "stale-selection", "stale-plan-source", "source-review-reject-record",
                "actual-coordinator-early-dispatch", "preimport-denial-self-test", "wrong-mock-still-denies-popen",
                "positive-source-review-and-prelaunch-identity", "stale-source-identity", "stale-rom-identity",
                "stale-contract-identity", "stale-case-identity", "stale-build-identity", "terminal-deadline-bound",
                "workspace-disk-bound", "bounded-stream-output-limit", "double-writer", "failure-before-report",
                "duplicate-json-key", "mixed-legacy-flags-rejected", "ctest-old-summary-form-accepted",
                "ctest-new-summary-form-accepted", "ctest-missing-row", "ctest-duplicate-row",
                "ctest-wrong-test", "ctest-six-denominator"}
    boundary = report.get("boundary", {})
    if (report.get("schema") != "genewhip-phase6-tank-checkpoint47-tests-v1" or report.get("status") != "passed" or
            report.get("tested_sources") != {name:digest(ROOT / name) for name in reviewed} or
            not checks or report.get("tests_executed") != len(checks) or len(names) != len(checks) or
            any(item.get("status") != "passed" for item in checks) or not required <= set(names) or
            report.get("os_process_creations") != 0 or not report.get("observed_attempts") or
            boundary.get("installed_before_changed_import") is not True or
            boundary.get("self_tested_before_import") is not True or
            boundary.get("denied_sticky_even_if_caught") is not True or
            boundary.get("usable_client_or_rom_present") is not False):
        raise ValueError("current-no-process-contract-incomplete-or-stale")
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path), "tests_executed": len(checks)}


def _prepare(build: pathlib.Path, selection_path: pathlib.Path) -> int:
    selected = check_identity(selection_path)
    if build.resolve(strict=False) != (ROOT / "build/phase6-checkpoint47").resolve(strict=False):
        raise ValueError("build-path-outside-selected-checkpoint")
    review = check_guard_review()
    tests = check_contract_tests()
    if (EVIDENCE/"writer.lock").exists() or (EVIDENCE/"slots").exists() or (EVIDENCE/"manifest.json").exists():
        raise ValueError("plan47-preparation-already-exists")
    inputs = source_identity()
    cmake = shutil.which("cmake")
    ninja = shutil.which("ninja")
    ctest = shutil.which("ctest")
    if not cmake or not ninja or not ctest:
        raise ValueError("required-cmake-or-ninja-missing")
    process_rows = []
    started = time.monotonic()
    setup_record = EVIDENCE / "setup-observations.json"
    _save_json(setup_record, {"status": "started", "started_monotonic": started, "processes": []})
    lanes = (("native", build, []), ("sanitize", build.parent / (build.name + "-sanitize"),
        ["-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
         "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]))
    targets = ["gw_headless", "load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
               "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract"]
    test_regex = "^(load_contract|time_contract|reset_contract|bus_boundary_contract|gameplay_bus_contract|movem_contract|phase6_repairs_contract)$"
    for lane, tree, extra in lanes:
        if _remaining() < 600:
            raise TimeoutError("insufficient-setup-lane-and-terminal-fit")
        tree.mkdir(parents=True, exist_ok=True)
        configure = [cmake, "-S", str(ROOT), "-B", str(tree), "-G", "Ninja", "-DBUILD_TESTING=ON",
                     "-DGENEWHIP_BUILD_TOOLS=ON", "-DGENEWHIP_BUILD_DESKTOP=OFF", "-DGENEWHIP_TEST_HOOKS=ON", *extra]
        row = _run_bounded(configure, timeout=min(600-(time.monotonic()-started), _remaining()), cwd=ROOT, cap=1048576, build=build)
        process_rows.append({"lane": lane, "kind": "configure", **_stream_metadata(row, f"{lane}.configure")})
        _save_json(setup_record, {"status": "in-progress", "started_monotonic": started,
            "last_finished_monotonic": time.monotonic(), "processes": process_rows})
        if row["returncode"] != 0:
            raise RuntimeError("configure-failed:" + lane)
        row = _run_bounded([cmake, "--build", str(tree), "--parallel", "2", "--target", *targets],
                           timeout=min(600-(time.monotonic()-started), _remaining()), cwd=ROOT, cap=1048576, build=build)
        process_rows.append({"lane": lane, "kind": "build", **_stream_metadata(row, f"{lane}.build")})
        _save_json(setup_record, {"status": "in-progress", "started_monotonic": started,
            "last_finished_monotonic": time.monotonic(), "processes": process_rows})
        if row["returncode"] != 0 or time.monotonic()-started > 600:
            raise RuntimeError("build-failed-or-setup-budget-exhausted:" + lane)
        lane_env = dict(os.environ)
        if lane == "sanitize":
            lane_env["ASAN_OPTIONS"] = "detect_leaks=" + ("0" if sys.platform == "darwin" else "1")
            lane_env["UBSAN_OPTIONS"] = "halt_on_error=1"
        row = _run_bounded([ctest, "--test-dir", str(tree), "--output-on-failure", "--no-tests=error", "-R", test_regex],
                           timeout=min(120, _remaining()), cwd=ROOT, cap=1048576, build=build, env=lane_env)
        process_rows.append({"lane": lane, "kind": "ctest", **_stream_metadata(row, f"{lane}.ctest")})
        _save_json(setup_record, {"status": "in-progress", "started_monotonic": started,
            "last_finished_monotonic": time.monotonic(), "processes": process_rows})
        if row["returncode"] != 0 or time.monotonic()-started > 600:
            raise RuntimeError("ctest-failed-or-setup-budget-exhausted:" + lane)
        validate_ctest_seven(row["stdout"], row["stderr"])
    if digest(LEDGER) != LEDGER_SHA:
        raise ValueError("historical-ledger-changed-during-prepare")
    cmake_cache = build / "CMakeCache.txt"
    manifest = {"schema": "genewhip-phase6-tank-checkpoint47-manifest-v1", "status": "prepared-only",
        "selection": {"path": selection_path.relative_to(ROOT).as_posix(), "sha256": digest(selection_path),
                      "plan_sha256": PLAN_SHA}, "source_review": review, "tests": tests,
        "continuation_sha256": digest(CONTINUATION),
        "sources": inputs, "source_identity_sha256": digest_bytes(canonical(inputs)),
        "build": {"path": build.relative_to(ROOT).as_posix(), "cache_sha256": digest(cmake_cache),
                  "binary_path": (build/"tools/session/gw_headless").relative_to(ROOT).as_posix(),
                  "binary_sha256": digest(build/"tools/session/gw_headless")},
        "toolchain": {"cmake": "cmake", "cmake_sha256": digest(pathlib.Path(cmake)),
                      "ninja": "ninja", "ninja_sha256": digest(pathlib.Path(ninja)),
                      "ctest": "ctest", "ctest_sha256": digest(pathlib.Path(ctest))},
        "runtime": {"python_implementation": platform.python_implementation(),
                    "python_version": platform.python_version(), "python_binary_sha256": digest(pathlib.Path(sys.executable)),
                    "os": platform.platform(), "machine": platform.machine()},
        "lanes": process_rows, "workload_starts": 0, "os_process_creations": len(process_rows),
        "limits": WORKLOAD_LIMITS, "prepared_wall_seconds": round(time.monotonic()-started, 6),
        "limitations": ["No guest or workload launched; preparation is not product acceptance.",
                        "Local reviewed runtime/toolchain are trusted; no hostile-code containment claim."]}
    _save_json(setup_record, {"status": "passed", "started_monotonic": started,
        "finished_monotonic": time.monotonic(), "processes": process_rows})
    _save_json(EVIDENCE / "manifest.json", manifest)
    print(json.dumps({"status": "prepared-only", "build": manifest["build"], "lane_processes": len(process_rows)}))
    return 0


def _stream_metadata(row: dict, name: str) -> dict:
    outp, errp = EVIDENCE / "raw" / (name + ".stdout.raw"), EVIDENCE / "raw" / (name + ".stderr.raw")
    outp.parent.mkdir(parents=True, exist_ok=True)
    out_prefix=redact_stream(row["stdout"][:1048576]);err_prefix=redact_stream(row["stderr"][:1048576])
    outp.write_bytes(out_prefix); errp.write_bytes(err_prefix)
    return {"argv": normalize_argv(row["argv"]), "argv_sha256": digest_bytes(canonical(row["argv"])),
            "returncode": row["returncode"], "wall_seconds": row["wall_seconds"],
            "pid": row["pid"], "pgid": row["pgid"],
            "process_creations": row["process_creations"], "stdout": {"path": outp.relative_to(ROOT).as_posix(),
            "sha256": row["stdout_sha256"], "retained_sha256": digest_bytes(out_prefix),
            "path_normalized": True, "observed_bytes": len(row["stdout"]), "retained_bytes": len(out_prefix)},
            "stderr": {"path": errp.relative_to(ROOT).as_posix(),
            "sha256": row["stderr_sha256"], "retained_sha256": digest_bytes(err_prefix),
            "path_normalized": True, "observed_bytes": len(row["stderr"]), "retained_bytes": len(err_prefix)}}


def check_prepared_inputs(manifest: dict, build: pathlib.Path) -> dict:
    """Shared real prelaunch identity checks, also exercised on synthetic files."""
    current = source_identity()
    if current != manifest.get("sources"):
        raise ValueError("source-identity-drift-before-slot")
    client = build / "tools/session/gw_headless"
    cache = build / "CMakeCache.txt"
    if (digest(client) != manifest.get("build", {}).get("binary_sha256") or
            digest(cache) != manifest.get("build", {}).get("cache_sha256")):
        raise ValueError("build-identity-drift-before-slot")
    return current


def claim_writer() -> int:
    lock = EVIDENCE / "writer.lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(fd, str(os.getpid()).encode()); os.fsync(fd)
    return fd


def _assert_prelaunch(selection_path: pathlib.Path, manifest_path: pathlib.Path, manifest_sha: str,
                      build: pathlib.Path, manifest: dict, source_sha: str) -> None:
    check_identity(selection_path)
    if check_contract_tests() != manifest.get("tests"):
        raise ValueError("contract-tests-drift-before-slot")
    if (digest(selection_path) != manifest.get("selection", {}).get("sha256") or
            digest(CONTINUATION) != manifest.get("continuation_sha256")):
        raise ValueError("selection-or-continuation-drift-before-slot")
    if check_guard_review() != manifest.get("source_review"):
        raise ValueError("source-review-binding-changed-before-slot")
    if digest(manifest_path) != manifest_sha:
        raise ValueError("prepared-manifest-changed")
    current = check_prepared_inputs(manifest, build)
    if digest_bytes(canonical(current)) != source_sha:
        raise ValueError("source-identity-drift-before-slot")
    if _workspace_size(build) > WORKLOAD_LIMITS["disk_bytes"]:
        raise ValueError("disk-limit-before-slot")
    if DEADLINE - time.monotonic() < 600 + TERMINAL:
        raise TimeoutError("slot-plus-terminal-no-longer-fits")


def validate_control_bundle(report_path: pathlib.Path, child_path: pathlib.Path,
                            build: pathlib.Path, manifest: dict) -> dict:
    report = load(report_path)
    scenario_path = ROOT / "fixtures/independent-game-v2/scenario.json"
    oracle_path = ROOT / "fixtures/independent-game-v2/oracle.json"
    scenario, oracle = load(scenario_path), load(oracle_path)
    if (digest(scenario_path) != "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2" or
            digest(oracle_path) != "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"):
        raise ValueError("original-control-input-identity-drift")
    if (report.get("schema") != "genewhip-phase4-gameplay-v1" or report.get("outcome") != "pass" or
            report.get("fixture_id") != scenario.get("fixture_id") or report.get("denominator") != 6 or
            report.get("scenario_sha256") != digest(scenario_path) or report.get("oracle_sha256") != digest(oracle_path) or
            report.get("source_sha256") != scenario["source"]["sha256"] or
            report.get("rom_sha256") != scenario["rom"]["sha256"] or
            report.get("build_configuration_sha256") != manifest.get("build", {}).get("cache_sha256") or
            report.get("client_sha256") != [manifest.get("build", {}).get("binary_sha256")] or
            report.get("clients") != ["headless"]):
        raise ValueError("control-report-identity-or-status-invalid")
    if report.get("visual_observations") != {"title_to_play_field_10_changed": True,
            "start_idle_to_moved_marker_field_19_changed": True}:
        raise ValueError("control-visual-transition-predicates-invalid")
    cases = report.get("results", [])
    if [case.get("id") for case in cases] != CONTROL_IDS:
        raise ValueError("control-case-order-invalid")
    expectations = {case["id"]: case for case in scenario["cases"]}
    if [case.get("id") for case in scenario["cases"]] != oracle.get("case_ids") or oracle.get("case_ids") != CONTROL_IDS:
        raise ValueError("independent-control-denominator-invalid")
    client_sha = manifest.get("build", {}).get("binary_sha256")
    for result in cases:
        source_case = expectations[result["id"]]
        expected = source_case["expect"]
        if (result.get("outcome") != "pass" or result.get("unsupported") != 0 or
                result.get("fields") != source_case["frames"] or
                result.get("play_state") != expected["play_state"] or
                not expected["position_min"] <= result.get("position", -1) <= expected["position_max"] or
                result.get("psg") != expected["psg_writes"]):
            raise ValueError("original-control-source-predicate-invalid:" + result["id"])
        pcm_frames = source_case["frames"] * FIELD_TICKS * 48000 // MASTER_HZ
        item = result.get("retained_pcm")
        if not item or item.get("bytes") != pcm_frames * 4:
            raise ValueError("original-control-pcm-denominator-invalid:" + result["id"])
        pcm = safe_file(item["path"])
        if pcm.stat().st_size != item["bytes"] or digest(pcm) != item["sha256"]:
            raise ValueError("original-control-pcm-hash-invalid:" + result["id"])
        import struct
        samples = [sample[0] for sample in struct.iter_unpack("<h", pcm.read_bytes())]
        ac_range = max(samples) - min(samples) if samples else 0
        if result.get("ac_range") != ac_range:
            raise ValueError("original-control-pcm-waveform-invalid:" + result["id"])
        if expected["psg_writes"] and result.get("ac_range", 0) <= 0:
            raise ValueError("original-action-sound-pcm-silent")
        if result["id"] == "action-no-trigger" and result.get("ac_range") != 0:
            raise ValueError("original-no-trigger-pcm-not-silent")
    children = report.get("native_child_processes", [])
    receipts = load(child_path).get("processes", [])
    if len(children) != 6 or len(receipts) != 6:
        raise ValueError("original-control-native-process-count-invalid")
    if [child.get("case") for child in children] != CONTROL_IDS:
        raise ValueError("original-control-child-order-invalid")
    for result, child, receipt in zip(cases, children, receipts):
        for name in ("stdout", "stderr"):
            stream = child.get("streams", {}).get(name, {})
            path = safe_file(stream.get("path", ""))
            if (stream.get("truncated") is not False or stream.get("observed_bytes") != path.stat().st_size or
                    stream.get("retained_bytes") != path.stat().st_size or digest(path) != stream.get("sha256") or
                    path.stat().st_size > WORKLOAD_LIMITS[name + "_bytes"]):
                raise ValueError("original-control-child-stream-invalid:" + result["id"])
        stdout = safe_file(child["streams"]["stdout"]["path"]).read_text()
        raw_rows = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
        final = next((row for row in reversed(raw_rows) if "unsupported" in row), None)
        hashes = [row["fnv1a64"] for row in raw_rows if "fnv1a64" in row and "sequence" in row]
        if (not final or final.get("fields") != result["fields"] or final.get("unsupported") != 0 or
                final.get("stop_reason") != 0 or final.get("fault_address") != 0 or
                final.get("ram_fnv1a64") != result.get("machine_digest") or
                len(hashes) != result["fields"] or
                digest_bytes("\n".join(hashes).encode()) != result.get("field_hashes_sha256")):
            raise ValueError("original-control-raw-observation-invalid:" + result["id"])
        state = bytes.fromhex(final.get("peek", ""))
        if len(state) != 4 or int.from_bytes(state[:2], "big") != result["play_state"] or int.from_bytes(state[2:], "big") != result["position"]:
            raise ValueError("original-control-raw-state-invalid:" + result["id"])
        if (child.get("case") not in CONTROL_IDS or child.get("return_code") != 0 or
                child.get("executable_path") != manifest.get("build", {}).get("binary_path") or
                child.get("executable_sha256") != client_sha or
                not receipt.get("outer_process_group") or receipt.get("pgid") != receipt.get("driver_pgid") or
                receipt.get("status") != "finished" or receipt.get("returncode") != 0):
            raise ValueError("original-control-child-identity-or-group-invalid")
    return report


def repeat_case_semantics(cases: list[dict]) -> list[dict]:
    """Compare gameplay/PCM content, keeping distinct process/file provenance."""
    rows = []
    for case in cases:
        row = {key: value for key, value in case.items()
               if key not in ("process", "process_streams", "retained_pcm")}
        pcm = case.get("retained_pcm", {})
        row["retained_pcm"] = {key: pcm.get(key) for key in ("bytes", "sha256")}
        rows.append(row)
    return rows


def _append_watches(descriptor: bytes) -> bytes:
    import struct
    if len(descriptor) < 128 or len(descriptor) % 4 or descriptor[:4] != b"GWRC":
        raise ValueError("route-descriptor-invalid")
    words = list(struct.unpack("<" + "I"*(len(descriptor)//4), descriptor))
    count = words[6]
    watches = (0x00EC32, 0x00EC34, 0x00EC36)
    if count + len(watches) > 64 or len(descriptor) < (32 + count * 4) * 4:
        raise ValueError("watch-count-bound")
    extension = b"".join(struct.pack("<IIII", address, address, 2, 0) for address in watches)
    words[6] = count + len(watches)
    insert_at = (32 + count * 4) * 4
    packed = struct.pack("<" + "I"*len(words), *words)
    return packed[:insert_at] + extension + packed[insert_at:]


def _span(state, address: int, length: int) -> bytes:
    """Join the observer's adjacent two-byte watches; reject gaps/conflicts."""
    observed = {}
    for item in state.get("spans", []):
        start = item.get("address")
        if type(start) is not int or not 0 <= start <= 0xFFFFFF:
            raise ValueError("invalid-instruction-span-address")
        try:
            raw = bytes.fromhex(item.get("bytes", ""))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid-instruction-span-bytes") from exc
        if not 0 < len(raw) <= 64 or start + len(raw) > 0x1000000:
            raise ValueError("invalid-instruction-span-range")
        for offset, byte in enumerate(raw):
            at = start + offset
            if address <= at < address + length:
                if at in observed and observed[at] != byte:
                    raise ValueError("conflicting-instruction-span-bytes")
                observed[at] = byte
    if any(at not in observed for at in range(address, address + length)):
        raise ValueError("required-instruction-bytes-missing")
    return bytes(observed[at] for at in range(address, address + length))


def pea_predicates(native: dict) -> dict:
    if native.get("schema") != "genewhip-route-native-v1":
        raise ValueError("native-report-schema-invalid")
    pair = native.get("probe_boundary")
    if not isinstance(pair, dict):
        raise ValueError("probe-boundary-missing")
    before, after = pair.get("before", {}), pair.get("after", {})
    obs = after.get("stack_observation", {})
    addr = pair.get("instruction_address")
    expected_addr = [(before.get("a", [None]*8)[7] - 4 + i) & 0xFFFFFF for i in range(4)]
    checks = {
      "probe_pc": addr == 0xEC32 and before.get("pc") == 0xEC32 and after.get("pc") == 0xEC38,
      "opcode": pair.get("opcode") == 0x4879,
      "retired_once": pair.get("retired") is True and after.get("instructions") == before.get("instructions", -2) + 1,
      "bytes": _span(before, 0xEC32, 6) == bytes.fromhex("48790006923c"),
      "effective_address": int.from_bytes(_span(before, 0xEC32+2, 4), "big") == 0x6923C,
      "stack_pointer": len(before.get("a", [])) == 8 and len(after.get("a", [])) == 8 and
          after["a"][7] == ((before["a"][7] - 4) & 0xFFFFFFFF),
      "stack_reads": before.get("stack_observation", {}).get("read_calls") + obs.get("read_calls", -99) == 8,
      "stack_addresses": (before.get("stack_observation", {}).get("addresses24") == expected_addr and
          obs.get("addresses24") == expected_addr),
      "stack_values": obs.get("bytes") == [0, 6, 0x92, 0x3C],
      "stack_status": (before.get("stack_observation", {}).get("status") == [0, 0, 0, 0] and
          obs.get("status") == [0, 0, 0, 0]),
      "stack_call_count": (before.get("stack_observation", {}).get("read_calls") == 4 and obs.get("read_calls") == 4),
      "stack_a7_binding": (before.get("stack_observation", {}).get("source_a7") == before.get("a", [None]*8)[7] and
          obs.get("source_a7") == before.get("a", [None]*8)[7] and
          before.get("stack_observation", {}).get("base32") == ((before.get("a", [None]*8)[7]-4)&0xFFFFFFFF) and
          obs.get("base32") == ((before.get("a", [None]*8)[7]-4)&0xFFFFFFFF)),
      "stack_disposition": (before.get("stack_observation", {}).get("disposition") == "observed" and
          obs.get("disposition") == "observed"),
      "sr_preserved": after.get("sr") == before.get("sr"),
      "timing_140": after.get("tick") - before.get("tick") == 140,
      "bounds": all(type(native.get(key)) is int and 0 <= native[key] <= maximum
          for key, maximum in (("fields",4500),("active_ticks",3600),("boundary_calls",128),("queue_high_water",64))),
    }
    last = native.get("last_boundary")
    if not isinstance(last, dict):
        raise ValueError("next-outcome-boundary-missing")
    terminal = {"instruction_address": native.get("instruction_address"), "opcode": native.get("opcode"),
        "stop_reason": native.get("stop_reason"), "first_stop_tick": native.get("first_stop_tick"),
        "final_tick": native.get("final_tick"), "last_boundary": last}
    stopped = (native.get("stop_reason") in (2, 3, 4) and
               native.get("first_stop_tick") == last.get("after", {}).get("tick"))
    completed = (native.get("stop_reason") == 0 and native.get("status") == 0 and
                 native.get("first_stop_tick") is None and native.get("termination") == "active-limit" and
                 native.get("active_ticks") == WORKLOAD_LIMITS["active_ticks"] and
                 native.get("audio_complete") is True and isinstance(native.get("predicates"), list) and
                 bool(native["predicates"]) and all(item.get("seen") is True for item in native["predicates"]))
    checks["next_outcome_metadata"] = (native.get("instruction_address") == last.get("instruction_address") and
        native.get("opcode") == last.get("opcode") and native.get("stop_reason") == last.get("stop_reason") and
        native.get("final_tick") == last.get("after", {}).get("tick") and (stopped or completed) and
        last.get("instruction_address") != 0xEC32 and
        last.get("after", {}).get("instructions", 0) > after.get("instructions", 0))
    if not all(checks.values()):
        raise ValueError("pea-check-failed:" + ",".join(k for k,v in checks.items() if not v))
    return {"assertions": checks, "next_outcome": terminal}


def _reserve(slot: str, manifest_sha: str, identity_sha: str, selection_sha: str,
             command: list[str], root: pathlib.Path = EVIDENCE) -> pathlib.Path:
    state = root / "slots" / f"{slot}.json"
    record = {"schema": "genewhip-plan47-slot-v1", "slot": slot, "status": "reserved-before-launch",
              "monotonic": time.monotonic(), "manifest_sha256": manifest_sha,
              "source_identity_sha256": identity_sha, "selection_sha256": selection_sha,
              "plan_sha256": PLAN_SHA, "command": normalize_argv(command),
              "command_sha256": digest_bytes(canonical(command)), "limits": WORKLOAD_LIMITS}
    if "--route-plan" in command:
        route_path = pathlib.Path(command[command.index("--route-plan") + 1])
        relative = route_path.resolve(strict=True).relative_to(ROOT.resolve(strict=True)).as_posix()
        record["route_descriptor"] = {"path": relative, "sha256": digest(safe_file(relative))}
    _save_json(state, record, exclusive=True)
    return state


def _run_workload(command: list[str], *, slot: str, build: pathlib.Path, deadline: float,
                  manifest_sha: str, identity_sha: str, selection_sha: str,
                  used_wall: float = 0.0, outer: bool = True,
                  bounded_file: pathlib.Path | None = None) -> dict:
    if deadline - time.monotonic() < 600 + TERMINAL or 1800.0 - used_wall <= 0:
        raise TimeoutError("slot-and-terminal-fit-failed")
    state = _reserve(slot, manifest_sha, identity_sha, selection_sha, command)
    started = time.monotonic()
    try:
        if ATTEMPT_HOOK:
            ATTEMPT_HOOK("workload", command)
        process = _run_bounded(command, timeout=min(600.0,1800.0-used_wall), cwd=ROOT, cap=1048576,
                               process_group=outer, build=build, bounded_file=bounded_file, receipt_path=state)
    except BaseException as exc:
        _save_json(state, {**load(state), "status":"interrupted-before-complete",
            "wall_seconds":round(time.monotonic()-started,6),
            "failure":f"{type(exc).__name__}: {redact_stream(str(exc).encode()).decode(errors='replace')}"})
        raise
    raw = {"status": "finished", "started_monotonic": started,
           "finished_monotonic": time.monotonic(), "returncode": process["returncode"],
           "wall_seconds": process["wall_seconds"], "stdout_sha256": process["stdout_sha256"],
           "stderr_sha256": process["stderr_sha256"], "stdout_bytes": len(process["stdout"]),
           "stderr_bytes": len(process["stderr"]), "pid": process["pid"], "pgid": process["pgid"],
           "reservation": state.relative_to(ROOT).as_posix()}
    if len(process["stdout"]) > 1048576 or len(process["stderr"]) > 1048576:
        raise RuntimeError("workload-stream-limit")
    stream_record = _stream_metadata(process, slot)
    raw["streams"] = {"stdout": stream_record["stdout"], "stderr": stream_record["stderr"]}
    raw["command"] = normalize_argv(command)
    raw["command_sha256"] = digest_bytes(canonical(command))
    _save_json(state, {**load(state), "observed": raw})
    return {"process": process, "receipt": raw}


def _execute(build: pathlib.Path, selection_path: pathlib.Path, output: pathlib.Path) -> int:
    selected = check_identity(selection_path)
    manifest_path = EVIDENCE / "manifest.json"
    manifest = load(manifest_path)
    if check_guard_review() != manifest.get("source_review"):
        raise ValueError("source-review-binding-changed-after-prepare")
    if manifest.get("status") != "prepared-only":
        raise ValueError("prepared-manifest-missing")
    current = source_identity()
    if current != manifest.get("sources"):
        raise ValueError("source-drift-after-prepare")
    if _workspace_size(build) > WORKLOAD_LIMITS["disk_bytes"]:
        raise ValueError("disk-limit-before-workload")
    fd = claim_writer()
    manifest_sha = digest(manifest_path)
    ident_sha = digest_bytes(canonical(current))
    workload_wall = 0.0
    outcomes = []
    top_level = 0
    workload_creation_start = OBSERVED_CREATIONS
    child_processes = 0
    result = {"schema": "genewhip-phase6-tank-checkpoint47-v1", "status": "halted",
              "plan_sha256": PLAN_SHA, "selection_sha256": digest(selection_path),
              "manifest_sha256": manifest_sha, "source_identity_sha256": ident_sha,
              "historical_ledger_sha256": digest(LEDGER), "workload_slots": [], "processes": [],
              "controls": [], "limitations": ["This is one bounded Tank PEA checkpoint, not route success.",
              "No complete Phase6, PLAY-02, HOST-04, SAFE-02, full-control compatibility, or hostile containment claim."]}
    tank_path = EVIDENCE / "raw/tank/report.json"
    try:
        route_mod = _load_route_module()
        route = next(r for r in route_mod.compile_routes()["routes"]
                     if r["fixture"] == "tank-battle" and r["case"]["id"] == "full-route")
        descriptor, _ = route_mod.lower_route(route)
        descriptor = _append_watches(descriptor)
        plan_path = EVIDENCE / "raw/tank/route.gwrc"
        plan_path.parent.mkdir(parents=True, exist_ok=True); plan_path.write_bytes(descriptor)
        client = build / "tools/session/gw_headless"
        rom = ROOT / "fixtures/phase5-a/game.bin"
        _assert_prelaunch(selection_path, manifest_path, manifest_sha, build, manifest, ident_sha)
        command = [str(client), "--route-plan", str(plan_path), "--route-report", str(tank_path),
                   "--route-instruction-probe", str(0xEC32), "--route-probe-stack-before-a7", str(rom)]
        top_level += 1
        tank = _run_workload(command, slot="47-tank", build=build, deadline=DEADLINE,
                             manifest_sha=manifest_sha, identity_sha=ident_sha,
                             selection_sha=digest(selection_path),bounded_file=tank_path)
        workload_wall += tank["receipt"]["wall_seconds"]
        outcomes.append(tank["receipt"])
        raw = tank_path.read_bytes()
        if len(raw) > WORKLOAD_LIMITS["report_bytes"]:
            raise ValueError("tank-report-size-bound")
        native = json.loads(raw)
        if len(native.get("samples", [])) > WORKLOAD_LIMITS["trace_rows"]:
            raise ValueError("tank-trace-row-bound")
        checked = pea_predicates(native)
        result["tank"] = {"command": normalize_argv(command), "command_sha256": digest_bytes(canonical(command)),
            "route_identity": route["identity"], "route_descriptor_sha256": digest_bytes(descriptor),
            "client_path": client.relative_to(ROOT).as_posix(), "client_sha256": digest(client),
            "report_path": tank_path.relative_to(ROOT).as_posix(), "report_sha256": digest_bytes(raw),
            "process": tank["receipt"], "pea": checked}
        if tank["process"]["returncode"] not in (0, 1):
            raise RuntimeError("tank-client-returncode")
        # Control route uses the existing independent source scenario and original oracle.
        controls = []
        for repetition in (1, 2):
            _remaining()
            root = EVIDENCE / "raw" / f"control-{repetition}"
            root.mkdir(parents=True, exist_ok=False)
            report = root / "report.json"
            pcm = root / "pcm"
            child_receipt = root / "processes.json"
            driver = ROOT / "tests/fixtures/phase4_game.py"
            _assert_prelaunch(selection_path, manifest_path, manifest_sha, build, manifest, ident_sha)
            cmd = [sys.executable, "-I", str(driver), str(client), "--outer-process-group",
                   "--report", str(report), "--retain-artifacts", str(pcm), "--process-receipt", str(child_receipt)]
            top_level += 1
            control = _run_workload(cmd, slot=f"47-control-{repetition}", build=build, deadline=DEADLINE,
                                    manifest_sha=manifest_sha, identity_sha=ident_sha,
                                    selection_sha=digest(selection_path), used_wall=workload_wall,
                                    bounded_file=report)
            workload_wall += control["receipt"]["wall_seconds"]
            outcomes.append(control["receipt"])
            if control["process"]["returncode"] != 0:
                raise RuntimeError(f"control-driver-failed-{repetition}")
            row = validate_control_bundle(report, child_receipt, build, manifest)
            if row.get("outcome") != "pass" or [x.get("id") for x in row.get("results", [])] != CONTROL_IDS:
                raise ValueError("control-denominator-or-status-invalid")
            child_rows = load(child_receipt).get("processes", [])
            if len(child_rows) != 6 or len(row.get("native_child_processes", [])) != 6:
                raise ValueError("control-child-denominator-invalid")
            if any(not item.get("outer_process_group") or item.get("pgid") != item.get("driver_pgid")
                   or item.get("status") != "finished" or item.get("returncode") != 0 for item in child_rows):
                raise ValueError("control-child-process-group-invalid")
            for case in row["results"]:
                if not (pcm / f"{case['id']}.pcm").is_file():
                    raise ValueError("control-pcm-not-in-slot")
            child_processes += len(child_rows)
            controls.append({"repetition": repetition, "report_path": report.relative_to(ROOT).as_posix(),
                "report_sha256": digest(report), "status": row["outcome"], "cases": row["results"],
                "native_child_processes": row["native_child_processes"], "child_process_receipt": child_receipt.relative_to(ROOT).as_posix(),
                "child_process_receipt_sha256": digest(child_receipt), "driver_process": control["receipt"]})
            result["controls"] = controls
        if repeat_case_semantics(controls[0]["cases"]) != repeat_case_semantics(controls[1]["cases"]):
            raise ValueError("control-repetitions-differ")
        os_processes = OBSERVED_CREATIONS - workload_creation_start + child_processes
        if os_processes > 15 or top_level != 3 or len(controls) != 2:
            raise ValueError("workload-denominator-invalid")
        result.update({"status": "captured-bounded-pea", "workload_slots": outcomes,
                       "top_level_workload_starts": top_level, "os_process_creations": os_processes,
                       "workload_process_wall_seconds": round(workload_wall, 6),
                       "control_rows": 12, "full_pcm_files": 12, "rec_processes": 0,
                       "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    except BaseException as exc:
        result["halt_reason"] = f"{type(exc).__name__}: {redact_stream(str(exc).encode()).decode(errors='replace')}"
        result["workload_slots"] = outcomes
        failed_children = []
        for repetition in (1, 2):
            path = EVIDENCE / "raw" / f"control-{repetition}" / "processes.json"
            if path.is_file():
                try:
                    failed_children.extend(load(path).get("processes", []))
                except (ValueError, OSError):
                    result["native_child_count_unknown"] = True
        result["observed_native_child_prefix"] = failed_children
        result["slot_prefix"] = [load(path) for path in sorted((EVIDENCE / "slots").glob("*.json"))]
        result["top_level_workload_starts"] = top_level
        result["os_process_creations"] = OBSERVED_CREATIONS - workload_creation_start + len(failed_children)
        result["workload_process_wall_seconds"] = round(sum(
            float(slot.get("observed", slot.get("observed_failure", {})).get("wall_seconds", 0))
            for slot in result["slot_prefix"]), 6)
        result["failed_prefix_preserved"] = True
    finally:
        result["historical_ledger_sha256_after"] = digest(LEDGER)
        result["historical_ledger_unchanged"] = result["historical_ledger_sha256_after"] == LEDGER_SHA
        result["source_identity_sha256_after"] = digest_bytes(canonical(source_identity()))
        result["source_unchanged"] = result["source_identity_sha256_after"] == ident_sha
        os.close(fd)
    _save_json(output, result)
    print(json.dumps({"status": result["status"], "halt_reason": result.get("halt_reason"),
        "top_level_workload_starts": result.get("top_level_workload_starts", 0),
        "os_process_creations": result.get("os_process_creations", 0)}, sort_keys=True))
    return 0 if result["status"] == "captured-bounded-pea" else 1


def _load_route_module():
    import importlib.util
    path = ROOT / "scripts/evidence/phase6_routes.py"
    spec = importlib.util.spec_from_file_location("phase6_routes47", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify_retained(receipt_path: pathlib.Path, review_path: pathlib.Path, output: pathlib.Path) -> int:
    source_review = check_guard_review()
    check_contract_tests()
    data = load(receipt_path)
    if data.get("schema") != "genewhip-phase6-tank-checkpoint47-v1":
        raise ValueError("checkpoint-receipt-schema")
    if data.get("status") != "captured-bounded-pea":
        raise ValueError("checkpoint-not-captured")
    manifest = load(EVIDENCE/"manifest.json")
    selection_sha = digest(SELECTION)
    expected_slots = ["47-tank", "47-control-1", "47-control-2"]
    if (digest(EVIDENCE/"manifest.json") != data.get("manifest_sha256") or
            data.get("selection_sha256") != selection_sha or
            data.get("workload_slots", []) != [load(EVIDENCE/"slots"/f"{name}.json").get("observed")
                                               for name in expected_slots]):
        raise ValueError("workload-slot-observation-mismatch")
    slot_rows = []
    for name, observed in zip(expected_slots, data["workload_slots"]):
        slot_path = safe_file(f"{EVIDENCE.relative_to(ROOT).as_posix()}/slots/{name}.json")
        slot = load(slot_path)
        if (slot.get("schema") != "genewhip-plan47-slot-v1" or slot.get("slot") != name or
                slot.get("status") != "reserved-before-launch" or slot.get("plan_sha256") != PLAN_SHA or
                slot.get("selection_sha256") != selection_sha or
                slot.get("manifest_sha256") != data.get("manifest_sha256") or
                slot.get("source_identity_sha256") != data.get("source_identity_sha256") or
                slot.get("limits") != WORKLOAD_LIMITS or not isinstance(slot.get("monotonic"), (int,float)) or
                not isinstance(observed, dict) or observed.get("status") != "finished" or
                observed.get("reservation") != slot_path.relative_to(ROOT).as_posix() or
                observed.get("command") != slot.get("command") or
                observed.get("command_sha256") != slot.get("command_sha256") or
                observed.get("returncode") not in (0,1) or
                not slot.get("monotonic") <= observed.get("started_monotonic", -1) <= observed.get("finished_monotonic", -1) <= DEADLINE - TERMINAL):
            raise ValueError("slot-reservation-or-observation-invalid:" + name)
        for stream_name in ("stdout", "stderr"):
            stream = observed.get("streams", {}).get(stream_name, {})
            stream_file = safe_file(stream.get("path", ""))
            if (stream.get("retained_bytes") != stream_file.stat().st_size or
                    digest(stream_file) != stream.get("retained_sha256") or
                    stream.get("observed_bytes", WORKLOAD_LIMITS[stream_name+"_bytes"]+1) > WORKLOAD_LIMITS[stream_name+"_bytes"]):
                raise ValueError("slot-stream-evidence-invalid:" + name + ":" + stream_name)
        slot_rows.append(slot)
    raw = safe_file(data["tank"]["report_path"]).read_bytes()
    if digest_bytes(raw) != data["tank"]["report_sha256"]:
        raise ValueError("tank-report-hash-mismatch")
    tank = data["tank"]
    tank_process = data["workload_slots"][0]
    evidence_rel = EVIDENCE.relative_to(ROOT).as_posix()
    expected_tank_command = [manifest["build"]["binary_path"], "--route-plan",
        f"{evidence_rel}/raw/tank/route.gwrc", "--route-report", f"{evidence_rel}/raw/tank/report.json",
        "--route-instruction-probe", str(0xEC32), "--route-probe-stack-before-a7", "fixtures/phase5-a/game.bin"]
    if (tank.get("command") != expected_tank_command or tank.get("command_sha256") != tank_process.get("command_sha256") or
            tank.get("client_sha256") != manifest["build"]["binary_sha256"] or
            tank.get("route_descriptor_sha256") != digest_bytes(safe_file(f"{evidence_rel}/raw/tank/route.gwrc").read_bytes()) or
            slot_rows[0].get("route_descriptor") != {"path": f"{evidence_rel}/raw/tank/route.gwrc",
                "sha256": tank.get("route_descriptor_sha256")} or
            tank_process.get("returncode") not in (0,1) or tank_process.get("pid", 0) <= 0 or
            tank_process.get("pgid") != tank_process.get("pid") or len(raw) > WORKLOAD_LIMITS["report_bytes"]):
        raise ValueError("tank-process-identity-or-bound-invalid")
    checks = pea_predicates(json.loads(raw))
    if checks != data["tank"]["pea"]:
        raise ValueError("pea-recomputation-mismatch")
    if len(data.get("controls", [])) != 2 or data.get("control_rows") != 12 or data.get("full_pcm_files") != 12:
        raise ValueError("controls-incomplete")
    if data.get("os_process_creations") != 15 or data.get("top_level_workload_starts") != 3:
        raise ValueError("process-denominator-invalid")
    for repetition, control in enumerate(data["controls"], 1):
        if control.get("repetition") != repetition or control.get("status") != "pass" or len(control.get("cases", [])) != 6:
            raise ValueError("control-row-invalid")
        report_path = safe_file(control.get("report_path", ""))
        child_path = safe_file(control.get("child_process_receipt", ""))
        driver = control.get("driver_process", {})
        observed = data["workload_slots"][repetition]
        if (driver != observed or driver.get("pid", 0) <= 0 or driver.get("pgid") != driver.get("pid") or
                driver.get("returncode") != 0 or driver.get("status") != "finished"):
            raise ValueError("control-driver-process-receipt-invalid")
        if digest(report_path) != control.get("report_sha256") or digest(child_path) != control.get("child_process_receipt_sha256"):
            raise ValueError("control-raw-hash-mismatch")
        report = validate_control_bundle(report_path, child_path, ROOT/"build/phase6-checkpoint47",
                                        manifest)
        if report.get("results") != control.get("cases"):
            raise ValueError("control-report-payload-mismatch")
        child_rows = load(child_path).get("processes", [])
        if len(child_rows) != 6 or any(row.get("driver_pgid") != driver.get("pgid") or
                row.get("pgid") != driver.get("pgid") or row.get("pid", 0) <= 0 or
                row.get("status") != "finished" or row.get("returncode") != 0 for row in child_rows):
            raise ValueError("control-child-process-evidence-invalid")
    if repeat_case_semantics(data["controls"][0]["cases"]) != repeat_case_semantics(data["controls"][1]["cases"]):
        raise ValueError("control-repetitions-differ")
    if review_path.is_symlink() or not review_path.is_file():
        raise ValueError("independent-result-review-missing")
    review = _load_review_record(review_path, "independent-result-review")
    expected_inputs = {
        "receipt_sha256": digest(receipt_path),
        "manifest_sha256": digest(EVIDENCE/"manifest.json"),
        "selection_sha256": digest(SELECTION),
        "source_identity_sha256": data.get("source_identity_sha256"),
        "tests_sha256": digest(EVIDENCE/"tests.json"),
        "tank_report_sha256": digest(safe_file(tank["report_path"])),
        "control_report_1_sha256": digest(safe_file(data["controls"][0]["report_path"])),
        "control_report_2_sha256": digest(safe_file(data["controls"][1]["report_path"])),
        "slot_47-tank_sha256": digest(safe_file(f"{evidence_rel}/slots/47-tank.json")),
        "slot_47-control-1_sha256": digest(safe_file(f"{evidence_rel}/slots/47-control-1.json")),
        "slot_47-control-2_sha256": digest(safe_file(f"{evidence_rel}/slots/47-control-2.json")),
    }
    review_findings = review.get("findings") if isinstance(review, dict) else None
    result_keys = {"schema", "reviewer_identity", "reviewer_role", "reviewed_inputs",
                   "independently_recomputed", "findings", "high_count", "critical_count", "verdict"}
    if (set(review) != result_keys or not isinstance(review_findings, list) or
            any(not isinstance(item, dict) or set(item) != {"finding", "severity", "blocking"} or
                not isinstance(item.get("finding"), str) or
                item.get("severity") not in ("critical", "high", "warning") or
                type(item.get("blocking")) is not bool for item in review_findings)):
        raise ValueError("independent-result-review-findings-invalid")
    review_high = sum(item.get("severity") in ("high", "critical") for item in review_findings)
    review_critical = sum(item.get("blocking") is True for item in review_findings)
    if (review_high != 0 or review_critical != 0 or review.get("schema") != "genewhip-plan47-result-review-v1" or
            review.get("reviewer_identity") != "/root/continuation47_result" or
            review.get("reviewer_role") != "independent retained-result reviewer" or
            review.get("reviewed_inputs") != expected_inputs or
            review.get("independently_recomputed") != ["PEA", "next-stop", "12 control cases", "complete PCM",
                "denominator", "reservations", "process evidence", "history"] or
            review.get("high_count") != review_high or review.get("critical_count") != review_critical or
            review.get("verdict") != ("ACCEPT" if review_high == 0 and review_critical == 0 else "REJECT")):
        raise ValueError("independent-result-review-not-accepted")
    current = source_identity()
    selected = check_identity(SELECTION)
    current_identity = digest_bytes(canonical(current))
    if (digest(LEDGER) != LEDGER_SHA or current != load(EVIDENCE/"manifest.json").get("sources") or
            current_identity != data.get("source_identity_sha256") or
            digest(LEDGER) != data.get("historical_ledger_sha256_after") or
            not data.get("historical_ledger_unchanged") or not data.get("source_unchanged") or
            digest(SELECTION) != data.get("selection_sha256")):
        raise ValueError("source-or-history-drift")
    checked = {"schema": "genewhip-phase6-tank-checkpoint47-check-v1", "status": "checked-bounded-checkpoint",
        "receipt_path": receipt_path.relative_to(ROOT).as_posix(), "receipt_sha256": digest(receipt_path),
        "result_review": {"path": review_path.relative_to(ROOT).as_posix(), "sha256": digest(review_path)},
        "source_review": source_review, "pea_recomputed": checks, "control_rows": 12,
        "full_pcm_files": 12, "source_identity_sha256": digest_bytes(canonical(current)),
        "historical_ledger_sha256": digest(LEDGER), "phase6_complete": False,
        "requirements_completed": [], "descendants_dispatched": False}
    _save_json(output, checked)
    print(json.dumps({"status": checked["status"], "control_rows": 12, "process_creations": data["os_process_creations"]}))
    return 0


def self_test(output: pathlib.Path | None = None) -> int:
    # The contract harness installs process denial before importing this module.
    # Exercise the actual early dispatcher callback through the lowest launch seam.
    global ATTEMPT_HOOK
    observed = []
    ATTEMPT_HOOK = lambda kind, argv: observed.append({"kind": kind, "argv": list(argv)})
    import tempfile
    from copy import deepcopy
    descriptor = bytearray(b"GWRC" + b"\0"*124 + bytes.fromhex("00100000001000000200000000000000"))
    descriptor[24:28] = (1).to_bytes(4, "little")
    watched = _append_watches(bytes(descriptor))
    assert watched[:4] == b"GWRC" and int.from_bytes(watched[24:28], "little") == 4
    import struct
    assert watched[128:144] == descriptor[128:144]
    assert list(struct.unpack("<" + "I"*12, watched[144:192])) == [
        0xEC32, 0xEC32, 2, 0, 0xEC34, 0xEC34, 2, 0, 0xEC36, 0xEC36, 2, 0]
    # Fixed expected semantics are checked from an independently described synthetic boundary.
    addrs = [0x0FFC, 0x0FFD, 0x0FFE, 0x0FFF]
    before = {"pc": 0xEC32, "sr": 0x2700, "tick": 100, "instructions": 9,
              "a": [0]*7+[0x1000], "spans": [{"address":0xEC32,"bytes":"48790006923c"}],
              "stack_observation":{"source_a7":0x1000,"base32":0x0FFC,"addresses24":addrs,
              "bytes":[0,0,0,0],"status":[0,0,0,0],"read_calls":4}}
    after = {"pc": 0xEC38, "sr": 0x2700, "tick": 240, "instructions": 10,
             "a": [0]*7+[0x0FFC], "stack_observation":{"source_a7":0x1000,"base32":0x0FFC,
             "addresses24":addrs,"read_calls":4,"bytes":[0,6,0x92,0x3C],"status":[0,0,0,0],"disposition":"observed"}}
    before["spans"] = [{"address": 0xEC32 + i, "bytes": raw}
                       for i, raw in ((0, "4879"), (2, "0006"), (4, "923c"))]
    before["stack_observation"]["disposition"]="observed"
    pair = {"instruction_address":0xEC32,"opcode":0x4879,"retired":True,"before":before,"after":after}
    native = {"schema":"genewhip-route-native-v1","probe_boundary":pair,"stop_reason":2,"fields":1,
       "active_ticks":140,"boundary_calls":1,"queue_high_water":1,"instruction_address":0xEC3A,"opcode":0x4E71,
       "first_stop_tick":280,"final_tick":280,"last_boundary":{"instruction_address":0xEC3A,"opcode":0x4E71,
       "stop_reason":2,"after":{"tick":280,"instructions":11}}}
    assert all(pea_predicates(native)["assertions"].values())
    mutants = []
    for change in (
        lambda x: x["probe_boundary"].update(opcode=0x4878),
        lambda x: x["probe_boundary"]["after"]["a"].__setitem__(7, 0xFFB),
        lambda x: x["probe_boundary"]["after"]["stack_observation"]["bytes"].__setitem__(3, 0),
        lambda x: x["probe_boundary"]["after"].update(tick=241),
        lambda x: x["last_boundary"]["after"].update(tick=281),
        lambda x: x["probe_boundary"]["after"]["stack_observation"]["status"].__setitem__(0, 9),
        lambda x: x["probe_boundary"]["after"]["stack_observation"]["addresses24"].__setitem__(0, 0),
    ):
        mutated = deepcopy(native); change(mutated)
        try:
            pea_predicates(mutated)
        except (ValueError, KeyError, TypeError):
            mutants.append("rejected")
        else:
            raise AssertionError("PEA semantic mutant passed")
    assert len(mutants) == 7
    with tempfile.TemporaryDirectory(prefix="phase6-47-synthetic-") as directory:
        synthetic = pathlib.Path(directory)
        try:
            _reserve("47-test", "a"*64, "b"*64, "c"*64, ["synthetic-command"], synthetic)
            _reserve("47-test", "a"*64, "b"*64, "c"*64, ["synthetic-command"], synthetic)
        except FileExistsError:
            mutants.append("spent-slot-rejected")
        else:
            raise AssertionError("duplicate reservation passed")
    try:
        json.loads('{"malformed":')
    except json.JSONDecodeError:
        mutants.append("malformed-json-rejected")
    else:
        raise AssertionError("malformed JSON passed")
    try:
        safe_file("/not/a/project/path")
    except ValueError:
        mutants.append("unsafe-path-rejected")
    else:
        raise AssertionError("unsafe retained path passed")
    # Reach the actual lowest launcher seam. The outer contract has replaced Popen
    # with a denial callback; a caught denial remains in the observed attempt list.
    try:
        _run_bounded([sys.executable, "-c", "pass"], timeout=1, cwd=ROOT, cap=1024)
    except RuntimeError as exc:
        if "denial" not in str(exc).lower() and "process" not in str(exc).lower():
            raise
    except BaseException:
        pass
    if len(observed) != 1 or observed[0].get("kind") != "process":
        raise AssertionError("lowest process callback was not reached exactly once")
    if output:
        _save_json(output, {"schema":"genewhip-phase6-tank-checkpoint47-tests-v1","status":"passed",
        "tests_executed":13,"positive_checks":["descriptor-layout", "valid-split-pea"],"named_mutants":["bad-opcode","bad-a7","bad-stack-bytes","bad-ticks",
            "changed-next-outcome-metadata","bad-stack-status","bad-stack-addresses","double-reservation",
            "malformed-json","unsafe-path","lowest-process-denial"],"os_process_creations":OBSERVED_CREATIONS,
            "observed_attempts":[{"api":"subprocess.Popen","denied":True}],"real_root_client_rom_injected":False})
    print("PLAN47 SELF-TEST PASS: 13 checks; observed OS process creations=0")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--execute-once", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-retained", type=pathlib.Path)
    parser.add_argument("--acceptance-review", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--build", type=pathlib.Path, default=ROOT/"build/phase6-checkpoint47")
    parser.add_argument("--selection", type=pathlib.Path, default=SELECTION)
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return self_test(args.output)
        if args.verify_retained:
            if not args.acceptance_review or not args.output:
                raise ValueError("verify-retained-requires-review-and-output")
            receipt = args.verify_retained if args.verify_retained.is_absolute() else ROOT/args.verify_retained
            review = args.acceptance_review if args.acceptance_review.is_absolute() else ROOT/args.acceptance_review
            out = args.output if args.output.is_absolute() else ROOT/args.output
            return verify_retained(receipt, review, out)
        build = args.build if args.build.is_absolute() else ROOT/args.build
        selection = args.selection if args.selection.is_absolute() else ROOT/args.selection
        if args.prepare and not args.execute_once:
            return _prepare(build, selection)
        if args.execute_once and not args.prepare:
            if not args.output:
                raise ValueError("execute-once-requires-output")
            output = args.output if args.output.is_absolute() else ROOT/args.output
            return _execute(build, selection, output)
        raise ValueError("select-exactly-one-plan47-mode")
    except BaseException as exc:
        print(json.dumps({"status":"halted","reason":f"{type(exc).__name__}: {exc}"}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
