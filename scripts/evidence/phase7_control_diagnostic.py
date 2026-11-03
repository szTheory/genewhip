#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the original six-case control driver twice as a bounded diagnostic."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import stat
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIAGNOSTIC_SECONDS = 45 * 60
CLEANUP_RESERVE_SECONDS = 60
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DRIVER_STATUSES = {"completed", "failed", "timeout", "launch-failed", "interrupted"}
CLEANUP_STATUSES = {"confirmed", "unconfirmed", "not-launched"}
BOUND_REASONS = {
    "phase7-wall-timeout", "phase7-stdout-stderr-byte-limit",
    "phase7-rss-observation-unavailable", "phase7-rss-byte-limit",
    "phase7-scratch-tree-unsafe", "phase7-scratch-byte-limit",
    "phase7-json-byte-limit", "phase7-capture-byte-limit",
    "phase7-retained-byte-limit", "phase7-binary-file-byte-limit",
}


class DiagnosticError(RuntimeError):
    def __init__(self, code: str, outcome: str = "unknown"):
        super().__init__(code)
        self.code, self.outcome = code, outcome


def _safe_tree(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        parts = path.absolute().relative_to(root.absolute()).parts
    except ValueError:
        return False
    current = root
    if current.is_symlink():
        return False
    for part in parts:
        current /= part
        if current.is_symlink():
            return False
    return True


def _read(path: pathlib.Path, maximum: int) -> bytes:
    if type(maximum) is not int or maximum <= 0:
        raise DiagnosticError("artifact-limit-invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise DiagnosticError("artifact-unavailable") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > maximum or
                info.st_nlink != 1 or info.st_uid != os.getuid()):
            raise DiagnosticError("artifact-unsafe")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise DiagnosticError("artifact-oversize")
        return raw
    finally:
        os.close(fd)


def _json(path: pathlib.Path, maximum: int) -> dict[str, Any]:
    try:
        value = json.loads(_read(path, maximum))
    except DiagnosticError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError) as exc:
        raise DiagnosticError("artifact-invalid") from exc
    if not isinstance(value, dict):
        raise DiagnosticError("artifact-invalid")
    return value


def _write_new(path: pathlib.Path, raw: bytes, maximum: int) -> None:
    if len(raw) > maximum or path.exists() or path.is_symlink():
        raise DiagnosticError("output-collision-or-oversize")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise DiagnosticError("output-unavailable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise DiagnosticError("output-unsafe")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _prepare_output(argument: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    base = ROOT / "build/v02"
    if base.is_symlink() or not base.is_dir():
        raise DiagnosticError("output-root-invalid")
    base = base.resolve(strict=True)
    out = (argument if argument.is_absolute() else ROOT / argument).absolute()
    if (out.parent != base or out.suffix != ".json" or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", out.name) or
            not _safe_tree(out, base) or out.exists() or out.is_symlink()):
        raise DiagnosticError("output-path-invalid")
    work = base / out.stem
    if work.exists() or not _safe_tree(work, base):
        raise DiagnosticError("output-work-root-invalid")
    work.mkdir(mode=0o700)
    if not stat.S_ISDIR(work.stat(follow_symlinks=False).st_mode):
        raise DiagnosticError("output-work-root-unsafe")
    return out, work


def _module(path: pathlib.Path, name: str):
    if path.is_symlink() or not path.is_file():
        raise DiagnosticError("source-oracle-invalid")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DiagnosticError("source-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise DiagnosticError("diagnostic-start-invalid")
    try:
        result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DiagnosticError("diagnostic-start-invalid") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise DiagnosticError("diagnostic-start-invalid")
    return result.astimezone(datetime.timezone.utc)


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _current_cases(phase4: Any, phase4_report: Any, maximum: int) -> dict[str, Any]:
    path = ROOT / "fixtures/independent-game-v2/scenario.json"
    if not _safe_tree(path, ROOT):
        raise DiagnosticError("source-scenario-invalid")
    raw = _read(path, maximum)
    if _sha(raw) != phase4_report.GAME_IDENTITIES["scenario_sha256"] or _sha(raw) != phase4.SCENARIO_SHA:
        raise DiagnosticError("source-scenario-invalid")
    try:
        scenario = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DiagnosticError("source-scenario-invalid") from exc
    rows = scenario.get("cases") if isinstance(scenario, dict) else None
    if (not isinstance(rows, list) or
            tuple(row.get("id") if isinstance(row, dict) else None for row in rows) != phase4_report.GAME_CASES):
        raise DiagnosticError("source-scenario-invalid")
    return {row["id"]: row for row in rows}


def _validate_report(report_path: pathlib.Path, nested_path: pathlib.Path,
        build: pathlib.Path, phase4: Any, phase4_report: Any, cases: dict[str, Any],
        identity: dict[str, Any], limits: dict[str, Any]
        ) -> list[dict[str, Any]]:
    report = _json(report_path, limits["max_json_bytes"])
    problems = phase4_report.validate_gameplay(report, qualification=False,
        expected_identity={"build_configuration_sha256": identity["build_configuration_sha256"],
                           "client_sha256": [identity["headless_client_sha256"]]})
    if problems or report.get("clients") != ["headless"]:
        raise DiagnosticError("control-report-invalid", "fail")
    expected_ids = phase4_report.GAME_CASES
    rows, children = report.get("results"), report.get("native_child_processes")
    if (not isinstance(rows, list) or tuple(r.get("id") if isinstance(r, dict) else None for r in rows) != expected_ids or
            not isinstance(children, list) or len(children) != len(expected_ids)):
        raise DiagnosticError("control-report-invalid", "fail")
    try:
        nested = _json(nested_path, limits["max_json_bytes"]).get("processes")
    except DiagnosticError as exc:
        raise DiagnosticError("nested-receipt-invalid") from exc
    if not isinstance(nested, list) or len(nested) != len(expected_ids):
        raise DiagnosticError("nested-receipt-invalid")
    executable = str((build / "tools/session/gw_headless").relative_to(ROOT))
    outcomes = []
    for case_id, row, child, receipt in zip(expected_ids, rows, children, nested):
        process = row.get("process")
        streams = row.get("process_streams")
        if (type(row.get("fields")) is not int or type(row.get("play_state")) is not int or
                type(row.get("position")) is not int or type(row.get("ac_range")) is not int or
                not isinstance(process, dict) or process.get("client") != "gw_headless" or
                type(process.get("return_code")) is not int or process["return_code"] != 0 or
                process.get("executable_sha256") != identity["headless_client_sha256"] or
                process.get("executable_path") != executable or process.get("cwd") != "." or
                not _hex(process.get("stdout_sha256")) or not _hex(process.get("stderr_sha256"))):
            raise DiagnosticError("control-report-invalid", "fail")
        for name in ("stdout", "stderr"):
            size, stream = process.get(name + "_bytes"), streams.get(name) if isinstance(streams, dict) else None
            if (type(size) is not int or not 0 <= size <= limits["max_stdout_stderr_bytes"] or
                    not isinstance(stream, dict) or stream.get("observed_bytes") != size or
                    stream.get("sha256") != process.get(name + "_sha256") or stream.get("truncated") is not False):
                raise DiagnosticError("control-report-invalid", "fail")
        if (row.get("input_sha256") != _sha(phase4.input_log(cases[case_id])) or
                not isinstance(child, dict) or child.get("case") != case_id or
                child.get("client") != "gw_headless" or child.get("return_code") != 0 or
                child.get("executable_sha256") != identity["headless_client_sha256"] or
                any(child.get(key) != process.get(key) for key in
                    ("stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256"))):
            raise DiagnosticError("control-report-invalid", "fail")
        if (not isinstance(receipt, dict) or receipt.get("status") != "completed" or
                type(receipt.get("return_code")) is not int or receipt["return_code"] != 0 or
                receipt.get("bound_violation") is not False or
                receipt.get("process_group_cleanup") != "confirmed" or receipt.get("client") != "headless" or
                not _finite(receipt.get("wall_seconds")) or receipt["wall_seconds"] > limits["wall_seconds"] or
                type(receipt.get("rss_bytes_peak")) is not int or
                not 0 <= receipt["rss_bytes_peak"] <= limits["max_rss_bytes"] or
                receipt.get("stdout_bytes") != process["stdout_bytes"] or
                receipt.get("stderr_bytes") != process["stderr_bytes"]):
            raise DiagnosticError("nested-child-failure", "fail")
        outcomes.append({"case_id": case_id, "status": "pass", "fields": row["fields"],
            "play_state": row["play_state"], "position": row["position"], "psg_writes": list(row["psg"]),
            "child_process": {"status": receipt["status"], "return_code": 0,
                "bound_violation": False, "cleanup": "confirmed",
                "wall_seconds": round(float(receipt["wall_seconds"]), 6),
                "rss_bytes_peak": receipt["rss_bytes_peak"]}})
    return outcomes


def _finite(value: Any) -> bool:
    return type(value) in (int, float) and value >= 0 and (type(value) is int or math.isfinite(value))


def _enum(value: Any, allowed: set[str]) -> str:
    return value if type(value) is str and value in allowed else "unavailable"


def _failure_summary(fixture: Any, result: Any, process: Any, streams: Any,
        nested_path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = fixture._original_control_failure_summary(result, process, streams, nested_path)
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 2048:
            raise ValueError("summary-limit")
        value = json.loads(raw)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return {"stderr_reason": "unclassified", "case_id": None}
    # phase6_game owns this projection: it replaces streams and paths with enums.
    if not isinstance(value, dict) or set(value) - {"driver", "nested", "nested_count", "stderr_reason", "case"}:
        return {"stderr_reason": "unclassified", "case_id": None}
    for key in ("driver", "nested"):
        facts = value.get(key)
        if isinstance(facts, dict):
            kind = facts.get("scratch_tree_kind")
            facts["scratch_tree_kind"] = kind if type(kind) is str and kind in {
                "scratch-root-invalid", "symlink-directory", "scan-oserror",
                "unsafe-file-symlink", "symlink-file", "non-regular-file",
                "hardlink-file", "foreign-owner-file", "path-disappeared-during-scan"
            } else "unavailable"
    return value


def _process_summary(process: Any) -> dict[str, Any]:
    process = process if isinstance(process, dict) else {}
    wall = process.get("wall_seconds")
    return {"status": _enum(process.get("status"), DRIVER_STATUSES),
        "return_code": process.get("return_code") if type(process.get("return_code")) is int and -255 <= process["return_code"] <= 255 else None,
        "bound_violation": process.get("bound_violation") if type(process.get("bound_violation")) is bool else None,
        "bound_reason": _enum(process.get("bound_violation_reason"), BOUND_REASONS),
        "cleanup": _enum(process.get("process_group_cleanup"), CLEANUP_STATUSES),
        "wall_seconds": round(float(wall), 6) if _finite(wall) else None}


def _failed_receipt(work: pathlib.Path, maximum: int):
    try:
        receipt = _json(work / "process.json", maximum)
    except DiagnosticError:
        return type("Result", (), {"returncode": None})(), {}, {}
    rows = receipt.get("processes")
    process = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else {}
    streams = receipt.get("streams")
    return type("Result", (), {"returncode": process.get("return_code")})(), process, streams if isinstance(streams, dict) else {}


def _failure_reason(result: Any, process: Any, summary: dict[str, Any]) -> str:
    process = process if isinstance(process, dict) else {}
    if process.get("bound_violation") is True:
        return "child-bound-violation"
    if process.get("process_group_cleanup") == "unconfirmed":
        return "child-cleanup-unconfirmed"
    nested = summary.get("nested")
    if isinstance(nested, dict):
        if nested.get("bound") is True:
            return "child-bound-violation"
        if nested.get("cleanup") == "unconfirmed":
            return "child-cleanup-unconfirmed"
        if nested.get("return") not in (None, "unavailable", 0):
            return "nested-child-failure"
    code = getattr(result, "returncode", None)
    return "driver-nonzero" if type(code) is int and code != 0 else "boundary-error"


def run_diagnostic(build_arg: pathlib.Path, scope_arg: pathlib.Path,
        out_arg: pathlib.Path) -> tuple[dict[str, Any], int]:
    out, work_root = _prepare_output(out_arg)
    result: dict[str, Any] = {"schema": "genewhip-phase7-original-control-diagnostic-v1",
        "status": "unknown", "diagnostic_only": True, "qualification_accepted": False,
        "failure_reason": None, "identity": {}, "budget": {}, "runs": []}
    output_limit = MAX_OUTPUT_BYTES
    fixture = None
    try:
        if os.environ.get("GENEWHIP_PROCESS_CONTEXT") != "host-cleanup-v1":
            raise DiagnosticError("host-process-context-required")
        runtime = _module(ROOT / "scripts/evidence/v02_run.py", "phase7_control_v02_run")
        scope_path = scope_arg if scope_arg.is_absolute() else ROOT / scope_arg
        scope_path = scope_path.absolute()
        if not _safe_tree(scope_path, ROOT):
            raise DiagnosticError("execution-scope-path-invalid")
        scope_path = scope_path.resolve(strict=True)
        scope, limits = runtime.validate_execution_scope(scope_path, "full")
        output_limit = min(output_limit, limits["max_json_bytes"])
        started = _utc(os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT"))
        diagnostic_started = _utc(os.environ.get("GENEWHIP_CONTROL_DIAGNOSTIC_STARTED_AT"))
        if diagnostic_started != started:
            raise DiagnosticError("diagnostic-start-mismatch")
        now_mono = time.monotonic()
        now_utc = utc_now()
        runtime_deadline = started + datetime.timedelta(seconds=scope["qualification_batch"]["runtime_wall_seconds"])
        diagnostic_deadline = started + datetime.timedelta(seconds=DIAGNOSTIC_SECONDS - CLEANUP_RESERVE_SECONDS)
        deadline = min(runtime_deadline, diagnostic_deadline)
        if now_utc < started or now_utc >= deadline:
            raise DiagnosticError("diagnostic-deadline-exhausted")
        remaining = (deadline - now_utc).total_seconds()
        if remaining <= limits["cleanup_grace_seconds"] + 5:
            raise DiagnosticError("diagnostic-deadline-exhausted")
        build = build_arg if build_arg.is_absolute() else ROOT / build_arg
        build = build.absolute()
        if not _safe_tree(build, ROOT):
            raise DiagnosticError("build-root-invalid")
        build = build.resolve(strict=True)
        owned_roots = runtime.resolve_owned_output_roots(scope)
        if not any(build.is_relative_to(root) for root in owned_roots):
            raise DiagnosticError("build-root-unowned")
        phase6 = _module(ROOT / "tests/fixtures/phase6_game.py", "phase7_control_fixture")
        phase4 = _module(ROOT / "tests/fixtures/phase4_game.py", "phase7_control_phase4")
        report_module = _module(ROOT / "scripts/evidence/phase4_report.py", "phase7_control_report")
        cases = _current_cases(phase4, report_module, limits["max_json_bytes"])
        headless = build / "tools/session/gw_headless"
        cache = build / "CMakeCache.txt"
        if not _safe_tree(headless, ROOT) or not _safe_tree(cache, ROOT):
            raise DiagnosticError("build-identity-invalid")
        headless_sha = _sha(_read(headless, limits["max_binary_file_bytes"]))
        build_sha = _sha(_read(cache, limits["max_json_bytes"]))
        if not os.access(headless, os.X_OK):
            raise DiagnosticError("build-identity-invalid")
        scope_bytes = _read(scope_path, limits["max_json_bytes"])
        identity = {**report_module.GAME_IDENTITIES,
            "scope_sha256": _sha(scope_bytes), "build_configuration_sha256": build_sha,
            "headless_client_sha256": headless_sha}
        if not any(work_root.resolve(strict=True).is_relative_to(root) for root in owned_roots):
            raise DiagnosticError("output-work-root-unowned")
        runtime_scope = {**scope, "qualification_started_at": started.isoformat(),
            "qualification_deadline": deadline.isoformat()}
        scope_copy = work_root / "execution-scope.json"
        _write_new(scope_copy, (json.dumps(runtime_scope, sort_keys=True, indent=2) + "\n").encode(), limits["max_json_bytes"])
        scoped = {**runtime_scope, "_scope_path": str(scope_copy.resolve(strict=True))}
        phase6.set_execution_scope(scoped)
        fixture = phase6
        deadline_mono = now_mono + remaining
        result["identity"] = identity
        result["budget"] = {"diagnostic_claim_started_at": diagnostic_started.isoformat(),
            "qualification_started_at": started.isoformat(), "runtime_deadline": runtime_deadline.isoformat(),
            "diagnostic_deadline": diagnostic_deadline.isoformat(), "effective_deadline": deadline.isoformat(),
            "maximum_child_wall_seconds": min(600, limits["wall_seconds"]),
            "cleanup_grace_seconds": limits["cleanup_grace_seconds"]}
        for repetition in (1, 2):
            left = deadline_mono - time.monotonic()
            timeout = min(600.0, float(limits["wall_seconds"]), left - 5.0)
            if left <= limits["cleanup_grace_seconds"] + 5 or timeout < 30:
                result["failure_reason"] = "insufficient-headroom"
                result["runs"].append({"repetition": repetition, "status": "unknown",
                    "failure_reason": "insufficient-headroom", "outer_process": None,
                    "nested_failure": None, "case_outcomes": []})
                break
            work = work_root / f"controls-{repetition}"
            retained = work / "artifacts"
            work.mkdir(mode=0o700)
            retained.mkdir(mode=0o700)
            report_path, nested_path = work / "control.json", work / "nested-processes.json"
            command = [sys.executable, "-I", str(ROOT / "tests/fixtures/phase4_game.py"), str(headless),
                "--outer-process-group", "--report", str(report_path), "--retain-artifacts", str(retained),
                "--execution-scope", scoped["_scope_path"], "--process-receipt", str(nested_path)]
            try:
                child, process, streams = phase6.shared_launch(headless, command, work, report_path, timeout)
            except Exception:
                child, process, streams = _failed_receipt(work, limits["max_json_bytes"])
                failure = _failure_summary(phase6, child, process, streams, nested_path)
                reason = _failure_reason(child, process, failure)
                result["runs"].append({"repetition": repetition, "status": "fail",
                    "failure_reason": reason, "outer_process": _process_summary(process),
                    "nested_failure": failure, "case_outcomes": []})
                result.update(status="fail", failure_reason=reason)
                break
            failure = _failure_summary(phase6, child, process, streams, nested_path)
            run = {"repetition": repetition, "status": "unknown", "failure_reason": None,
                "outer_process": _process_summary(process), "nested_failure": failure, "case_outcomes": []}
            result["runs"].append(run)
            if (getattr(child, "returncode", None) != 0 or not isinstance(process, dict) or
                    type(process.get("return_code")) is not int or process["return_code"] != 0 or
                    process.get("status") != "completed" or process.get("bound_violation") is not False or
                    process.get("process_group_cleanup") != "confirmed" or
                    not _finite(process.get("wall_seconds")) or process["wall_seconds"] > limits["wall_seconds"]):
                reason = _failure_reason(child, process, failure)
                run.update(status="fail", failure_reason=reason)
                result.update(status="fail", failure_reason=reason)
                break
            try:
                case_outcomes = _validate_report(report_path, nested_path, build, phase4,
                    report_module, cases, identity, limits)
            except DiagnosticError as exc:
                reason = "nested-receipt-invalid" if exc.code == "nested-receipt-invalid" else \
                    "nested-child-failure" if exc.code == "nested-child-failure" else "control-report-invalid"
                run.update(status=exc.outcome, failure_reason=reason)
                result.update(status=exc.outcome, failure_reason=reason)
                break
            run.update(status="pass", case_outcomes=case_outcomes)
        else:
            result["status"] = "pass"
    except DiagnosticError as exc:
        result.update(status=exc.outcome, failure_reason=exc.code)
    except Exception:
        result.update(status="unknown", failure_reason="diagnostic-preflight-failed")
    finally:
        if fixture is not None:
            try:
                fixture.set_execution_scope(None)
            except Exception:
                result.update(status="unknown", failure_reason="diagnostic-cleanup-failed")
        result["qualification_accepted"] = False
        result["diagnostic_only"] = True
        payload = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        _write_new(out, payload, output_limit)
    return result, 0 if result["status"] == "pass" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--scope", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        result, code = run_diagnostic(args.build, args.scope, args.out)
        print("control_diagnostic_status=" + result["status"])
        print("qualification_accepted=false")
        return code
    except DiagnosticError as exc:
        print("BLOCKED: control diagnostic " + exc.code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
