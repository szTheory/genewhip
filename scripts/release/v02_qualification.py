#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-bound v0.2 qualification plan, runtime orchestration and proof close."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile
import time
import datetime
import urllib.parse
import uuid
import shutil
import stat
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIMENSIONS = ("core", "host", "host-native", "media", "safety", "determinism", "measurements",
              "public-matrix", "package", "docs", "privacy", "rights")
REQUIRED_DIMENSIONS = DIMENSIONS
IDENTITY_FIELDS = ("source_sha", "head_sha", "base_sha", "run_id", "run_attempt")
NATIVE_REQUIRED = "host-native"
RECOVERY_CAMPAIGN_SCHEMA = "genewhip.v02-recovery-campaign.v1"
ATTEMPT3_CUMULATIVE_LIMITS = {
    "campaign_control_bytes": 66833, "campaign_elapsed_seconds": 360,
    "campaign_host_invocations": 4, "campaign_native_rss_pid_queries": 8388608,
    "campaign_observer_queries": 24, "campaign_retained_bytes": 8408394,
    "campaign_rss_samples": 2048, "campaign_start_events": 130,
    "campaign_status_helper_starts": 124, "campaign_status_output_bytes": 10485760,
    "campaign_wrapper_calls": 4, "future_control_bytes_reserved": 65536,
    "future_elapsed_seconds_reserved": 120, "future_host_invocations_reserved": 1,
    "future_native_rss_queries_reserved": 4194304, "future_observer_queries_reserved": 16,
    "future_retained_bytes_reserved": 8388608, "future_rss_samples_reserved": 1024,
    "future_starts_reserved": 84, "future_status_helpers_reserved": 80,
    "future_status_output_bytes_reserved": 5242880, "future_wrapper_calls_reserved": 2,
    "prior_control_bytes_measured": 1297, "prior_controller_starts_measured": 12,
    "prior_control_entries_measured": 2,
    "future_control_entries_reserved": 1, "campaign_control_entries": 3,
    "prior_elapsed_seconds_reserved": 240, "prior_host_invocations_used": 3,
    "prior_native_rss_queries_reserved": 4194304, "prior_observer_queries_measured": 8,
    "prior_owner_rss_samples_unknown_reserved": 1016,
    "prior_owner_starts_unknown_reserved": 34,
    "prior_owner_status_helpers_unknown_reserved": 34,
    "prior_retained_bytes_measured": 19786, "prior_rss_samples_measured": 8,
    "prior_rss_samples_reserved": 1024, "prior_starts_reserved": 46,
    "prior_status_helpers_measured": 10, "prior_status_helpers_reserved": 44,
    "prior_status_output_bytes_reserved": 5242880, "prior_wrapper_calls_used": 2,
}
ATTEMPT4_CUMULATIVE_LIMITS = {
    **ATTEMPT3_CUMULATIVE_LIMITS,
    "prior_host_invocations_used": 4,
    "campaign_elapsed_seconds": 480,
    "prior_elapsed_seconds_reserved": 360,
    "campaign_control_bytes": 69222,
    "campaign_host_invocations": 5,
    "prior_control_bytes_measured": 3686,
    "prior_control_entries_measured": 3,
    "campaign_control_entries": 4,
}
PUBLIC_PHASE5_HISTORY = {
    "phase5-baseline.json", "phase5-baseline-roster.json", "phase5-failure-inventory.json",
    "phase5-current-reference.json", "phase5-reference-d118.json",
}


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: pathlib.Path, *args: str, check: bool = True) -> str:
    """Run a bounded Git read/write without including remote diagnostics in errors."""
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True,
                                capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("public-snapshot-git-command-failed") from None
    if check and result.returncode:
        raise ValueError("public-snapshot-git-command-failed")
    return result.stdout.strip()


def _external(argv: list[str], *, cwd: pathlib.Path = ROOT, timeout: int = 120,
              check: bool = True, env: dict[str, str] | None = None,
              phase: str | None = None,
              owned_roots: tuple[pathlib.Path, ...] = (),
              scratch_limit_bytes: int | None = None,
              stdout_limit_bytes: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run delivery commands under the established monitored PGID boundary."""
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    started_at = child_env.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    phase = phase or child_env.get("GENEWHIP_QUALIFICATION_PHASE") or "preparation"
    if phase == "preparation" and child_env.get("GENEWHIP_RECOVERY_CAMPAIGN_SHA256"):
        phase = "runtime"
    if started_at:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _require_hosted_budget(started_at, now, scope, phase=phase)
        elapsed = (_parse_utc(now) - _parse_utc(started_at)).total_seconds()
        batch = scope["qualification_batch"]
        boundary = (batch["runtime_wall_seconds"] if phase == "runtime" else
            batch["runtime_wall_seconds"] + batch["package_wall_seconds"] if phase == "package" else
            batch["wall_seconds"] if phase == "close" else
            batch["wall_seconds"] - batch["close_wall_seconds"])
        timeout = min(timeout, max(0.001, boundary - elapsed))
    limits = dict(scope["per_child_limits"])
    if scratch_limit_bytes is not None:
        limits["max_scratch_bytes"] = min(limits["max_scratch_bytes"], scratch_limit_bytes)
    if stdout_limit_bytes is not None:
        if stdout_limit_bytes <= 0:
            raise ValueError("hosted-delivery-stdout-limit-invalid")
        for key in ("max_stdout_stderr_bytes", "max_capture_bytes", "max_retained_bytes"):
            limits[key] = min(limits[key], stdout_limit_bytes)
    limits["wall_seconds"] = timeout
    scratch = ROOT / "build/v02/coordinator-external-attempts"
    label = f"external-{os.getpid()}-{time.monotonic_ns()}"
    temporary_root = scratch / (label + ".tmp")
    temporary_root.mkdir(parents=True, exist_ok=False)
    child_env.update({"TMPDIR": str(temporary_root), "TMP": str(temporary_root),
                      "TEMP": str(temporary_root)})
    try:
        attempt = _bounded_command(argv, limits=limits, scratch=scratch, timeout=timeout,
            label=label, env=child_env, cwd=cwd, check=check,
            scratch_roots=(temporary_root, *owned_roots))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise ValueError("hosted-delivery-command-unavailable:" + pathlib.Path(argv[0]).name) from None
    result = subprocess.CompletedProcess(argv, int(attempt.get("returncode") or 0),
        str(attempt.get("streams", {}).get("stdout", {}).get("text", attempt.get("stdout_tail", ""))),
        str(attempt.get("streams", {}).get("stderr", {}).get("text", attempt.get("stderr_tail", ""))))
    if stdout_limit_bytes is not None:
        stream = attempt.get("streams", {}).get("stdout", {})
        encoded = result.stdout.encode("utf-8")
        if (stream.get("truncated") is not False or
                stream.get("observed_bytes") != stream.get("retained_bytes") or
                stream.get("observed_bytes", stdout_limit_bytes + 1) > stdout_limit_bytes or
                stream.get("sha256") != hashlib.sha256(encoded).hexdigest()):
            raise ValueError("hosted-delivery-stdout-not-byte-exact")
    if result.returncode == 0 and attempt.get("process_group_cleanup") == "confirmed":
        shutil.rmtree(temporary_root)
    if check and result.returncode:
        combined = (result.stdout + "\n" + result.stderr).lower()
        if any(term in combined for term in ("not logged in", "not authenticated", "unauthorized", "401")):
            raise ValueError("github-authentication-required")
        raise ValueError("hosted-delivery-command-failed:" + pathlib.Path(argv[0]).name)
    return result


def read_bounded_git_blob(candidate: pathlib.Path, ref: str) -> bytes:
    """Read a small Git blob through the monitored process-group boundary."""
    ceiling = 128 * 1024
    result = _external(["git", "show", ref], cwd=candidate, timeout=15,
        scratch_limit_bytes=ceiling, stdout_limit_bytes=ceiling)
    return result.stdout.encode("utf-8")


def _gh_json(repository: str, endpoint: str, *, phase: str = "preparation") -> Any:
    encoded = urllib.parse.quote(repository, safe="/")
    result = _external(["gh", "api", f"repos/{encoded}/{endpoint}"], timeout=45, phase=phase)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-response-invalid") from None


def _parse_utc(value: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("hosted-time-identity-invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("hosted-time-identity-invalid")
    return parsed.astimezone(datetime.timezone.utc)


def _validate_hosted_run(run: dict[str, Any], repository: str,
                         expected_source_sha: str, *, allow_active: bool = False,
                         expected_event: str = "push", expected_nonce: str | None = None) -> dict[str, str]:
    """Validate the selected exact-source attempt and immutable run facts."""
    if not isinstance(run, dict):
        raise ValueError("hosted-run-record-invalid")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    created_at = run.get("created_at")
    repo_record = run.get("repository")
    path = run.get("path")
    if (not isinstance(run_id, (int, str)) or not str(run_id).isdigit()
            or not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1
            or not isinstance(path, str)
            or path.split("@", 1)[0] != ".github/workflows/ci.yml"
            or run.get("event") != expected_event or run.get("head_branch") != "main"
            or run.get("head_sha") != expected_source_sha
            or (run.get("status") != "completed" and not (allow_active and run.get("status") in
                {"queued", "in_progress", "requested", "waiting", "pending"}))
            or (run.get("status") == "completed" and run.get("conclusion") != "success")
            or not isinstance(repo_record, dict) or repo_record.get("full_name") != repository
            or not isinstance(created_at, str)):
        raise ValueError("hosted-run-source-event-or-result-mismatch")
    expected_title = "Plan10 qualification " + expected_nonce if expected_nonce else None
    if expected_title is not None and run.get("display_title") != expected_title:
        raise ValueError("hosted-run-dispatch-nonce-mismatch")
    _parse_utc(created_at)
    return {"run_id": str(run_id), "run_attempt": str(attempt), "created_at": created_at,
            "event": expected_event}


def _validate_workflow_clock(started_at: str, run_created_at: str,
                             nonce: str, base_sha: str,
                             now: str | None = None,
                             phase: str = "runtime") -> str:
    """Validate carried publication time against immutable Actions queue evidence."""
    start = _parse_utc(started_at)
    created = _parse_utc(run_created_at)
    current = _parse_utc(now or datetime.datetime.now(datetime.timezone.utc).isoformat())
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("qualification-dispatch-nonce-invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise ValueError("qualification-dispatch-base-invalid")
    if start > current or created < start or created > current:
        raise ValueError("qualification-dispatch-clock-invalid")
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    _require_hosted_budget(started_at, current.isoformat(), scope, phase=phase)
    return started_at


def _bind_qualification_clock(journal: dict[str, Any], run_created_at: str) -> dict[str, Any]:
    """Keep the publication journal start as the immutable batch cutoff."""
    started_at = journal.get("started_at") if isinstance(journal, dict) else None
    if not isinstance(started_at, str):
        raise ValueError("hosted-delivery-journal-clock-missing")
    start = _parse_utc(started_at)
    run_created = _parse_utc(run_created_at)
    now = datetime.datetime.now(datetime.timezone.utc)
    if start > now:
        raise ValueError("hosted-delivery-journal-clock-is-future")
    if run_created < start or run_created > now:
        raise ValueError("hosted-run-creation-clock-invalid")
    existing = journal.get("qualification_started_at")
    env_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if existing is not None and existing != started_at:
        raise ValueError("hosted-delivery-journal-qualification-clock-replaced")
    if env_start is not None and env_start != started_at:
        raise ValueError("workflow-qualification-clock-does-not-match-publication-journal")
    if existing is None:
        journal["qualification_started_at"] = started_at
    prior_run_created = journal.get("selected_run_created_at")
    if prior_run_created is not None and prior_run_created != run_created_at:
        raise ValueError("selected-hosted-run-creation-clock-replaced")
    journal["selected_run_created_at"] = run_created_at
    return journal


def _check_environment_clock(scope: dict[str, Any], phase: str | None = None) -> None:
    started = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if started:
        _require_hosted_budget(started, datetime.datetime.now(datetime.timezone.utc).isoformat(),
            scope, phase=phase or os.environ.get("GENEWHIP_QUALIFICATION_PHASE") or "package")


def _require_hosted_budget(started_at: str, now: str,
                           scope: dict[str, Any], *, phase: str | None = None) -> float:
    """Keep one shared deadline and the declared final-close time reserved."""
    batch = scope.get("qualification_batch") if isinstance(scope, dict) else None
    if not isinstance(batch, dict):
        raise ValueError("qualification-common-cutoff-invalid")
    total = batch.get("wall_seconds")
    runtime = batch.get("runtime_wall_seconds")
    package = batch.get("package_wall_seconds")
    close = batch.get("close_wall_seconds")
    if (any(not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in (total, runtime, package, close))
            or runtime + package + close > total):
        raise ValueError("qualification-common-cutoff-invalid")
    elapsed = (_parse_utc(now) - _parse_utc(started_at)).total_seconds()
    if elapsed < 0 or elapsed >= total:
        raise ValueError("qualification-common-cutoff-exhausted")
    remaining = total - elapsed
    if phase == "runtime" and elapsed >= runtime:
        raise ValueError("qualification-runtime-partition-deadline-exhausted")
    if phase == "package" and elapsed >= runtime + package:
        raise ValueError("qualification-package-partition-deadline-exhausted")
    if remaining <= close and phase != "close":
        raise ValueError("qualification-final-close-reserve-exhausted")
    return remaining


def _campaign_projection(path: pathlib.Path, scope_path: pathlib.Path,
                         journal_path: pathlib.Path | None = None,
                         *, phase: str = "package",
                         expected_sha256: str | None = None,
                         require_return: bool = True,
                         selection: str = "15",
                         continuation_path: pathlib.Path | None = None,
                         continuation_purpose: str = "original17",
                         preparation_only: bool = False,
                         allow_unconsumed_attempt4: bool = False,
                         allow_live_evidence: bool = False) -> dict[str, Any]:
    """Reopen an immutable, started Plan 15 campaign before delivery effects."""
    expected = ROOT / "build/v02/campaign15/campaign.json"
    scope_expected = ROOT / "evidence/v02-execution.json"
    candidate = path if path.is_absolute() else ROOT / path
    candidate = pathlib.Path(os.path.abspath(candidate))
    scope_candidate = scope_path if scope_path.is_absolute() else ROOT / scope_path
    scope_candidate = pathlib.Path(os.path.abspath(scope_candidate))
    if selection not in ("15", "16", "17"):
        raise ValueError("recovery-campaign-selection-invalid")
    if preparation_only and (selection != "17" or require_return):
        raise ValueError("continuation-preparation-purpose-invalid")
    if continuation_purpose not in ("original17", "current-native-preparation", "current-native-return"):
        raise ValueError("continuation-purpose-invalid")
    if continuation_purpose == "current-native-preparation" and not (
            selection == "17" and preparation_only and not require_return
            and continuation_path is not None):
        raise ValueError("current-native-purpose-requires-prepare-only")
    if continuation_purpose == "current-native-return" and not (
            selection == "17" and require_return and not preparation_only
            and continuation_path is not None):
        raise ValueError("current-return-purpose-requires-accepted-return")
    if selection == "17" and not require_return and not preparation_only:
        raise ValueError("continuation-preparation-purpose-required")
    phase_dir = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    admission_selection = "16" if selection == "17" else selection
    admission_path = ROOT / (phase_dir + f"/07-{admission_selection}-ADMISSION.json")
    def has_symlink_component(item: pathlib.Path) -> bool:
        try:
            relative = item.relative_to(ROOT)
        except ValueError:
            return True
        current = ROOT
        if current.is_symlink():
            return True
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return True
        return False
    if (candidate != pathlib.Path(os.path.abspath(expected)) or candidate.is_symlink()
            or has_symlink_component(candidate.parent)
            or not candidate.is_file() or expected_sha256 is None):
        raise ValueError("recovery-campaign-path-invalid")
    if (scope_candidate != pathlib.Path(os.path.abspath(scope_expected))
            or has_symlink_component(scope_candidate) or not scope_candidate.is_file()):
        raise ValueError("recovery-campaign-scope-path-invalid")
    scope_info = scope_candidate.lstat()
    if (scope_info.st_uid != os.getuid() or scope_info.st_nlink != 1
            or scope_info.st_size > 1024 * 1024):
        raise ValueError("recovery-campaign-scope-file-invalid")
    scope_path = scope_candidate
    path = candidate
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 65536:
        raise ValueError("recovery-campaign-file-invalid")
    try:
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("recovery-campaign-record-invalid")
        start = value["started_at"]
        canonical = json.dumps({key: item for key, item in value.items()
                                if key != "record_sha256"}, sort_keys=True,
                               separators=(",", ":")).encode()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise ValueError("recovery-campaign-record-invalid") from None
    if (value.get("schema") != RECOVERY_CAMPAIGN_SCHEMA
            or value.get("status") != "started"
            or value.get("campaign_id") != "phase7-renewed-2026-10-30"
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256
            or value.get("record_sha256") != hashlib.sha256(canonical).hexdigest()
            or value.get("scope_path") != "evidence/v02-execution.json"
            or value.get("scope_sha256") != _sha(scope_path)
            or value.get("journal_path") != "build/v02/campaign15/hosted-delivery-journal.json"
            or has_symlink_component(admission_path) or not admission_path.is_file()
            or admission_path.stat().st_uid != os.getuid()
            or admission_path.stat().st_nlink != 1 or admission_path.stat().st_size > 65536):
        raise ValueError("recovery-campaign-identity-invalid")
    admission = json.loads(admission_path.read_bytes())
    admission_sha = _sha(admission_path)
    if selection == "16":
        _validate_current_admission16(admission, admission_sha)
    elif selection == "17":
        if continuation_path is None:
            raise ValueError("continuation-input-required")
        continuation_spec = importlib.util.spec_from_file_location(
            "v02_continuation_gate", ROOT / "scripts/release/v02_continuation.py")
        if continuation_spec is None or continuation_spec.loader is None:
            raise ValueError("continuation-module-unavailable")
        continuation = importlib.util.module_from_spec(continuation_spec)
        continuation_spec.loader.exec_module(continuation)
        if continuation_purpose == "current-native-preparation":
            continuation.validate_current_native_continuation(ROOT, continuation_path)
        elif continuation_purpose == "current-native-return":
            continuation.validate_current_native_return(ROOT, continuation_path)
        else:
            continuation.validate_attestation(ROOT, continuation_path,
                require_candidate=require_return, require_return=require_return)
    campaign_admission_resumed = value.get("admission_sha256") != admission_sha
    if (value.get("admission_sha256") != admission_sha
            and not (_validate_campaign_resume16(admission, value, expected_sha256,
                    admission_sha, allow_unconsumed=allow_unconsumed_attempt4,
                    allow_live=allow_live_evidence or (require_return and selection == "16")
                        or selection == "17")
                if selection in ("16", "17") else
                _validate_campaign_resume(admission, value, expected_sha256, admission_sha))):
        raise ValueError("recovery-campaign-identity-invalid")
    started = _parse_utc(start)
    now = datetime.datetime.now(datetime.timezone.utc)
    if started > now or (now - started).total_seconds() >= 86400:
        raise ValueError("recovery-campaign-clock-invalid")
    try:
        batch = json.loads(scope_path.read_text(encoding="utf-8"))["qualification_batch"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        raise ValueError("recovery-campaign-scope-invalid") from None
    required_batch = {"wall_seconds": 86400, "runtime_wall_seconds": 64800,
        "package_wall_seconds": 14400, "close_wall_seconds": 7200}
    if not isinstance(batch, dict) or any(batch.get(key) != expected
            for key, expected in required_batch.items()):
        raise ValueError("recovery-campaign-scope-policy-mismatch")
    expected_cutoffs = {
        "runtime_cutoff": (started + datetime.timedelta(seconds=64800)).isoformat(),
        "package_cutoff": (started + datetime.timedelta(seconds=79200)).isoformat(),
        "global_cutoff": (started + datetime.timedelta(seconds=86400)).isoformat(),
    }
    for key, cutoff in expected_cutoffs.items():
        if value.get(key) != cutoff:
            raise ValueError("recovery-campaign-cutoff-mismatch")
    _require_hosted_budget(start, now.isoformat(), {"qualification_batch": batch}, phase=phase)
    env_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if env_start is not None and env_start != start:
        raise ValueError("recovery-campaign-environment-clock-conflict")
    if journal_path is not None:
        resolved = journal_path if journal_path.is_absolute() else ROOT / journal_path
        expected_journal = pathlib.Path(os.path.abspath(ROOT / value["journal_path"]))
        resolved = pathlib.Path(os.path.abspath(resolved))
        if (resolved != expected_journal or has_symlink_component(resolved.parent)
                or resolved.is_symlink()):
            raise ValueError("recovery-campaign-journal-path-conflict")
        if resolved.exists():
            if resolved.is_symlink() or not resolved.is_file() or resolved.stat().st_size > 65536:
                raise ValueError("recovery-campaign-journal-invalid")
            try:
                journal = json.loads(resolved.read_bytes())
            except (OSError, json.JSONDecodeError):
                raise ValueError("recovery-campaign-journal-invalid") from None
            if not isinstance(journal, dict):
                raise ValueError("recovery-campaign-journal-invalid")
            if journal.get("started_at") != start:
                raise ValueError("recovery-campaign-journal-clock-conflict")
    if require_return and selection == "16":
        _validate_campaign_return16(value, expected_sha256, admission, admission_sha)
    elif require_return and selection == "17" and continuation_purpose == "original17":
        continuation_spec = importlib.util.spec_from_file_location(
            "v02_continuation_return_gate", ROOT / "scripts/release/v02_continuation.py")
        if continuation_spec is None or continuation_spec.loader is None:
            raise ValueError("continuation-module-unavailable")
        continuation = importlib.util.module_from_spec(continuation_spec)
        continuation_spec.loader.exec_module(continuation)
        if continuation_path is None:
            raise ValueError("continuation-input-required")
        continuation.validate_attestation(ROOT, continuation_path,
            require_candidate=True, require_return=True)
    elif require_return and selection != "17":
        return_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-RETURN.md"
        live_path = ROOT / "build/v02/recovery15/live.json"
        review_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-RETURN-REVIEW.md"
        security_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-SECURITY.md"
        for item in (return_path, live_path, review_path, security_path):
            if item.is_symlink() or not item.is_file() or item.stat().st_size > 65536:
                raise ValueError("recovery-campaign-return-gate-missing")
            info = item.lstat()
            if info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("recovery-campaign-return-gate-file-invalid")
        return_text = return_path.read_text(encoding="utf-8")
        review_text = review_path.read_text(encoding="utf-8")
        security_text = security_path.read_text(encoding="utf-8")
        live = json.loads(live_path.read_bytes())
        live_sha = hashlib.sha256(live_path.read_bytes()).hexdigest()
        admission_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
        source_review_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-REVIEW.md"
        if (admission_path.is_symlink() or not admission_path.is_file()
                or admission_path.stat().st_size > 65536
                or source_review_path.is_symlink() or not source_review_path.is_file()
                or source_review_path.stat().st_size > 65536):
            raise ValueError("recovery-campaign-current-admission-missing")
        for item in (admission_path, source_review_path):
            item_info = item.lstat()
            if item_info.st_uid != os.getuid() or item_info.st_nlink != 1:
                raise ValueError("recovery-campaign-current-admission-file-invalid")
        admission = json.loads(admission_path.read_bytes())
        admission_sha = hashlib.sha256(admission_path.read_bytes()).hexdigest()
        protocol_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PROTOCOL.md"
        source_pins = admission.get("sources") if isinstance(admission, dict) else None
        if (admission.get("schema") != "genewhip.phase7-wrapper-return-admission.v1"
                or admission.get("status") != "candidate"
                or (admission_sha != value.get("admission_sha256") and not campaign_admission_resumed)
                or not isinstance(source_pins, dict)
                or not {"scripts/release/v02_qualification.py",
                        "tests/evidence/phase7_wrapper_return.py",
                        "tests/evidence/phase7_wrapper_return_contract.py"}.issubset(source_pins)
                or protocol_path.is_symlink() or not protocol_path.is_file()
                or hashlib.sha256(protocol_path.read_bytes()).hexdigest() != admission.get("protocol_sha256")):
            raise ValueError("recovery-campaign-current-admission-invalid")
        for relative, digest in source_pins.items():
            candidate_source = pathlib.Path(relative)
            if (not isinstance(relative, str) or candidate_source.is_absolute()
                    or ".." in candidate_source.parts or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("recovery-campaign-current-source-pin-invalid")
            source_path = ROOT / candidate_source
            if (has_symlink_component(source_path) or not source_path.is_file()
                    or hashlib.sha256(source_path.read_bytes()).hexdigest() != digest):
                raise ValueError("recovery-campaign-current-source-stale:" + relative)
        interpreter = admission.get("interpreter")
        interpreter_path = pathlib.Path(sys.executable)
        expected_interpreter = {"executable": sys.executable,
            "sha256": hashlib.sha256(interpreter_path.read_bytes()).hexdigest(),
            "version": sys.version, "platform": {"system": platform.system(),
                "release": platform.release(), "machine": platform.machine()}}
        if interpreter != expected_interpreter:
            raise ValueError("recovery-campaign-current-interpreter-stale")
        source_review = source_review_path.read_text(encoding="utf-8")
        source_review_sha = hashlib.sha256(source_review_path.read_bytes()).hexdigest()
        security_sha = hashlib.sha256(security_path.read_bytes()).hexdigest()
        source_pin_sha = hashlib.sha256(json.dumps(source_pins, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if ("Independent review: ACCEPTED" not in source_review
                or "reviewer_role: gsd-code-reviewer" not in source_review
                or "reviewer_model: gpt-6-luna" not in source_review
                or "author_role: gsd-executor" not in source_review
                or "source-review: current-source-and-packet" not in source_review
                or "unresolved high/critical: 0" not in source_review
                or f"packet_sha256: {admission_sha}" not in source_review
                or f"protocol_sha256: {admission['protocol_sha256']}" not in source_review):
            raise ValueError("recovery-campaign-current-source-review-rejected")
        if ("status: accepted" not in return_text
                or f"campaign_sha256: {expected_sha256}" not in return_text
                or f"live_sha256: {live_sha}" not in return_text
                or f"packet_sha256: {admission_sha}" not in return_text
                or f"source_pins_sha256: {source_pin_sha}" not in return_text
                or "Independent review: ACCEPTED" not in review_text
                or "reviewer_role: gsd-code-reviewer" not in review_text
                or "reviewer_model: gpt-6-luna" not in review_text
                or "unresolved high/critical: 0" not in review_text
                or f"campaign_sha256: {expected_sha256}" not in review_text
                or f"live_sha256: {live_sha}" not in review_text
                or f"packet_sha256: {admission_sha}" not in review_text
                or f"source_pins_sha256: {source_pin_sha}" not in review_text
                or f"source_review_sha256: {source_review_sha}" not in return_text
                or f"security_sha256: {security_sha}" not in return_text
                or f"security_sha256: {security_sha}" not in review_text
                or "reviewer_role: gsd-security-auditor" not in security_text
                or "reviewer_model: gpt-6.1-sol" not in security_text
                or "Independent security disposition: ACCEPTED" not in security_text
                or "unresolved current high/critical: 0" not in security_text
                or f"packet_sha256: {admission_sha}" not in security_text
                or f"source_pins_sha256: {source_pin_sha}" not in security_text
                or "residual T-07-07: nonblocking" not in security_text
                or "historical identity/liveness: UNKNOWN" not in security_text
                or live.get("status") != "pass" or live.get("campaign_sha256") != expected_sha256
                or live.get("packet_sha256") != admission_sha
                or live.get("review_sha256") != source_review_sha
                or live.get("source_pins") != source_pins):
            raise ValueError("recovery-campaign-return-gate-stale-or-rejected")
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = start
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = phase
    os.environ["GENEWHIP_RECOVERY_CAMPAIGN_SHA256"] = expected_sha256
    os.environ["GENEWHIP_RECOVERY_SELECTION"] = selection
    os.environ["GENEWHIP_RECOVERY_CONTINUATION_PURPOSE"] = continuation_purpose
    return value


def _validate_campaign_resume(admission: dict[str, Any], campaign: dict[str, Any],
                              campaign_sha256: str, current_admission_sha: str) -> bool:
    """Accept a reviewed packet correction while preserving a pre-child campaign clock."""
    resume = admission.get("resume_campaign") if isinstance(admission, dict) else None
    expected_paths = {
        "prior_review_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REVIEW.md",
        "prior_security_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-SECURITY.md",
        "rejection_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REJECTION.md",
    }
    if not isinstance(resume, dict) or any(resume.get(key) != value for key, value in expected_paths.items()):
        return False
    if (resume.get("schema") != "genewhip.phase7-return-campaign-resume.v1"
            or resume.get("campaign_sha256") != campaign_sha256
            or resume.get("campaign_started_at") != campaign.get("started_at")
            or resume.get("original_admission_sha256") != campaign.get("admission_sha256")
            or resume.get("original_admission_sha256") == current_admission_sha
            or resume.get("rejection_code") != "recovery-campaign-scope-policy-mismatch"):
        return False
    loaded = {}
    for key, relative in expected_paths.items():
        path = ROOT / relative
        current = ROOT
        path_has_symlink = current.is_symlink()
        for part in pathlib.Path(relative).parts:
            current = current / part
            path_has_symlink = path_has_symlink or current.is_symlink()
        if (path_has_symlink or not path.is_file() or path.stat().st_size > 65536):
            return False
        info = path.lstat()
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            return False
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if resume.get(key.replace("_path", "_sha256")) != digest:
            return False
        loaded[key] = path.read_text(encoding="utf-8")
    parent_sha = resume["original_admission_sha256"]
    campaign_sha = resume["campaign_sha256"]
    start = resume["campaign_started_at"]
    if ("Independent review: ACCEPTED" not in loaded["prior_review_path"]
            or f"packet_sha256: {parent_sha}" not in loaded["prior_review_path"]
            or "Independent source-level diagnostic eligibility: ACCEPTED" not in loaded["prior_security_path"]
            or f"packet_sha256: {parent_sha}" not in loaded["prior_security_path"]
            or f"initial packet SHA-256: `{parent_sha}`" not in loaded["rejection_path"]
            or f"campaign SHA-256 after rejection: `{campaign_sha}`" not in loaded["rejection_path"]
            or f"persisted started_at: `{start}`" not in loaded["rejection_path"]
            or "recovery-campaign-scope-policy-mismatch" not in loaded["rejection_path"]
            or "before any controller/owner/leaf child start" not in loaded["rejection_path"]):
        return False
    if resume.get("attempt_number") in (2, 3):
        if not _validate_failed_attempt1(admission, resume, campaign_sha256, start,
                                         current_admission_sha):
            return False
        if resume.get("attempt_number") == 3 and not _validate_failed_attempt2(
                admission, resume, campaign_sha256, start, current_admission_sha):
            return False
    elif resume.get("attempt_number", 1) != 1:
        return False
    return True


def _validate_campaign_resume16(admission: dict[str, Any], campaign: dict[str, Any],
                                campaign_sha256: str, current_admission_sha: str,
                                *, allow_unconsumed: bool = False,
                                allow_live: bool = False) -> bool:
    """Validate the exact new16 debit over immutable, already-consumed15 history."""
    phase_dir = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    resume = admission.get("resume_campaign") if isinstance(admission, dict) else None
    if (not isinstance(admission, dict)
            or admission.get("schema") != "genewhip.phase7-wrapper-return-admission.v1"
            or admission.get("status") != "candidate"
            or admission.get("plan") != "GW-07-16"
            or admission.get("cumulative_limits") != ATTEMPT4_CUMULATIVE_LIMITS
            or not isinstance(resume, dict)
            or resume.get("attempt_number") != 4
            or resume.get("attempt4_marker_path") != "build/v02/campaign15/attempt4-started.json"
            or resume.get("campaign_sha256") != campaign_sha256
            or resume.get("campaign_started_at") != campaign.get("started_at")
            or resume.get("prior_host_invocations_used") != 4
            or resume.get("prior_host_invocations_unknown_reserved") != 0
            or resume.get("attempt3_failure_before_case") != {
                "host_invocation": 4, "case_starts": 0,
                "reason": "recovery-campaign-identity-invalid"}):
        return False
    required = {
        "prior_packet_path": phase_dir + "/07-15-ADMISSION.json",
        "prior_protocol_path": phase_dir + "/07-15-PROTOCOL.md",
        "prior_return_path": phase_dir + "/07-15-RETURN.md",
        "prior_summary_path": phase_dir + "/07-15-SUMMARY.md",
        "authorization_path": phase_dir + "/07-16-AUTHORIZATION.md",
        "supersession_path": phase_dir + "/07-16-SUPERSESSION.md",
    }
    if any(resume.get(key) != value for key, value in required.items()):
        return False
    if (resume.get("attempt3_marker_path") != "build/v02/campaign15/attempt3-started.json"
            or not re.fullmatch(r"[0-9a-f]{64}", str(resume.get("attempt3_marker_sha256", "")))):
        return False
    for key, relative in required.items():
        path = ROOT / relative
        try:
            if (path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024
                    or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1
                    or hashlib.sha256(path.read_bytes()).hexdigest() != resume.get(key.replace("_path", "_sha256"))):
                return False
        except OSError:
            return False
    prior_path = ROOT / required["prior_packet_path"]
    prior_return_path = ROOT / required["prior_return_path"]
    prior_summary_path = ROOT / required["prior_summary_path"]
    try:
        prior = json.loads(prior_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    prior_sha = hashlib.sha256(prior_path.read_bytes()).hexdigest()
    try:
        prior_return = prior_return_path.read_text(encoding="utf-8")
        prior_summary = prior_summary_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if (prior.get("schema") != "genewhip.phase7-wrapper-return-admission.v1"
            or prior.get("status") != "candidate"
            or prior.get("plan") not in (None, "GW-07-15")
            or resume.get("attempt1_failure_manifest_sha256")
                != prior.get("resume_campaign", {}).get("failed_attempt", {}).get("sha256")
            or resume.get("attempt2_failure_manifest_sha256")
                != prior.get("resume_campaign", {}).get("attempt2_failure", {}).get("sha256")
            or "It was invoked once. It returned exit code 1 with `REJECT: recovery-campaign-identity-invalid`." not in prior_return
            or "No diagnostic case started." not in prior_return
            or "No `live.json` was created." not in prior_return
            or "| 2 | Failed after one actual approved attempt-3 invocation" not in prior_summary
            or "| 3 | Blocked." not in prior_summary
            or not _validate_campaign_resume(prior, campaign, campaign_sha256, prior_sha)):
        return False
    marker2_path = ROOT / "build/v02/campaign15/attempt2-started.json"
    marker3_path = ROOT / resume["attempt3_marker_path"]
    try:
        if (marker2_path.is_symlink() or not marker2_path.is_file()
                or hashlib.sha256(marker2_path.read_bytes()).hexdigest()
                    != prior.get("resume_campaign", {}).get("attempt2_marker_sha256")
                or marker2_path.stat().st_size != 625
                or marker3_path.is_symlink() or not marker3_path.is_file()
                or hashlib.sha256(marker3_path.read_bytes()).hexdigest()
                    != resume["attempt3_marker_sha256"]
                or marker3_path.stat().st_size != 2389):
            return False
        marker3 = json.loads(marker3_path.read_bytes())
        marker3_digest = marker3.pop("record_sha256")
        consumed3 = datetime.datetime.fromisoformat(marker3["consumed_at"])
        if (marker3.get("schema") != "genewhip.phase7-wrapper-return-attempt-entry.v1"
                or marker3.get("attempt") != 3
                or marker3.get("campaign_sha256") != campaign_sha256
                or marker3.get("campaign_started_at") != campaign.get("started_at")
                or marker3.get("packet_sha256") != prior_sha
                or marker3.get("attempt1_failure_manifest_sha256")
                    != resume.get("attempt1_failure_manifest_sha256")
                or marker3.get("attempt2_failure_manifest_sha256")
                    != resume.get("attempt2_failure_manifest_sha256")
                or marker3.get("cumulative_limits") != ATTEMPT3_CUMULATIVE_LIMITS
                or marker3.get("prior_host_invocations_used") != 3
                or marker3.get("prior_wrapper_calls_used") != 2
                or hashlib.sha256(json.dumps(marker3, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest() != marker3_digest
                or consumed3.tzinfo is None or consumed3 > datetime.datetime.now(datetime.timezone.utc)
                or consumed3 < datetime.datetime.fromisoformat(campaign.get("started_at", ""))):
            return False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return False
    marker = ROOT / resume["attempt4_marker_path"]
    if marker.exists() or marker.is_symlink():
        if allow_unconsumed:
            return False
        try:
            if (marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 65536
                    or marker.stat().st_uid != os.getuid() or marker.stat().st_nlink != 1):
                return False
            record = json.loads(marker.read_bytes())
            digest = record.pop("record_sha256")
            consumed = datetime.datetime.fromisoformat(record["consumed_at"])
            if (record.get("schema") != "genewhip.phase7-wrapper-return-attempt-entry.v1"
                    or record.get("attempt") != 4
                    or record.get("campaign_sha256") != campaign_sha256
                    or record.get("campaign_started_at") != campaign.get("started_at")
                    or record.get("packet_sha256") != current_admission_sha
                    or record.get("cumulative_limits") != ATTEMPT4_CUMULATIVE_LIMITS
                    or record.get("attempt3_marker_sha256") != resume.get("attempt3_marker_sha256")
                    or record.get("attempt1_failure_manifest_sha256") != resume.get("attempt1_failure_manifest_sha256")
                    or record.get("attempt2_failure_manifest_sha256") != resume.get("attempt2_failure_manifest_sha256")
                    or record.get("authorization_sha256") != resume.get("authorization_sha256")
                    or hashlib.sha256(json.dumps(record, sort_keys=True,
                        separators=(",", ":")).encode()).hexdigest() != digest
                    or consumed.tzinfo is None or consumed > datetime.datetime.now(datetime.timezone.utc)
                    or consumed < datetime.datetime.fromisoformat(campaign.get("started_at", ""))):
                return False
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False
    elif not allow_unconsumed:
        return False
    root = ROOT / "build/v02/recovery15"
    try:
        if root.is_symlink() or not root.is_dir():
            return False
        names = sorted(os.listdir(root))
        lock = root / ".limits.lock"
        allowed_names = [".limits.lock"]
        if marker.is_file() and not marker.is_symlink():
            allowed_names.extend(name for name in ("case-1", "case-2") if (root / name).exists())
            if allow_live and (root / "live.json").is_file() and not (root / "live.json").is_symlink():
                allowed_names.append("live.json")
        if (names != sorted(allowed_names) or lock.is_symlink() or not lock.is_file()
                or lock.stat().st_uid != os.getuid() or lock.stat().st_nlink != 1
                or lock.stat().st_size != 0):
            return False
        total_bytes = 0
        total_entries = 0
        if "live.json" in allowed_names:
            live_path = root / "live.json"
            if (live_path.stat().st_uid != os.getuid() or live_path.stat().st_nlink != 1
                    or live_path.stat().st_size > 65536):
                return False
            live = json.loads(live_path.read_bytes())
            if (live.get("schema") != "genewhip.phase7-wrapper-return.v1"
                    or live.get("attempt_number") != 4 or live.get("status") != "pass"
                    or live.get("campaign_sha256") != campaign_sha256
                    or live.get("packet_sha256") != current_admission_sha):
                return False
            total_bytes += live_path.stat().st_size
            total_entries += 1
        for name in allowed_names[1:]:
            if name == "live.json":
                continue
            case_root = root / name
            if case_root.is_symlink() or not case_root.is_dir() or case_root.stat().st_uid != os.getuid():
                return False
            total_entries += 1
            case_bytes = case_entries = 0
            pending = [case_root]
            while pending:
                current = pending.pop()
                with os.scandir(current) as entries:
                    for entry in entries:
                        info = entry.stat(follow_symlinks=False)
                        case_entries += 1
                        total_entries += 1
                        if entry.is_symlink() or info.st_uid != os.getuid():
                            return False
                        if stat.S_ISDIR(info.st_mode):
                            pending.append(pathlib.Path(entry.path))
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536:
                            case_bytes += info.st_size
                            total_bytes += info.st_size
                        else:
                            return False
                        if (case_entries > 64 or case_bytes > 4 * 1024 * 1024
                                or total_entries > 127 or total_bytes > 8 * 1024 * 1024):
                            return False
    except OSError:
        return False
    campaign_path = ROOT / "build/v02/campaign15/campaign.json"
    if (campaign_path.stat().st_size != 672 or marker2_path.stat().st_size != 625
            or marker3_path.stat().st_size != 2389
            or campaign_path.stat().st_size + marker2_path.stat().st_size
                + marker3_path.stat().st_size != 3686):
        return False
    return True


def _validate_current_admission16(admission: dict[str, Any], admission_sha256: str) -> None:
    """Bind coordinator admission to the exact independently reviewed Plan16 packet."""
    import platform
    phase_dir = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    protocol_path = ROOT / (phase_dir + "/07-16-PROTOCOL.md")
    review_path = ROOT / (phase_dir + "/07-16-REVIEW.md")
    security_path = ROOT / (phase_dir + "/07-16-SECURITY.md")
    authorization_path = ROOT / (phase_dir + "/07-16-AUTHORIZATION.md")
    supersession_path = ROOT / (phase_dir + "/07-16-SUPERSESSION.md")
    active15_path = ROOT / (phase_dir + "/07-15-PLAN.md")
    original15_path = ROOT / (phase_dir + "/history/07-15-before-supersession.md")
    sources = admission.get("sources") if isinstance(admission, dict) else None
    resume = admission.get("resume_campaign") if isinstance(admission, dict) else None
    required_sources = {
        "evidence/v02-execution.json",
        "scripts/release/v02_qualification.py", "tests/evidence/phase7_wrapper_return.py",
        "tests/evidence/phase7_wrapper_return_contract.py", "tests/evidence/phase7_return_archive_contract.py",
        "tests/evidence/phase7_wrapper16_contract.py", "tests/evidence/phase7_sticky_denial.py",
        "tests/fixtures/phase6_game.py", "tests/session/phase6_route_contract.py",
        "scripts/evidence/phase6_routes.py", "fixtures/phase6/media-expectations-v1.json",
        "scripts/evidence/phase5_process.py", "tests/evidence/phase7_cleanup_transition_contract.py",
        "tests/evidence/phase7_cleanup_budget_contract.py", "tests/evidence/phase7_creation_receipts_contract.py",
        "tests/evidence/phase7_darwin_status_contract.py", "tests/evidence/phase7_rss_contract.py",
    }
    paths = (protocol_path, review_path, security_path, authorization_path, supersession_path,
             active15_path, original15_path)
    if any(path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024
           or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1 for path in paths):
        raise ValueError("recovery-campaign-current16-artifact-invalid")
    protocol_sha = _sha(protocol_path)
    review = review_path.read_text(encoding="utf-8")
    security = security_path.read_text(encoding="utf-8")
    authorization = authorization_path.read_text(encoding="utf-8")
    supersession = supersession_path.read_text(encoding="utf-8")
    active15 = active15_path.read_bytes()
    original15 = original15_path.read_bytes()
    active15_original = active15.replace(b"status: superseded\n", b"", 1)
    if (admission.get("schema") != "genewhip.phase7-wrapper-return-admission.v1"
            or admission.get("status") != "candidate" or admission.get("plan") != "GW-07-16"
            or not isinstance(resume, dict)
            or not isinstance(sources, dict) or not required_sources.issubset(sources)
            or admission.get("protocol_sha256") != protocol_sha
            or resume.get("authorization_sha256") != _sha(authorization_path)
            or resume.get("supersession_sha256") != _sha(supersession_path)
            or active15.count(b"status: superseded\n") != 1
            or active15_original != original15
            or hashlib.sha256(original15).hexdigest()
                != "ae5cf79d99e01fbf6bad61a29104397e68b1f6990f85981bbe764c1c90347d78"
            or hashlib.sha256(active15).hexdigest()
                != "15854c3063aa5bc12cbe2c11aca77af2e569bc57836528bd08199dae39e82f34"
            or "authorizes exactly one additional diagnostic invocation" not in authorization
            or "Four prior host invocations remain recorded; the new invocation is number five" not in authorization
            or "Plan15 remains **blocked/failed**" not in supersession
            or "Tasks1/2 implement the user's separately authorized exact attempt4/host5" not in supersession
            or not _review_frontmatter_accepted(review, packet_sha256=admission_sha256,
                protocol_sha256=protocol_sha, reviewer_role="gsd-code-reviewer",
                reviewer_model="gpt-6-luna")
            or not _security_disposition_accepted(security,
                packet_sha256=admission_sha256, protocol_sha256=protocol_sha,
                source_pins_sha256=hashlib.sha256(json.dumps(sources, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest())):
        raise ValueError("recovery-campaign-current16-admission-invalid")
    for relative, digest in sources.items():
        source = pathlib.Path(relative) if isinstance(relative, str) else pathlib.Path("..")
        if (source.is_absolute() or ".." in source.parts or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("recovery-campaign-current16-source-pin-invalid")
        candidate = ROOT / source
        if (candidate.is_symlink() or not candidate.is_file() or _sha(candidate) != digest):
            raise ValueError("recovery-campaign-current16-source-stale:" + relative)
    interpreter_path = pathlib.Path(sys.executable)
    expected_interpreter = {"executable": sys.executable,
        "sha256": _sha(interpreter_path), "version": sys.version,
        "platform": {"system": platform.system(), "release": platform.release(),
                     "machine": platform.machine()}}
    if admission.get("interpreter") != expected_interpreter:
        raise ValueError("recovery-campaign-current16-interpreter-stale")


def _review_frontmatter_accepted(text: str, *, packet_sha256: str,
        protocol_sha256: str, reviewer_role: str, reviewer_model: str) -> bool:
    """Fail closed on duplicate or contradictory independent review metadata."""
    fields = _canonical_review_fields(text)
    return (fields.get("status") == "accepted"
        and fields.get("reviewer_role") == reviewer_role
        and fields.get("reviewer_model") == reviewer_model
        and fields.get("author_role") == "gsd-executor"
        and fields.get("source-review") == "current-source-and-packet"
        and fields.get("unresolved high/critical") == "0"
        and fields.get("critical") == "0" and fields.get("high") == "0"
        and fields.get("packet_sha256") == packet_sha256
        and fields.get("protocol_sha256") == protocol_sha256)


def _canonical_review_fields(text: str) -> dict[str, str]:
    """Read one flat, unquoted mapping at byte zero; body text is never metadata."""
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line or line.startswith("#"):
            continue
        if line[0].isspace() or ":" not in line:
            return {}
        key, value = line.split(":", 1)
        if (key != key.strip() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _/-]*", key)):
            return {}
        value = value.strip()
        if key in fields or not value:
            return {}
        fields[key] = value
    return fields


def _security_disposition_accepted(text: str, *, packet_sha256: str,
        protocol_sha256: str, source_pins_sha256: str) -> bool:
    required = {
        "prospective diagnostic source eligibility": "accepted",
        "reviewer_role": "gsd-security-auditor",
        "reviewer_model": "gpt-6.1-sol",
        "unresolved current high/critical": "0",
        "packet_sha256": packet_sha256,
        "protocol_sha256": protocol_sha256,
        "source_pins_sha256": source_pins_sha256,
        "historical identity/liveness": "UNKNOWN",
        "T-07-07": "OPEN/high",
    }
    lines = text.splitlines()
    expected = [f"{key}: {value}" for key, value in required.items()]
    canonical = _canonical_review_fields(text)
    return (bool(canonical) and all(canonical.get(key) == value for key, value in required.items())
        or len(lines) >= len(expected) + 1
        and lines[:len(expected)] == expected
        and lines[len(expected)] == "---")


def _validate_campaign_return16(campaign: dict[str, Any], campaign_sha256: str,
                                admission: dict[str, Any], admission_sha256: str) -> None:
    """Require the separately reviewed live16 return before downstream consumers."""
    phase_dir = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    return_path = ROOT / (phase_dir + "/07-16-RETURN.md")
    review_path = ROOT / (phase_dir + "/07-16-RETURN-REVIEW.md")
    security_path = ROOT / (phase_dir + "/07-16-SECURITY.md")
    live_path = ROOT / "build/v02/recovery15/live.json"
    for path in (return_path, review_path, security_path, live_path):
        if (path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024
                or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1):
            raise ValueError("recovery-campaign-return16-gate-missing")
    return_text = return_path.read_text(encoding="utf-8")
    review_text = review_path.read_text(encoding="utf-8")
    security_text = security_path.read_text(encoding="utf-8")
    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError("recovery-campaign-return16-gate-rejected-or-stale")
            fields[key] = value
        return fields
    live = json.loads(live_path.read_bytes(), object_pairs_hook=unique_fields)
    live_sha = hashlib.sha256(live_path.read_bytes()).hexdigest()
    source_pins_sha = hashlib.sha256(json.dumps(admission.get("sources"), sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    common = {"status": "accepted", "campaign_sha256": campaign_sha256,
        "packet_sha256": admission_sha256, "live_sha256": live_sha,
        "protocol_sha256": admission.get("protocol_sha256"),
        "source_pins_sha256": source_pins_sha}
    reviewer = {"author_role": "gsd-executor",
        "source-review": "actual-live-and-return-readiness", "critical": "0", "high": "0"}
    expected_return = {**common, "review_sha256": _sha(review_path),
        "security_sha256": _sha(security_path)}
    expected_review = {**common, **reviewer, "reviewer_role": "gsd-code-reviewer",
        "reviewer_model": "gpt-6-luna", "unresolved high/critical": "0",
        "independent_security_role": "gsd-security-auditor", "security_model": "gpt-6.1-sol",
        "security_sha256": _sha(security_path)}
    expected_security = {**common, **reviewer, "reviewer_role": "gsd-security-auditor",
        "reviewer_model": "gpt-6.1-sol", "unresolved current high/critical": "0",
        "historical identity/liveness": "UNKNOWN", "residual T-07-07": "nonblocking",
        "prospective diagnostic source eligibility": "accepted", "T-07-07": "OPEN/high"}
    if (any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for key, value in common.items() if key.endswith("sha256"))
            or _canonical_review_fields(return_text) != expected_return
            or _canonical_review_fields(review_text) != expected_review
            or _canonical_review_fields(security_text) != expected_security
            or not isinstance(live, dict)
            or live.get("status") != "pass" or type(live.get("attempt_number")) is not int
            or live.get("attempt_number") != 4
            or live.get("campaign_sha256") != campaign_sha256
            or live.get("packet_sha256") != admission_sha256
            or live.get("historical_identity_liveness") != "UNKNOWN"
            or live.get("historical_T-07-07") != "OPEN/high"
            or live.get("requirements_qualified") != []):
        raise ValueError("recovery-campaign-return16-gate-rejected-or-stale")


def _validate_failed_attempt1(admission: dict[str, Any], resume: dict[str, Any],
                              campaign_sha256: str, campaign_started_at: str,
                              current_admission_sha: str) -> bool:
    phase = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    expected_manifest = phase + "/07-15-ATTEMPT1-FAILURE.json"
    failed = resume.get("failed_attempt")
    limits = admission.get("cumulative_limits") if isinstance(admission, dict) else None
    if (not isinstance(failed, dict) or failed.get("path") != expected_manifest
            or resume.get("attempt2_marker_path") != "build/v02/campaign15/attempt2-started.json"
            or not isinstance(limits, dict)):
        return False
    manifest_path = ROOT / expected_manifest
    if (manifest_path.is_symlink() or not manifest_path.is_file()
            or manifest_path.stat().st_size > 65536):
        return False
    info = manifest_path.lstat()
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        return False
    raw_manifest = manifest_path.read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != failed.get("sha256"):
        return False
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if (manifest.get("schema") != "genewhip.phase7-wrapper-return-attempt.v1"
            or manifest.get("attempt") != 1
            or manifest.get("campaign_sha256") != campaign_sha256
            or manifest.get("campaign_started_at") != campaign_started_at
            or manifest.get("packet_sha256") != failed.get("failed_packet_sha256")
            or manifest.get("live_status") != "failed"
            or manifest.get("case_roster") != ["shared_launch"]
            or manifest.get("failure") != "return-wrapper-result-missing"
            or manifest.get("owner_settled") is not True
            or manifest.get("leaf_settled") is not True
            or manifest.get("owner_final_group_absent") is not True
            or manifest.get("leaf_final_group_absent") is not True
            or manifest.get("archive_root") != "build/v02/recovery15-attempt1"):
        return False
    review_path = ROOT / manifest.get("review_path", "")
    security_path = ROOT / manifest.get("security_path", "")
    if (review_path != ROOT / (phase + "/07-15-ATTEMPT1-REVIEW.md")
            or security_path != ROOT / (phase + "/07-15-ATTEMPT1-SECURITY.md")):
        return False
    for path, digest in ((review_path, manifest.get("review_sha256")),
                         (security_path, manifest.get("security_sha256"))):
        if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65536
                or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            return False
    review_text = review_path.read_text(encoding="utf-8")
    security_text = security_path.read_text(encoding="utf-8")
    if (manifest.get("review_sha256") != failed.get("review_sha256")
            or manifest.get("security_sha256") != failed.get("security_sha256")
            or not isinstance(manifest.get("cumulative_reserve"), dict)):
        return False
    accounting = manifest.get("attempt_accounting", {})
    if (accounting.get("host_invocations") != 2
            or accounting.get("actual_wrapper_calls") != 1
            or accounting.get("measured") != {"controller_starts": 6,
                "status_helper_starts": 5, "observer_queries": 4,
                "controller_rss_samples": 4, "elapsed_seconds": 0.2984199159545824,
                "retained_bytes": 9665}
            or accounting.get("unknown_reserves") != {"owner_starts": 17,
                "owner_status_helper_starts": 17, "owner_rss_samples": 508,
                "native_rss_pid_queries": 2097152}
            or accounting.get("not_measurements", {}).get("meaning") !=
                "fallback fields written when owner count receipt was missing; not observed zero"
            or accounting.get("not_measurements", {}).get("live_case_owner_starts") != 0
            or accounting.get("not_measurements", {}).get("live_case_owner_rss_samples") != 0):
        return False
    expected_caps = {
        "campaign_host_invocations": 3, "campaign_wrapper_calls": 3,
        "campaign_start_events": 126, "campaign_status_helper_starts": 120,
        "campaign_observer_queries": 24, "campaign_rss_samples": 1536,
        "campaign_native_rss_pid_queries": 6291456,
        "campaign_retained_bytes": 12582912,
        "campaign_status_output_bytes": 7864320,
        "campaign_elapsed_seconds": 240,
        "prior_host_invocations_used": 2, "future_host_invocations_reserved": 1,
        "prior_wrapper_calls_used": 1, "future_wrapper_calls_reserved": 2,
        "prior_controller_starts_measured": 6, "prior_owner_starts_unknown_reserved": 17,
        "prior_starts_reserved": 23, "future_starts_reserved": 84,
        "prior_status_helpers_measured": 5,
        "prior_owner_status_helpers_unknown_reserved": 17,
        "prior_status_helpers_reserved": 22, "future_status_helpers_reserved": 80,
        "prior_observer_queries_measured": 4, "future_observer_queries_reserved": 16,
        "prior_rss_samples_measured": 4,
        "prior_owner_rss_samples_unknown_reserved": 508,
        "prior_rss_samples_reserved": 512, "future_rss_samples_reserved": 1024,
        "prior_native_rss_queries_reserved": 2097152,
        "future_native_rss_queries_reserved": 4194304,
        "prior_retained_bytes_measured": 9665,
        "future_retained_bytes_reserved": 8388608,
        "prior_status_output_bytes_reserved": 2621440,
        "future_status_output_bytes_reserved": 5242880,
        "prior_elapsed_seconds_reserved": 120,
        "future_elapsed_seconds_reserved": 120,
    }
    historical_limits = manifest.get("cumulative_reserve")
    if (historical_limits != expected_caps
            or any(type(value) is not int for value in historical_limits.values())):
        return False
    if ("Independent review: ACCEPTED" not in review_text
            or f"packet_sha256: {manifest['packet_sha256']}" not in review_text
            or "Source-level diagnostic eligibility: ACCEPTED" not in security_text
            or f"packet_sha256: {manifest['packet_sha256']}" not in security_text):
        return False
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > 64:
        return False
    archive = ROOT / manifest["archive_root"]
    active = ROOT / "build/v02/recovery15"
    marker = ROOT / resume["attempt2_marker_path"]

    def inspect_tree(base: pathlib.Path, exact: bool) -> tuple[bool, dict[str, Any]]:
        if base.is_symlink() or not base.is_dir():
            return False, {}
        actual: dict[str, Any] = {}
        pending = [base]
        entries = total = 0
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as children:
                    for child in children:
                        entries += 1
                        if entries > 64:
                            return False, {}
                        item = pathlib.Path(child.path)
                        item_info = child.stat(follow_symlinks=False)
                        if child.is_symlink() or item_info.st_uid != os.getuid():
                            return False, {}
                        if stat.S_ISDIR(item_info.st_mode):
                            pending.append(item)
                        elif stat.S_ISREG(item_info.st_mode) and item_info.st_nlink == 1 and item_info.st_size <= 65536:
                            data = item.read_bytes()
                            total += len(data)
                            if total > (4 * 1024 * 1024 if exact else 12 * 1024 * 1024):
                                return False, {}
                            actual[item.relative_to(base).as_posix()] = {
                                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        else:
                            return False, {}
            except OSError:
                return False, {}
        if exact and (actual != files or total != manifest.get("tree_bytes")
                      or entries != manifest.get("tree_entries")):
            return False, {}
        return True, {"entries": entries, "bytes": total}

    if archive.exists():
        archive_ok, _ = inspect_tree(archive, True)
        if not archive_ok or marker.is_symlink() or not marker.is_file():
            return False
        marker_info = marker.lstat()
        if marker_info.st_uid != os.getuid() or marker_info.st_nlink != 1 or marker_info.st_size > 65536:
            return False
        try:
            marker_doc = json.loads(marker.read_bytes())
            marker_digest = marker_doc.pop("record_sha256")
            consumed = datetime.datetime.fromisoformat(marker_doc["consumed_at"])
            if (marker_doc.get("schema") != "genewhip.phase7-wrapper-return-attempt-entry.v1"
                    or marker_doc.get("attempt") != 2
                    or marker_doc.get("campaign_sha256") != campaign_sha256
                    or marker_doc.get("campaign_started_at") != campaign_started_at
                    or marker_doc.get("packet_sha256") != (current_admission_sha
                        if resume.get("attempt_number") == 2 else resume.get("attempt2_packet_sha256"))
                    or marker_doc.get("failed_attempt_manifest_sha256") != failed.get("sha256")
                    or marker_doc.get("prior_host_invocations_used") != 2
                    or marker_doc.get("prior_wrapper_calls_used") != 1
                    or marker_doc.get("future_wrapper_calls_reserved") != 2
                    or hashlib.sha256(json.dumps(marker_doc, sort_keys=True,
                        separators=(",", ":")).encode()).hexdigest() != marker_digest
                    or consumed > datetime.datetime.now(datetime.timezone.utc)):
                return False
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False
        active_ok, _ = inspect_tree(active, False)
        if not active_ok:
            return False
        base = archive
    else:
        if marker.exists() or marker.is_symlink():
            return False
        active_ok, _ = inspect_tree(active, True)
        if not active_ok:
            return False
        base = active
    live_row = None
    try:
        live = json.loads((base / "live.json").read_bytes())
        rows = live.get("cases")
        if isinstance(rows, list) and len(rows) == 1:
            live_row = rows[0]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return False
    if (live.get("schema") != "genewhip.phase7-wrapper-return.v1"
            or live.get("status") != "failed"
            or live.get("campaign_sha256") != campaign_sha256
            or live.get("packet_sha256") != manifest["packet_sha256"]
            or live.get("started_at") != campaign_started_at
            or live.get("historical_identity_liveness") != "UNKNOWN"
            or live.get("historical_T-07-07") != "OPEN/high"
            or live.get("requirements_qualified") != []
            or not isinstance(live_row, dict)
            or live_row.get("case") != "shared_launch"
            or live_row.get("status") != "failed"
            or live_row.get("error") != manifest.get("failure")
            or live_row.get("owner_settled") is not True or live_row.get("leaf_settled") is not True
            or live_row.get("owner_final_observation", {}).get("identity") is not None
            or live_row.get("owner_final_observation", {}).get("group_members") != []
            or live_row.get("leaf_final_observation", {}).get("identity") is not None
            or live_row.get("leaf_final_observation", {}).get("group_members") != []):
        return False
    return True


def _validate_failed_attempt2(admission: dict[str, Any], resume: dict[str, Any],
                              campaign_sha256: str, campaign_started_at: str,
                              current_admission_sha: str) -> bool:
    """Validate the second failed run at its pre- or post-archive location."""
    phase = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
    failed = resume.get("attempt2_failure")
    expected_manifest = phase + "/07-15-ATTEMPT2-FAILURE.json"
    if (not isinstance(failed, dict) or failed.get("path") != expected_manifest
            or resume.get("attempt2_marker_path") != "build/v02/campaign15/attempt2-started.json"
            or not isinstance(admission.get("cumulative_limits"), dict)):
        return False
    manifest_path = ROOT / expected_manifest
    marker_path = ROOT / resume["attempt2_marker_path"]
    campaign_path = ROOT / "build/v02/campaign15/campaign.json"
    try:
        if (campaign_path.is_symlink() or not campaign_path.is_file()
                or campaign_path.stat().st_size != 672
                or manifest_path.is_symlink() or marker_path.is_symlink()
                or not manifest_path.is_file() or not marker_path.is_file()
                or manifest_path.stat().st_size > 65536 or marker_path.stat().st_size > 65536
                or marker_path.stat().st_size != 625
                or manifest_path.stat().st_uid != os.getuid() or manifest_path.stat().st_nlink != 1
                or marker_path.stat().st_uid != os.getuid() or marker_path.stat().st_nlink != 1):
            return False
        manifest_raw = manifest_path.read_bytes()
        if hashlib.sha256(manifest_raw).hexdigest() != failed.get("sha256"):
            return False
        manifest = json.loads(manifest_raw)
        marker_raw = marker_path.read_bytes()
        if hashlib.sha256(marker_raw).hexdigest() != resume.get("attempt2_marker_sha256"):
            return False
        marker = json.loads(marker_raw)
        marker_digest = marker.pop("record_sha256")
        consumed = datetime.datetime.fromisoformat(marker["consumed_at"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return False
    if admission.get("cumulative_limits") != ATTEMPT3_CUMULATIVE_LIMITS:
        return False
    if (manifest.get("schema") != "genewhip.phase7-wrapper-return-attempt.v1"
            or manifest.get("attempt") != 2 or manifest.get("live_status") != "failed"
            or manifest.get("failure") != "return-wrapper-result-missing"
            or manifest.get("campaign_sha256") != campaign_sha256
            or manifest.get("campaign_started_at") != campaign_started_at
            or manifest.get("attempt_entry_sha256") != resume.get("attempt2_marker_sha256")
            or manifest.get("case_roster") != ["shared_launch"]
            or manifest.get("owner_settled") is not True or manifest.get("leaf_settled") is not True
            or manifest.get("owner_final_group_absent") is not True
            or manifest.get("leaf_final_group_absent") is not True
            or manifest.get("archive_root") != "build/v02/recovery15-attempt2"
            or marker.get("schema") != "genewhip.phase7-wrapper-return-attempt-entry.v1"
            or marker.get("attempt") != 2 or marker.get("campaign_sha256") != campaign_sha256
            or marker.get("campaign_started_at") != campaign_started_at
            or marker.get("packet_sha256") != manifest.get("packet_sha256")
            or marker.get("prior_host_invocations_used") != 2
            or marker.get("prior_wrapper_calls_used") != 1
            or marker.get("future_wrapper_calls_reserved") != 2
            or hashlib.sha256(json.dumps(marker, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != marker_digest
            or consumed > datetime.datetime.now(datetime.timezone.utc)):
        return False
    measured = manifest.get("measured", {})
    unknown = manifest.get("unknown_not_zero", {})
    not_measurements = manifest.get("fallback_fields_not_measurements", {})
    prior = manifest.get("cumulative_campaign_usage_and_reserve_after_attempt2", {})
    proposed = manifest.get("proposed_only_not_authorized_adjusted_last_attempt_envelope", {})
    provenance = manifest.get("host_tool_provenance", {})
    expected_argv = ["/opt/homebrew/opt/python@3.14/bin/python3.14", "-I",
        "tests/evidence/phase7_wrapper_return.py", "--run-selected", "--packet",
        ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json",
        "--campaign", "build/v02/campaign15/campaign.json", "--out",
        "build/v02/recovery15/live.json"]
    if (measured.get("controller_starts") != 6
            or measured.get("controller_status_helper_starts") != 5
            or measured.get("observer_queries") != 4
            or measured.get("observer_rss_samples") != 4
            or measured.get("retained_bytes") != 10121
            or measured.get("actual_wrapper_calls") != 1
            or manifest.get("case2") != "not started because case1 failed"
            or not_measurements.get("meaning") != "Owner count receipt was absent; these fields are fallback placeholders, not measured zeros."
            or not_measurements.get("live.owner_starts") != 0
            or not_measurements.get("live.owner_rss_samples") != 0
            or not_measurements.get("case_result.owner_starts") != 0
            or unknown != {"owner_start_events": 17, "owner_status_helper_starts": 17,
                "owner_rss_samples": 508, "total_start_events_reserved": 23,
                "total_status_helper_starts_reserved": 22, "total_rss_samples_reserved": 512,
                "native_rss_pid_queries_reserved": 2097152,
                "status_output_bytes_reserved": 2621440}
            or prior != {"host_invocations_used": 3, "wrapper_calls_used": 2,
                "starts_reserved": 46, "status_helper_starts_reserved": 44,
                "observer_queries_used": 8, "rss_samples_reserved": 1024,
                "native_rss_pid_queries_reserved": 4194304,
                "retained_bytes_measured_and_reserved": 19786,
                "status_output_bytes_reserved": 5242880, "elapsed_seconds_reserved": 240}
            or proposed.get("host_invocations_total") != 4
            or proposed.get("wrapper_calls_total") != 4
            or proposed.get("starts_total_reserved") != 130
            or proposed.get("status_helper_starts_total_reserved") != 124
            or proposed.get("observer_queries_total_reserved") != 24
            or proposed.get("rss_samples_total_reserved") != 2048
            or proposed.get("native_rss_pid_queries_total_reserved") != 8388608
            or proposed.get("retained_bytes_total_reserved") != 8408394
            or proposed.get("status_output_bytes_total_reserved") != 10485760
            or proposed.get("elapsed_seconds_total_reserved") != 360
            or provenance.get("tool") != "functions.exec_command"
            or provenance.get("sandbox_permissions") != "require_escalated"
            or provenance.get("argv") != expected_argv
            or provenance.get("exit_code") != 1):
        return False
    for key, path_key, sha_key, content in (
            ("attempt2_admission", "attempt2_admission_path", "attempt2_admission_sha256", "status"),
            ("attempt2_review", "attempt2_review_path", "attempt2_review_sha256", "Independent review: ACCEPTED"),
            ("attempt2_security", "attempt2_security_path", "attempt2_security_sha256", "Source-level reentry eligibility: ACCEPTED"),
            ("attempt2_denied", "attempt2_denied_path", "attempt2_denied_sha256", "102")):
        relative = resume.get(path_key)
        path = ROOT / relative if isinstance(relative, str) else pathlib.Path("/")
        expected_name = {
            "attempt2_admission": "07-15-ATTEMPT2-ADMISSION.json",
            "attempt2_review": "07-15-ATTEMPT2-REVIEW.md",
            "attempt2_security": "07-15-ATTEMPT2-SECURITY.md",
            "attempt2_denied": "07-15-DENIED-FOLLOWUP.md"}[key]
        if (path != ROOT / (phase + "/" + expected_name)
                or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536
                or _sha(path) != resume.get(sha_key)
                or content not in path.read_text(encoding="utf-8")):
            return False
    if (f"packet_sha256: {resume.get('attempt2_packet_sha256')}" not in
            (ROOT / resume["attempt2_review_path"]).read_text(encoding="utf-8")
            or f"| Packet | `{resume.get('attempt2_packet_sha256')}` |" not in
            (ROOT / resume["attempt2_security_path"]).read_text(encoding="utf-8")
            or resume.get("attempt2_admission_sha256") != resume.get("attempt2_packet_sha256")):
        return False
    if (resume.get("attempt2_review_sha256") != manifest.get("review_sha256")
            or resume.get("attempt2_security_sha256") != manifest.get("security_sha256")):
        return False
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > 64:
        return False
    root = ROOT / "build/v02/recovery15"
    archive = ROOT / "build/v02/recovery15-attempt2"
    marker3 = ROOT / "build/v02/campaign15/attempt3-started.json"
    if root.is_symlink() or not root.is_dir() or archive.is_symlink():
        return False
    if archive.exists():
        # The runner debits the one-shot before moving history. Reopening that
        # history is validation of this transition, never permission to reenter.
        try:
            if (not archive.is_dir() or marker3.is_symlink() or not marker3.is_file()
                    or marker3.stat().st_uid != os.getuid() or marker3.stat().st_nlink != 1
                    or marker3.stat().st_size > 65536):
                return False
            entry = json.loads(marker3.read_bytes())
            if not isinstance(entry, dict):
                return False
            digest = entry.pop("record_sha256")
            consumed_at = entry.pop("consumed_at")
            consumed3 = datetime.datetime.fromisoformat(consumed_at)
            signed = dict(entry, consumed_at=consumed_at)
            if (consumed3.tzinfo is None
                    or consumed3 > datetime.datetime.now(datetime.timezone.utc)
                    or consumed3 < datetime.datetime.fromisoformat(campaign_started_at)
                    or hashlib.sha256(json.dumps(signed, sort_keys=True,
                        separators=(",", ":")).encode()).hexdigest() != digest):
                return False
            if any(type(entry.get(key)) is not int for key in (
                    "attempt", "prior_host_invocations_used", "future_host_invocations_reserved",
                    "prior_wrapper_calls_used", "future_wrapper_calls_reserved")):
                return False
            if entry != {
                    "schema": "genewhip.phase7-wrapper-return-attempt-entry.v1",
                    "attempt": 3, "campaign_sha256": campaign_sha256,
                    "campaign_started_at": campaign_started_at,
                    "packet_sha256": current_admission_sha,
                    "attempt1_failure_manifest_sha256": resume.get("failed_attempt", {}).get("sha256"),
                    "attempt2_failure_manifest_sha256": failed.get("sha256"),
                    "attempt2_marker_sha256": resume.get("attempt2_marker_sha256"),
                    "prior_host_invocations_used": 3, "future_host_invocations_reserved": 1,
                    "prior_wrapper_calls_used": 2, "future_wrapper_calls_reserved": 2,
                    "cumulative_limits": ATTEMPT3_CUMULATIVE_LIMITS}:
                return False
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False
        root = archive
    elif marker3.exists() or marker3.is_symlink():
        return False
    actual: dict[str, dict[str, Any]] = {}
    pending = [root]
    total = entries = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as children:
                for child in children:
                    entries += 1
                    if entries > 64:
                        return False
                    item = pathlib.Path(child.path)
                    info = child.stat(follow_symlinks=False)
                    if child.is_symlink() or info.st_uid != os.getuid():
                        return False
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(item)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536:
                        data = item.read_bytes()
                        total += len(data)
                        if total > 4 * 1024 * 1024:
                            return False
                        actual[item.relative_to(root).as_posix()] = {
                            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                    else:
                        return False
        except OSError:
            return False
    if (actual != files or total != manifest.get("tree_bytes")
            or entries != manifest.get("tree_entries")):
        return False
    try:
        live_path = root / "live.json"
        live = json.loads(live_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (hashlib.sha256(live_path.read_bytes()).hexdigest() == manifest.get("live_sha256")
        and live.get("status") == "failed"
        and live.get("campaign_sha256") == campaign_sha256
        and live.get("packet_sha256") == manifest.get("packet_sha256")
        and live.get("started_at") == campaign_started_at
        and live.get("historical_identity_liveness") == "UNKNOWN"
        and live.get("historical_T-07-07") == "OPEN/high"
        and live.get("requirements_qualified") == [])


def _require_campaign_for_journal(journal_path: pathlib.Path, scope_path: pathlib.Path,
                                  campaign_path: pathlib.Path | None,
                                  campaign_sha256: str | None,
                                  *, phase: str, recovery_selection: str = "15",
                                  continuation_path: pathlib.Path | None = None,
                                  continuation_purpose: str = "original17") -> None:
    if continuation_purpose not in ("original17", "current-native-preparation", "current-native-return"):
        raise ValueError("continuation-purpose-invalid")
    if continuation_purpose == "current-native-preparation":
        raise ValueError("current-native-purpose-requires-stage-public-prepare-only")
    if continuation_purpose == "current-native-return" and (
            recovery_selection != "17" or continuation_path is None):
        raise ValueError("current-return-purpose-requires-protected-return-mode")
    if recovery_selection not in ("15", "16", "17"):
        raise ValueError("recovery-campaign-selection-invalid")
    selected = pathlib.Path(os.path.abspath(journal_path if journal_path.is_absolute()
        else ROOT / journal_path))
    campaign_journal = pathlib.Path(os.path.abspath(
        ROOT / "build/v02/campaign15/hosted-delivery-journal.json"))
    if selected != campaign_journal:
        if recovery_selection != "15":
            raise ValueError("recovery-campaign-selected-journal-required")
        return
    if campaign_path is None or campaign_sha256 is None:
        raise ValueError("recovery-campaign-required-for-selected-journal")
    _campaign_projection(campaign_path, scope_path, journal_path, phase=phase,
                         expected_sha256=campaign_sha256, selection=recovery_selection,
                         continuation_path=continuation_path,
                         continuation_purpose=continuation_purpose)


def _require_campaign_layout(args: argparse.Namespace) -> None:
    """Keep renewed-window inputs and outputs inside its fresh campaign root."""
    root = pathlib.Path(os.path.abspath(ROOT / "build/v02/campaign15"))
    def under_root(value: pathlib.Path) -> bool:
        candidate = pathlib.Path(os.path.abspath(value if value.is_absolute() else ROOT / value))
        return candidate != root and candidate.is_relative_to(root)
    journal = args.journal if args.journal.is_absolute() else ROOT / args.journal
    if pathlib.Path(os.path.abspath(journal)) != root / "hosted-delivery-journal.json":
        raise ValueError("recovery-campaign-journal-layout-invalid")
    if not under_root(args.out):
        raise ValueError("recovery-campaign-output-layout-invalid")
    if args.mode in {"hosted", "retry-source", "successor-source",
            "failed-hosted-successor-source"} and not under_root(args.preflight):
        raise ValueError("recovery-campaign-preflight-layout-invalid")
    if args.mode in {"hosted", "retry-source", "stage-public", "successor-source",
            "failed-hosted-successor-source"} \
            and args.publication_copy is not None:
        if not under_root(args.publication_copy):
            raise ValueError("recovery-campaign-publication-layout-invalid")
    for value in (args.journal, args.out, args.preflight, args.publication_copy):
        if value is None:
            continue
        candidate = value if value.is_absolute() else ROOT / value
        candidate = pathlib.Path(os.path.abspath(candidate))
        try:
            relative = candidate.relative_to(ROOT)
        except ValueError:
            raise ValueError("recovery-campaign-path-outside-project") from None
        current = ROOT
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("recovery-campaign-output-symlink")


def _reject_output_collisions(args: argparse.Namespace) -> None:
    """Reject mode output paths that alias consumed inputs or candidate bytes."""
    output = args.out if args.out.is_absolute() else ROOT / args.out
    if output.is_symlink():
        raise ValueError("qualification-output-path-aliases-input")
    output_resolved = output.resolve(strict=False)
    mode_inputs: dict[str, tuple[str, ...]] = {
        "plan": ("scope",), "runtime": ("scope",),
        "semantic-mutants": ("scope",), "semantic-mutants-worker": ("scope",),
        "package": ("scope", "public_evidence"),
        "validate": ("scope", "evidence"), "close": ("scope", "evidence"),
        "stage-public": ("preflight", "scope", "campaign", "journal", "continuation", "authorization"),
        "retry-source": ("preflight", "publication_copy", "scope", "campaign", "journal",
            "continuation"),
        "successor-source": ("preflight", "publication_copy", "scope", "campaign", "journal",
            "continuation"),
        "failed-hosted-successor-source": ("preflight", "publication_copy", "scope", "campaign",
            "journal", "continuation"),
        "hosted": ("preflight", "publication_copy", "scope", "campaign", "journal",
            "continuation")}
    names = list(mode_inputs.get(args.mode, ()))
    # Prepare-only intentionally writes the generated packet at --out; the
    # parser's default --preflight path is not read in this mode.
    if args.mode == "stage-public" and args.prepare_only:
        names = [name for name in names if name not in {"preflight", "authorization"}]
        # Authorization is a consumed input even in prepare-only mode when supplied;
        # only the default output/preflight overlap is intentionally permitted.
        if args.authorization is not None:
            names.append("authorization")
    for name in names:
        value = getattr(args, name, None)
        if value is None:
            continue
        input_path = value if value.is_absolute() else ROOT / value
        input_resolved = input_path.resolve(strict=False)
        if output_resolved == input_resolved:
            raise ValueError("qualification-output-path-aliases-input")
        try:
            output_info, input_info = output.stat(), input_path.stat()
        except OSError:
            pass
        else:
            if (output_info.st_dev, output_info.st_ino) == (input_info.st_dev, input_info.st_ino):
                raise ValueError("qualification-output-path-aliases-input")
        if name == "publication_copy":
            lexical_candidate = pathlib.Path(os.path.abspath(input_path))
            lexical_output = pathlib.Path(os.path.abspath(output))
            if (lexical_output == lexical_candidate
                    or lexical_output.is_relative_to(lexical_candidate)
                    or output_resolved.is_relative_to(input_resolved)):
                raise ValueError("qualification-output-path-aliases-candidate")
            if input_path.is_dir() and not input_path.is_symlink() and output.exists():
                visited = 0
                for parent, directories, files in os.walk(input_path, followlinks=False):
                    directories[:] = [entry for entry in directories
                        if not (pathlib.Path(parent) / entry).is_symlink()]
                    visited += len(directories)
                    if visited > 5000:
                        raise ValueError("qualification-candidate-tree-exceeds-collision-scan-bound")
                    for filename in files:
                        visited += 1
                        if visited > 5000:
                            raise ValueError("qualification-candidate-tree-exceeds-collision-scan-bound")
                        candidate_file = pathlib.Path(parent) / filename
                        if candidate_file.is_symlink() or not candidate_file.is_file():
                            continue
                        try:
                            candidate_info, output_info = candidate_file.stat(), output.stat()
                        except OSError:
                            continue
                        if (candidate_info.st_dev, candidate_info.st_ino) == (
                                output_info.st_dev, output_info.st_ino):
                            raise ValueError("qualification-output-path-aliases-candidate")


def _validate_package_transfer_identity(inventory: Any, source_sha: str) -> dict[str, Any]:
    if (not isinstance(inventory, dict)
            or inventory.get("schema") != "genewhip.v02-package-transfer.v1"
            or inventory.get("source_sha") != source_sha
            or not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
            or not isinstance(inventory.get("members"), dict)
            or inventory.get("member_count") != len(inventory["members"])
            or not inventory["members"]):
        raise ValueError("hosted-package-transfer-identity-invalid")
    total = 0
    for name, facts in inventory["members"].items():
        if (not isinstance(name, str) or not isinstance(facts, dict)
                or not re.fullmatch(r"[0-9a-f]{64}", str(facts.get("sha256", "")))
                or not isinstance(facts.get("size"), int) or isinstance(facts.get("size"), bool)
                or facts["size"] < 0):
            raise ValueError("hosted-package-transfer-member-invalid")
        total += facts["size"]
    if total != inventory.get("total_bytes"):
        raise ValueError("hosted-package-transfer-total-mismatch")
    return inventory


def _validate_release_transfer_join(assets: Any, release_assets: pathlib.Path,
                                   transfer_members: dict[str, Any]) -> dict[str, str]:
    """Require every staged release byte to equal its authenticated transfer member."""
    if not isinstance(assets, dict) or len(assets) != 6:
        raise ValueError("hosted-release-inventory-roster-invalid")
    joined: dict[str, str] = {}
    names = set(assets) | {"inventory.json", "SHA256SUMS"}
    for name in sorted(names):
        if not isinstance(name, str) or pathlib.PurePosixPath(name).name != name:
            raise ValueError("hosted-release-input-name-invalid")
        actual = release_assets / name
        transfer_record = transfer_members.get("artifacts/release-assets/" + name)
        if (actual.is_symlink() or not actual.is_file() or not isinstance(transfer_record, dict)
                or actual.stat().st_size > 512 * 1024 * 1024):
            raise ValueError("hosted-release-input-differs-from-authenticated-package-transfer:" + name)
        digest = _sha(actual)
        expected = assets.get(name) if name in assets else None
        if (expected is not None and (not isinstance(expected, dict)
                or expected.get("sha256") != digest or expected.get("size") != actual.stat().st_size)):
            raise ValueError("hosted-release-inventory-member-mismatch:" + name)
        if (transfer_record.get("sha256") != digest
                or transfer_record.get("size") != actual.stat().st_size):
            raise ValueError("hosted-release-input-differs-from-authenticated-package-transfer:" + name)
        joined[name] = digest
    return joined


def _validate_hosted_release_inputs(release_assets: pathlib.Path, source_sha: str,
                                    transfer_members: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], list[str]]:
    """Require the selected v0.2 release roster and exact transfer bytes."""
    try:
        inventory = json.loads((release_assets / "inventory.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("hosted-release-inventory-invalid") from None
    assets = inventory.get("assets") if isinstance(inventory, dict) else None
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("hosted-release-inventory-source-invalid")
    suffix = "-" + source_sha[:12] + ".tar.gz"
    archives = [f"genewhip-0.2.0-sdk-diagnostic-darwin-arm64{suffix}",
                f"genewhip-0.2.0-playable-preview-macos-arm64{suffix}"]
    expected_assets = {name + ending for name in archives
                       for ending in ("", ".sha256", ".qualification.json")}
    if (not isinstance(inventory, dict)
            or inventory.get("schema") != "genewhip.release-inventory.v2"
            or inventory.get("version") != "0.2.0"
            or inventory.get("source_revision") != source_sha
            or not isinstance(assets, dict) or set(assets) != expected_assets):
        raise ValueError("hosted-release-inventory-roster-invalid")
    joined = _validate_release_transfer_join(assets, release_assets, transfer_members)
    return inventory, assets, joined, archives


def _validate_docs_adoption_receipt(receipt: Any, assets: dict[str, Any],
                                    source_sha: str) -> dict[str, dict[str, str]]:
    """Bind documentation adoption receipts to the exact authenticated SDK/desktop archives."""
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "genewhip-docs-command-qualification-v2"
            or receipt.get("version") != "0.2.0" or receipt.get("outcome") != "pass"
            or receipt.get("mode") != "clean-local-qualified"):
        raise ValueError("hosted-docs-adoption-receipt-invalid")
    expected = {
        "sdk": "genewhip-0.2.0-sdk-diagnostic-darwin-arm64-",
        "desktop": "genewhip-0.2.0-playable-preview-macos-arm64-",
    }
    packages = receipt.get("packages")
    if not isinstance(packages, dict) or set(packages) != set(expected):
        raise ValueError("hosted-docs-adoption-package-roster-invalid")
    identities = {}
    for role, prefix in expected.items():
        package = packages[role]
        archive = next((name for name in assets if name.startswith(prefix)
                        and name.endswith(".tar.gz")), None)
        if (archive is None or not isinstance(package, dict)
                or package.get("archive") != archive
                or package.get("archive_sha256") != assets[archive].get("sha256")
                or package.get("source_revision") != source_sha
                or package.get("source_state") != "clean"):
            raise ValueError("hosted-docs-receipt-does-not-name-authenticated-release-bytes:" + role)
        identities[role] = {"archive": archive,
            "archive_sha256": package["archive_sha256"], "source_revision": source_sha}
    return identities


def _valid_packet_for_delivery(packet_path: pathlib.Path,
                               publication_copy: pathlib.Path) -> dict[str, Any]:
    packet_path = packet_path.resolve(strict=True)
    if packet_path.is_symlink():
        raise ValueError("public-preflight-packet-unsafe")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("public-preflight-packet-invalid")
    candidate = publication_copy.resolve(strict=True)
    identity = packet.get("public_identity", {})
    source_identity = packet.get("source_identity", {})
    manifest = packet.get("source_manifest")
    privacy = packet.get("privacy", {})
    if (packet.get("schema") != "genewhip.v02-public-source-preflight.v1"
            or packet.get("status") != "prepared"
            or not isinstance(identity, dict)
            or not isinstance(source_identity, dict)
            or not isinstance(manifest, list)
            or not isinstance(privacy, dict)
            or packet.get("repository") != _authorized_public_repository(ROOT)
            or packet.get("mutations_performed") != 0
            or packet.get("push_performed") is not False
            or packet.get("pull_request_opened") is not False
            or packet.get("workflow_dispatched") is not False
            or privacy.get("status") != "pass"
            or packet.get("blockers")
            or packet.get("source_manifest_sha256") != source_identity.get("source_manifest_sha256")
            or source_identity.get("private_git_head") != _git(ROOT, "rev-parse", "HEAD")
            or any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in manifest)
            or _git(candidate, "rev-parse", "HEAD") != identity.get("head_sha")
            or _git(candidate, "rev-parse", "HEAD^{tree}") != identity.get("tree_sha")
            or _git(candidate, "rev-parse", "HEAD^") != identity.get("base_sha")):
        raise ValueError("public-preflight-packet-does-not-bind-candidate")
    validate_public_snapshot(candidate, identity["base_sha"], identity["head_sha"],
                             [row["path"] for row in manifest])
    return packet


def _fresh_public_policy(packet: dict[str, Any], publication_copy: pathlib.Path) -> dict[str, Any]:
    """Re-read main and effective policy immediately before a source branch push."""
    repository = packet["repository"]
    identity = packet["public_identity"]
    candidate = publication_copy.resolve(strict=True)
    remote = _external(["git", "remote", "get-url", "origin"], cwd=candidate,
                       timeout=30, phase="preparation").stdout.strip()
    owner, name = repository.split("/", 1)
    allowed = {f"https://github.com/{owner}/{name}.git", f"https://github.com/{owner}/{name}"}
    if remote not in allowed:
        raise ValueError("public-snapshot-remote-is-not-authorized-destination")
    _external(["git", "fetch", "--no-tags", "origin", "main"], cwd=candidate, timeout=300)
    fetched_main = _external(["git", "rev-parse", "refs/remotes/origin/main"], cwd=candidate,
                             timeout=30, phase="preparation").stdout.strip()
    if fetched_main != identity["base_sha"]:
        raise ValueError("public-main-moved-after-candidate-freeze")
    delivery_root = candidate.parent
    preflight_out = delivery_root / f"repository-preflight-{identity['head_sha']}-delivery.json"
    preflight_out.parent.mkdir(parents=True, exist_ok=True)
    _external([sys.executable, str(ROOT / "scripts/ci/repository_preflight.py"),
        "--inspect-authorized", "--repository", repository, "--destination", repository,
        "--visibility", "public", "--history-disposition",
        "sanitized-snapshots-preserve-local-history", "--publication-copy", str(candidate),
        "--expected-head", identity["head_sha"], "--expected-base", identity["base_sha"],
        "--out", preflight_out.relative_to(ROOT).as_posix()], timeout=90)
    policy = json.loads(preflight_out.read_text(encoding="utf-8"))
    observations = policy.get("repository_observations", {}).get("observations", {})
    branch = observations.get("branch_protection", {})
    if (policy.get("schema") != "genewhip.publication-readiness-packet.v1"
            or policy.get("repository") != repository
            or policy.get("mutations_performed") != 0
            or policy.get("repository_observations", {}).get("ready") is not True
            or policy.get("repository_observations", {}).get("blockers")
            or policy.get("privacy_scan", {}).get("publication_copy", {}).get("status") != "pass"
            or observations.get("visibility") != "public"
            or observations.get("default_branch") != "main"
            or observations.get("expected_identity", {}).get("observed_default_branch_sha") != identity["base_sha"]
            or "required-ci" not in branch.get("required_status_checks", [])
            or branch.get("pull_request_required") is not True
            or observations.get("auto_merge_enabled") is not True
            or observations.get("caller_write_permission") != "write"
            or not isinstance(observations.get("permitted_merge_methods"), list)
            or not set(observations["permitted_merge_methods"]) & {"merge", "squash"}):
        raise ValueError("live-public-repository-policy-not-qualified")
    return policy


def _pr_body(candidate_sha: str, base_sha: str) -> str:
    return f"""## Summary

```text
sanitized private source snapshot
  -> one-parent public-main commit {candidate_sha}
  -> required public CI checks
```

This PR adds the reviewed v0.2 source snapshot. It excludes `.planning`, local receipts, build output, secrets, and private history.

## Evidence

- **Before:** existing public `main` at `{base_sha}`.
- **After:** frozen candidate `{candidate_sha}`; source and history privacy scans passed.
- Public PR checks run on this exact head. Full v0.2 hosted qualification follows the protected `main` merge.

## Merge Danger

**Door:** One-way for public disclosure; the source branch can be removed, but a public source disclosure cannot be recalled.

**Blast Radius:** Repository
"""


def _verified_merge_receipt(pr: dict[str, Any], repository: str, candidate: pathlib.Path,
                            head: str, base: str, branch: str, *,
                            phase: str = "preparation") -> dict[str, Any]:
    """Reopen a completed protected merge after a client-side interruption."""
    if pr.get("state") != "MERGED" or pr.get("headRefOid") != head or pr.get("baseRefName") != "main":
        raise ValueError("public-source-pull-request-identity-or-base-changed")
    merge_sha = pr.get("mergeCommit", {}).get("oid")
    if not isinstance(merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("protected-merge-commit-identity-invalid")
    # The REST Commits endpoint includes per-file patches and can exceed the
    # coordinator's bounded capture. The Git Database endpoint returns the
    # commit object metadata needed here without the diff payload.
    commit = _gh_json(repository, f"git/commits/{merge_sha}", phase=phase)
    parents = [row.get("sha") for row in commit.get("parents", [])]
    expected_tree = _git(candidate, "rev-parse", "HEAD^{tree}")
    actual_tree = commit.get("tree", {}).get("sha")
    if (commit.get("sha") != merge_sha or actual_tree != expected_tree
            or parents not in ([base], [base, head], [head, base])):
        raise ValueError("protected-merge-parents-or-tree-mismatch")
    return {"pull_request": str(pr["number"]), "pull_request_url": pr.get("url"),
        "public_source_sha": merge_sha, "candidate_sha": head, "public_base_sha": base,
        "merge_parents": parents, "branch": branch,
        "merge_strategy": "squash" if parents == [base] else "merge", "tree_sha": actual_tree}


def _r10_successor_constants() -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("gw_v02_r10_predecessor",
        ROOT / "scripts/release/v02_continuation.py")
    if spec is None or spec.loader is None:
        raise ValueError("source-successor-predecessor-validator-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(module.R10_SUCCESSOR_PREDECESSOR)


def _validate_r10_predecessor_artifacts(journal_bytes: bytes) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("gw_v02_r10_predecessor",
        ROOT / "scripts/release/v02_continuation.py")
    if spec is None or spec.loader is None:
        raise ValueError("source-successor-predecessor-validator-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.validate_r10_merged_predecessor(ROOT, journal_bytes=journal_bytes)
    except ValueError as error:
        raise ValueError("source-successor-predecessor-artifacts-invalid") from None


def _required_preview_success(pr: dict[str, Any], run: dict[str, Any],
                              expected: dict[str, Any]) -> None:
    checks = pr.get("statusCheckRollup")
    preview_lanes = {"safety", "gameplay", "desktop", "package", "performance",
        "product-smoke", "phase7-fast"}
    conditional_skips = {"v02-runtime", "extended", "v02-benchmark-control",
        "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package",
        "v02-release-qualification", "attestation"}
    if not isinstance(checks, list):
        raise ValueError("source-successor-prior-required-check-not-success")
    by_name: dict[str, dict[str, Any]] = {}
    for row in checks:
        if (not isinstance(row, dict) or not isinstance(row.get("name"), str)
                or not row["name"] or row["name"] in by_name):
            raise ValueError("source-successor-prior-required-check-not-success")
        by_name[row["name"]] = row
    expected_names = preview_lanes | conditional_skips | {"required-ci"}
    if set(by_name) != expected_names:
        raise ValueError("source-successor-prior-required-check-not-success")
    if any(by_name[name].get("status") != "COMPLETED"
            or by_name[name].get("conclusion") != "SUCCESS"
            for name in preview_lanes | {"required-ci"}):
        raise ValueError("source-successor-prior-required-check-not-success")
    if any(by_name[name].get("status") != "COMPLETED"
            or by_name[name].get("conclusion") != "SKIPPED" for name in conditional_skips):
        raise ValueError("source-successor-prior-required-check-not-success")
    if (run.get("id") != int(expected["preview_run_id"])
            or run.get("head_sha") != expected["source_head"]
            or run.get("event") != "pull_request"
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise ValueError("source-successor-prior-preview-run-mismatch")


def _verify_r10_merged_source(repository: str, journal: dict[str, Any],
                              journal_bytes: bytes, *, phase: str) -> dict[str, Any]:
    expected = _validate_r10_predecessor_artifacts(journal_bytes)
    if (journal.get("source_head") != expected["source_head"]
            or journal.get("public_base_sha") != expected["public_base_sha"]
            or journal.get("repository") != "szTheory/genewhip"
            or journal.get("branch") != "v0.2-source-" + expected["source_head"][:12]
            or journal.get("started_at") != "2026-10-30T16:50:39.837827+00:00"
            or journal.get("push_performed") is not True):
        raise ValueError("source-successor-prior-journal-identity-invalid")
    if repository != "szTheory/genewhip":
        raise ValueError("source-successor-prior-repository-mismatch")
    encoded = urllib.parse.quote(repository, safe="/")
    listing = _external(["gh", "pr", "list", "--repo", repository, "--head", journal["branch"],
        "--state", "all", "--json",
        "number,url,state,headRefName,headRefOid,baseRefName,baseRefOid,mergeCommit,statusCheckRollup"],
        timeout=45, phase=phase)
    try:
        prs = json.loads(listing.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-successor-prior-pr-list-invalid") from None
    matches = [row for row in prs if isinstance(row, dict)
        and str(row.get("number")) == expected["pull_request"]]
    if (len(matches) != 1 or matches[0].get("state") != "MERGED"
            or matches[0].get("headRefName") != journal["branch"]
            or matches[0].get("headRefOid") != expected["source_head"]
            or matches[0].get("baseRefName") != "main"
            or matches[0].get("baseRefOid") != expected["public_base_sha"]):
        raise ValueError("source-successor-prior-pr-not-exact-merged-source")
    pr = matches[0]
    workflow_result = _external(["gh", "api",
        f"repos/{encoded}/actions/runs/{expected['preview_run_id']}", "--jq",
        "{id,head_sha,event,status,conclusion}"], timeout=45, phase=phase)
    try:
        run = json.loads(workflow_result.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-successor-prior-preview-run-invalid") from None
    _required_preview_success(pr, run, expected)
    for sha in (expected["source_head"], expected["merge_commit_sha"]):
        query = _external(["gh", "api",
            f"repos/{encoded}/actions/runs?head_sha={sha}&per_page=100", "--jq",
            "{total_count,workflow_runs:[.workflow_runs[]|{id,head_sha,event,status,conclusion,display_title,head_branch,path}]}"],
            timeout=45, phase=phase)
        try:
            runs_value = json.loads(query.stdout)
        except json.JSONDecodeError:
            raise ValueError("source-successor-prior-run-list-invalid") from None
        runs = runs_value.get("workflow_runs") if isinstance(runs_value, dict) else None
        if (not isinstance(runs, list) or runs_value.get("total_count") != len(runs) or len(runs) >= 100
                or any(not isinstance(row, dict) or row.get("status") != "completed"
                    or row.get("event") == "workflow_dispatch"
                    or str(row.get("display_title", "")).startswith("Plan10 qualification ")
                    for row in runs)):
            raise ValueError("source-successor-prior-workflow-active-or-qualified")
        if sha == expected["source_head"] and runs != [{"id": int(expected["preview_run_id"]),
                "head_sha": expected["source_head"], "event": "pull_request", "status": "completed",
                "conclusion": "success", "display_title": "Required preview checks",
                "head_branch": journal["branch"], "path": ".github/workflows/ci.yml"}]:
            raise ValueError("source-successor-prior-preview-run-roster-mismatch")
        if sha == expected["merge_commit_sha"] and runs != [{
                "id": int(expected["merge_preview_run_id"]), "head_sha": expected["merge_commit_sha"],
                "event": "push", "status": "completed", "conclusion": "success",
                "display_title": "Required preview checks", "head_branch": "main",
                "path": ".github/workflows/ci.yml"}]:
            raise ValueError("source-successor-prior-merge-preview-run-mismatch")
    old_candidate = ROOT / expected["candidate_root"] / "publication"
    receipt = _verified_merge_receipt(pr, repository, old_candidate,
        expected["source_head"], expected["public_base_sha"], journal["branch"], phase=phase)
    if (receipt["public_source_sha"] != expected["merge_commit_sha"]
            or receipt["tree_sha"] != expected["merge_tree_sha"]):
        raise ValueError("source-successor-prior-merge-metadata-mismatch")
    main = _gh_json(repository, "git/ref/heads/main", phase=phase)
    if main.get("object", {}).get("sha") != receipt["public_source_sha"]:
        raise ValueError("source-successor-public-main-moved")
    return {**receipt, "preview_run_id": expected["preview_run_id"],
        "required_check": {"name": "required-ci", "status": "COMPLETED", "conclusion": "SUCCESS"}}


def _validate_source_retry_history(journal: dict[str, Any]) -> None:
    """Reopen the immutable prior attempt before trusting an active retry journal."""
    retry = journal.get("source_retry") if isinstance(journal, dict) else None
    if retry is None:
        return
    if (not isinstance(retry, dict) or retry.get("schema") != "genewhip.v02-source-retry.v1"
            or not isinstance(retry.get("archive"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(retry.get("archive_sha256", "")))
            or retry.get("started_at") != journal.get("started_at")
            or retry.get("active_source_head") != journal.get("source_head")
            or retry.get("active_repository") != journal.get("repository")
            or retry.get("active_base_sha") != journal.get("public_base_sha")):
        raise ValueError("hosted-delivery-journal-source-retry-identity-invalid")
    archive_input = ROOT / retry["archive"]
    if archive_input.is_symlink():
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid")
    archive = archive_input.resolve(strict=True)
    expected_root = (ROOT / "build/v02/failures").resolve()
    if not archive.is_relative_to(expected_root):
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid")
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != retry["archive_sha256"]:
        raise ValueError("hosted-delivery-journal-source-retry-archive-digest-mismatch")
    try:
        prior = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid") from None
    if (not isinstance(prior, dict)
            or prior.get("schema") != "genewhip.v02-delivery-journal.v1"
            or prior.get("started_at") != journal.get("started_at")
            or prior.get("source_head") != retry.get("prior_source_head")
            or prior.get("repository") != journal.get("repository")
            or prior.get("public_base_sha") != journal.get("public_base_sha")
            or prior.get("push_performed") is not True
            or any(key in prior for key in ("public_source_sha", "merge_commit", "merge_parents",
                "candidate_sha", "merge_strategy", "qualification_started_at", "source_sha",
                "run_id", "run_attempt"))
            or any(key.startswith(("qualification_", "selected_run_")) for key in prior)
            or not isinstance(retry.get("failed_pull_request"), str)
            or retry.get("failed_required_check") != {"name": "required-ci",
                "status": "COMPLETED", "conclusion": "FAILURE"}):
        raise ValueError("hosted-delivery-journal-source-retry-archive-conflicts")
    if prior.get("source_successor") is not None:
        _validate_source_successor_history(prior)


def _validate_source_successor_history(journal: dict[str, Any]) -> None:
    successor = journal.get("source_successor") if isinstance(journal, dict) else None
    if successor is None:
        return
    required_keys = {"schema", "archive", "archive_sha256", "started_at", "prior_source_head",
        "prior_public_base_sha", "prior_merge_commit_sha", "prior_merge_tree_sha",
        "prior_pull_request", "prior_preview_run_id", "active_source_head", "active_base_sha",
        "active_repository", "required_check"}
    if (not isinstance(successor, dict) or set(successor) not in
            (required_keys, required_keys | {"failed_hosted"})
            or successor.get("schema") != "genewhip.v02-source-successor.v1"
            or not isinstance(successor.get("archive"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(successor.get("archive_sha256", "")))
            or successor.get("started_at") != journal.get("started_at")
            or successor.get("active_source_head") != journal.get("source_head")
            or successor.get("active_base_sha") != journal.get("public_base_sha")
            or successor.get("active_repository") != journal.get("repository")
            or successor.get("required_check") != {"name": "required-ci", "status": "COMPLETED",
                "conclusion": "SUCCESS"}):
        raise ValueError("hosted-delivery-journal-source-successor-identity-invalid")
    archive_input = ROOT / successor["archive"]
    if archive_input.is_symlink():
        raise ValueError("hosted-delivery-journal-source-successor-archive-invalid")
    archive = archive_input.resolve(strict=True)
    expected_root = (ROOT / "build/v02/failures").resolve()
    if not archive.is_relative_to(expected_root):
        raise ValueError("hosted-delivery-journal-source-successor-archive-invalid")
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != successor["archive_sha256"]:
        raise ValueError("hosted-delivery-journal-source-successor-archive-digest-mismatch")
    predecessor = _r10_successor_constants()
    if (hashlib.sha256(raw).hexdigest() != predecessor["journal_sha256"]
            or successor.get("prior_source_head") != predecessor["source_head"]
            or successor.get("prior_public_base_sha") != predecessor["public_base_sha"]
            or successor.get("prior_merge_commit_sha") != predecessor["merge_commit_sha"]
            or successor.get("prior_merge_tree_sha") != predecessor["merge_tree_sha"]
            or successor.get("prior_pull_request") != predecessor["pull_request"]
            or successor.get("prior_preview_run_id") != predecessor["preview_run_id"]):
        raise ValueError("hosted-delivery-journal-source-successor-archive-conflicts")
    _validate_source_retry_history(json.loads(raw))
    _validate_r10_predecessor_artifacts(raw)
    if "failed_hosted" in successor:
        _validate_r13_failed_hosted_successor(journal)


def _write_journal_atomically(path: pathlib.Path, value: dict[str, Any], *,
                              expected_current_bytes: bytes | None = None) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("delivery-journal-path-invalid")
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                prefix=path.name + ".transition-", suffix=".tmp", delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if expected_current_bytes is not None:
            try:
                current_bytes = path.read_bytes()
            except OSError:
                raise ValueError("delivery-journal-transition-source-changed") from None
            if current_bytes != expected_current_bytes:
                raise ValueError("delivery-journal-transition-source-changed")
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise ValueError("delivery-journal-atomic-write-failed") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _resume_source_successor(packet: dict[str, Any], publication_copy: pathlib.Path,
        journal_path: pathlib.Path, journal_bytes: bytes, active: dict[str, Any],
        expected: dict[str, Any], scope_path: pathlib.Path) -> dict[str, Any]:
    """Resume only an exact unpushed successor after its result write failed."""
    if (set(active) != {"schema", "started_at", "repository", "source_head", "public_base_sha",
            "branch", "push_performed", "source_successor"}
            or active.get("schema") != "genewhip.v02-delivery-journal.v1"
            or active.get("push_performed") is not False):
        raise ValueError("source-successor-resume-state-invalid")
    transition = active.get("source_successor")
    head = packet["public_identity"]["head_sha"]
    base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    branch = "v0.2-source-" + head[:12]
    if (active.get("source_head") != head or active.get("public_base_sha") != base
            or active.get("repository") != repository or active.get("branch") != branch
            or active.get("started_at") != "2026-10-30T16:50:39.837827+00:00"
            or any(key in active for key in ("public_source_sha", "pull_request", "merge_commit",
                "merge_parents", "candidate_sha", "merge_strategy", "qualification_started_at",
                "source_sha", "run_id", "run_attempt"))
            or any(key.startswith(("qualification_", "selected_run_")) for key in active)):
        raise ValueError("source-successor-resume-state-invalid")
    _validate_source_successor_history(active)
    if (not isinstance(transition, dict)
            or base != expected["merge_commit_sha"] or repository != "szTheory/genewhip"
            or transition.get("active_source_head") != head
            or transition.get("active_base_sha") != base
            or transition.get("active_repository") != repository
            or transition.get("started_at") != active.get("started_at")
            or transition.get("prior_source_head") != expected["source_head"]
            or transition.get("prior_public_base_sha") != expected["public_base_sha"]
            or transition.get("prior_merge_commit_sha") != expected["merge_commit_sha"]
            or transition.get("prior_merge_tree_sha") != expected["merge_tree_sha"]
            or transition.get("prior_pull_request") != expected["pull_request"]
            or transition.get("prior_preview_run_id") != expected["preview_run_id"]
            or transition.get("required_check") != {"name": "required-ci", "status": "COMPLETED",
                "conclusion": "SUCCESS"}):
        raise ValueError("source-successor-resume-lineage-invalid")
    archive_path = ROOT / transition["archive"]
    if archive_path.is_symlink():
        raise ValueError("source-successor-archive-path-invalid")
    try:
        predecessor_bytes = archive_path.read_bytes()
        predecessor = json.loads(predecessor_bytes)
    except (OSError, json.JSONDecodeError):
        raise ValueError("source-successor-predecessor-archive-invalid") from None
    if (hashlib.sha256(predecessor_bytes).hexdigest() != transition["archive_sha256"]
            or transition["archive_sha256"] != expected["journal_sha256"]
            or not isinstance(predecessor, dict)):
        raise ValueError("source-successor-predecessor-archive-invalid")
    _validate_r10_predecessor_artifacts(predecessor_bytes)
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    _require_hosted_budget(active["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    policy = _fresh_public_policy(packet, publication_copy)
    observations = policy.get("repository_observations", {}).get("observations", {})
    if (policy.get("repository") != repository
            or observations.get("expected_identity", {}).get("observed_default_branch_sha") != base):
        raise ValueError("source-successor-live-public-base-mismatch")
    prior_env = {key: os.environ.get(key) for key in
        ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE")}
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = active["started_at"]
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    try:
        merge = _verify_r10_merged_source(repository, predecessor, predecessor_bytes,
            phase="preparation")
    finally:
        for key, value in prior_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    if (merge.get("public_source_sha") != transition["prior_merge_commit_sha"]
            or merge.get("tree_sha") != transition["prior_merge_tree_sha"]
            or merge.get("pull_request") != transition["prior_pull_request"]
            or merge.get("preview_run_id") != transition["prior_preview_run_id"]):
        raise ValueError("source-successor-resume-merge-changed")
    repository_q = urllib.parse.quote(repository, safe="/")
    branch_result = _external(["gh", "pr", "list", "--repo", repository, "--head", branch,
        "--state", "all", "--json", "number,state,headRefOid"], timeout=45, phase="preparation")
    try:
        branches = json.loads(branch_result.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-successor-resume-pr-list-invalid") from None
    if not isinstance(branches, list) or branches:
        raise ValueError("source-successor-resume-already-published")
    refs = _gh_json(repository, "git/matching-refs/heads/" + urllib.parse.quote(branch, safe=""),
        phase="preparation")
    if not isinstance(refs, list) or refs:
        raise ValueError("source-successor-resume-already-published")
    run_result = _external(["gh", "api",
        f"repos/{repository_q}/actions/runs?head_sha={head}&per_page=100", "--jq",
        "{total_count,workflow_runs:[.workflow_runs[]|{id,head_sha,event,status,conclusion}]}"],
        timeout=45, phase="preparation")
    try:
        runs_value = json.loads(run_result.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-successor-resume-run-list-invalid") from None
    runs = runs_value.get("workflow_runs") if isinstance(runs_value, dict) else None
    if (not isinstance(runs, list) or runs_value.get("total_count") != len(runs)
            or len(runs) >= 100 or runs):
        raise ValueError("source-successor-resume-already-published")
    if journal_path.read_bytes() != journal_bytes:
        raise ValueError("source-successor-resume-journal-changed")
    _require_hosted_budget(active["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    return {"source_head": head, "public_base_sha": base, "repository": repository,
        "started_at": active["started_at"], "push_performed": False,
        "predecessor_archive": transition["archive"],
        "predecessor_journal_sha256": transition["archive_sha256"],
        "predecessor_merge": merge}


def retry_sanitized_source(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                           journal_path: pathlib.Path, *, campaign_path: pathlib.Path | None = None,
                           campaign_sha256: str | None = None,
                           scope_path: pathlib.Path | None = None,
                           recovery_selection: str = "15",
                           continuation_path: pathlib.Path | None = None,
                           continuation_purpose: str = "original17") -> dict[str, Any]:
    """Explicitly archive a failed, unmerged source attempt and bind a replacement."""
    _require_campaign_for_journal(journal_path, scope_path or ROOT / "evidence/v02-execution.json",
        campaign_path, campaign_sha256, phase="runtime", recovery_selection=recovery_selection,
        continuation_path=continuation_path, continuation_purpose=continuation_purpose)
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    if journal_path.is_symlink():
        raise ValueError("source-retry-journal-path-invalid")
    journal_path = journal_path.resolve()
    build_root = (ROOT / "build/v02").resolve()
    if not journal_path.parent.is_relative_to(build_root):
        raise ValueError("source-retry-journal-path-invalid")
    try:
        original_bytes = journal_path.read_bytes()
        previous = json.loads(original_bytes)
    except (OSError, json.JSONDecodeError):
        raise ValueError("source-retry-prior-journal-unavailable") from None
    new_head = packet["public_identity"]["head_sha"]
    new_base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    forbidden = ("public_source_sha", "merge_commit", "merge_parents", "candidate_sha",
                 "merge_strategy", "pull_request_url", "source_sha", "run_id", "run_attempt")
    if (not isinstance(previous, dict)
            or previous.get("schema") != "genewhip.v02-delivery-journal.v1"
            or previous.get("repository") != repository
            or previous.get("public_base_sha") != new_base
            or previous.get("source_head") == new_head
            or previous.get("push_performed") is not True
            or any(key in previous for key in forbidden)
            or any(key.startswith(("qualification_", "selected_run_")) for key in previous)
            or not isinstance(previous.get("started_at"), str)
            or not isinstance(previous.get("branch"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", str(previous.get("source_head", "")))
            or previous["branch"] != "v0.2-source-" + previous["source_head"][:12]):
        raise ValueError("source-retry-prior-journal-not-retryable")
    start = previous["started_at"]
    workflow_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if workflow_start and workflow_start != start:
        raise ValueError("source-retry-clock-conflicts-with-workflow")
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    prior_env = {key: os.environ.get(key) for key in
                 ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE")}
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = start
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    try:
        return _retry_sanitized_source_bound(packet, publication_copy, journal_path,
            original_bytes, previous, start, scope, build_root)
    finally:
        for key, value in prior_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _retry_sanitized_source_bound(packet: dict[str, Any], publication_copy: pathlib.Path,
                                  journal_path: pathlib.Path, original_bytes: bytes,
                                  previous: dict[str, Any], start: str,
                                  scope: dict[str, Any], build_root: pathlib.Path) -> dict[str, Any]:
    """Perform retry reads and journal replacement under the selected cutoff."""
    new_head = packet["public_identity"]["head_sha"]
    new_base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    policy = _fresh_public_policy(packet, publication_copy)
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    if (policy.get("repository") != repository
            or policy.get("repository_observations", {}).get("observations", {})
                .get("expected_identity", {}).get("observed_default_branch_sha") != new_base):
        raise ValueError("source-retry-live-public-base-mismatch")

    repository_q = urllib.parse.quote(repository, safe="/")
    listing = _external(["gh", "pr", "list", "--repo", repository, "--head", previous["branch"],
        "--state", "all", "--json",
        "number,url,state,headRefName,headRefOid,baseRefName,baseRefOid,mergeCommit,autoMergeRequest,statusCheckRollup"],
        timeout=45, phase="preparation")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    try:
        prs = json.loads(listing.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-retry-pull-request-list-invalid") from None
    matches = [row for row in prs if isinstance(row, dict)
               and row.get("headRefOid") == previous["source_head"]]
    if len(matches) != 1:
        raise ValueError("source-retry-prior-pull-request-ambiguous")
    pr = matches[0]
    if (pr.get("state") != "OPEN" or pr.get("headRefName") != previous["branch"]
            or pr.get("baseRefName") != "main"
            or pr.get("baseRefOid") != new_base or pr.get("mergeCommit")
            or pr.get("autoMergeRequest") is not None
            or str(pr.get("number", "")) == ""):
        raise ValueError("source-retry-prior-pull-request-not-open-unmerged")
    checks = pr.get("statusCheckRollup")
    required = [row for row in checks if isinstance(row, dict) and row.get("name") == "required-ci"] \
        if isinstance(checks, list) else []
    if (len(required) != 1 or required[0].get("status") != "COMPLETED"
            or required[0].get("conclusion") != "FAILURE"
            or any(not isinstance(row, dict) or row.get("status") != "COMPLETED" for row in checks)):
        raise ValueError("source-retry-required-check-not-exact-failure")
    runs_response = _external(["gh", "api",
        f"repos/{repository_q}/actions/runs?head_sha={previous['source_head']}&per_page=100"],
        timeout=45, phase="preparation")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    try:
        runs_value = json.loads(runs_response.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-retry-workflow-runs-invalid") from None
    runs = runs_value.get("workflow_runs") if isinstance(runs_value, dict) else None
    if (not isinstance(runs, list) or runs_value.get("total_count") != len(runs)
            or len(runs) >= 100):
        raise ValueError("source-retry-workflow-runs-incomplete")
    if any(row.get("status") != "completed"
           or row.get("event") == "workflow_dispatch"
           or str(row.get("display_title", "")).startswith("Plan10 qualification ")
           for row in runs if isinstance(row, dict)):
        raise ValueError("source-retry-prior-workflow-active-or-qualified")
    if any(not isinstance(row, dict) for row in runs):
        raise ValueError("source-retry-workflow-run-invalid")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")

    old_head = previous["source_head"]
    archive_sha = hashlib.sha256(original_bytes).hexdigest()
    archive_root = ROOT / "build/v02/failures"
    archive_dir = archive_root
    if archive_root.is_symlink() or archive_dir.is_symlink():
        raise ValueError("source-retry-archive-path-invalid")
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    if (not archive_root.resolve().is_relative_to(build_root)
            or not archive_dir.resolve().is_relative_to(archive_root.resolve())):
        raise ValueError("source-retry-archive-path-invalid")
    archive = archive_dir / f"source-attempt-{old_head}-{archive_sha}.json"
    try:
        with archive.open("xb") as stream:
            stream.write(original_bytes)
    except FileExistsError:
        if archive.read_bytes() != original_bytes:
            raise ValueError("source-retry-archive-path-conflicts") from None
    archive_relative = archive.resolve().relative_to(ROOT.resolve()).as_posix()
    retry_record = {"schema": "genewhip.v02-source-retry.v1",
        "archive": archive_relative, "archive_sha256": archive_sha,
        "started_at": start, "prior_source_head": old_head,
        "active_source_head": new_head, "active_repository": repository,
        "active_base_sha": new_base, "failed_pull_request": str(pr["number"]),
        "failed_required_check": {"name": "required-ci", "status": "COMPLETED",
                                  "conclusion": "FAILURE"}}
    active = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
        "repository": repository, "source_head": new_head, "public_base_sha": new_base,
        "branch": "v0.2-source-" + new_head[:12], "push_performed": False,
        "source_retry": retry_record}
    _validate_source_retry_history(active)
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    temporary_journal = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=journal_path.parent,
                prefix=journal_path.name + ".retry-", suffix=".tmp", delete=False) as stream:
            temporary_journal = pathlib.Path(stream.name)
            stream.write((json.dumps(active, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="preparation")
        os.replace(temporary_journal, journal_path)
        temporary_journal = None
    finally:
        if temporary_journal is not None:
            temporary_journal.unlink(missing_ok=True)
    return {"archive": archive_relative, "archive_sha256": archive_sha,
        "prior_source_head": old_head, "source_head": new_head,
        "public_base_sha": new_base, "repository": repository,
        "failed_pull_request": str(pr["number"]), "started_at": start,
        "push_performed": False}


def source_successor_sanitized_source(packet_path: pathlib.Path, publication_copy: pathlib.Path,
        journal_path: pathlib.Path, *, campaign_path: pathlib.Path,
        campaign_sha256: str, scope_path: pathlib.Path,
        recovery_selection: str, continuation_path: pathlib.Path,
        continuation_purpose: str) -> dict[str, Any]:
    """Bind one reviewed replacement to the exact R10 source already merged."""
    _require_campaign_for_journal(journal_path, scope_path, campaign_path, campaign_sha256,
        phase="runtime", recovery_selection=recovery_selection,
        continuation_path=continuation_path, continuation_purpose=continuation_purpose)
    if continuation_purpose != "current-native-return" or recovery_selection != "17":
        raise ValueError("source-successor-current-return-required")
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    expected = _r10_successor_constants()
    fixed_journal = ROOT / "build/v02/campaign15/hosted-delivery-journal.json"
    if (journal_path.is_symlink() or journal_path.resolve(strict=True) != fixed_journal.resolve(strict=True)
            or not journal_path.is_file()):
        raise ValueError("source-successor-journal-path-invalid")
    original_bytes = journal_path.read_bytes()
    try:
        current_journal = json.loads(original_bytes)
    except json.JSONDecodeError:
        raise ValueError("source-successor-prior-journal-invalid") from None
    if isinstance(current_journal, dict) and "source_successor" in current_journal:
        return _resume_source_successor(packet, publication_copy, journal_path,
            original_bytes, current_journal, expected, scope_path)
    if hashlib.sha256(original_bytes).hexdigest() != expected["journal_sha256"]:
        raise ValueError("source-successor-prior-journal-not-exact-r10")
    previous = current_journal
    _validate_source_retry_history(previous)
    _validate_r10_predecessor_artifacts(original_bytes)
    new_head = packet["public_identity"]["head_sha"]
    new_base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    if (new_head == expected["source_head"] or new_base != expected["merge_commit_sha"]
            or repository != "szTheory/genewhip"):
        raise ValueError("source-successor-candidate-not-based-on-exact-merged-source")
    if any(key in previous for key in ("public_source_sha", "merge_commit", "merge_parents",
            "candidate_sha", "merge_strategy", "qualification_started_at", "source_sha",
            "run_id", "run_attempt")) or any(key.startswith(("qualification_", "selected_run_"))
                for key in previous):
        raise ValueError("source-successor-prior-journal-already-consumed")
    start = previous.get("started_at")
    if not isinstance(start, str) or start != "2026-10-30T16:50:39.837827+00:00":
        raise ValueError("source-successor-campaign-start-mismatch")
    workflow_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if workflow_start and workflow_start != start:
        raise ValueError("source-successor-clock-conflicts-with-workflow")
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    policy = _fresh_public_policy(packet, publication_copy)
    observations = policy.get("repository_observations", {}).get("observations", {})
    if (policy.get("repository") != repository
            or observations.get("expected_identity", {}).get("observed_default_branch_sha") != new_base):
        raise ValueError("source-successor-live-public-base-mismatch")
    prior_env = {key: os.environ.get(key) for key in
        ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE")}
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = start
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    try:
        merge = _verify_r10_merged_source(repository, previous, original_bytes, phase="preparation")
    finally:
        for key, value in prior_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    old_sha = hashlib.sha256(original_bytes).hexdigest()
    build_root = (ROOT / "build/v02").resolve()
    archive_root = ROOT / "build/v02/failures"
    if archive_root.is_symlink():
        raise ValueError("source-successor-archive-path-invalid")
    archive_root.mkdir(parents=True, exist_ok=True)
    if not archive_root.resolve().is_relative_to(build_root):
        raise ValueError("source-successor-archive-path-invalid")
    archive = archive_root / f"merged-source-predecessor-{expected['source_head']}-{old_sha}.json"
    try:
        with archive.open("xb") as stream:
            stream.write(original_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if archive.read_bytes() != original_bytes:
            raise ValueError("source-successor-archive-path-conflicts") from None
    except OSError:
        raise ValueError("source-successor-archive-write-failed") from None
    archive_relative = archive.resolve().relative_to(ROOT.resolve()).as_posix()
    transition = {"schema": "genewhip.v02-source-successor.v1", "archive": archive_relative,
        "archive_sha256": old_sha, "started_at": start,
        "prior_source_head": expected["source_head"],
        "prior_public_base_sha": expected["public_base_sha"],
        "prior_merge_commit_sha": merge["public_source_sha"],
        "prior_merge_tree_sha": merge["tree_sha"],
        "prior_pull_request": merge["pull_request"],
        "prior_preview_run_id": expected["preview_run_id"],
        "active_source_head": new_head, "active_base_sha": new_base,
        "active_repository": repository, "required_check": merge["required_check"]}
    active = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
        "repository": repository, "source_head": new_head, "public_base_sha": new_base,
        "branch": "v0.2-source-" + new_head[:12], "push_performed": False,
        "source_successor": transition}
    _validate_source_successor_history(active)
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    _write_journal_atomically(journal_path, active, expected_current_bytes=original_bytes)
    return {"source_head": new_head, "public_base_sha": new_base,
        "repository": repository, "started_at": start, "push_performed": False,
        "predecessor_archive": archive_relative, "predecessor_journal_sha256": old_sha,
        "predecessor_merge": merge}


def _r13_failed_hosted_predecessor(journal_bytes: bytes) -> tuple[Any, dict[str, Any]]:
    spec = importlib.util.spec_from_file_location("gw_v02_r13_predecessor",
        ROOT / "scripts/release/v02_continuation.py")
    if spec is None or spec.loader is None:
        raise ValueError("source-successor-predecessor-validator-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        result = module.validate_r13_failed_hosted_predecessor(ROOT, journal_bytes=journal_bytes)
    except ValueError:
        raise ValueError("source-successor-r13-predecessor-invalid") from None
    return module, result


def _r13_remote_json(repository: str, endpoint: str, *, phase: str) -> Any:
    encoded = urllib.parse.quote(repository, safe="/")
    response = _external(["gh", "api", f"repos/{encoded}/{endpoint}"],
        timeout=45, phase=phase)
    try:
        return json.loads(response.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-successor-r13-remote-response-invalid") from None


def _verify_r13_failed_hosted_predecessor(repository: str, journal_bytes: bytes,
        *, phase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reopen R15's PR preview, failed push preview, and failed full run."""
    module, _predecessor = _r13_failed_hosted_predecessor(journal_bytes)
    expected = module.R13_FAILED_HOSTED_PREDECESSOR
    if repository != "szTheory/genewhip":
        raise ValueError("source-successor-r13-repository-mismatch")
    branch = "v0.2-source-" + expected["source_head"][:12]
    pr = _r13_remote_json(repository, f"pulls/{expected['pull_request']}", phase=phase)
    if (not isinstance(pr, dict) or pr.get("state") != "closed" or pr.get("merged") is not True
            or not isinstance(pr.get("head"), dict) or pr["head"].get("sha") != expected["source_head"]
            or pr["head"].get("ref") != branch
            or not isinstance(pr.get("base"), dict) or pr["base"].get("ref") != "main"
            or pr["base"].get("sha") != expected["public_base_sha"]
            or pr.get("merge_commit_sha") != expected["public_source_sha"]):
        raise ValueError("source-successor-r13-merged-pr-identity-invalid")
    predecessor = _predecessor
    merge_receipt = _verified_merge_receipt({
        "number": pr.get("number", expected["pull_request"]),
        "url": pr.get("html_url"), "state": "MERGED",
        "headRefOid": pr["head"]["sha"], "baseRefName": pr["base"]["ref"],
        "mergeCommit": {"oid": pr["merge_commit_sha"]}}, repository,
        predecessor["candidate_root"] / "publication", expected["source_head"],
        expected["public_base_sha"], branch, phase=phase)
    if (merge_receipt["public_source_sha"] != expected["public_source_sha"]
            or merge_receipt["tree_sha"] != expected["public_tree_sha"]
            or merge_receipt["public_base_sha"] != expected["public_base_sha"]):
        raise ValueError("source-successor-r13-merge-receipt-changed")
    run_specs = (
        (expected["preview_run_id"], {"head_sha": expected["source_head"], "event": "pull_request",
            "status": "completed", "conclusion": "success", "path": ".github/workflows/ci.yml",
            "head_branch": branch, "display_title": "Required preview checks"}),
        (expected["merge_preview_run_id"], {"head_sha": expected["public_source_sha"], "event": "push",
            "status": "completed", "conclusion": "failure", "path": ".github/workflows/ci.yml",
            "head_branch": "main", "display_title": "Required preview checks"}),
        (expected["qualification_run_id"], {"head_sha": expected["public_source_sha"],
            "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
            "path": ".github/workflows/ci.yml", "head_branch": "main",
            "display_title": "Plan10 qualification " + expected["qualification_nonce"],
            "run_attempt": expected["qualification_attempt"],
            "created_at": expected["qualification_created_at"]}))
    for run_id, fields in run_specs:
        run = _r13_remote_json(repository, f"actions/runs/{run_id}", phase=phase)
        if (not isinstance(run, dict) or run.get("id") != int(run_id)
                or any(run.get(key) != value for key, value in fields.items())):
            raise ValueError("source-successor-r13-run-identity-invalid")
    run_rosters = (
        (expected["source_head"], {int(expected["preview_run_id"])}),
        (expected["public_source_sha"], {
            int(expected["merge_preview_run_id"]), int(expected["qualification_run_id"])}))
    for head, expected_ids in run_rosters:
        roster = _r13_remote_json(repository,
            f"actions/runs?head_sha={head}&per_page=100", phase=phase)
        rows = roster.get("workflow_runs") if isinstance(roster, dict) else None
        if (not isinstance(rows, list) or roster.get("total_count") != len(rows) or len(rows) >= 100
                or {row.get("id") for row in rows if isinstance(row, dict)} != expected_ids
                or any(not isinstance(row, dict) or row.get("status") != "completed"
                    or row.get("event") == "workflow_dispatch"
                        and row.get("id") != int(expected["qualification_run_id"])
                    for row in rows)):
            raise ValueError("source-successor-r13-workflow-roster-changed")
    push_jobs_value = _r13_remote_json(repository,
        f"actions/runs/{expected['merge_preview_run_id']}/jobs?per_page=100", phase=phase)
    push_jobs = push_jobs_value.get("jobs") if isinstance(push_jobs_value, dict) else None
    push_statuses = {
        "product-smoke": "success", "phase7-fast": "success", "desktop": "success",
        "safety": "failure", "package": "success", "performance": "success",
        "gameplay": "success", "extended": "skipped", "v02-benchmark-recursion94": "skipped",
        "v02-runtime": "skipped", "v02-benchmark-control": "skipped",
        "v02-benchmark-tank-battle": "skipped", "v02-package": "skipped",
        "v02-release-qualification": "skipped", "attestation": "success",
        "required-ci": "failure"}
    if (not isinstance(push_jobs, list) or push_jobs_value.get("total_count") != len(push_jobs)
            or len(push_jobs) >= 100 or len(push_jobs) != len(push_statuses)
            or {row.get("name") for row in push_jobs if isinstance(row, dict)} != set(push_statuses)):
        raise ValueError("source-successor-r13-push-preview-job-roster-invalid")
    push_by_name = {row["name"]: row for row in push_jobs}
    for name, conclusion in push_statuses.items():
        row = push_by_name[name]
        if row.get("status") != "completed" or row.get("conclusion") != conclusion:
            raise ValueError("source-successor-r13-push-preview-job-result-changed")
    if (push_by_name["safety"].get("id") != int(expected["merge_preview_safety_job_id"])
            or push_by_name["required-ci"].get("id") != int(expected["merge_preview_required_ci_job_id"])):
        raise ValueError("source-successor-r13-push-preview-job-identity-changed")
    safety_steps = push_by_name["safety"].get("steps")
    push_required_steps = push_by_name["required-ci"].get("steps")
    if (not isinstance(safety_steps, list) or not isinstance(push_required_steps, list)
            or not any(row.get("name") == "Run bash scripts/ci/required-gate.sh"
                and row.get("conclusion") == "failure" for row in safety_steps)
            or not any(row.get("name") == "Reject incomplete or stale required lanes"
                and row.get("conclusion") == "failure" for row in push_required_steps)):
        raise ValueError("source-successor-r13-push-preview-failure-step-changed")
    jobs_value = _r13_remote_json(repository,
        f"actions/runs/{expected['qualification_run_id']}/attempts/{expected['qualification_attempt']}/jobs?per_page=100",
        phase=phase)
    jobs = jobs_value.get("jobs") if isinstance(jobs_value, dict) else None
    if not isinstance(jobs, list) or jobs_value.get("total_count") != len(jobs) or len(jobs) >= 100:
        raise ValueError("source-successor-r13-job-roster-invalid")
    job_statuses = {
        "phase7-fast": "success", "gameplay": "success", "safety": "success",
        "product-smoke": "success", "desktop": "success", "performance": "success",
        "package": "success", "v02-runtime": "failure", "extended": "skipped",
        "required-ci": "failure", "v02-benchmark-control": "skipped",
        "v02-benchmark-tank-battle": "skipped", "v02-benchmark-recursion94": "skipped",
        "v02-package": "skipped", "v02-release-qualification": "skipped", "attestation": "skipped"}
    if (len(jobs) != len(job_statuses) or {row.get("name") for row in jobs if isinstance(row, dict)}
            != set(job_statuses)):
        raise ValueError("source-successor-r13-job-roster-invalid")
    by_name = {row["name"]: row for row in jobs}
    for name, conclusion in job_statuses.items():
        row = by_name[name]
        if row.get("status") != "completed" or row.get("conclusion") != conclusion:
            raise ValueError("source-successor-r13-job-result-changed")
    if (by_name["v02-runtime"].get("id") != int(expected["runtime_job_id"])
            or by_name["required-ci"].get("id") != int(expected["required_ci_job_id"])):
        raise ValueError("source-successor-r13-job-identity-changed")
    runtime_steps = by_name["v02-runtime"].get("steps")
    required_steps = by_name["required-ci"].get("steps")
    if (not isinstance(runtime_steps, list) or not isinstance(required_steps, list)
            or not any(row.get("name") == "Run complete current-source product safety and chunk roster"
                and row.get("conclusion") == "failure" for row in runtime_steps)
            or not any(row.get("name") == "Reject incomplete or stale required lanes"
                and row.get("conclusion") == "failure" for row in required_steps)):
        raise ValueError("source-successor-r13-failure-step-changed")
    artifacts_value = _r13_remote_json(repository,
        f"actions/runs/{expected['qualification_run_id']}/artifacts?per_page=100", phase=phase)
    artifacts = artifacts_value.get("artifacts") if isinstance(artifacts_value, dict) else None
    expected_artifacts = {
        (13036610344, "phase4-host-evidence-41182437107-1", 10644,
            "sha256:f1ed56d6ed25e005f2d70888a5b85b824de2cdb7cbf4d9da5b4b0dd1150faa18"),
        (13035314966, "safety-evidence-41182437107-1", 12640,
            "sha256:224115d7acf0430e312acc2368a40b3be4fce33b052487ca059a24b17fb23746")}
    observed_artifacts = {(row.get("id"), row.get("name"), row.get("size_in_bytes"), row.get("digest"))
        for row in artifacts if isinstance(row, dict)} if isinstance(artifacts, list) else set()
    if observed_artifacts != expected_artifacts or artifacts_value.get("total_count") != len(expected_artifacts):
        raise ValueError("source-successor-r13-hosted-output-roster-changed")
    main = _gh_json(repository, "git/ref/heads/main", phase=phase)
    if main.get("object", {}).get("sha") != expected["public_source_sha"]:
        raise ValueError("source-successor-r13-public-main-moved")
    return expected, {"runtime_job_conclusion": "failure", "required_ci_conclusion": "failure",
        "runtime_failure_step": "Run complete current-source product safety and chunk roster",
        "runtime_artifact": "absent", "runtime_child_cleanup": "UNKNOWN",
        "push_preview_safety_conclusion": "failure",
        "push_preview_required_ci_conclusion": "failure",
        "push_preview_failure_step": "Run bash scripts/ci/required-gate.sh",
        "push_preview_sanitized_failure": "phase5_baseline_contract method UNKNOWN",
        "qualification_run_id": expected["qualification_run_id"],
        "qualification_attempt": expected["qualification_attempt"]}


def _validate_r13_failed_hosted_successor(journal: dict[str, Any]) -> None:
    successor = journal.get("source_successor") if isinstance(journal, dict) else None
    failed = successor.get("failed_hosted") if isinstance(successor, dict) else None
    if failed is None:
        return
    required = {"schema", "archive", "archive_sha256", "started_at", "prior_source_head",
        "prior_public_source_sha", "prior_public_tree_sha", "prior_pull_request",
        "prior_qualification_run_id", "prior_qualification_attempt", "prior_qualification_nonce",
        "prior_failure_facts", "active_source_head", "active_base_sha", "active_repository"}
    if (not isinstance(failed, dict) or set(failed) != required
            or failed.get("schema") != "genewhip.v02-source-successor-r13-failed-hosted.v1"
            or failed.get("started_at") != journal.get("started_at")
            or failed.get("active_source_head") != journal.get("source_head")
            or failed.get("active_base_sha") != journal.get("public_base_sha")
            or failed.get("active_repository") != journal.get("repository")):
        raise ValueError("hosted-delivery-journal-r13-successor-identity-invalid")
    archive_input = ROOT / failed["archive"]
    if archive_input.is_symlink():
        raise ValueError("hosted-delivery-journal-r13-successor-archive-invalid")
    try:
        archive = archive_input.resolve(strict=True)
        raw = archive.read_bytes()
    except OSError:
        raise ValueError("hosted-delivery-journal-r13-successor-archive-invalid") from None
    if (not archive.is_relative_to((ROOT / "build/v02/failures").resolve())
            or len(raw) > 64 * 1024
            or hashlib.sha256(raw).hexdigest() != failed.get("archive_sha256")):
        raise ValueError("hosted-delivery-journal-r13-successor-archive-invalid")
    module, _ = _r13_failed_hosted_predecessor(raw)
    expected = module.R13_FAILED_HOSTED_PREDECESSOR
    expected_facts = {"runtime_job_conclusion": "failure", "required_ci_conclusion": "failure",
        "runtime_failure_step": "Run complete current-source product safety and chunk roster",
        "runtime_artifact": "absent", "runtime_child_cleanup": "UNKNOWN",
        "push_preview_safety_conclusion": "failure",
        "push_preview_required_ci_conclusion": "failure",
        "push_preview_failure_step": "Run bash scripts/ci/required-gate.sh",
        "push_preview_sanitized_failure": "phase5_baseline_contract method UNKNOWN",
        "qualification_run_id": expected["qualification_run_id"],
        "qualification_attempt": expected["qualification_attempt"]}
    if (failed.get("archive_sha256") != expected["journal_sha256"]
            or failed.get("prior_source_head") != expected["source_head"]
            or failed.get("prior_public_source_sha") != expected["public_source_sha"]
            or failed.get("prior_public_tree_sha") != expected["public_tree_sha"]
            or failed.get("prior_pull_request") != expected["pull_request"]
            or failed.get("prior_qualification_run_id") != expected["qualification_run_id"]
            or failed.get("prior_qualification_attempt") != expected["qualification_attempt"]
            or failed.get("prior_qualification_nonce") != expected["qualification_nonce"]
            or failed.get("prior_failure_facts") != expected_facts
            or successor.get("prior_merge_commit_sha") != "ac7c5bdc8e4e87e3a6423de7a64524f5f0ca498b"):
        raise ValueError("hosted-delivery-journal-r13-successor-lineage-invalid")


def _resume_r13_failed_hosted_successor(packet: dict[str, Any], journal_path: pathlib.Path,
        journal_bytes: bytes, journal: dict[str, Any], scope_path: pathlib.Path) -> dict[str, Any]:
    _validate_source_successor_history(journal)
    transition = journal["source_successor"]["failed_hosted"]
    original_bytes = (ROOT / transition["archive"]).read_bytes()
    expected, failure_facts = _verify_r13_failed_hosted_predecessor(
        packet["repository"], original_bytes, phase="preparation")
    if (packet["public_identity"].get("base_sha") != expected["public_source_sha"]
            or packet["public_identity"].get("head_sha") != journal["source_head"]):
        raise ValueError("source-successor-r13-resume-candidate-mismatch")
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    _require_hosted_budget(journal["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope, phase="preparation")
    repository, branch = packet["repository"], journal["branch"]
    prs = _r13_remote_json(repository,
        f"pulls?head={urllib.parse.quote('szTheory:' + branch, safe='')}&state=all&per_page=100",
        phase="preparation")
    if not isinstance(prs, list) or prs:
        raise ValueError("source-successor-r13-resume-already-published")
    refs = _gh_json(repository, "git/matching-refs/heads/" + urllib.parse.quote(branch, safe=""),
        phase="preparation")
    if not isinstance(refs, list) or refs:
        raise ValueError("source-successor-r13-resume-already-published")
    runs = _r13_remote_json(repository,
        f"actions/runs?head_sha={packet['public_identity']['head_sha']}&per_page=100",
        phase="preparation")
    if not isinstance(runs, dict) or runs.get("total_count") != 0 or runs.get("workflow_runs") != []:
        raise ValueError("source-successor-r13-resume-already-published")
    if journal_path.read_bytes() != journal_bytes:
        raise ValueError("source-successor-r13-resume-journal-changed")
    _require_hosted_budget(journal["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope, phase="preparation")
    return {"source_head": journal["source_head"], "public_base_sha": journal["public_base_sha"],
        "repository": repository, "started_at": journal["started_at"], "push_performed": False,
        "predecessor_archive": transition["archive"],
        "predecessor_journal_sha256": transition["archive_sha256"],
        "predecessor_merge": {"public_source_sha": expected["public_source_sha"],
            "tree_sha": expected["public_tree_sha"], "pull_request": expected["pull_request"],
            "qualification_failure": failure_facts}}


def failed_hosted_successor_sanitized_source(packet_path: pathlib.Path,
        publication_copy: pathlib.Path, journal_path: pathlib.Path, *, scope_path: pathlib.Path,
        campaign_path: pathlib.Path, campaign_sha256: str,
        continuation_path: pathlib.Path, recovery_selection: str,
        continuation_purpose: str) -> dict[str, Any]:
    """Prepare one fixed replacement after the exact R13 hosted qualification failure."""
    _require_campaign_for_journal(journal_path, scope_path, campaign_path, campaign_sha256,
        phase="preparation", recovery_selection=recovery_selection,
        continuation_path=continuation_path, continuation_purpose=continuation_purpose)
    if recovery_selection != "17" or continuation_purpose != "current-native-return":
        raise ValueError("source-successor-current-return-required")
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    journal_path = journal_path.resolve(strict=True)
    expected_path = (ROOT / "build/v02/campaign15/hosted-delivery-journal.json").resolve(strict=True)
    if journal_path != expected_path:
        raise ValueError("source-successor-journal-path-invalid")
    original_bytes = journal_path.read_bytes()
    try:
        previous = json.loads(original_bytes)
    except json.JSONDecodeError:
        raise ValueError("source-successor-r13-journal-invalid") from None
    if (isinstance(previous, dict) and isinstance(previous.get("source_successor"), dict)
            and "failed_hosted" in previous["source_successor"]):
        return _resume_r13_failed_hosted_successor(
            packet, journal_path, original_bytes, previous, scope_path)
    module, predecessor = _r13_failed_hosted_predecessor(original_bytes)
    expected = module.R13_FAILED_HOSTED_PREDECESSOR
    if (packet["repository"] != "szTheory/genewhip"
            or packet["public_identity"].get("base_sha") != expected["public_source_sha"]
            or packet["public_identity"].get("head_sha") == expected["source_head"]):
        raise ValueError("source-successor-r13-candidate-not-based-on-exact-merged-source")
    if os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT", expected["started_at"]) != expected["started_at"]:
        raise ValueError("source-successor-campaign-start-mismatch")
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    _require_hosted_budget(expected["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope, phase="preparation")
    policy = _fresh_public_policy(packet, publication_copy)
    observations = policy.get("repository_observations", {}).get("observations", {})
    if (policy.get("repository") != packet["repository"]
            or observations.get("expected_identity", {}).get("observed_default_branch_sha")
                != expected["public_source_sha"]):
        raise ValueError("source-successor-r13-live-public-base-mismatch")
    verified, failure_facts = _verify_r13_failed_hosted_predecessor(
        packet["repository"], original_bytes, phase="preparation")
    new_head, new_base = packet["public_identity"]["head_sha"], packet["public_identity"]["base_sha"]
    old_sha = hashlib.sha256(original_bytes).hexdigest()
    archive_root = ROOT / "build/v02/failures"
    if archive_root.is_symlink():
        raise ValueError("source-successor-r13-archive-path-invalid")
    archive_root.mkdir(parents=True, exist_ok=True)
    if not archive_root.resolve(strict=True).is_relative_to((ROOT / "build/v02").resolve(strict=True)):
        raise ValueError("source-successor-r13-archive-path-invalid")
    archive = archive_root / f"failed-hosted-predecessor-r13-{old_sha}.json"
    try:
        with archive.open("xb") as stream:
            stream.write(original_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if archive.read_bytes() != original_bytes:
            raise ValueError("source-successor-r13-archive-conflict") from None
    archive_relative = archive.resolve(strict=True).relative_to(ROOT.resolve(strict=True)).as_posix()
    failed = {"schema": "genewhip.v02-source-successor-r13-failed-hosted.v1",
        "archive": archive_relative, "archive_sha256": old_sha, "started_at": expected["started_at"],
        "prior_source_head": expected["source_head"], "prior_public_source_sha": expected["public_source_sha"],
        "prior_public_tree_sha": expected["public_tree_sha"], "prior_pull_request": expected["pull_request"],
        "prior_qualification_run_id": expected["qualification_run_id"],
        "prior_qualification_attempt": expected["qualification_attempt"],
        "prior_qualification_nonce": expected["qualification_nonce"],
        "prior_failure_facts": failure_facts, "active_source_head": new_head,
        "active_base_sha": new_base, "active_repository": packet["repository"]}
    lineage = dict(predecessor["source_successor_lineage"])
    lineage.update({"active_source_head": new_head, "active_base_sha": new_base,
        "active_repository": packet["repository"], "failed_hosted": failed})
    active = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": expected["started_at"],
        "repository": packet["repository"], "source_head": new_head, "public_base_sha": new_base,
        "branch": "v0.2-source-" + new_head[:12], "push_performed": False, "source_successor": lineage}
    _validate_source_successor_history(active)
    _require_hosted_budget(expected["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope, phase="preparation")
    _write_journal_atomically(journal_path, active, expected_current_bytes=original_bytes)
    return {"source_head": new_head, "public_base_sha": new_base,
        "repository": packet["repository"], "started_at": expected["started_at"],
        "push_performed": False, "predecessor_archive": archive_relative,
        "predecessor_journal_sha256": old_sha,
        "predecessor_merge": {"public_source_sha": verified["public_source_sha"],
            "tree_sha": verified["public_tree_sha"], "pull_request": verified["pull_request"],
            "qualification_failure": failure_facts}}


def _adopt_incomplete_merged_source(packet: dict[str, Any], candidate: pathlib.Path,
        journal_path: pathlib.Path, previous: dict[str, Any]) -> dict[str, Any] | None:
    """Recover a verified merge receipt before the moved-main preflight can reject it."""
    head = packet["public_identity"]["head_sha"]
    base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    branch = previous.get("branch")
    if (previous.get("push_performed") is not True or previous.get("source_head") != head
            or previous.get("public_base_sha") != base
            or branch != "v0.2-source-" + head[:12]):
        return None
    if any(key in previous for key in ("public_source_sha", "merge_commit", "merge_parents",
            "candidate_sha", "merge_strategy", "qualification_started_at", "source_sha",
            "run_id", "run_attempt")):
        raise ValueError("hosted-delivery-journal-already-consumed")
    try:
        original_bytes = journal_path.read_bytes()
        if json.loads(original_bytes) != previous:
            raise ValueError("hosted-delivery-journal-changed-before-merge-adoption")
    except (OSError, json.JSONDecodeError):
        raise ValueError("hosted-delivery-journal-unavailable-for-merge-adoption") from None
    listing = _external(["gh", "pr", "list", "--repo", repository, "--head", branch,
        "--state", "all", "--json",
        "number,url,state,headRefName,headRefOid,baseRefName,baseRefOid,mergeCommit,statusCheckRollup"],
        timeout=45, phase="runtime")
    try:
        prs = json.loads(listing.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-pull-request-list-invalid") from None
    matches = [row for row in prs if isinstance(row, dict) and row.get("headRefOid") == head]
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("hosted-delivery-journal-merge-pr-not-unique")
    pr = matches[0]
    if pr.get("state") != "MERGED":
        return None
    if (pr.get("headRefName") != branch or pr.get("baseRefName") != "main"
            or pr.get("baseRefOid") != base):
        raise ValueError("hosted-delivery-journal-merge-pr-identity-invalid")
    checks = pr.get("statusCheckRollup")
    required = [row for row in checks if isinstance(row, dict) and row.get("name") == "required-ci"] \
        if isinstance(checks, list) else []
    if (len(required) != 1 or required[0].get("status") != "COMPLETED"
            or required[0].get("conclusion") != "SUCCESS"
            or any(not isinstance(row, dict) or row.get("status") != "COMPLETED"
                or row.get("conclusion") != "SUCCESS" for row in checks)):
        raise ValueError("hosted-delivery-journal-merge-required-check-not-success")
    receipt = _verified_merge_receipt(pr, repository, candidate, head, base, branch, phase="runtime")
    main = _gh_json(repository, "git/ref/heads/main", phase="runtime")
    if main.get("object", {}).get("sha") != receipt["public_source_sha"]:
        raise ValueError("public-main-moved-after-journaled-merge")
    journal = {**previous, **receipt}
    _write_journal_atomically(journal_path, journal, expected_current_bytes=original_bytes)
    return receipt


def publish_sanitized_source(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                             journal_path: pathlib.Path, *, campaign_path: pathlib.Path | None = None,
                             campaign_sha256: str | None = None,
                             scope_path: pathlib.Path | None = None,
                             recovery_selection: str = "15",
                             continuation_path: pathlib.Path | None = None,
                             continuation_purpose: str = "original17") -> dict[str, Any]:
    """Push only the reviewed sanitized candidate, merge through required protection."""
    _require_campaign_for_journal(journal_path, scope_path or ROOT / "evidence/v02-execution.json",
        campaign_path, campaign_sha256, phase="runtime", recovery_selection=recovery_selection,
        continuation_path=continuation_path, continuation_purpose=continuation_purpose)
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    journal_path = journal_path.resolve()
    previous = None
    if journal_path.is_file():
        previous = json.loads(journal_path.read_text(encoding="utf-8"))
        _validate_source_retry_history(previous)
        _validate_source_successor_history(previous)
        if (not isinstance(previous, dict)
                or previous.get("schema") != "genewhip.v02-delivery-journal.v1"
                or previous.get("repository") != packet["repository"]
                or previous.get("source_head") != packet["public_identity"]["head_sha"]
                or previous.get("public_base_sha") != packet["public_identity"]["base_sha"]
                or not isinstance(previous.get("started_at"), str)):
            raise ValueError("hosted-delivery-journal-conflicts-with-candidate")
        workflow_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
        if workflow_start and workflow_start != previous.get("started_at"):
            raise ValueError("hosted-delivery-journal-clock-conflicts-with-workflow")
        _require_hosted_budget(previous["started_at"],
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = previous["started_at"]
        if previous.get("public_source_sha"):
            # A local journal is a resume hint only. Reopen the actual PR and
            # merge commit (including parents and tree) before treating it as
            # authority, exactly as on the uninterrupted path.
            required = ("pull_request", "pull_request_url", "candidate_sha", "public_base_sha",
                        "merge_parents", "branch")
            if any(key not in previous for key in required):
                raise ValueError("hosted-delivery-journal-merge-receipt-incomplete")
            resume_phase = "package" if previous.get("qualification_started_at") else "runtime"
            listing = _external(["gh", "pr", "list", "--repo", packet["repository"],
                "--head", previous["branch"], "--state", "all", "--json",
                "number,url,headRefOid,baseRefName,state,mergeCommit"], timeout=45, phase=resume_phase)
            try:
                prs = json.loads(listing.stdout)
            except json.JSONDecodeError:
                raise ValueError("github-pull-request-list-invalid") from None
            matches = [row for row in prs if str(row.get("number")) == str(previous["pull_request"])]
            if len(matches) != 1:
                raise ValueError("hosted-delivery-journal-merge-pr-not-reopened")
            receipt = _verified_merge_receipt(matches[0], packet["repository"], publication_copy.resolve(strict=True),
                packet["public_identity"]["head_sha"], packet["public_identity"]["base_sha"],
                previous["branch"], phase=resume_phase)
            if any(previous.get(key) != receipt.get(key) for key in
                   ("public_source_sha", "candidate_sha", "public_base_sha", "merge_parents")):
                raise ValueError("hosted-delivery-journal-merge-receipt-conflicts-with-remote")
            main = _gh_json(packet["repository"], "git/ref/heads/main", phase=resume_phase)
            if main.get("object", {}).get("sha") != receipt["public_source_sha"]:
                raise ValueError("public-main-moved-after-journaled-merge")
            return {**receipt, "pull_request_url": matches[0].get("url")}
        recovered = _adopt_incomplete_merged_source(packet=packet,
            candidate=publication_copy.resolve(strict=True), journal_path=journal_path,
            previous=previous)
        if recovered is not None:
            return recovered
    policy = _fresh_public_policy(packet, publication_copy)
    candidate = publication_copy.resolve(strict=True)
    head, base = packet["public_identity"]["head_sha"], packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    started_at = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    if previous is not None:
        if (previous.get("source_head") != head or previous.get("public_base_sha") != base
                or previous.get("repository") != repository):
            raise ValueError("hosted-delivery-journal-conflicts-with-candidate")
        started_at = previous.get("started_at", started_at)
    branch = "v0.2-source-" + head[:12]
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_header = {"schema": "genewhip.v02-delivery-journal.v1",
        "started_at": started_at, "repository": repository, "source_head": head,
        "public_base_sha": base, "branch": branch, "push_performed": False}
    if previous and "source_retry" in previous:
        journal_header["source_retry"] = previous["source_retry"]
    if previous and "source_successor" in previous:
        journal_header["source_successor"] = previous["source_successor"]
    _write_json(journal_path, journal_header)
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    process = _external(["git", "push", "origin", f"HEAD:refs/heads/{branch}"],
                        cwd=candidate, timeout=300, check=False)
    if process.returncode:
        raise ValueError("sanitized-public-branch-push-failed")
    journal = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": started_at,
        "repository": repository, "source_head": head, "public_base_sha": base,
        "branch": branch, "push_performed": True, "policy_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()).hexdigest()}
    if previous and "source_retry" in previous:
        journal["source_retry"] = previous["source_retry"]
    if previous and "source_successor" in previous:
        journal["source_successor"] = previous["source_successor"]
    _write_json(journal_path, journal)
    listed = _external(["gh", "pr", "list", "--repo", repository, "--head", branch,
        "--state", "all", "--json",
        "number,url,headRefName,headRefOid,baseRefOid,baseRefName,state,mergeCommit,statusCheckRollup"],
        timeout=45)
    try:
        prs = json.loads(listed.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-pull-request-list-invalid") from None
    if not prs:
        body_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                    prefix="genewhip-pr-body-", suffix=".md", delete=False) as body_file:
                body_path = pathlib.Path(body_file.name)
                body_file.write(_pr_body(head, base))
            created = _external(["gh", "pr", "create", "--repo", repository, "--base", "main",
                "--head", branch, "--title", "Prepare sanitized v0.2 source snapshot",
                "--body-file", str(body_path)], timeout=120)
        finally:
            if body_path is not None:
                body_path.unlink(missing_ok=True)
        number = re.search(r"/pull/([0-9]+)", created.stdout)
        if number is None:
            raise ValueError("github-pull-request-number-unavailable")
        pr_number = number.group(1)
    elif len(prs) == 1 and prs[0].get("state") == "MERGED":
        checks = prs[0].get("statusCheckRollup")
        required = [row for row in checks if isinstance(row, dict) and row.get("name") == "required-ci"] \
            if isinstance(checks, list) else []
        if (len(required) != 1 or required[0].get("status") != "COMPLETED"
                or required[0].get("conclusion") != "SUCCESS"):
            raise ValueError("hosted-delivery-merged-pr-required-check-not-success")
        receipt = _verified_merge_receipt(prs[0], repository, candidate, head, base, branch)
        journal.update(receipt)
        _write_json(journal_path, journal)
        return receipt
    elif len(prs) == 1 and prs[0].get("state") == "OPEN" \
            and prs[0].get("headRefOid") == head and prs[0].get("baseRefName") == "main":
        pr_number = str(prs[0]["number"])
    else:
        raise ValueError("conflicting-public-source-pull-request-exists")
    while True:
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        pr_data = _external(["gh", "pr", "view", pr_number, "--repo", repository,
            "--json", "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"], timeout=45)
        try:
            current = json.loads(pr_data.stdout)
        except json.JSONDecodeError:
            raise ValueError("github-pull-request-state-invalid") from None
        if (current.get("headRefOid") != head or current.get("baseRefOid") != base
                or current.get("state") != "OPEN"):
            raise ValueError("public-source-pull-request-identity-or-base-changed")
        checks = current.get("statusCheckRollup")
        required = [item for item in checks or [] if item.get("name") == "required-ci"]
        if any(item.get("conclusion") in {"FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"}
               for item in required):
            raise ValueError("required-public-pull-request-check-failed")
        if len(required) == 1 and required[0].get("conclusion") == "SUCCESS":
            break
        time.sleep(30)
    # The PR can wait for checks for hours. Re-open effective protection and
    # base immediately before the merge decision.
    policy = _fresh_public_policy(packet, publication_copy)
    policy_observations = policy["repository_observations"]["observations"]
    strategy = ("merge" if "merge" in policy_observations["permitted_merge_methods"]
                else "squash")
    _external(["gh", "pr", "merge", pr_number, "--repo", repository,
               "--match-head-commit", head,
               "--" + strategy], timeout=300)
    while True:
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        merged = _external(["gh", "pr", "view", pr_number, "--repo", repository,
            "--json", "state,mergedAt,mergeCommit,headRefOid,baseRefOid"], timeout=45)
        current = json.loads(merged.stdout)
        if current.get("state") == "MERGED":
            receipt = _verified_merge_receipt({**current, "number": pr_number,
                "baseRefName": "main"}, repository, candidate, head, base, branch)
            if receipt["merge_strategy"] != strategy:
                raise ValueError("protected-merge-strategy-mismatch")
            journal.update(receipt)
            _write_json(journal_path, journal)
            return receipt
        if current.get("state") != "OPEN":
            raise ValueError("public-source-pull-request-closed-without-merge")
        time.sleep(30)


def _publication_paths(root: pathlib.Path) -> list[str]:
    """Return the tracked product tree, excluding local planning/runtime material."""
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    names = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    excluded = {".planning", "build", "artifacts", "node_modules", "target", "dist",
                "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    result = []
    for name in names:
        path = pathlib.PurePosixPath(name)
        parts = path.parts
        if (not parts or any(part in excluded for part in parts)
                or path.name == ".DS_Store" or path.name.startswith(".env")
                or (parts[0] == "evidence" and path.name.startswith("phase5-")
                    and path.name not in PUBLIC_PHASE5_HISTORY)
                or name == "fixtures/candidate-screening-v2.json"
                or any(part.lower() in {"private-receipts", "private-receipt", "crosswalks"}
                       for part in parts)
                or path.name.startswith("raw-build-") and path.suffix.lower() == ".bin"
                or path.suffix.lower() == ".json" and
                   ("-red-" in path.name or path.name.endswith("-red.json")
                    or name == "evidence/phase6-repairs.json")):
            continue
        candidate = root / name
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("public-snapshot-source-entry-invalid")
        result.append(name)
    if not result:
        raise ValueError("public-snapshot-source-empty")
    return sorted(result)


def _projection_crosswalk(root: pathlib.Path, included: list[str]) -> dict[str, Any]:
    """Account for every filtered tracked path; retain exact local receipt/binary rows."""
    names = [item.decode("utf-8") for item in
             subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0") if item]
    counts: dict[str, int] = {}
    exact: list[dict[str, str]] = []
    for name in names:
        if name in included:
            continue
        path = pathlib.PurePosixPath(name)
        parts = path.parts
        if ".planning" in parts:
            reason = "private-planning-history-and-crosswalks"
        elif (parts[0] == "evidence" and path.name.startswith("phase5-")
              and path.name not in PUBLIC_PHASE5_HISTORY):
            reason = "private-phase5-historical-evidence-and-receipts"
            exact.append({"path": name, "reason": reason})
        elif name == "fixtures/candidate-screening-v2.json":
            reason = "private-phase5-screening-history"
            exact.append({"path": name, "reason": reason})
        elif any(part in {"build", "artifacts", "node_modules", "target", "dist",
                          "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"} for part in parts):
            reason = "generated-output-or-cache"
        elif path.name.startswith(".env"):
            reason = "local-environment-file"
        elif path.name.startswith("raw-build-") and path.suffix.lower() == ".bin":
            reason = "intermediate-fixture-build-product"
            exact.append({"path": name, "reason": reason})
        elif path.suffix.lower() == ".json" and ("-red-" in path.name or path.name.endswith("-red.json")
                                                   or name == "evidence/phase6-repairs.json"):
            reason = "local-failed-or-diagnostic-receipt"
            exact.append({"path": name, "reason": reason})
        elif path.name == ".DS_Store":
            reason = "local-filesystem-metadata"
        elif any(part.lower() in {"private-receipts", "private-receipt", "crosswalks"} for part in parts):
            reason = "private-receipt-or-crosswalk"
        else:
            raise ValueError("public-snapshot-exclusion-unclassified")
        counts[reason] = counts.get(reason, 0) + 1
    retained_history = [{"path": f"evidence/{name}",
                         "sha256": _sha(root / "evidence" / name),
                         "reason": "required-by-public-matrix-and-current-route-consumers; historical-only"}
                        for name in sorted(PUBLIC_PHASE5_HISTORY)
                        if f"evidence/{name}" in included]
    return {"excluded_path_counts": dict(sorted(counts.items())),
            "exact_local_exclusions": sorted(exact, key=lambda row: row["path"]),
            "retained_historical_evidence": retained_history}


def _authorized_public_repository(root: pathlib.Path) -> str:
    """Resolve the previously authorized destination from local Phase 4 policy records."""
    candidates = (root / "build/phase4/delivery-preflight.json",
                  root / "build/phase4/authorized-preflight.json")
    for path in candidates:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        repository = record.get("repository")
        destination = record.get("destination")
        if (record.get("schema") == "genewhip.publication-readiness-packet.v1"
                and record.get("history_disposition") == "sanitized-snapshots-preserve-local-history"
                and isinstance(destination, dict)
                and destination.get("owner_repository") == repository
                and destination.get("visibility") == "public"
                and isinstance(repository, str)
                and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
                and all(part and part not in (".", "..") for part in repository.split("/"))):
            return repository
    raise ValueError("authorized-public-destination-record-unavailable")


def preserve_existing_public_fixture_revision(source: pathlib.Path, candidate: pathlib.Path,
                                              public_base: str) -> None:
    """Keep unchanged Genewhip fixture bytes bound to prior public source revisions."""
    manifest_rel = "fixtures/manifest.json"
    try:
        base_manifest = json.loads(_git(candidate, "show", f"{public_base}:{manifest_rel}"))
        manifest_path = candidate / manifest_rel
        current_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, KeyError):
        raise ValueError("public-fixture-source-baseline-unavailable") from None
    fixture_inputs = {
        "genewhip-independent-game-v1": ("fixtures/independent-game/src/game.s",
            "fixtures/independent-game/game.bin", "evidence/independent-game.json"),
        "genewhip-independent-game-v2": ("fixtures/independent-game-v2/src/game.s",
            "fixtures/independent-game-v2/game.bin", "evidence/independent-game-v2.json"),
    }
    base_rows = {row.get("id"): row for row in base_manifest.get("fixtures", [])}
    current_rows = {row.get("id"): row for row in current_manifest.get("fixtures", [])}
    changed = False
    for fixture_id, (source_rel, rom_rel, evidence_rel) in fixture_inputs.items():
        old, current = base_rows.get(fixture_id), current_rows.get(fixture_id)
        if not isinstance(old, dict) or not isinstance(current, dict):
            continue
        if (old.get("status") != "admitted" or old.get("outcome") != "pass"
                or old.get("source") != source_rel or old.get("rom") != rom_rel
                or current.get("source") != source_rel or current.get("rom") != rom_rel
                or current.get("source_sha256") != old.get("source_sha256")
                or current.get("sha256") != old.get("sha256")
                or _sha(source / source_rel) != old.get("source_sha256")
                or _sha(source / rom_rel) != old.get("sha256")):
            raise ValueError("public-fixture-source-or-rom-bytes-changed")
        base_evidence_bytes = read_bounded_git_blob(candidate, f"{public_base}:{evidence_rel}")
        base_evidence = json.loads(base_evidence_bytes)
        evidence_path = candidate / evidence_rel
        current_evidence_bytes = evidence_path.read_bytes()
        current_evidence = json.loads(current_evidence_bytes)
        if (old.get("evidence_sha256") != hashlib.sha256(base_evidence_bytes).hexdigest()
                or current.get("evidence_sha256") != hashlib.sha256(current_evidence_bytes).hexdigest()):
            raise ValueError("public-fixture-evidence-source-mismatch")
        old_identity, current_identity = base_evidence.get("identities"), current_evidence.get("identities")
        old_revision = old.get("revision")
        if not isinstance(old_identity, dict) or not isinstance(current_identity, dict):
            raise ValueError("public-fixture-evidence-revision-mismatch")
        if fixture_id == "genewhip-independent-game-v1" and "source_revision" not in old_identity:
            if current_evidence_bytes != base_evidence_bytes:
                raise ValueError("public-fixture-evidence-changed-beyond-source-revision")
            current["revision"] = old_revision
            changed = True
            continue
        if (old_identity.get("source_revision") != old_revision
                or current_identity.get("source_revision") != current.get("revision")):
            raise ValueError("public-fixture-evidence-revision-mismatch")
        old_identity, current_identity = dict(old_identity), dict(current_identity)
        old_identity.pop("source_revision", None)
        current_identity.pop("source_revision", None)
        if (old_identity != current_identity
                or {key: value for key, value in base_evidence.items() if key != "identities"}
                != {key: value for key, value in current_evidence.items() if key != "identities"}):
            raise ValueError("public-fixture-evidence-changed-beyond-source-revision")
        current["revision"] = old_revision
        current_evidence["identities"]["source_revision"] = old_revision
        evidence_bytes = (json.dumps(current_evidence, sort_keys=True, indent=2) + "\n").encode()
        evidence_path.write_bytes(evidence_bytes)
        current["evidence_sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
        changed = True
    if changed:
        manifest_path.write_text(json.dumps(current_manifest, sort_keys=True, indent=2) + "\n",
                                 encoding="utf-8")


def preserved_fixture_provenance(source_manifest: dict[str, Any],
                                 public_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe only v1/v2 fixture source histories retained from the public base."""
    public_by_id = {row.get("id"): row for row in public_manifest.get("fixtures", [])
                    if isinstance(row, dict)}
    result = []
    for source_fixture in source_manifest.get("fixtures", []):
        if not isinstance(source_fixture, dict) or source_fixture.get("id") not in {
                "genewhip-independent-game-v1", "genewhip-independent-game-v2"}:
            continue
        public_fixture = public_by_id.get(source_fixture["id"])
        if not isinstance(public_fixture, dict):
            continue
        result.append({"fixture_id": source_fixture["id"], "source_path": source_fixture["source"],
            "source_sha256": source_fixture["source_sha256"], "rom_path": source_fixture["rom"],
            "rom_sha256": source_fixture["sha256"],
            "private_tree_revision": source_fixture["revision"],
            "public_source_revision": public_fixture["revision"],
            "evidence_sha256": public_fixture["evidence_sha256"],
            "basis": "unchanged-source-and-ROM-bytes-match-existing-public-main-source-history"})
    return result


def validate_public_snapshot(candidate: pathlib.Path, base_sha: str, head_sha: str,
                             expected_paths: list[str] | None = None,
                             *, require_hygiene: bool = True) -> dict[str, Any]:
    """Reopen ancestry, refs, filtered tree, notices, and public hygiene at the consumer."""
    candidate = candidate.resolve(strict=True)
    if (not candidate.is_dir() or candidate.is_symlink() or
            _git(candidate, "rev-parse", "HEAD") != head_sha or
            _git(candidate, "symbolic-ref", "--short", "HEAD") != "main"):
        raise ValueError("public-snapshot-head-identity-invalid")
    parents = _git(candidate, "show", "-s", "--format=%P", head_sha).split()
    if parents != [base_sha]:
        raise ValueError("public-snapshot-parent-is-not-observed-main")
    refs = [item for item in _git(candidate, "for-each-ref", "--format=%(refname)").splitlines() if item]
    if any(item.startswith("refs/tags/") for item in refs) or any(
            item not in ("refs/heads/main", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
            for item in refs):
        raise ValueError("public-snapshot-unexpected-refs")
    tracked = [item for item in _git(candidate, "ls-files", "-z").split("\0") if item]
    if expected_paths is not None and tracked != sorted(expected_paths):
        raise ValueError("public-snapshot-tree-does-not-match-source-manifest")
    forbidden = {".planning", "build", "artifacts", "node_modules", "target", "dist",
                 "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                 "private-receipts", "private-receipt", "crosswalks"}
    for name in tracked:
        path = pathlib.PurePosixPath(name)
        if (any(part in forbidden for part in path.parts) or path.name.startswith(".env")
                or path.name == ".DS_Store"):
            raise ValueError("public-snapshot-private-or-generated-path-present")
        if (candidate / name).is_symlink():
            raise ValueError("public-snapshot-symlink-present")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gw_v02_public_hygiene", ROOT / "scripts/ci/public_hygiene.py")
    if spec is None or spec.loader is None:
        raise ValueError("public-snapshot-hygiene-unavailable")
    hygiene = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hygiene)
    findings = hygiene.inspect(candidate, tracked)
    history = hygiene.scan_git_history(candidate)
    if require_hygiene and (findings or history.get("findings")):
        raise ValueError("public-snapshot-hygiene-rejected")
    manifest = [{"path": name, "size_bytes": (candidate / name).stat().st_size,
                 "sha256": _sha(candidate / name)} for name in tracked]
    return {"parent_shas": parents, "refs": refs, "tracked_paths": tracked,
            "manifest": manifest, "history_commits": history["commits_scanned"],
            "history_blobs": history["unique_blobs_scanned"],
            "current_findings": [{"path": path, "reason": reason} for path, reason in findings],
            "history_findings": history.get("findings", []),
            "finding_counts": history.get("finding_counts", {})}


def _inspect_preparation_policy(root: pathlib.Path, destination: pathlib.Path,
                                repository: str, public_head: str,
                                base: str) -> tuple[pathlib.Path, dict[str, Any]]:
    """Consume only a successful inspector invocation's fresh output."""
    output_root = destination.parent
    output_root.mkdir(parents=True, exist_ok=True)
    attempt = pathlib.Path(tempfile.mkdtemp(prefix="repository-preflight-", dir=output_root))
    output = attempt / "policy.json"
    try:
        result = subprocess.run([sys.executable, str(root / "scripts/ci/repository_preflight.py"),
            "--inspect-authorized", "--repository", repository, "--destination", repository,
            "--visibility", "public", "--history-disposition",
            "sanitized-snapshots-preserve-local-history", "--publication-copy", str(destination),
            "--expected-head", public_head, "--expected-base", base, "--out",
            str(output.relative_to(root))], cwd=root, text=True, capture_output=True,
            timeout=180, check=False)
        if result.returncode and not output.is_file():
            raise subprocess.CalledProcessError(result.returncode, result.args)
    except (OSError, subprocess.SubprocessError, ValueError):
        policy = {"blockers": ["repository_preflight_inspection_failed"]}
    else:
        try:
            policy = json.loads(output.read_text(encoding="utf-8"))
            if not isinstance(policy, dict):
                raise ValueError("repository-preflight-object-required")
            if (policy.get("schema") != "genewhip.publication-readiness-packet.v1"
                    or policy.get("repository") != repository
                    or policy.get("destination") != {"owner_repository": repository,
                        "visibility": "public"}
                    or policy.get("expected_identity") != {"head": public_head, "base": base}
                    or policy.get("mutations_performed") != 0):
                raise ValueError("repository-preflight-output-identity-invalid")
            if result.returncode:
                policy["inspector_exit_code"] = result.returncode
        except (OSError, ValueError):
            policy = {"blockers": ["repository_preflight_output_invalid"]}
    output.write_text(json.dumps(policy, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return output, policy


def prepare_public_snapshot(publication_copy: pathlib.Path, scope: pathlib.Path,
                            out: pathlib.Path, authorization: pathlib.Path | None = None,
                            *, root: pathlib.Path = ROOT) -> dict[str, Any]:
    """Build a local sanitized checkout rooted at the currently observed public main."""
    root = root.resolve(strict=True)
    scope = scope.resolve(strict=True)
    if json.loads(scope.read_text(encoding="utf-8")).get("schema") != "genewhip-v02-execution-v1":
        raise ValueError("public-snapshot-execution-scope-invalid")
    auth_input = authorization or root / "build/phase4/delivery-preflight.json"
    if auth_input.is_symlink():
        raise ValueError("authorized-public-destination-record-unavailable")
    auth_path = auth_input.resolve(strict=True)
    if root not in auth_path.parents or not auth_path.is_file():
        raise ValueError("authorized-public-destination-record-unavailable")
    repository = _authorized_public_repository(root) if authorization is None else None
    if authorization is not None:
        record = json.loads(auth_path.read_text(encoding="utf-8"))
        destination_record = record.get("destination") if isinstance(record, dict) else None
        # Explicit records use the same complete authorization contract as the default.
        if (not isinstance(record, dict) or not isinstance(destination_record, dict) or
                record.get("schema") != "genewhip.publication-readiness-packet.v1" or
                record.get("history_disposition") != "sanitized-snapshots-preserve-local-history" or
                destination_record.get("visibility") != "public" or
                destination_record.get("owner_repository") != record.get("repository")):
            raise ValueError("authorized-public-destination-record-invalid")
        repository = record["repository"]
    source_head = _git(root, "rev-parse", "HEAD")
    paths = _publication_paths(root)
    projection = _projection_crosswalk(root, paths)
    destination = publication_copy if publication_copy.is_absolute() else root / publication_copy
    if destination.is_symlink():
        raise ValueError("public-snapshot-destination-must-be-new-workspace-child")
    destination = destination.resolve()
    if root not in destination.parents or destination.exists():
        raise ValueError("public-snapshot-destination-must-be-new-workspace-child")
    destination.parent.mkdir(parents=True, exist_ok=True)
    owner, name = repository.split("/", 1)
    remote = f"https://github.com/{owner}/{name}.git"
    try:
        subprocess.run(["git", "clone", "--single-branch", "--no-tags", "--branch", "main",
                        remote, str(destination)], cwd=root, text=True,
                       capture_output=True, timeout=300, check=True)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("authorized-public-main-checkout-failed") from None
    base = _git(destination, "rev-parse", "HEAD")
    if len(base) != 40 or _git(destination, "symbolic-ref", "--short", "HEAD") != "main":
        raise ValueError("public-snapshot-base-identity-invalid")

    # Make the snapshot tree equal to the filtered source tree while retaining the
    # cloned public main commit as its sole parent.
    existing = _git(destination, "ls-files", "-z").split("\0")
    if any((destination / item).is_symlink() for item in existing if item):
        raise ValueError("public-snapshot-base-contains-symlink")
    for name_in_public in (item for item in existing if item):
        candidate = destination / name_in_public
        if name_in_public not in paths and candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
    for name_in_source in paths:
        source = root / name_in_source
        target = destination / name_in_source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(source.stat().st_mode & 0o777)
    # Recheck the full local admission chains, then carry only a narrow public
    # byte/rights projection. The historical records themselves stay private.
    manifest_path = destination / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validator_spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
    validator_loader = validator_spec.spec_from_file_location(
        "gw_stage_fixture_manifest", root / "tools/evidence/fixture_manifest.py")
    provenance_loader = validator_spec.spec_from_file_location(
        "gw_stage_source_provenance", root / "scripts/fixtures/source_provenance.py")
    public_loader = validator_spec.spec_from_file_location(
        "gw_stage_public_admission", root / "scripts/fixtures/public_admission.py")
    if any(item is None or item.loader is None for item in
           (validator_loader, provenance_loader, public_loader)):
        raise ValueError("phase5-public-admission-projection-unavailable")
    validator = validator_spec.module_from_spec(validator_loader)
    validator_loader.loader.exec_module(validator)
    provenance = validator_spec.module_from_spec(provenance_loader)
    provenance_loader.loader.exec_module(provenance)
    public_admission = validator_spec.module_from_spec(public_loader)
    public_loader.loader.exec_module(public_admission)
    source_manifest = json.loads((root / "fixtures/manifest.json").read_text(encoding="utf-8"))
    private_rows = [row for row in source_manifest["fixtures"]
                    if row.get("kind") == "phase5-independent-game-v1"]
    projections = []
    for source_row in private_rows:
        private_record = provenance._phase5_candidate_record(validator, source_row, root)
        projection_record = public_admission.project_private_record(private_record)
        if public_admission.validate_projection(projection_record, root, source_row["id"]) != "ok":
            raise ValueError("phase5-public-admission-projection-invalid")
        projections.append(projection_record)
    if {item["fixture_id"] for item in projections} != {
            "genewhip-phase5-a", "genewhip-phase5-b"}:
        raise ValueError("phase5-public-admission-roster-incomplete")
    public_projection = {"schema": "genewhip-phase5-public-admission-set-v1",
                         "admissions": projections}
    projection_bytes = (json.dumps(public_projection, sort_keys=True, indent=2) + "\n").encode()
    projection_path = destination / "evidence/phase5-public-admissions.json"
    projection_path.parent.mkdir(parents=True, exist_ok=True)
    projection_path.write_bytes(projection_bytes)
    paths = sorted([*paths, "evidence/phase5-public-admissions.json"])
    projection_digest = hashlib.sha256(projection_bytes).hexdigest()
    for row in manifest["fixtures"]:
        if row.get("kind") == "phase5-independent-game-v1":
            row["admission"] = {"path": "evidence/phase5-public-admissions.json",
                                "sha256": projection_digest}
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
    preserve_existing_public_fixture_revision(root, destination, base)
    source_manifest = json.loads((root / "fixtures/manifest.json").read_text(encoding="utf-8"))
    public_manifest = json.loads((destination / "fixtures/manifest.json").read_text(encoding="utf-8"))
    projection["provenance_preserved"] = preserved_fixture_provenance(source_manifest, public_manifest)
    if any((destination / part).exists() for part in (".planning", "build", "artifacts")):
        raise ValueError("public-snapshot-private-or-generated-tree-present")
    _git(destination, "add", "--all")
    _git(destination, "-c", "user.name=Genewhip Maintainers", "-c",
         "user.email=maintainers@users.noreply.github.com", "commit", "-m",
         "chore(v0.2): prepare sanitized public source snapshot")
    public_head = _git(destination, "rev-parse", "HEAD")
    parents = _git(destination, "show", "-s", "--format=%P", public_head).split()
    if parents != [base]:
        raise ValueError("public-snapshot-parent-is-not-observed-main")
    if _git(destination, "tag", "--list"):
        raise ValueError("public-snapshot-unexpected-tags")

    reopened = validate_public_snapshot(destination, base, public_head, paths, require_hygiene=False)
    hygiene_ready = not reopened["current_findings"] and not reopened["history_findings"]
    tree = _git(destination, "rev-parse", "HEAD^{tree}")
    manifest = reopened["manifest"]
    # The repository preflight reopens live visibility, rules, write permission,
    # public head and exact candidate identities; it never mutates GitHub.
    preflight_out, preflight = _inspect_preparation_policy(
        root, destination, repository, public_head, base)
    ready = (hygiene_ready and preflight.get("expected_identity", {}).get("head") == public_head and
             preflight.get("expected_identity", {}).get("base") == base and
             ("inspector_exit_code" not in preflight or
              (type(preflight["inspector_exit_code"]) is int and
               preflight["inspector_exit_code"] == 0)) and
             preflight.get("repository_observations", {}).get("ready") is True and
             preflight.get("privacy_scan", {}).get("publication_copy", {}).get("status") == "pass")
    packet = {"schema": "genewhip.v02-public-source-preflight.v1",
        "status": "prepared" if ready else "blocked",
        "repository": repository, "source_identity": {"private_git_head": source_head,
            "source_manifest_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "public_identity": {"base_sha": base, "head_sha": public_head, "tree_sha": tree,
            "parent_shas": parents}, "publication_copy": str(destination.relative_to(root)),
        "source_manifest": manifest, "source_manifest_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "privacy": {"status": "pass" if hygiene_ready else "blocked",
            "current_findings": reopened["current_findings"],
            "history_findings": reopened["history_findings"],
            "finding_counts": reopened["finding_counts"],
            "commits_scanned": reopened["history_commits"],
            "blobs_scanned": reopened["history_blobs"]},
        "repository_preflight": str(preflight_out.relative_to(root)),
        "blockers": list(preflight.get("blockers", [])) if not ready else [],
        "projection_crosswalk": projection,
        "mutations_performed": 0, "push_performed": False, "pull_request_opened": False,
        "workflow_dispatched": False, "requirements_qualified": []}
    if not hygiene_ready and "public-snapshot-hygiene-rejected" not in packet["blockers"]:
        packet["blockers"].append("public-snapshot-hygiene-rejected")
    output = out if out.is_absolute() else root / out
    output = output.resolve()
    if root not in output.parents or output == preflight_out.resolve():
        raise ValueError("public-preflight-output-path-invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(packet, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return packet


def _workflow_runs(repository: str, source_sha: str) -> list[dict[str, Any]]:
    owner, name = repository.split("/", 1)
    response = _external(["gh", "api", f"repos/{owner}/{name}/actions/workflows/ci.yml/runs?branch=main&per_page=100"],
                         timeout=45)
    try:
        value = json.loads(response.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-workflow-run-list-invalid") from None
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise ValueError("github-workflow-run-list-invalid")
    return [row for row in runs if isinstance(row, dict) and row.get("head_sha") == source_sha]


def _dispatch_qualification_run(repository: str, source_sha: str, base_sha: str,
                                journal_path: pathlib.Path, journal: dict[str, Any],
                                scope: dict[str, Any]) -> str:
    """Dispatch exact main qualification while carrying the existing journal cutoff."""
    started_at = journal.get("started_at")
    _require_hosted_budget(started_at,
        datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
    nonce = journal.get("qualification_dispatch_nonce")
    if nonce is None:
        nonce = uuid.uuid4().hex
        journal["qualification_dispatch_nonce"] = nonce
        journal["qualification_dispatch_requested"] = True
        journal["qualification_started_at"] = started_at
        _write_json(journal_path, journal)
        _external(["gh", "workflow", "run", ".github/workflows/ci.yml", "--repo", repository,
            "--ref", "main", "--field", "qualification_started_at=" + started_at,
            "--field", "qualification_base_sha=" + base_sha,
            "--field", "qualification_nonce=" + nonce], timeout=120, phase="runtime")
        journal["qualification_dispatch_submitted"] = True
        _write_json(journal_path, journal)
    elif (not re.fullmatch(r"[0-9a-f]{32}", nonce)
          or journal.get("qualification_started_at") != started_at):
        raise ValueError("hosted-delivery-journal-dispatch-identity-invalid")
    elif journal.get("qualification_dispatch_submitted") is not True:
        _external(["gh", "workflow", "run", ".github/workflows/ci.yml", "--repo", repository,
            "--ref", "main", "--field", "qualification_started_at=" + started_at,
            "--field", "qualification_base_sha=" + base_sha,
            "--field", "qualification_nonce=" + nonce], timeout=120, phase="runtime")
        journal["qualification_dispatch_submitted"] = True
        _write_json(journal_path, journal)
    return nonce


def _wait_for_exact_qualification_run(repository: str, source_sha: str, base_sha: str,
                                      started_at: str, nonce: str,
                                      scope: dict[str, Any]) -> dict[str, Any]:
    began = time.monotonic()
    next_notice = began
    while True:
        remaining = _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        matching = [run for run in _workflow_runs(repository, source_sha)
                    if run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
                    and run.get("path", "").split("@", 1)[0] == ".github/workflows/ci.yml"
                    and run.get("display_title") == "Plan10 qualification " + nonce]
        if len(matching) > 1:
            raise ValueError("duplicate-exact-source-hosted-runs")
        if matching:
            run = matching[0]
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise ValueError("exact-source-hosted-qualification-failed")
                identity = _validate_hosted_run(run, repository, source_sha,
                    expected_event="workflow_dispatch", expected_nonce=nonce)
                _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
                return run
            if run.get("status") not in {"queued", "in_progress", "requested", "waiting", "pending"}:
                raise ValueError("exact-source-hosted-run-status-invalid")
            identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
                expected_event="workflow_dispatch", expected_nonce=nonce)
            _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
            return run
        elif time.monotonic() - began > 300:
            # The protected main push is the only accepted trigger because the
            # attestation lane is intentionally limited to push on main.
            raise ValueError("exact-main-dispatched-qualification-run-not-found")
        if time.monotonic() >= next_notice:
            print("hosted-qualification: waiting for exact public main run; remaining_seconds=" + str(remaining))
            next_notice = time.monotonic() + 60
        time.sleep(min(30, max(1, remaining - scope["qualification_batch"]["close_wall_seconds"])))


def _wait_for_selected_run_completion(repository: str, source_sha: str,
                                      selected: dict[str, Any], started_at: str,
                                      scope: dict[str, Any], *, nonce: str,
                                      base_sha: str) -> dict[str, Any]:
    """Wait within the selected run creation cutoff; reruns keep that same clock."""
    initial = _validate_hosted_run(selected, repository, source_sha, allow_active=True,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    _validate_workflow_clock(started_at, initial["created_at"], nonce, base_sha)
    selected_id = initial["run_id"]
    current_attempt = int(initial["run_attempt"])
    while True:
        _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        matching = [row for row in _workflow_runs(repository, source_sha)
                    if str(row.get("id")) == selected_id]
        if len(matching) != 1:
            raise ValueError("selected-hosted-run-disappeared-or-duplicated")
        run = matching[0]
        identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
            expected_event="workflow_dispatch", expected_nonce=nonce)
        if identity["created_at"] != initial["created_at"]:
            raise ValueError("selected-hosted-run-creation-clock-changed")
        _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
        attempt = int(identity["run_attempt"])
        if attempt < current_attempt:
            raise ValueError("selected-hosted-run-attempt-regressed")
        current_attempt = attempt
        if run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise ValueError("exact-source-hosted-qualification-failed")
            return run
        remaining = _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        time.sleep(min(30, max(1, remaining - scope["qualification_batch"]["close_wall_seconds"])))


def _download_run_artifact(repository: str, run_id: str, run_attempt: str,
                           artifact_prefix: str, directory: pathlib.Path, *,
                           phase: str = "preparation") -> None:
    if directory.exists():
        raise ValueError("hosted-artifact-download-path-collision")
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir()
    _external(["gh", "run", "download", run_id, "--repo", repository,
        "--name", f"{artifact_prefix}-{run_id}-{run_attempt}", "--dir", str(directory)],
        timeout=4 * 60 * 60, phase=phase, owned_roots=(directory,))
    if not directory.is_dir() or not any(directory.iterdir()):
        raise ValueError("hosted-artifact-download-empty")


def _verify_attestation(subject: pathlib.Path, repository: str, source_sha: str,
                        run_id: str, run_attempt: int, expected_sha256: str) -> dict[str, Any]:
    """Delegate signer, issuer and exact invocation checks to the publisher verifier."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("gw_v02_promotion_attestation",
        ROOT / "scripts/release/promote.py")
    if spec is None or spec.loader is None:
        raise ValueError("hosted-attestation-verifier-unavailable")
    promote = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = promote
    spec.loader.exec_module(promote)
    try:
        verified = promote.verify_attestation(subject, repository, source_sha,
            str(run_id), int(run_attempt), expected_sha256=expected_sha256,
            runner=lambda command: _external(command, timeout=60, phase="package"))
    except (promote.PromotionError, OSError, ValueError, TypeError) as error:
        raise ValueError("hosted-attestation-rejected:" + str(error)) from None
    return {"status": "verified", "subject": subject.name, "sha256": expected_sha256,
            "repository": repository, "source_sha": source_sha,
            "run_id": str(run_id), "run_attempt": str(run_attempt),
            "signer_workflow": verified["workflow"], "oidc_issuer": "https://token.actions.githubusercontent.com"}


def run_hosted_qualification(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                             scope_path: pathlib.Path, out: pathlib.Path,
                             journal_path: pathlib.Path | None = None,
                             campaign_path: pathlib.Path | None = None,
                             campaign_sha256: str | None = None,
                             recovery_selection: str = "15",
                             continuation_path: pathlib.Path | None = None,
                             *, continuation_purpose: str = "original17") -> dict[str, Any]:
    """Merge sanitized source through protection, consume its exact CI artifacts, and freeze them."""
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    journal_path = journal_path or ROOT / "build/v02/hosted-delivery-journal.json"
    source_receipt = publish_sanitized_source(packet_path, publication_copy, journal_path,
        campaign_path=campaign_path, campaign_sha256=campaign_sha256, scope_path=scope_path,
        recovery_selection=recovery_selection, continuation_path=continuation_path,
        continuation_purpose=continuation_purpose)
    existing = json.loads(journal_path.read_text(encoding="utf-8"))
    started_at = existing["started_at"]
    repository = existing["repository"]
    source_sha = source_receipt["public_source_sha"]
    main_ref = _gh_json(repository, "git/ref/heads/main", phase="preparation")
    if main_ref.get("object", {}).get("sha") != source_sha:
        raise ValueError("public-main-moved-before-hosted-qualification")
    nonce = _dispatch_qualification_run(repository, source_sha,
        source_receipt["public_base_sha"], journal_path, existing, scope)
    base_sha = source_receipt["public_base_sha"]
    run = _wait_for_exact_qualification_run(repository, source_sha, base_sha,
        started_at, nonce, scope)
    run_identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    existing = _bind_qualification_clock(existing, run_identity["created_at"])
    _write_json(journal_path, existing)
    started_at = existing["qualification_started_at"]
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "runtime"
    os.environ["GENEWHIP_QUALIFICATION_NONCE"] = nonce
    run = _wait_for_selected_run_completion(repository, source_sha, run, started_at, scope,
        nonce=nonce, base_sha=base_sha)
    run_identity = _validate_hosted_run(run, repository, source_sha,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    run_id, run_attempt = run_identity["run_id"], run_identity["run_attempt"]
    if _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime") <= 0:
        raise ValueError("qualification-common-cutoff-exhausted")
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "package"

    campaign_root = (journal_path.parent if campaign_path is not None
                     else ROOT / "build/v02")
    download_root = campaign_root / "hosted-downloads" / f"{run_id}-{run_attempt}"
    package_download = download_root / "v02-package"
    release_download = download_root / "release-input"
    identity_download = download_root / "release-identity"
    for prefix, target in (("v02-package", package_download),
                           ("release-input", release_download),
                           ("release-identity", identity_download)):
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="package")
        _download_run_artifact(repository, run_id, run_attempt, prefix, target, phase="package")
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="package")
    transfer_inventory_path = package_download / "inventory.json"
    package_payload = package_download / "payload"
    transfer_inventory = _validate_package_transfer_identity(
        json.loads(transfer_inventory_path.read_text(encoding="utf-8")), source_sha)

    hosted_root = campaign_root / f"hosted-source-{source_sha[:12]}"
    if hosted_root.exists():
        if _git(hosted_root, "rev-parse", "HEAD") != source_sha:
            raise ValueError("hosted-source-checkout-collision")
    else:
        owner, name = repository.split("/", 1)
        remote = f"https://github.com/{owner}/{name}.git"
        hosted_root.mkdir(parents=True)
        _external(["git", "clone", "--no-tags", "--no-checkout", remote, str(hosted_root)],
                  timeout=300, phase="package", owned_roots=(hosted_root,))
        _external(["git", "checkout", "--detach", source_sha], cwd=hosted_root,
                  phase="package", owned_roots=(hosted_root,))
    if _git(hosted_root, "rev-parse", "HEAD") != source_sha or (hosted_root / ".planning").exists():
        raise ValueError("hosted-source-checkout-identity-invalid")
    install = _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_transfer.py"),
        "install-package", "--payload", str(package_payload), "--inventory", str(transfer_inventory_path),
        "--root", str(hosted_root), "--source-sha", source_sha], cwd=hosted_root,
        timeout=4 * 60 * 60, phase="package", owned_roots=(hosted_root,))
    installed = json.loads(install.stdout)
    if installed.get("status") != "pass" or installed.get("member_count") != transfer_inventory["member_count"]:
        raise ValueError("hosted-package-transfer-install-rejected")

    identity_file = identity_download / "_ci-identity.json"
    ci_identity = json.loads(identity_file.read_text(encoding="utf-8"))
    expected_identity = {"repository": repository, "source_sha": source_sha, "run_id": run_id,
        "run_attempt": run_attempt, "event": run_identity["event"], "ref": "refs/heads/main",
        "workflow": "Required preview checks", "workflow_file": ".github/workflows/ci.yml",
        "qualification_started_at": started_at, "qualification_nonce": nonce,
        "base_sha": base_sha}
    if ci_identity != expected_identity:
        raise ValueError("hosted-package-run-identity-mismatch")
    environment = os.environ.copy()
    environment.update({"GITHUB_REPOSITORY": repository, "GITHUB_SHA": source_sha,
        "GITHUB_BASE_SHA": base_sha, "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": run_attempt, "GITHUB_EVENT_NAME": run_identity["event"],
        "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW": "Required preview checks",
        "GENEWHIP_QUALIFICATION_STARTED_AT": started_at,
        "GENEWHIP_QUALIFICATION_NONCE": nonce})
    semantic_expected = {"source_sha": source_sha, "head_sha": source_sha, "base_sha": base_sha,
        "run_id": str(run_id), "run_attempt": str(run_attempt)}
    semantic_mutants_out = hosted_root / "build/v02/semantic-mutant-receipt.json"
    _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_qualification.py"),
        "--mode", "semantic-mutants", "--out", "build/v02/semantic-mutant-receipt.json",
        *_semantic_identity_args(semantic_expected)],
        cwd=hosted_root, timeout=900, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    semantic_mutant_receipt = json.loads(semantic_mutants_out.read_text(encoding="utf-8"))
    _validate_semantic_mutant_receipt(semantic_mutant_receipt, semantic_expected, hosted_root,
                                      source_root=hosted_root)
    # The workflow uploads several globbed files from one common directory;
    # upload-artifact strips that common root, so the inventory is at the
    # downloaded artifact root alongside its archives.
    release_assets = release_download
    release_identity = identity_download
    _external([sys.executable, "-I", str(hosted_root / "scripts/ci/verify_attestation_inputs.py"),
        "verify", "--directory", str(release_assets), "--identity-directory", str(release_identity)],
        cwd=hosted_root, timeout=300, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    inventory, assets, release_transfer_join, archives = _validate_hosted_release_inputs(
        release_assets, source_sha, transfer_inventory["members"])
    attestation_results = []
    subjects = [*(release_assets / name for name in archives), release_assets / "inventory.json"]
    for subject in subjects:
        if not subject.is_file() or subject.is_symlink():
            raise ValueError("hosted-release-inventory-member-missing")
        digest = _sha(subject)
        if subject.name in assets and (assets[subject.name].get("sha256") != digest
                                       or assets[subject.name].get("size") != subject.stat().st_size):
            raise ValueError("hosted-release-inventory-member-mismatch")
        attestation_results.append(_verify_attestation(subject, repository, source_sha,
            run_id, int(run_attempt), digest))


    close_out = hosted_root / "build/v02/hosted-close.json"
    _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_qualification.py"),
        "--mode", "validate", "--evidence", "build/v02/qualification-dimensions.json",
        "--out", "build/v02/hosted-close.json"], cwd=hosted_root, timeout=300,
        env={**environment, "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    close_evidence = hosted_root / "build/v02/qualification-dimensions.json"
    close_closure = hosted_root / "build/v02/qualification-evidence-closure.json"
    close_scope = hosted_root / "evidence/v02-execution.json"
    close_expected = {"source_sha": source_sha, "head_sha": source_sha,
        "base_sha": base_sha, "run_id": run_id, "run_attempt": run_attempt}
    close_receipt = json.loads(close_out.read_text(encoding="utf-8"))
    _validate_validation_readiness_receipt(close_receipt, close_expected,
        evidence_path=close_evidence, closure_path=close_closure, scope_path=close_scope)
    docs_out = hosted_root / "build/v02/hosted-docs-adoption.json"
    _external([sys.executable, "-I", str(hosted_root / "tests/package/docs_commands.py"),
        "--local-artifacts", "artifacts/v02", "--version", "0.2.0",
        "--expected-source", source_sha, "--require-clean-local", "--offline",
        "--out", "build/v02/hosted-docs-adoption.json"],
        cwd=hosted_root, timeout=4 * 60 * 60, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    docs_receipt = json.loads(docs_out.read_text(encoding="utf-8"))
    docs_archive_identities = _validate_docs_adoption_receipt(docs_receipt, assets, source_sha)
    latest_main = _gh_json(repository, "git/ref/heads/main", phase="package")
    if latest_main.get("object", {}).get("sha") != source_sha:
        raise ValueError("public-main-moved-during-hosted-qualification")
    _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="package")
    result = {"schema": "genewhip.v02-hosted-qualification.v1",
        "status": "prepublication-ready", "final_qualified": False,
        "reason": "postpublication-download-adoption-remains-required",
        "repository": repository, "source_sha": source_sha,
        "public_base_sha": source_receipt["public_base_sha"], "run_id": run_id,
        "run_attempt": run_attempt, "run_created_at": run_identity["created_at"],
        "pull_request": source_receipt, "transfer_inventory_sha256": _sha(transfer_inventory_path),
        "transfer_member_count": transfer_inventory["member_count"],
        "qualification_close": {"path": "build/v02/hosted-close.json", "sha256": _sha(close_out)},
        "semantic_mutant_receipt": {"path": "build/v02/semantic-mutant-receipt.json",
                                     "sha256": _sha(semantic_mutants_out),
                                     "core_denominator": semantic_mutant_receipt["core"]["denominator"],
                                     "host_denominator": semantic_mutant_receipt["host"]["denominator"]},
        "docs_adoption": {"path": "build/v02/hosted-docs-adoption.json", "sha256": _sha(docs_out)},
        "release_inventory_sha256": _sha(release_assets / "inventory.json"),
        "release_transfer_join": release_transfer_join,
        "asset_count": len(assets), "attestations": attestation_results,
        "required_dimensions": list(DIMENSIONS), "qualified_requirements": []}
    _write_json(out, result)
    staged = {"schema": "genewhip.v02-staged-inventory.v1", "repository": repository,
        "source_sha": source_sha, "run_id": run_id, "run_attempt": run_attempt,
        "inventory_path": "release-assets/inventory.json", "inventory_sha256": _sha(release_assets / "inventory.json"),
        "assets": [{"path": name, "size_bytes": (release_assets / name).stat().st_size,
                    "sha256": _sha(release_assets / name)} for name in sorted(assets)],
        "attestations": attestation_results,
        "transfer_inventory_sha256": _sha(transfer_inventory_path),
        "release_transfer_join": release_transfer_join,
        "docs_archive_identities": docs_archive_identities,
        "qualification_close_sha256": _sha(close_out), "docs_adoption_sha256": _sha(docs_out)}
    _write_json(campaign_root / "staged-inventory.json", staged)
    return result


def _identity() -> dict[str, str]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          text=True, capture_output=True).stdout.strip()
    base = os.environ.get("GITHUB_BASE_SHA")
    if not base and os.environ.get("GITHUB_EVENT_PATH"):
        try:
            event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            base = event.get("before") or event.get("pull_request", {}).get("base", {}).get("sha")
        except (OSError, ValueError, TypeError):
            base = None
    return {"source_sha": head, "head_sha": os.environ.get("GITHUB_SHA", head),
            "base_sha": base or head,
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1")}


def _step(name: str, argv: list[str], output: str, files: list[str]) -> dict[str, Any]:
    return {"name": name, "argv": argv, "output": output,
            "identity_dependencies": files, "source_sha": _identity()["source_sha"]}


def qualification_plan(build: pathlib.Path, scope: pathlib.Path) -> dict[str, Any]:
    """Resolve executable runtime, safety, chunk, measurement and package commands without starts."""
    build = build.resolve(strict=True)
    scope = scope.resolve(strict=True)
    if not (build / "CMakeCache.txt").is_file():
        raise ValueError("qualification-build-identity-missing")
    scope_data = json.loads(scope.read_text(encoding="utf-8"))
    if scope_data.get("schema") != "genewhip-v02-execution-v1":
        raise ValueError("qualification-execution-scope-invalid")
    ident = _identity()
    out = pathlib.Path("build/v02/qualification")
    runner = ROOT / "scripts/evidence/v02_run.py"
    commands = []
    for mode in ("full", "safety", "chunk"):
        target = out / f"{mode}.json"
        commands.append(_step(mode, [sys.executable, "-I", str(runner), "--mode", mode,
            "--build", str(build), "--scope", str(scope), "--plan-only", "--out", str(ROOT / target)],
            str(target), ["CMakeCache.txt", "evidence/v02-execution.json", "fixtures/phase6/"]))
    benchmark = ROOT / "tools/evidence/core_benchmark.py"
    for workload in ("control", "recursion94", "tank-battle"):
        target = out / "measurements" / f"{workload}.json"
        commands.append(_step("benchmark-" + workload, [sys.executable, "-I", str(benchmark),
            "--build", str(build), "--workload", workload, "--scope", str(scope),
            "--out", str(ROOT / target)], str(target), ["CMakeCache.txt", "evidence/v02-execution.json"]))
    commands.extend([
        _step("public-matrix", [sys.executable, "-I", str(ROOT / "scripts/evidence/v02_matrix.py"),
            "verify", "--bundle", str(ROOT / "build/v02/public/bundle.json"), "--roster",
            str(ROOT / "evidence/v02-roster.json"), "--schema", str(ROOT / "evidence/v02-schema.json")],
            "build/v02/qualification/public-matrix.json", ["evidence/v02-roster.json", "evidence/v02-schema.json"]),
        _step("package-sdk", [sys.executable, "-I", str(ROOT / "scripts/package_sdk.py"),
            "--release-version", "0.2.0", "--source-sha", ident["source_sha"],
            "--public-evidence", str(ROOT / "build/v02/public"), "--output-dir", str(ROOT / "artifacts/v02")],
            "artifacts/v02/sdk-archive-and-receipt", ["scripts/package_sdk.py", "packaging/", "build/v02/public/"]),
        _step("package-desktop", [sys.executable, "-I", str(ROOT / "scripts/package_desktop.py"),
            "--release-version", "0.2.0", "--source-sha", ident["source_sha"],
            "--public-evidence", str(ROOT / "build/v02/public"), "--output-dir", str(ROOT / "artifacts/v02")],
            "artifacts/v02/desktop-archive-and-receipt", ["scripts/package_desktop.py", "packaging/", "build/v02/public/"]),
        _step("docs", [sys.executable, "-I", str(ROOT / "tests/package/docs_commands.py"),
            "--local-artifacts", "artifacts/v02", "--version", "0.2.0", "--refresh-local", "--offline", "--out",
            str(ROOT / "build/v02/qualification/docs.json")], "build/v02/qualification/docs.json", ["docs/", "packaging/"]),
        _step("privacy", ["bash", "scripts/ci/public-hygiene.sh", "--self-test"],
            "build/v02/qualification/privacy.json", ["scripts/ci/public-hygiene.sh"]),
    ])
    return {"schema": "genewhip.v02-qualification-plan.v1", "status": "plan-only",
        "identity": ident, "build": str(build), "build_sha256": _sha(build / "CMakeCache.txt"),
        "scope": str(scope), "scope_sha256": _sha(scope), "dimensions": list(DIMENSIONS),
        "host_native_required": True, "launch_count": 0, "commands": commands,
        "limits": {"batch_seconds": 86400, "runtime_seconds": 64800,
            "benchmark_jobs": 3, "benchmark_job_seconds": 14400,
            "package_seconds": 14400, "close_reserve_seconds": 7200},
        "proof_order": ["runtime", "public-projection", "package-and-docs", "inventory", "attestation", "external-download-adoption", "final-conjunction"],
        "publisher_packet_schema": "genewhip.v02-publisher-packet.v1",
        "final_credit_source": "authenticated-downloaded-byte-adoption-only"}


def _run_semantic_mutant_suites(out: pathlib.Path, expected: dict[str, str],
                                scope: dict[str, Any]) -> dict[str, Any]:
    """Run the retained actual-validator mutation duties against fresh v0.2 reports."""
    import importlib.util
    _check_environment_clock(scope, "package")
    runtime_root = ROOT / "build/v02/runtime-observation"
    candidate_path = runtime_root / "candidate.json"
    core_path = runtime_root / "core-report.json"
    media_path = runtime_root / "media-report.json"
    software_path = runtime_root / "host-software.json"
    native_path = runtime_root / "host-native.json"
    if runtime_root.is_symlink() or not runtime_root.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError("qualification-semantic-mutant-root-invalid")
    for path in (candidate_path, core_path, media_path, software_path, native_path):
        if (path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True))
                or path.stat().st_size > 32 * 1024 * 1024):
            raise ValueError("qualification-semantic-mutant-input-invalid:" + path.name)
    evidence = ROOT / "build/v02/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    build = ROOT / "build/v02"
    fixture_spec = importlib.util.spec_from_file_location("gw_v02_mutant_fixture",
        ROOT / "tests/fixtures/phase6_game.py")
    host_spec = importlib.util.spec_from_file_location("gw_v02_mutant_host",
        ROOT / "tests/desktop/phase6_routes.py")
    if not fixture_spec or not fixture_spec.loader or not host_spec or not host_spec.loader:
        raise ValueError("qualification-semantic-mutant-module-unavailable")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    host = importlib.util.module_from_spec(host_spec)
    host_spec.loader.exec_module(host)
    core_out = evidence / "core-mutants.json"
    host_out = evidence / "host-mutants.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    if fixture.core_contract(build, candidate_path, core_out, core_path, media_path) != 0:
        raise ValueError("qualification-core-semantic-mutants-failed")
    if host.negative_controls(build, ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json",
            ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json", host_out,
            candidate_path, software_override=software_path, native_override=native_path,
            semantic_only=True) != 0:
        raise ValueError("qualification-host-semantic-mutants-failed")
    _check_environment_clock(scope, "package")
    core_result = json.loads(core_out.read_text(encoding="utf-8"))
    host_result = json.loads(host_out.read_text(encoding="utf-8"))
    core_rows = core_result.get("negative_controls")
    host_rows = host_result.get("mutations")
    if (core_result.get("status") != "pass" or core_result.get("candidate_sha256") != fixture.canonical_sha(candidate)
            or not isinstance(core_rows, list) or not core_rows
            or host_result.get("outcome") != "pass" or not isinstance(host_rows, list) or not host_rows
            or any(row.get("status") != "pass" for row in core_rows)
            or any(row.get("rejected") is not True for row in host_rows)):
        raise ValueError("qualification-semantic-mutant-roster-invalid")
    reports = {path.name: _sha(path) for path in (candidate_path, core_path, media_path, software_path, native_path)}
    receipt = {"schema": "genewhip.v02-semantic-mutants.v1", "status": "pass",
        "identity": expected, "candidate_sha256": fixture.canonical_sha(candidate),
        "positive_reports": reports,
        "core": {"denominator": len(core_rows), "pass": sum(row.get("status") == "pass" for row in core_rows),
                 "rows_sha256": hashlib.sha256(json.dumps(core_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "host": {"denominator": len(host_rows), "pass": sum(row.get("rejected") is True for row in host_rows),
                 "rows_sha256": hashlib.sha256(json.dumps(host_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "mutant_results": {"core": {"path": core_out.relative_to(ROOT).as_posix(), "sha256": _sha(core_out),
                "rows_sha256": hashlib.sha256(json.dumps(core_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
            "host": {"path": host_out.relative_to(ROOT).as_posix(), "sha256": _sha(host_out),
                "rows_sha256": hashlib.sha256(json.dumps(host_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}},
        "production_consumers": ["scripts/evidence/phase6_routes.py::validate_product_report",
                                 "scripts/evidence/phase6_routes.py::validate_media_report",
                                 "scripts/evidence/phase6_routes.py::validate_host_report"],
        "positive_validated_before_mutants": True, "host_native_positive_validated": True,
        "coverage_transfer": {"from": ["phase6_core_report_contract", "phase6_host_contract"],
            "to": "required-v02-hosted-source-qualified-runtime",
            "core_media_mutants": 32, "host_mutants": 21,
            "includes": ["core-report", "candidate-identities", "raw-native", "media-capture",
                "media-image", "media-audio", "six-host-roster", "native-host-capability",
                "host-process-receipts", "raw-input-audio-renderer-core-output"],
            "skip_allowed": False},
        "new_title_launches": 0}
    _validate_semantic_mutant_receipt(receipt, expected)
    _check_environment_clock(scope, "package")
    _write_json(out, receipt)
    return receipt


def _validate_semantic_mutant_receipt(receipt: Any, expected: dict[str, str],
                                      root: pathlib.Path = ROOT,
                                      source_root: pathlib.Path | None = None) -> None:
    """Single receipt gate shared by hosted orchestration and dimension consumers."""
    import importlib.util
    required = {"source_sha", "head_sha", "base_sha", "run_id", "run_attempt"}
    if (not isinstance(receipt, dict) or not isinstance(expected, dict) or set(expected) != required
            or any(not isinstance(expected.get(key), str) or
                not re.fullmatch(r"[0-9a-f]{40}", expected[key])
                for key in ("source_sha", "head_sha", "base_sha"))
            or not re.fullmatch(r"[0-9]+", str(expected.get("run_id", "")))
            or not re.fullmatch(r"[1-9][0-9]*", str(expected.get("run_attempt", "")))):
        raise ValueError("qualification-semantic-mutant-receipt-invalid")
    runtime = root / "build/v02/runtime-observation"
    report_names = ("candidate.json", "core-report.json", "media-report.json",
                    "host-software.json", "host-native.json")
    expected_reports = {}
    for name in report_names:
        path = runtime / name
        if (path.is_symlink() or not path.is_file() or
                not path.resolve(strict=True).is_relative_to(root.resolve(strict=True))):
            raise ValueError("qualification-semantic-mutant-positive-report-invalid:" + name)
        expected_reports[name] = _sha(path)
    candidate_doc = json.loads((runtime / "candidate.json").read_text(encoding="utf-8"))
    candidate_sha = hashlib.sha256(json.dumps(candidate_doc, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    specs = (
        ("core", "tests/fixtures/phase6_game.py", "CORE_SEMANTIC_MUTANT_EXPECTATIONS", "negative_controls", "name", "reason", "status"),
        ("host", "tests/desktop/phase6_routes.py", "HOST_SEMANTIC_MUTANT_EXPECTATIONS", "mutations", "id", "expected_reason", "rejected"),
    )
    source_root = (source_root or pathlib.Path(__file__).resolve().parents[2]).resolve(strict=True)
    expected_receipt_rows = {}
    for name, source_path, constant_name, rows_key, name_key, reason_key, pass_key in specs:
        spec = importlib.util.spec_from_file_location("gw_expected_" + name, source_root / source_path)
        if spec is None or spec.loader is None:
            raise ValueError("qualification-semantic-mutant-roster-unavailable:" + name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expectations = getattr(module, constant_name, None)
        if not isinstance(expectations, tuple) or not expectations:
            raise ValueError("qualification-semantic-mutant-roster-unavailable:" + name)
        expected_rows = ([{name_key: ident, reason_key: reason, pass_key: "pass"}
                          for ident, reason in expectations] if name == "core" else
                         [{"id": ident, "expected_reason": reason, "actual_reason": reason,
                           "rejected": True} for ident, reason in expectations])
        result_refs = receipt.get("mutant_results")
        if not isinstance(result_refs, dict) or not isinstance(receipt.get(name), dict):
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        result_ref = result_refs.get(name, {})
        if not isinstance(result_ref, dict):
            raise ValueError("qualification-semantic-mutant-result-invalid:" + name)
        relative = pathlib.PurePosixPath(result_ref.get("path", "")) if isinstance(result_ref, dict) else pathlib.PurePosixPath("/")
        result_path = root / relative
        if (relative.is_absolute() or ".." in relative.parts or result_path.is_symlink()
                or not result_path.is_file() or result_path.stat().st_size > 8 * 1024 * 1024
                or not result_path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
                or _sha(result_path) != result_ref.get("sha256")):
            raise ValueError("qualification-semantic-mutant-result-invalid:" + name)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        rows = result.get(rows_key) if isinstance(result, dict) else None
        expected_digest = hashlib.sha256(json.dumps(expected_rows, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if rows != expected_rows or receipt.get(name, {}).get("rows_sha256") != expected_digest:
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        if (result_ref.get("rows_sha256") != expected_digest
                or len(expected_rows) != (32 if name == "core" else 21)):
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        expected_receipt_rows[name] = {"denominator": len(expected_rows),
            "pass": len(expected_rows), "rows_sha256": expected_digest}
    coverage = {"from": ["phase6_core_report_contract", "phase6_host_contract"],
        "to": "required-v02-hosted-source-qualified-runtime", "core_media_mutants": 32,
        "host_mutants": 21, "includes": ["core-report", "candidate-identities", "raw-native",
            "media-capture", "media-image", "media-audio", "six-host-roster",
            "native-host-capability", "host-process-receipts", "raw-input-audio-renderer-core-output"],
        "skip_allowed": False}
    if (receipt.get("schema") != "genewhip.v02-semantic-mutants.v1" or receipt.get("status") != "pass"
            or receipt.get("identity") != expected or receipt.get("positive_reports") != expected_reports
            or receipt.get("candidate_sha256") != candidate_sha or receipt.get("coverage_transfer") != coverage
            or receipt.get("positive_validated_before_mutants") is not True
            or receipt.get("host_native_positive_validated") is not True
            or receipt.get("new_title_launches") != 0
            or receipt.get("core") != expected_receipt_rows.get("core")
            or receipt.get("host") != expected_receipt_rows.get("host")):
        raise ValueError("qualification-semantic-mutant-receipt-invalid")


def _semantic_identity_args(identity: dict[str, str]) -> list[str]:
    return [item for key in ("source_sha", "head_sha", "base_sha", "run_id", "run_attempt")
            for item in ("--" + key.replace("_", "-"), str(identity[key]))]


def _selected_semantic_identity(args: argparse.Namespace) -> dict[str, str]:
    values = {"source_sha": args.source_sha, "head_sha": args.head_sha,
        "base_sha": args.base_sha, "run_id": args.run_id, "run_attempt": args.run_attempt}
    if (any(not isinstance(value, str) or not value for value in values.values())
            or any(not re.fullmatch(r"[0-9a-f]{40}", values[key])
                   for key in ("source_sha", "head_sha", "base_sha"))
            or not re.fullmatch(r"[0-9]+", values["run_id"])
            or not re.fullmatch(r"[1-9][0-9]*", values["run_attempt"])):
        raise ValueError("qualification-semantic-mutant-explicit-identity-required")
    return values


def _dimension_semantic_errors(name: str, evidence_path: pathlib.Path,
                               expected: dict[str, Any]) -> list[str]:
    """Reopen one bounded raw dimension with the producer's authoritative validators."""
    try:
        if evidence_path.is_symlink() or not evidence_path.is_file() or evidence_path.stat().st_size > 32 * 1024 * 1024:
            return ["proof-evidence-file-type-or-size-invalid:" + name]
        doc = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            return ["proof-evidence-not-object:" + name]
        runtime = _load_runtime_module()
        fixture = runtime._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_dimension_fixture")
        route = runtime._module(ROOT / "scripts/evidence/phase6_routes.py", "gw_v02_dimension_routes")
        candidate_path = ROOT / "build/v02/runtime-observation/candidate.json"
        if name in ("core", "host", "host-native", "media", "safety", "determinism"):
            if candidate_path.is_symlink() or not candidate_path.is_file() or candidate_path.stat().st_size > 8 * 1024 * 1024:
                return ["proof-current-candidate-unavailable:" + name]
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        if name == "core":
            route.validate_product_report(doc, candidate)
            if (doc.get("outcomes", {}).get("status") not in ("pass", "pass-diagnostic") or
                    len(doc.get("runs", [])) != 24 or len(doc.get("stages", [])) != 120 or
                    len(doc.get("media_captures", [])) < 2):
                return ["proof-core-roster-progress-or-media-invalid"]
            mutant_error = _semantic_mutant_receipt_error(expected)
            if mutant_error: return [mutant_error]
        elif name in ("host", "host-native"):
            route.validate_host_report(doc, candidate)
            backend = "software" if name == "host" else "native"
            if (doc.get("backend") != backend or doc.get("outcome", doc.get("status")) not in ("pass", "pass-diagnostic") or
                    len(doc.get("runs", [])) != 6):
                return ["proof-host-roster-or-backend-invalid:" + name]
            mutant_error = _semantic_mutant_receipt_error(expected)
            if mutant_error: return [mutant_error]
        elif name == "media":
            route.validate_media_report(doc, candidate)
            if doc.get("result") != "pass":
                return ["proof-media-outcome-invalid"]
        elif name == "safety":
            safety = runtime._module(ROOT / "tests/api/safety_contract.py", "gw_v02_dimension_safety")
            reason = safety.validate_phase6_safety_report(doc)
            if reason:
                return ["proof-safety-semantic-invalid:" + str(reason)]
            if (doc.get("schema") != "genewhip-phase6-safety-v1" or doc.get("status") != "pass" or
                    doc.get("candidate_sha256") != fixture.canonical_sha(candidate) or
                    doc.get("source_provenance") != {path: _sha(ROOT / path) for path in fixture.SAFETY_SOURCE_PATHS} or
                    any(row.get("bounded_fuzz", {}).get("denominator") != 4096 or
                        row.get("bounded_fuzz", {}).get("pass") != 4096 or
                        row.get("bounded_fuzz", {}).get("unknown") != 0 or
                        row.get("bounded_fuzz", {}).get("skipped") != 0 for row in doc["variants"])):
                return ["proof-safety-current-roster-or-fuzz-invalid"]
            ref = doc.get("build_evidence")
            manifest_path = pathlib.Path(ref.get("path", "")) if isinstance(ref, dict) else pathlib.Path()
            if not manifest_path.is_absolute(): manifest_path = ROOT / manifest_path
            if manifest_path.is_symlink() or not manifest_path.is_file() or _sha(manifest_path) != ref.get("sha256"):
                return ["proof-safety-build-evidence-binding-invalid"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (manifest.get("schema") != "genewhip.v02-safety-build-evidence.v2" or
                    manifest.get("identity") != json.loads((ROOT / "build/v02/runtime-identity.json").read_text(encoding="utf-8")) or
                    manifest.get("evidence_basis") != "producer-observed-source-identities-plus-portable-facts"):
                return ["proof-safety-build-evidence-identity-invalid"]
            expected_binaries = {}
            expected_variants = {}
            for variant in doc["variants"]:
                directory = pathlib.PurePosixPath(variant.get("build_directory", ""))
                if (directory.is_absolute() or ".." in directory.parts or
                        not str(directory).startswith("build/v02/")):
                    return ["proof-safety-build-directory-invalid"]
                identity = variant.get("build_identity", {})
                variant_sources = {(directory / "CMakeCache.txt").as_posix(): identity.get("cache_sha256"),
                    (directory / "phase6_safety").as_posix(): identity.get("phase6_safety_sha256")}
                variant_sources.update(identity.get("test_executables", {}))
                expected_binaries.update(variant_sources)
                expected_variants[variant.get("variant")] = variant_sources
            entries = manifest.get("entries", [])
            observed_binaries = {row.get("source_path"): row.get("source_sha256") for row in entries if isinstance(row, dict)}
            if (manifest.get("raw_build_artifact_bytes_transferred") is not False or
                    len(entries) != manifest.get("entry_count") or observed_binaries != expected_binaries or
                    sum(row.get("source_size", 0) for row in entries) != manifest.get("source_bytes_total")):
                return ["proof-safety-build-roster-invalid"]
            import importlib.util
            facts_spec = importlib.util.spec_from_file_location("gw_v02_validate_safety_facts",
                ROOT / "scripts/evidence/v02_safety_build_facts.py")
            facts_module = importlib.util.module_from_spec(facts_spec)
            facts_spec.loader.exec_module(facts_module)
            compiler_identity = None
            for variant, sources in expected_variants.items():
                variant_rows = [row for row in entries if row.get("variant") == variant]
                if len(variant_rows) != len(sources):
                    return ["proof-safety-build-facts-roster-invalid"]
                facts_paths = {row.get("path") for row in variant_rows}
                if len(facts_paths) != 1:
                    return ["proof-safety-build-facts-roster-invalid"]
                fact_path = pathlib.PurePosixPath(next(iter(facts_paths)))
                if fact_path.is_absolute() or ".." in fact_path.parts:
                    return ["proof-safety-build-facts-path-invalid"]
                facts_file = ROOT / fact_path
                if facts_file.is_symlink() or not facts_file.is_file() or facts_file.stat().st_size > 1024 * 1024:
                    return ["proof-safety-build-facts-unavailable"]
                facts = json.loads(facts_file.read_text(encoding="utf-8"))
                observed_sources = {row.get("source_path"): row.get("sha256")
                    for row in facts.get("raw_build_artifact_identities", [])}
                if (facts.get("schema") != "genewhip.v02-portable-build-facts.v1" or
                        facts.get("variant") != variant or observed_sources != sources or
                        facts.get("raw_build_artifact_bytes_transferred") is not False or
                        facts.get("evidence_basis") != "producer-observed-source-identities-plus-portable-facts" or
                        facts_module.validate_projection(facts, variant, sources)):
                    return ["proof-safety-build-facts-invalid"]
                facts_identity = (facts["build_facts"]["CMAKE_C_COMPILER_ID"],
                    facts["build_facts"]["CMAKE_C_COMPILER_VERSION"])
                if compiler_identity is not None and facts_identity != compiler_identity:
                    return ["proof-safety-build-facts-compiler-mismatch"]
                compiler_identity = facts_identity
            portable_paths = {row.get("path") for row in entries}
            if sum((ROOT / name).stat().st_size for name in portable_paths) != manifest.get("portable_fact_bytes_total"):
                return ["proof-safety-build-facts-total-invalid"]
            for entry in entries:
                facts_file = ROOT / entry["path"]
                if (facts_file.is_symlink() or not facts_file.is_file() or
                        facts_file.stat().st_size != entry.get("size") or _sha(facts_file) != entry.get("sha256")):
                    return ["proof-safety-build-facts-identity-invalid"]
        elif name == "determinism":
            if doc.get("schema") != "genewhip-phase6-chunk-v1" or doc.get("status") != "pass" or len(doc.get("routes", [])) != 2:
                return ["proof-chunk-roster-invalid"]
            chunk_module = runtime._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_dimension_chunk")
            seen = set()
            for row in doc["routes"]:
                title = row.get("fixture")
                if title not in ("recursion94", "tank-battle") or title in seen or row.get("status") != "pass":
                    return ["proof-chunk-title-roster-invalid"]
                seen.add(title)
                native, _ = _read_project_json(row.get("source_run", {}).get("native_report"), "chunk-native")
                child, _ = _read_project_json(row.get("chunk_report"), "chunk-child")
                cap = 100_000_000 if title == "recursion94" else 10_000_000
                chunk_module._validate_title_pair_facts(child, native, cap, title)
                if (child.get("events") != row.get("source_run", {}).get("inputs") or
                        row.get("process", {}).get("process_group_cleanup") != "confirmed" or
                        row.get("process", {}).get("bound_violation")):
                    return ["proof-chunk-event-or-cleanup-invalid"]
        elif name == "measurements":
            if doc.get("schema") != "genewhip-v02-measurement-summary-v1" or set(doc.get("workloads", {})) != {
                    "control", "recursion94", "tank-battle"} or any(doc.get(k) != expected.get(k) for k in IDENTITY_FIELDS):
                return ["proof-measurement-roster-invalid"]
            benchmark = _load_benchmark_module()
            scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
            for workload, facts in doc["workloads"].items():
                report_path = pathlib.Path(facts.get("path", ""))
                if not report_path.is_absolute(): report_path = ROOT / report_path
                if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 32 * 1024 * 1024 or _sha(report_path) != facts.get("sha256"):
                    return ["proof-measurement-bytes-mismatch:" + workload]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                errors = benchmark.validate_workload_report(report, workload, benchmark.source_identity(), scope["scope_id"])
                if (errors or report.get("head_sha") != expected.get("head_sha") or report.get("base_sha") != expected.get("base_sha") or
                        report.get("run_id") != expected.get("run_id") or report.get("run_attempt") != expected.get("run_attempt") or
                        report.get("host_identity") != facts.get("host_identity") or facts.get("process_starts") != 21):
                    return ["proof-measurement-semantics-invalid:" + workload]
        elif name == "public-matrix":
            identity_path = ROOT / "build/v02/runtime-identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            matrix = _load_matrix_module()
            matrix.verify_public_closure(evidence_path.parent, ROOT / "evidence/v02-roster.json", identity)
            matrix.validate_qualification_matrix(json.loads((evidence_path.parent / "observations.json").read_text(encoding="utf-8")))
        elif name in ("package", "rights"):
            promote = runtime._module(ROOT / "scripts/release/promote.py", "gw_v02_dimension_promote")
            inventory_path = evidence_path
            if name == "package":
                inventory_path = pathlib.Path(doc.get("inventory", ""))
                if not inventory_path.is_absolute(): inventory_path = ROOT / inventory_path
                if doc.get("schema") != "genewhip.v02-package-receipt.v1" or doc.get("source_sha") != expected["source_sha"]:
                    return ["proof-package-receipt-invalid"]
                if inventory_path.is_symlink() or not inventory_path.is_file() or _sha(inventory_path) != doc.get("inventory_sha256"):
                    return ["proof-package-inventory-binding-invalid"]
                attempts = doc.get("attempts", [])
                if (doc.get("identity") != expected or len(attempts) != 4 or
                        [attempt.get("label") for attempt in attempts] != ["package-sdk", "package-desktop", "package-docs", "package-inventory"] or
                        any(attempt.get("returncode") != 0 or attempt.get("process_group_cleanup") != "confirmed" or
                            len(attempt.get("processes", [])) != 1 for attempt in attempts)):
                    return ["proof-package-attempts-invalid"]
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            asset_dir = inventory_path.parent
            _, errors = promote.validate_release_inventory(asset_dir, inventory)
            if not errors: errors = promote.validate_qualified_inventory(asset_dir, inventory, expected["source_sha"])
            if errors: return ["proof-rights-inventory-invalid:" + ",".join(errors)]
        elif name == "docs":
            packages = doc.get("packages", {})
            if (doc.get("schema") != "genewhip-docs-command-qualification-v2" or doc.get("version") != "0.2.0" or
                    doc.get("outcome") != "pass" or doc.get("mode") != "clean-local-qualified" or
                    doc.get("local_source_identity") != expected["source_sha"] or
                    set(packages) != {"sdk", "desktop"} or any(
                        not isinstance(item, dict) or item.get("source_revision") != expected["source_sha"] or
                        item.get("source_state") != "clean" or not isinstance(item.get("archive_sha256"), str) or
                        len(item["archive_sha256"]) != 64 for item in packages.values()) or
                    set(doc.get("commands", {}).values()) != {"pass"} or
                    any(row.get("process_group_cleanup") != "confirmed" for row in doc.get("processes", []))):
                return ["proof-docs-command-semantics-invalid"]
        elif name == "privacy":
            attempt_path = ROOT / "artifacts/qualification-command-attempts/public-hygiene.attempt.json"
            if (doc.get("schema") != "genewhip-v02-public-hygiene-v1" or doc.get("status") != "pass" or
                    doc.get("identity") != expected or attempt_path.is_symlink() or not attempt_path.is_file() or
                    _sha(attempt_path) != doc.get("attempt_sha256")):
                return ["proof-privacy-attempt-binding-invalid"]
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            if (attempt.get("label") != "public-hygiene" or attempt.get("argv") != ["bash", "scripts/ci/public-hygiene.sh", "--self-test"] or
                    attempt.get("returncode") != 0 or
                    attempt.get("process_group_cleanup") != "confirmed" or
                    attempt.get("streams", {}).get("stdout", {}).get("sha256") != doc.get("stdout_sha256") or
                    attempt.get("streams", {}).get("stdout", {}).get("text", "").strip() != "public hygiene: PASS"):
                return ["proof-privacy-attempt-invalid"]
        else:
            return ["proof-dimension-validator-missing:" + name]
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        return ["proof-dimension-semantic-invalid:" + name + ":" + type(error).__name__]
    return []


def _referenced_evidence_files(dimension_sources: dict[str, pathlib.Path]) -> dict[str, str]:
    """Collect and bound every path+digest attachment reachable from direct evidence JSON."""
    found: dict[str, str] = {}
    total = 0
    visited_documents: set[str] = set()
    def add_file(relative: str, digest: str) -> tuple[str, pathlib.Path]:
        path = pathlib.Path(relative)
        if not path.is_absolute(): path = ROOT / path
        try: name = path.resolve(strict=True).relative_to(ROOT.resolve()).as_posix()
        except (OSError, ValueError) as error: raise ValueError("qualification-evidence-reference-outside-root") from error
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024 or _sha(path) != digest:
            raise ValueError("qualification-evidence-reference-invalid:" + name)
        prior = found.get(name)
        if prior is not None and prior != digest:
            raise ValueError("qualification-evidence-reference-conflict:" + name)
        found[name] = digest
        return name, path
    def visit(value: Any, depth: int = 0) -> None:
        nonlocal total
        if isinstance(value, dict):
            for ref_key in ("path", "retained_path"):
                relative, digest = value.get(ref_key), value.get("sha256")
                if isinstance(relative, str) and isinstance(digest, str) and len(digest) == 64:
                    name, path = add_file(relative, digest)
                    if path.suffix == ".json" and name not in visited_documents and depth < 4:
                        visited_documents.add(name)
                        visit(json.loads(path.read_text(encoding="utf-8")), depth + 1)
            for child in value.values(): visit(child, depth)
        elif isinstance(value, list):
            for child in value: visit(child, depth)
    for path in dimension_sources.values():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("qualification-evidence-source-invalid")
        visit(json.loads(path.read_text(encoding="utf-8")))
    if len(found) > 256:
        raise ValueError("qualification-evidence-reference-count-cap")
    for name in found:
        total += (ROOT / name).stat().st_size
    if total > 512 * 1024 * 1024:
        raise ValueError("qualification-evidence-reference-byte-cap")
    return dict(sorted(found.items()))


def validate_conjunction(evidence: Any, expected: dict[str, Any], closure: Any = None) -> list[str]:
    """Validate exact-source dimension receipts before any qualification credit."""
    problems: list[str] = []
    if not isinstance(evidence, dict):
        return ["qualification-evidence-not-object"]
    closure_dimensions = closure.get("dimensions") if isinstance(closure, dict) else None
    references = closure.get("referenced_files") if isinstance(closure, dict) else None
    if (not isinstance(closure, dict) or closure.get("schema") != "genewhip.v02-evidence-closure.v1" or
            closure.get("identity") != expected or not isinstance(closure_dimensions, dict) or
            set(closure_dimensions) != set(REQUIRED_DIMENSIONS) or not isinstance(references, dict) or len(references) > 256):
        problems.append("qualification-evidence-closure-invalid")
    else:
        closure_bytes = 0
        for name, digest in references.items():
            if not isinstance(name, str) or pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
                problems.append("qualification-evidence-closure-reference-invalid")
                continue
            path = ROOT / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024 or _sha(path) != digest:
                problems.append("qualification-evidence-closure-reference-invalid")
                continue
            closure_bytes += path.stat().st_size
        if closure_bytes > 512 * 1024 * 1024:
            problems.append("qualification-evidence-closure-byte-cap")
    for name in REQUIRED_DIMENSIONS:
        row = evidence.get(name)
        if not isinstance(row, dict):
            problems.append("proof-missing:" + name)
            continue
        if row.get("outcome") != "pass":
            problems.append("proof-not-pass:" + name)
        if row.get("schema") != "genewhip.v02-dimension-proof.v1" or row.get("dimension") != name:
            problems.append("proof-dimension-binding-invalid:" + name)
        if row.get("evidence_schema") != "genewhip.v02-dimension-observation.v1":
            problems.append("proof-evidence-schema-invalid:" + name)
        for field in IDENTITY_FIELDS:
            if row.get(field) != expected.get(field):
                problems.append(f"proof-identity-mismatch:{name}:{field}")
        digest = row.get("output_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            problems.append("proof-output-digest-invalid:" + name)
        output = row.get("output")
        if not isinstance(output, str) or not output:
            problems.append("proof-output-missing:" + name)
        else:
            path = pathlib.Path(output)
            if not path.is_absolute():
                path = ROOT / path
            try:
                if path.is_symlink() or not path.is_file() or _sha(path) != digest:
                    problems.append("proof-output-bytes-mismatch:" + name)
                else:
                    observation = json.loads(path.read_text(encoding="utf-8"))
                    if (observation.get("schema") != "genewhip.v02-dimension-observation.v1" or
                            observation.get("dimension") != name or observation.get("outcome") != "pass" or
                            observation.get("identity") != expected):
                        problems.append("proof-observation-binding-invalid:" + name)
                    evidence_path = pathlib.Path(observation.get("evidence_path", ""))
                    if not evidence_path.is_absolute():
                        evidence_path = ROOT / evidence_path
                    if (evidence_path.is_symlink() or not evidence_path.is_file() or
                            _sha(evidence_path) != observation.get("evidence_sha256")):
                        problems.append("proof-evidence-bytes-mismatch:" + name)
                    elif isinstance(closure, dict):
                        entry = closure.get("dimensions", {}).get(name, {})
                        if not isinstance(entry, dict):
                            problems.append("proof-closure-binding-invalid:" + name)
                            continue
                        try:
                            relative = evidence_path.resolve().relative_to(ROOT.resolve()).as_posix()
                        except ValueError:
                            relative = ""
                        if (entry.get("path") != relative or entry.get("sha256") != _sha(evidence_path) or
                                entry.get("identity") != expected):
                            problems.append("proof-closure-binding-invalid:" + name)
                        else:
                            problems.extend(_dimension_semantic_errors(name, evidence_path, expected))
            except OSError:
                problems.append("proof-output-unavailable:" + name)
            except (ValueError, TypeError):
                problems.append("proof-observation-invalid:" + name)
    native = evidence.get(NATIVE_REQUIRED)
    if not isinstance(native, dict) or native.get("capability") != "present":
        problems.append("native-capability-missing")
    if isinstance(closure, dict) and isinstance(closure_dimensions, dict):
        source_paths = {}
        for name, row in evidence.items():
            if not isinstance(row, dict) or not isinstance(row.get("output"), str): continue
            output = pathlib.Path(row["output"])
            if not output.is_absolute(): output = ROOT / output
            if not output.is_file() or output.is_symlink(): continue
            try:
                observation = json.loads(output.read_text(encoding="utf-8"))
                direct = pathlib.Path(observation.get("evidence_path", ""))
                if not direct.is_absolute(): direct = ROOT / direct
                if direct.is_file() and not direct.is_symlink(): source_paths[name] = direct
            except (OSError, ValueError, TypeError):
                continue
        if set(source_paths) == set(REQUIRED_DIMENSIONS):
            try:
                if _referenced_evidence_files(source_paths) != references:
                    problems.append("qualification-evidence-closure-reference-set-mismatch")
            except (OSError, ValueError, TypeError):
                problems.append("qualification-evidence-closure-reference-invalid")
    return problems


def _write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _public_argv(command: list[str]) -> list[str]:
    """Represent repository-local absolute argv paths as portable project paths."""
    result = []
    for argument in command:
        try:
            result.append(pathlib.Path(argument).resolve().relative_to(ROOT.resolve()).as_posix()
                if pathlib.Path(argument).is_absolute() else argument)
        except (OSError, ValueError):
            result.append(argument)
    return result


def _bounded_command(command: list[str], *, limits: dict[str, Any], scratch: pathlib.Path,
                     timeout: int, label: str, env: dict[str, str] | None = None,
                     cwd: pathlib.Path = ROOT, check: bool = True,
                     scratch_roots: tuple[pathlib.Path, ...] | None = None,
                     ownership_callback=None) -> dict[str, Any]:
    """Run one coordinator child through the existing monitored PGID launcher and journal it first."""
    import importlib.util
    boundary_path = ROOT / "tests/session/phase6_route_contract.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_boundary", boundary_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-bounded-launcher-import")
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    scratch.mkdir(parents=True, exist_ok=True)
    monitored_roots = scratch_roots if scratch_roots is not None else (scratch,)
    receipt: list[dict[str, Any]] = []; streams: dict[str, Any] = {}
    scratch_diagnostics: list[dict[str, Any]] = []
    output = scratch / (label + ".json")
    launch_error=None; launch_exception=None; returncode=None;stdout="";stderr=""
    try:
        receipt_spec = importlib.util.spec_from_file_location(
            "gw_v02_process_receipts",
            pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase5_process.py")
        if receipt_spec is None or receipt_spec.loader is None:
            raise RuntimeError("qualification-process-receipt-import")
        receipt_module = importlib.util.module_from_spec(receipt_spec)
        receipt_spec.loader.exec_module(receipt_module)
        receipt_path = pathlib.Path("process-receipts") / (uuid.uuid4().hex + ".json")
        with receipt_module.receipt_file(scratch, receipt_path) as receipt_stream:
            result = boundary._run_client(pathlib.Path(command[0]), command, receipt,
                report=output, timeout=min(timeout, limits["wall_seconds"]), cwd=cwd, env=env,
                retained_streams=streams, limits=limits, scratch_roots=monitored_roots,
                scratch_diagnostics=scratch_diagnostics,
                process_receipt_stream=receipt_stream, ownership_callback=ownership_callback)
        returncode=result.returncode;stdout=result.stdout;stderr=result.stderr
    except BaseException as exc:
        launch_exception=exc
        launch_error=f"{type(exc).__name__}: {exc}"
    for name in ("stdout","stderr"):
        streams.setdefault(name,{"status":"not-started","observed_bytes":0,"retained_bytes":0,
            "sha256":hashlib.sha256(b"").hexdigest(),"truncated":False})
    attempt = {"schema":"genewhip.v02-coordinator-child-attempt.v1", "label":label,
        "argv":_public_argv(command), "returncode":returncode, "launch_error":launch_error,
        "stdout_tail":stdout[-8192:],"stderr_tail":stderr[-8192:],"processes":receipt,
        "streams":streams, "process_group_cleanup":receipt[-1].get("process_group_cleanup") if receipt else "missing",
        "output":str(output.relative_to(ROOT)) if output.is_file() else None,
        "output_sha256":_sha(output) if output.is_file() else None}
    if scratch_diagnostics:
        attempt["scratch_tree_diagnostics"] = scratch_diagnostics[:8]
    try:
        _write_json(scratch / (label + ".attempt.json"), attempt)
    except BaseException as persistence_error:
        if launch_exception is not None:
            raise persistence_error from launch_exception
        raise
    if launch_error is not None:
        raise RuntimeError("qualification-child-boundary-error:"+label+":"+launch_error) from launch_exception
    if (len(receipt) != 1 or
            receipt[0].get("process_group_cleanup") != "confirmed" or receipt[0].get("bound_violation")):
        raise RuntimeError(f"qualification-child-failed:{label}:{returncode}:{stderr[-2048:]}")
    if check and returncode != 0:
        raise RuntimeError(f"qualification-child-failed:{label}:{returncode}:{stderr[-2048:]}")
    return attempt


def run_runtime(build: pathlib.Path, scope: pathlib.Path, out: pathlib.Path) -> dict[str, Any]:
    """Run an explicitly selected bounded v02 mode and retain its actual receipt."""
    plan = qualification_plan(build, scope)
    command = [sys.executable, "-I", str(ROOT / "scripts/evidence/v02_run.py"),
               "--mode", "full", "--build", str(build), "--scope", str(scope), "--out", str(out)]
    started = time.monotonic()
    scope_data=json.loads(pathlib.Path(scope).read_text(encoding="utf-8"))
    limits=dict(scope_data["per_child_limits"])
    runtime_budget = int(plan["limits"]["runtime_seconds"])
    shared_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if shared_start:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _require_hosted_budget(shared_start, now, scope_data, phase="runtime")
        elapsed = (_parse_utc(now) - _parse_utc(shared_start)).total_seconds()
        runtime_budget = min(runtime_budget,
            max(1, int(scope_data["qualification_batch"]["runtime_wall_seconds"] - elapsed)))
    limits["wall_seconds"] = runtime_budget
    scratch=out.parent/(out.stem+"-attempts")
    attempt=_bounded_command(command,limits=limits,scratch=scratch,
        timeout=runtime_budget,label="runtime")
    if shared_start:
        _require_hosted_budget(shared_start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope_data, phase="runtime")
    stdout=attempt["streams"].get("stdout",{}).get("text","")
    stderr=attempt["streams"].get("stderr",{}).get("text","")
    record = {"schema": "genewhip.v02-runtime-attempt.v1", "command": command,
        "identity": plan["identity"], "returncode": attempt["returncode"],
        "stdout": stdout[-8192:], "stderr": stderr[-8192:], "processes":attempt["processes"],
        "stream_receipts":attempt["streams"],"cleanup":attempt["process_group_cleanup"],
        "elapsed_seconds": round(time.monotonic() - started, 3), "receipt": str(out)}
    _write_json(out.with_suffix(out.suffix + ".attempt.json"), record)
    if attempt["returncode"] != 0:
        raise RuntimeError("qualification-runtime-failed:" + str(attempt["returncode"]))
    import importlib.util
    transfer_spec = importlib.util.spec_from_file_location("gw_v02_runtime_transfer",
        ROOT / "scripts/release/v02_transfer.py")
    transfer = importlib.util.module_from_spec(transfer_spec)
    transfer_spec.loader.exec_module(transfer)
    transfer.export(ROOT, ROOT / "build/v02/runtime-transfer")
    return record


def validate_receipt_map(path: pathlib.Path, expected: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    closure_path = ROOT / "build/v02/qualification-evidence-closure.json"
    if closure_path.is_symlink() or not closure_path.is_file() or closure_path.stat().st_size > 1024 * 1024:
        raise ValueError("qualification-close-evidence-closure-missing")
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and set(value) == set(REQUIRED_DIMENSIONS):
        dimensions = value
    elif isinstance(value, dict) and isinstance(value.get("dimensions"), dict):
        dimensions = value["dimensions"]
    else:
        dimensions = None
    problems = validate_conjunction(dimensions, expected, closure)
    if problems:
        raise ValueError("qualification-close-rejected:" + ",".join(problems))
    return {"dimensions": dimensions, "evidence": value, "closure": closure}


def _validation_readiness_receipt(validated: dict[str, Any], expected: dict[str, Any],
                                  evidence_path: pathlib.Path, scope_path: pathlib.Path) -> dict[str, Any]:
    closure_path = ROOT / "build/v02/qualification-evidence-closure.json"
    dimensions = validated["dimensions"]
    canonical_dimensions = json.dumps(dimensions, sort_keys=True, separators=(",", ":")).encode()
    return {"schema": "genewhip.v02-validation-readiness.v1",
        "status": "readiness-pass", "final_qualified": False,
        "reason": "postpublication-download-adoption-required", "identity": expected,
        "dimensions": dimensions, "dimension_count": len(dimensions),
        "dimensions_sha256": hashlib.sha256(canonical_dimensions).hexdigest(),
        "evidence_sha256": _sha(evidence_path.resolve(strict=True)),
        "closure_sha256": _sha(closure_path),
        "scope_sha256": _sha(scope_path.resolve(strict=True)),
        "qualified_requirements": []}


def _validate_validation_readiness_receipt(receipt: Any, expected: dict[str, Any], *,
                                           evidence_path: pathlib.Path,
                                           closure_path: pathlib.Path,
                                           scope_path: pathlib.Path) -> dict[str, Any]:
    """Reopen the hosted validator's exact readiness output before hashing it into qualification."""
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        dimensions = evidence.get("dimensions") if isinstance(evidence, dict) else None
        if not isinstance(dimensions, dict) and isinstance(evidence, dict) and set(evidence) == set(REQUIRED_DIMENSIONS):
            dimensions = evidence
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        if (not isinstance(receipt, dict)
                or receipt.get("schema") != "genewhip.v02-validation-readiness.v1"
                or receipt.get("status") != "readiness-pass"
                or receipt.get("final_qualified") is not False
                or receipt.get("reason") != "postpublication-download-adoption-required"
                or receipt.get("identity") != expected
                or receipt.get("dimensions") != dimensions
                or receipt.get("dimension_count") != len(REQUIRED_DIMENSIONS)
                or not isinstance(dimensions, dict)
                or set(dimensions) != set(REQUIRED_DIMENSIONS)
                or not isinstance(closure, dict)
                or closure.get("schema") != "genewhip.v02-evidence-closure.v1"
                or closure.get("identity") != expected
                or not isinstance(closure.get("dimensions"), dict)
                or set(closure["dimensions"]) != set(REQUIRED_DIMENSIONS)
                or receipt.get("evidence_sha256") != _sha(evidence_path)
                or receipt.get("closure_sha256") != _sha(closure_path)
                or receipt.get("scope_sha256") != _sha(scope_path)):
            raise ValueError("hosted-validation-readiness-receipt-invalid")
        for name, row in dimensions.items():
            if (not isinstance(row, dict) or row.get("outcome") != "pass"
                    or any(row.get(field) != expected.get(field) for field in IDENTITY_FIELDS)):
                raise ValueError("hosted-validation-readiness-dimension-invalid")
        canonical_dimensions = json.dumps(dimensions, sort_keys=True, separators=(",", ":")).encode()
        if receipt.get("dimensions_sha256") != hashlib.sha256(canonical_dimensions).hexdigest():
            raise ValueError("hosted-validation-readiness-dimensions-digest-invalid")
        return receipt
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("hosted-validation-readiness-receipt-invalid") from None


def run_package(public_evidence: pathlib.Path, out: pathlib.Path) -> dict[str, Any]:
    """Build actual clean-source archives and bind every proof dimension to retained bytes."""
    public_evidence = public_evidence.resolve(strict=True)
    out = out.resolve()
    expected = _identity()
    source = expected["source_sha"]
    runtime_identity_path = public_evidence.parent / "runtime-identity.json"
    runtime_identity = json.loads(runtime_identity_path.read_text(encoding="utf-8"))
    runtime_module = _load_runtime_module()
    route_module = runtime_module._module(ROOT / "scripts/evidence/phase6_routes.py", "gw_v02_package_routes")
    current_product_identity = runtime_module.source_identity(route_module)
    if (runtime_identity.get("source_sha256") != current_product_identity.get("source_sha256") or
            runtime_identity.get("git_head") != expected["head_sha"] or
            runtime_identity.get("base_sha") != expected["base_sha"] or
            runtime_identity.get("run_id") != expected["run_id"] or
            runtime_identity.get("run_attempt") != expected["run_attempt"]):
        raise ValueError("qualification-runtime-identity-mismatch")
    matrix_module = _load_matrix_module()
    matrix_module.verify_public_closure(public_evidence, ROOT / "evidence/v02-roster.json", runtime_identity)
    observations = json.loads((public_evidence / "observations.json").read_text(encoding="utf-8"))
    matrix_module.validate_qualification_matrix(observations)
    scope=json.loads((ROOT/"evidence/v02-execution.json").read_text(encoding="utf-8"))
    limits=scope["per_child_limits"]
    batch_start_value = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    try:
        batch_start = (datetime.datetime.fromisoformat(batch_start_value.replace("Z", "+00:00"))
            if batch_start_value else datetime.datetime.now(datetime.timezone.utc))
        now = datetime.datetime.now(datetime.timezone.utc)
        if batch_start.tzinfo is None or (now - batch_start).total_seconds() < 0:
            raise ValueError("timezone-or-future-start")
    except ValueError as error:
        raise ValueError("qualification-common-batch-start-invalid") from error
    package_deadline = batch_start + datetime.timedelta(seconds=scope["qualification_batch"]["runtime_wall_seconds"] +
        scope["qualification_batch"]["package_wall_seconds"])
    if batch_start_value and (now - batch_start).total_seconds() >= scope["qualification_batch"]["runtime_wall_seconds"]:
        raise RuntimeError("qualification-runtime-partition-deadline-exhausted")
    # Validate the exact-attempt reports and materialize the required public
    # projection before crossing either package-builder boundary.
    benchmark_reports = {}
    benchmark_documents = {}
    benchmark_root = ROOT / "build/v02/collected"
    benchmark_module = _load_benchmark_module()
    scope_path = ROOT / "evidence/v02-execution.json"
    for workload in ("control", "recursion94", "tank-battle"):
        report_path = benchmark_root / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        errors = benchmark_module.validate_workload_report(report, workload,
            benchmark_module.source_identity(), scope["scope_id"])
        if errors or report.get("head_sha") != expected["head_sha"] or report.get("base_sha") != expected["base_sha"] or \
                report.get("run_id") != expected["run_id"] or report.get("run_attempt") != expected["run_attempt"]:
            raise ValueError("qualification-benchmark-invalid:" + workload + ":" + ",".join(errors))
        benchmark_reports[workload] = report_path
        benchmark_documents[workload] = report
    performance_projection = benchmark_module.build_public_performance_projection(
        benchmark_documents, {name: _sha(path) for name, path in benchmark_reports.items()},
        identity=expected, source_identity_sha256=benchmark_module.source_identity(),
        scope_id=scope["scope_id"], scope_sha256=_sha(scope_path))
    _write_json(public_evidence / "performance.json", performance_projection)

    def package_budget():
        remaining = min(4 * 60 * 60, int((package_deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
        if remaining <= 0:
            raise RuntimeError("qualification-package-partition-deadline-exhausted")
        return remaining, {**limits, "wall_seconds": remaining}
    out.mkdir(parents=True, exist_ok=False)
    attempts=[]
    command_scratch = out.parent / "qualification-command-attempts"
    def run_package_child(command: list[str], label: str, *, cap: int | None = None) -> dict[str, Any]:
        budget, package_limits = package_budget()
        if cap is not None: budget = min(budget, cap)
        package_temp = command_scratch / (label + "-tmp")
        if package_temp.exists() or package_temp.is_symlink():
            raise RuntimeError("qualification-package-scratch-collision:" + label)
        package_temp.mkdir(parents=True)
        child_env = os.environ.copy()
        child_env["TMPDIR"] = str(package_temp)
        package_limits["wall_seconds"] = budget
        return _bounded_command(command, limits=package_limits, scratch=command_scratch,
            timeout=budget, label=label, env=child_env)
    for role in ("sdk", "desktop"):
        script = ROOT / ("scripts/package_sdk.py" if role == "sdk" else "scripts/package_desktop.py")
        command = [sys.executable, "-I", str(script), "--release-version", "0.2.0",
            "--source-sha", source, "--public-evidence", str(public_evidence), "--output-dir", str(out)]
        attempts.append(run_package_child(command, "package-" + role))
    docs = out.parent / "qualification-docs.json"
    command = [sys.executable, "-I", str(ROOT / "tests/package/docs_commands.py"),
        "--local-artifacts", str(out), "--version", "0.2.0", "--expected-source", source,
        "--require-clean-local", "--offline", "--out", str(docs)]
    attempts.append(run_package_child(command, "package-docs"))
    inventory = out.parent / "release-assets"
    command = [sys.executable, "-I", str(ROOT / "scripts/release/promote.py"), "prepare",
        "--input-dir", str(out), "--output-dir", str(inventory), "--source-sha", source,
        "--release-version", "0.2.0"]
    attempts.append(run_package_child(command, "package-inventory", cap=300))
    value = {"schema": "genewhip.v02-package-receipt.v1", "identity": expected,
        "source_sha": source, "archives": sorted(p.name for p in out.glob("*.tar.gz")),
        "performance_projection_sha256": _sha(public_evidence / "performance.json"),
        "inventory": (inventory / "inventory.json").relative_to(ROOT).as_posix(), "inventory_sha256": _sha(inventory / "inventory.json"),
        "docs_receipt": docs.relative_to(ROOT).as_posix(), "docs_sha256": _sha(docs),
        "rights_and_members_checked_by": "scripts/release/promote.py prepare --release-version 0.2.0",
        "attempts": attempts, "commands": [_public_argv(command)]}
    _write_json(out.parent / "package-receipt.json", value)
    runtime_root = public_evidence.parent / "runtime-observation"
    runtime_receipt_path = public_evidence.parent / "runtime-observation.json"
    runtime_receipt = json.loads(runtime_receipt_path.read_text(encoding="utf-8"))
    if (runtime_receipt.get("status") != "pass" or runtime_receipt.get("scope_id") != scope["scope_id"] or
            runtime_receipt.get("current_execution_identity") != runtime_identity):
        raise ValueError("qualification-runtime-observation-invalid")
    core_report_path = runtime_root / "core-report.json"
    core_report = json.loads(core_report_path.read_text(encoding="utf-8"))
    candidate_ref = core_report.get("candidate_manifest", {})
    candidate_path = pathlib.Path(candidate_ref.get("path", ""))
    if not candidate_path.is_absolute(): candidate_path = ROOT / candidate_path
    if (candidate_path.is_symlink() or not candidate_path.is_file() or
            hashlib.sha256(candidate_path.read_bytes()).hexdigest() != candidate_ref.get("sha256")):
        raise ValueError("qualification-current-candidate-manifest-invalid")
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    route_module.validate_product_report(core_report, candidate)
    media_path = runtime_root / "media-report.json"
    media_report = json.loads(media_path.read_text(encoding="utf-8"))
    route_module.validate_media_report(media_report, candidate)
    for backend in ("software", "native"):
        host_report = json.loads((runtime_root / f"host-{backend}.json").read_text(encoding="utf-8"))
        route_module.validate_host_report(host_report, candidate)
    chunk_report_path = runtime_root / "chunk.json"
    chunk_report = json.loads(chunk_report_path.read_text(encoding="utf-8"))
    if chunk_report.get("schema") != "genewhip-phase6-chunk-v1" or chunk_report.get("status") != "pass" or \
            len(chunk_report.get("routes", [])) != 2:
        raise ValueError("qualification-chunk-report-roster-invalid")
    fixture_module = runtime_module._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_package_chunk_validator")
    chunk_fixtures = set()
    for row in chunk_report["routes"]:
        fixture = row.get("fixture")
        if fixture not in ("recursion94", "tank-battle") or fixture in chunk_fixtures or row.get("status") != "pass":
            raise ValueError("qualification-chunk-route-identity-invalid")
        chunk_fixtures.add(fixture)
        native, native_path = _read_project_json(row.get("source_run", {}).get("native_report"), "chunk-native")
        child, _ = _read_project_json(row.get("chunk_report"), "chunk-child")
        cap = 100_000_000 if fixture == "recursion94" else 10_000_000
        fixture_module._validate_title_pair_facts(child, native, cap, fixture)
        if (child.get("events") != row.get("source_run", {}).get("inputs") or
                row.get("process", {}).get("process_group_cleanup") != "confirmed" or
                row.get("process", {}).get("bound_violation")):
            raise ValueError("qualification-chunk-event-or-cleanup-invalid")
    if chunk_fixtures != {"recursion94", "tank-battle"}:
        raise ValueError("qualification-chunk-title-roster-invalid")
    measurement_summary = ROOT / "build/v02/measurements.json"
    _write_json(measurement_summary, {"schema": "genewhip-v02-measurement-summary-v1",
        "source_sha": expected["source_sha"], "head_sha": expected["head_sha"],
        "base_sha": expected["base_sha"], "run_id": expected["run_id"],
        "run_attempt": expected["run_attempt"], "workloads": {name: {
            "path": path.relative_to(ROOT).as_posix(), "sha256": _sha(path),
            "host_identity": json.loads(path.read_text(encoding="utf-8"))["host_identity"],
            "process_starts": 21} for name, path in benchmark_reports.items()}})
    hygiene_path = ROOT / "build/v02/public-hygiene.json"
    hygiene_attempt = run_package_child(["bash", "scripts/ci/public-hygiene.sh", "--self-test"],
        "public-hygiene", cap=300)
    _write_json(hygiene_path, {"schema": "genewhip-v02-public-hygiene-v1", "status": "pass",
        "identity": expected, "attempt_sha256": _sha(out.parent / "qualification-command-attempts/public-hygiene.attempt.json"),
        "stdout_sha256": hygiene_attempt["streams"]["stdout"]["sha256"]})
    dimension_sources = {
        "core": runtime_root / "core-report.json",
        "host": runtime_root / "host-software.json",
        "host-native": runtime_root / "host-native.json",
        "media": media_path,
        "safety": runtime_root / "safety.json",
        "determinism": runtime_root / "chunk.json",
        "measurements": measurement_summary,
        "public-matrix": public_evidence / "manifest.json",
        "package": out.parent / "package-receipt.json",
        "docs": docs,
        "privacy": ROOT / "build/v02/public-hygiene.json",
        "rights": inventory / "inventory.json"}
    dimensions = {}
    closure_dimensions = {}
    for name, proof_path in dimension_sources.items():
        if proof_path.is_symlink() or not proof_path.is_file():
            raise ValueError("qualification-dimension-source-missing:" + name)
        if name in ("core", "host", "host-native", "safety", "determinism"):
            report = json.loads(proof_path.read_text(encoding="utf-8"))
            outcome = (report.get("outcomes", {}).get("status") if name == "core" else
                report.get("outcome", report.get("status")))
            if outcome not in ("pass", "pass-diagnostic"):
                raise ValueError("qualification-dimension-not-pass:" + name)
            if name == "core" and (len(report.get("runs", [])) != 24 or len(report.get("stages", [])) != 120 or
                    len(report.get("media_captures", [])) < 2):
                raise ValueError("qualification-core-roster-or-media-incomplete")
            if name in ("host", "host-native") and (len(report.get("runs", [])) != 6 or
                    report.get("backend") != ("software" if name == "host" else "native")):
                raise ValueError("qualification-host-roster-incomplete:" + name)
            if name == "safety" and (len(report.get("variants", [])) != 3 or any(
                    row.get("bounded_fuzz", {}).get("denominator") != 4096 or
                    row.get("bounded_fuzz", {}).get("pass") != 4096 or
                    row.get("bounded_fuzz", {}).get("unknown") != 0 or
                    row.get("bounded_fuzz", {}).get("skipped") != 0 for row in report["variants"])):
                raise ValueError("qualification-safety-variants-or-fuzz-incomplete")
            if name == "determinism" and (len(report.get("routes", [])) != 2 or any(
                    row.get("status") != "pass" for row in report["routes"])):
                raise ValueError("qualification-chunk-route-roster-incomplete")
        if name == "media" and (json.loads(proof_path.read_text(encoding="utf-8")).get("result") != "pass"):
            raise ValueError("qualification-media-report-not-pass")
        semantic_errors = _dimension_semantic_errors(name, proof_path, expected)
        if semantic_errors:
            raise ValueError("qualification-dimension-semantic-invalid:" + ",".join(semantic_errors))
        dimension_doc = {"schema": "genewhip.v02-dimension-observation.v1", "dimension": name,
            "outcome": "pass", "evidence_path": proof_path.relative_to(ROOT).as_posix(), "evidence_sha256": _sha(proof_path),
            "identity": expected}
        observation_path = out.parent / ("dimension-" + name + ".json")
        _write_json(observation_path, dimension_doc)
        row = {"schema": "genewhip.v02-dimension-proof.v1", "dimension": name,
            "evidence_schema": dimension_doc["schema"], "outcome": "pass", **expected,
            "output": observation_path.relative_to(ROOT).as_posix(), "output_sha256": _sha(observation_path)}
        if name == "host-native": row["capability"] = "present"
        dimensions[name] = row
        closure_dimensions[name] = {"path": proof_path.relative_to(ROOT).as_posix(),
            "sha256": _sha(proof_path), "identity": expected}
    dimensions_path = ROOT / "build/v02/qualification-dimensions.json"
    _write_json(dimensions_path, dimensions)
    closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": expected,
        "dimensions": closure_dimensions, "referenced_files": _referenced_evidence_files(dimension_sources)}
    _write_json(ROOT / "build/v02/qualification-evidence-closure.json", closure)
    problems = validate_conjunction(dimensions, expected, closure)
    if problems:
        raise ValueError("qualification-dimensions-rejected:" + ",".join(problems))
    return value


def _load_benchmark_module():
    import importlib.util
    path = ROOT / "tools/evidence/core_benchmark.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-benchmark-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_matrix_module():
    import importlib.util
    path = ROOT / "scripts/evidence/v02_matrix.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_matrix", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-matrix-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_runtime_module():
    import importlib.util
    path = ROOT / "scripts/evidence/v02_run.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-runtime-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_project_json(reference: Any, label: str) -> tuple[dict[str, Any], pathlib.Path]:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise ValueError("qualification-artifact-reference-invalid:" + label)
    path = pathlib.Path(reference["path"])
    if not path.is_absolute(): path = ROOT / path
    root = ROOT.resolve()
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or \
            path.stat().st_size > 32 * 1024 * 1024 or _sha(path) != reference.get("sha256"):
        raise ValueError("qualification-artifact-reference-identity:" + label)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise ValueError("qualification-artifact-reference-json:" + label)
    return value, path


def _semantic_mutant_receipt_error(expected: dict[str, Any]) -> str | None:
    path = ROOT / "build/v02/semantic-mutant-receipt.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            return "proof-semantic-mutant-receipt-missing"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        _validate_semantic_mutant_receipt(receipt, expected, ROOT)
        return None
    except ValueError as error:
        message = str(error)
        if "result-roster" in message:
            return "proof-semantic-mutant-result-roster-invalid"
        if "result-invalid" in message:
            return "proof-semantic-mutant-result-invalid"
        return "proof-semantic-mutant-receipt-invalid"
    except (OSError, TypeError, KeyError, AttributeError):
        return "proof-semantic-mutant-receipt-invalid"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("plan", "runtime", "package", "validate", "semantic-mutants", "semantic-mutants-worker", "stage-public", "retry-source", "successor-source", "failed-hosted-successor-source", "hosted", "close"))
    parser.add_argument("--build", type=pathlib.Path, default=ROOT / "build/phase6")
    parser.add_argument("--scope", type=pathlib.Path, default=ROOT / "evidence/v02-execution.json")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--public-evidence", type=pathlib.Path)
    parser.add_argument("--prepare-only", action="store_true",
                        help="prepare a sanitized local public snapshot and read-only policy packet")
    parser.add_argument("--publication-copy", type=pathlib.Path)
    parser.add_argument("--preflight", type=pathlib.Path,
                        default=ROOT / "build/v02/preflight.json",
                        help="frozen sanitized-source and policy packet used by delivery modes")
    parser.add_argument("--journal", type=pathlib.Path,
                        default=ROOT / "build/v02/hosted-delivery-journal.json",
                        help="persistent bounded delivery journal")
    parser.add_argument("--campaign", type=pathlib.Path,
                        help="explicit started Phase 7 recovery campaign")
    parser.add_argument("--campaign-sha256",
                        help="independently recorded digest of the immutable campaign record")
    parser.add_argument("--recovery-selection", choices=("15", "16", "17"), default="15",
                        help="explicit recovery return gate (default: 15)")
    parser.add_argument("--continuation", type=pathlib.Path,
                        help="dependency-specific source continuation input")
    parser.add_argument("--continuation-purpose", choices=("original17", "current-native-preparation", "current-native-return"),
                        default="original17",
                        help="scope a current-native preparation or return record")
    parser.add_argument("--authorization", type=pathlib.Path,
                        help="previously authorized public destination packet")
    parser.add_argument("--contracts-only", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    args = parser.parse_args(argv)
    try:
        if args.prepare_only and args.mode != "stage-public":
            raise ValueError("prepare-only-is-only-valid-for-stage-public")
        selected_campaign_journal = pathlib.Path(os.path.abspath(
            args.journal if args.journal.is_absolute() else ROOT / args.journal)) == pathlib.Path(
                os.path.abspath(ROOT / "build/v02/campaign15/hosted-delivery-journal.json"))
        if args.recovery_selection == "17" and args.continuation is None:
            raise ValueError("continuation-input-required")
        if args.continuation is not None and args.recovery_selection != "17":
            raise ValueError("continuation-input-requires-selection17")
        if args.continuation_purpose == "current-native-preparation" and not (
                args.mode == "stage-public" and args.prepare_only
                and args.recovery_selection == "17" and args.continuation is not None):
            raise ValueError("current-native-purpose-requires-stage-public-prepare-only")
        if args.continuation_purpose == "current-native-return" and not (
                args.mode in ("stage-public", "retry-source", "successor-source",
                    "failed-hosted-successor-source", "hosted") and not args.prepare_only
                and args.recovery_selection == "17" and args.continuation is not None):
            raise ValueError("current-return-purpose-requires-protected-return-mode")
        if args.continuation_purpose in ("current-native-preparation", "current-native-return"):
            expected_current_continuation = ROOT / (
                ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/"
                + ("07-10-CURRENT-SOURCE-CONTINUATION.json" if args.continuation_purpose == "current-native-preparation"
                   else "07-10-CURRENT-SOURCE-RETURN.json"))
            supplied_continuation = args.continuation if args.continuation.is_absolute() else ROOT / args.continuation
            if pathlib.Path(os.path.abspath(supplied_continuation)) != pathlib.Path(
                    os.path.abspath(expected_current_continuation)):
                raise ValueError("current-native-continuation-path-invalid")
        if args.mode == "successor-source" and (
                args.recovery_selection != "17"
                or args.continuation_purpose != "current-native-return"):
            raise ValueError("source-successor-current-return-required")
        if args.mode == "failed-hosted-successor-source" and (
                args.recovery_selection != "17"
                or args.continuation_purpose != "current-native-return"):
            raise ValueError("source-successor-current-return-required")
        _reject_output_collisions(args)
        if selected_campaign_journal and args.campaign is None:
            raise ValueError("recovery-campaign-required-for-selected-journal")
        if args.campaign is not None:
            if args.campaign_sha256 is None:
                raise ValueError("recovery-campaign-digest-required")
            _require_campaign_layout(args)
            phase = "close" if args.mode == "close" else "package" if args.mode in (
                "package", "validate", "semantic-mutants", "semantic-mutants-worker") else "runtime"
            preparation_only = args.mode == "stage-public" and args.prepare_only
            _campaign_projection(args.campaign, args.scope, args.journal, phase=phase,
                                 expected_sha256=args.campaign_sha256,
                                 require_return=not preparation_only,
                                 selection=args.recovery_selection,
                                 continuation_path=args.continuation,
                                 continuation_purpose=args.continuation_purpose,
                                 preparation_only=preparation_only)
            for key in ("out", "preflight", "journal", "publication_copy"):
                value = getattr(args, key)
                if value is not None and not value.is_absolute():
                    setattr(args, key, ROOT / value)
        elif args.campaign_sha256 is not None:
            raise ValueError("recovery-campaign-path-required")
        elif args.recovery_selection != "15":
            raise ValueError("recovery-campaign-required-for-selection")
        if args.mode == "plan":
            value = qualification_plan(args.build, args.scope)
            _write_json(args.out, value)
            print(f"qualification-plan: {len(value['commands'])} concrete commands; launch_count=0")
        elif args.mode == "runtime":
            value = run_runtime(args.build, args.scope, args.out)
            print("qualification-runtime: returncode=" + str(value["returncode"]))
        elif args.mode == "semantic-mutants":
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "package")
            expected = _selected_semantic_identity(args)
            out = args.out if args.out.is_absolute() else ROOT / args.out
            if out.is_symlink():
                raise ValueError("qualification-semantic-mutant-output-path-invalid")
            out = out.resolve()
            if not out.is_relative_to(ROOT.resolve()) or out == ROOT.resolve():
                raise ValueError("qualification-semantic-mutant-output-path-invalid")
            out.parent.mkdir(parents=True, exist_ok=True)
            command = [sys.executable, "-I", str(ROOT / "scripts/release/v02_qualification.py"),
                "--mode", "semantic-mutants-worker", "--scope", str(args.scope),
                "--out", str(out), *_semantic_identity_args(expected)]
            _external(command, timeout=900, env={"GENEWHIP_SEMANTIC_MUTANTS_WORKER": "1"},
                phase="package", owned_roots=(out.parent,))
            _check_environment_clock(scope_value, "package")
            receipt_path = out
            if receipt_path.is_symlink() or not receipt_path.is_file() or receipt_path.stat().st_size > 1024 * 1024:
                raise ValueError("qualification-semantic-mutant-receipt-missing")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            _validate_semantic_mutant_receipt(receipt, expected)
            print("qualification-semantic-mutants: core=" + str(receipt["core"]["pass"]) +
                  "; host=" + str(receipt["host"]["pass"]) + "; launches=0")
        elif args.mode == "semantic-mutants-worker":
            if os.environ.get("GENEWHIP_SEMANTIC_MUTANTS_WORKER") != "1":
                raise ValueError("qualification-semantic-mutant-worker-admission-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "package")
            expected = _selected_semantic_identity(args)
            value = _run_semantic_mutant_suites(args.out, expected, scope_value)
            _validate_semantic_mutant_receipt(value, expected)
            _check_environment_clock(scope_value, "package")
            print("qualification-semantic-mutant-worker: core=" + str(value["core"]["pass"]) +
                  "; host=" + str(value["host"]["pass"]) + "; launches=0")
        elif args.mode == "validate":
            if args.evidence is None:
                raise ValueError("qualification-evidence-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value)
            expected = _identity()
            value = validate_receipt_map(args.evidence, expected)
            _check_environment_clock(scope_value)
            _write_json(args.out, _validation_readiness_receipt(value, expected,
                args.evidence, args.scope))
            print("qualification-evidence: PASS; " + str(len(value["dimensions"])) + " dimensions")
        elif args.mode == "package":
            if args.public_evidence is None:
                raise ValueError("qualification-public-evidence-required")
            package_scope = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(package_scope, "package")
            value = run_package(args.public_evidence, args.out)
            _check_environment_clock(package_scope, "package")
            print("qualification-package: " + str(len(value["archives"])) + " exact archives; inventory=" + value["inventory_sha256"])
        elif args.mode == "hosted":
            if args.publication_copy is None:
                raise ValueError("hosted-publication-copy-required")
            value = run_hosted_qualification(args.preflight, args.publication_copy,
                                             args.scope, args.out, args.journal,
                                             args.campaign, args.campaign_sha256,
                                             args.recovery_selection, args.continuation,
                                             continuation_purpose=args.continuation_purpose)
            print("qualification-hosted: " + value["status"] +
                  "; source=" + value["source_sha"] + "; run=" + value["run_id"] +
                  "; attempt=" + value["run_attempt"] + "; final_qualified=false")
        elif args.mode == "close":
            if args.evidence is None:
                raise ValueError("qualification-evidence-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "close")
            value = validate_receipt_map(args.evidence, _identity())
            _check_environment_clock(scope_value, "close")
            _write_json(args.out, {"schema": "genewhip.v02-final-close.v1", "status": "readiness-pass",
                "final_qualified": False, "reason": "authenticated-download-adoption-required",
                "dimensions": value["dimensions"]})
            print("qualification-close: readiness-pass; final_qualified=false")
        elif args.mode == "stage-public":
            if args.publication_copy is None:
                raise ValueError("stage-public-publication-copy-required")
            if args.prepare_only:
                value = prepare_public_snapshot(args.publication_copy, args.scope, args.out,
                                               args.authorization)
                print("public-source-preparation: " + value["status"] +
                      "; files=" + str(len(value["source_manifest"])) +
                      "; public_head=" + value["public_identity"]["head_sha"] +
                      "; base=" + value["public_identity"]["base_sha"])
                if value["status"] != "prepared":
                    return 1
            else:
                value = publish_sanitized_source(args.preflight, args.publication_copy, args.journal,
                    campaign_path=args.campaign, campaign_sha256=args.campaign_sha256,
                    scope_path=args.scope, recovery_selection=args.recovery_selection,
                    continuation_path=args.continuation,
                    continuation_purpose=args.continuation_purpose)
                _write_json(args.out, {"schema": "genewhip.v02-public-source-delivery.v1",
                    "status": "merged", **value})
                print("public-source-delivery: merged; public_source_sha=" + value["public_source_sha"])
        elif args.mode == "retry-source":
            if args.publication_copy is None:
                raise ValueError("stage-public-publication-copy-required")
            value = retry_sanitized_source(args.preflight, args.publication_copy, args.journal,
                campaign_path=args.campaign, campaign_sha256=args.campaign_sha256,
                scope_path=args.scope, recovery_selection=args.recovery_selection,
                continuation_path=args.continuation,
                continuation_purpose=args.continuation_purpose)
            _write_json(args.out, {"schema": "genewhip.v02-source-retry-transition.v1",
                "status": "prepared", **value})
            print("public-source-retry: prepared; source=" + value["source_head"] +
                  "; original_started_at=" + value["started_at"] + "; push_performed=false")
        elif args.mode == "successor-source":
            if args.publication_copy is None:
                raise ValueError("stage-public-publication-copy-required")
            if args.campaign is None or args.continuation is None:
                raise ValueError("source-successor-current-return-required")
            value = source_successor_sanitized_source(args.preflight, args.publication_copy,
                args.journal, campaign_path=args.campaign, campaign_sha256=args.campaign_sha256,
                scope_path=args.scope, recovery_selection=args.recovery_selection,
                continuation_path=args.continuation,
                continuation_purpose=args.continuation_purpose)
            _write_json(args.out, {"schema": "genewhip.v02-source-successor-transition.v1",
                "status": "prepared", **value})
            print("public-source-successor: prepared; source=" + value["source_head"] +
                  "; original_started_at=" + value["started_at"] + "; push_performed=false")
        elif args.mode == "failed-hosted-successor-source":
            if args.publication_copy is None or args.campaign is None or args.continuation is None:
                raise ValueError("source-successor-current-return-required")
            value = failed_hosted_successor_sanitized_source(args.preflight, args.publication_copy,
                args.journal, scope_path=args.scope, recovery_selection=args.recovery_selection,
                campaign_path=args.campaign, campaign_sha256=args.campaign_sha256,
                continuation_path=args.continuation,
                continuation_purpose=args.continuation_purpose)
            _write_json(args.out, {"schema": "genewhip.v02-source-successor-transition.v1",
                "status": "prepared", **value})
            print("public-source-successor: prepared; source=" + value["source_head"] +
                  "; original_started_at=" + value["started_at"] + "; push_performed=false")
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            subprocess.SubprocessError, RuntimeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Executing the production CLI declares host cleanup context. Importing
    # this module never grants admission to contract tests.
    if "--contracts-only" not in sys.argv:
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())
