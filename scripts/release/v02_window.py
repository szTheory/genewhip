#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the fixed prospective four-hour Phase 7 execution window."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


AUTH_PATH = Path("build/v02/phase7-qualification-20261102T165630Z/authorization.json")
AUTH_SHA256 = "d9aa7ecce2826cc3832dd99333cc637ba8ef9d4cdb6e261331abec89ac0b4ebf"
SCOPE_PATH = Path("evidence/v02-phase7-full-execution-scope.json")
SCOPE_SHA256 = "6deaf18aab75f45ac412a141caf9e089158f5c39d3971d49cb9bb7bb1be58df4"
LEGACY_SCOPE_PATH = Path("evidence/v02-execution.json")
LEGACY_SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"
SCHEMA = "genewhip.phase7-four-hour-authorization.v1"
REPOSITORY = "szTheory/genewhip"
SOURCE_ANCESTOR = "0de74de60375f044336711f86090cec2f77394ee"
STARTED_AT = "2026-11-02T16:56:30+00:00"
RUNTIME_CUTOFF = "2026-11-02T19:56:30+00:00"
PACKAGE_CUTOFF = "2026-11-02T20:41:30+00:00"
GLOBAL_CUTOFF = "2026-11-02T20:56:30+00:00"
ATTEMPT_NAMESPACE = Path("build/v02/phase7-qualification-20261102T165630Z/attempts")
SELECTION_REF = {
    "path": "build/v02/phase7-qualification-20261102T165630Z/selection.json",
    "sha256": "2d9310d9152b583dbc3d9a6afb7372845f1d930b9bff449bc18470cfe320a48c",
}
EVIDENCE_REF = {
    "path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-10-FOUR-HOUR-WINDOW.md",
    "sha256": "805a973ba0b8dd8268bf74df872271ecf2599a128d17d3bbdf2a4ed41a8c3728",
}
PREDECESSOR_REF = {
    "path": "build/v02/phase7-iterations/attempt-0001/terminal-assessment.json",
    "sha256": "a4690d9a81fd094b977d71603b6236dfa667fa35a99482e711c522df773b4c70",
}
BUDGET = {"wall_seconds": 14400, "runtime_wall_seconds": 10800,
    "package_wall_seconds": 2700, "close_wall_seconds": 900}
AUTH_KEYS = {"schema", "repository", "source_ancestor", "started_at", "runtime_cutoff",
    "package_cutoff", "global_cutoff", "budget", "scope_path", "scope_sha256",
    "attempt_namespace", "ordinary_ci_retries_approved", "per_attempt_user_approval",
    "per_child_limits_unchanged", "full_qualification_authorized", "merge_authorized",
    "release_authorized", "next_phase_authorized", "historical_risk_accepted",
    "safety_stop_required", "failure_stop_scope", "selection", "evidence", "predecessor"}
PHASE_CUTOFFS = {
    "preparation": RUNTIME_CUTOFF,
    "runtime": RUNTIME_CUTOFF,
    "package": PACKAGE_CUTOFF,
    "close": GLOBAL_CUTOFF,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(root: Path, relative: Path, *, cap: int = 65536) -> bytes:
    if relative.is_absolute() or any(part in ("", ".", "..") or "\\" in part
            for part in relative.parts):
        raise ValueError("phase7-window-reference-path-invalid")
    path = root / relative
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError:
            raise ValueError("phase7-window-reference-unavailable") from None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("phase7-window-reference-symlink")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > cap):
            raise ValueError("phase7-window-reference-invalid")
        raw = path.read_bytes()
    except OSError:
        raise ValueError("phase7-window-reference-invalid") from None
    if len(raw) > cap:
        raise ValueError("phase7-window-reference-invalid")
    return raw


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError(label) from None
    if not isinstance(value, dict):
        raise ValueError(label)
    return value


def _utc(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError(label)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(label) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(label)
    return parsed.astimezone(datetime.timezone.utc)


def _reference(root: Path, value: Any, expected: dict[str, str], label: str) -> bytes:
    if (not isinstance(value, dict) or set(value) != {"path", "sha256"}
            or value != expected):
        raise ValueError(label)
    raw = _read_regular(root, Path(expected["path"]))
    if _sha(raw) != expected["sha256"]:
        raise ValueError(label)
    return raw


def load_window(root: Path, *, authority_path: Path = AUTH_PATH,
        authority_sha256: str = AUTH_SHA256, scope_path: Path = SCOPE_PATH,
        scope_sha256: str = SCOPE_SHA256) -> dict[str, Any]:
    """Reopen exact user authority and public scope, including immutable basis refs."""
    supplied = Path(os.path.abspath(root))
    root = supplied.resolve(strict=True)
    if supplied != root:
        raise ValueError("phase7-window-root-invalid")
    if (Path(authority_path) != AUTH_PATH or authority_sha256 != AUTH_SHA256
            or Path(scope_path) != SCOPE_PATH or scope_sha256 != SCOPE_SHA256):
        raise ValueError("phase7-window-authority-or-scope-pin-invalid")
    authority_raw = _read_regular(root, AUTH_PATH)
    if _sha(authority_raw) != AUTH_SHA256:
        raise ValueError("phase7-window-authority-stale")
    authority = _json(authority_raw, "phase7-window-authority-invalid")
    expected_authority = {
        "schema": SCHEMA, "repository": REPOSITORY,
        "source_ancestor": SOURCE_ANCESTOR, "started_at": STARTED_AT,
        "runtime_cutoff": RUNTIME_CUTOFF, "package_cutoff": PACKAGE_CUTOFF,
        "global_cutoff": GLOBAL_CUTOFF, "budget": BUDGET,
        "scope_path": SCOPE_PATH.as_posix(), "scope_sha256": SCOPE_SHA256,
        "attempt_namespace": ATTEMPT_NAMESPACE.as_posix(),
        "ordinary_ci_retries_approved": True, "per_attempt_user_approval": False,
        "per_child_limits_unchanged": True, "full_qualification_authorized": True,
        "merge_authorized": True, "release_authorized": True,
        "next_phase_authorized": False, "historical_risk_accepted": False,
        "safety_stop_required": True, "failure_stop_scope": "attempt",
        "selection": SELECTION_REF, "evidence": EVIDENCE_REF,
        "predecessor": PREDECESSOR_REF,
    }
    if set(authority) != AUTH_KEYS or authority != expected_authority:
        raise ValueError("phase7-window-authority-identity-invalid")
    selection = _json(_reference(root, authority["selection"], SELECTION_REF,
        "phase7-window-selection-invalid"), "phase7-window-selection-invalid")
    if (selection.get("schema") != "genewhip.phase7-four-hour-selection.v1"
            or selection.get("source_ancestor") != "0de74de"
            or selection.get("started_at") != STARTED_AT
            or selection.get("runtime_deadline") != RUNTIME_CUTOFF
            or selection.get("package_deadline") != PACKAGE_CUTOFF
            or selection.get("hard_deadline") != GLOBAL_CUTOFF
            or selection.get("retries_reset_clock") is not False
            or selection.get("phase_advance_authorized") is not False):
        raise ValueError("phase7-window-selection-invalid")
    _reference(root, authority["evidence"], EVIDENCE_REF,
        "phase7-window-evidence-invalid")
    _reference(root, authority["predecessor"], PREDECESSOR_REF,
        "phase7-window-predecessor-invalid")
    scope_raw = _read_regular(root, SCOPE_PATH)
    if _sha(scope_raw) != SCOPE_SHA256:
        raise ValueError("phase7-window-scope-stale")
    scope = _json(scope_raw, "phase7-window-scope-invalid")
    old_raw = _read_regular(root, LEGACY_SCOPE_PATH)
    if _sha(old_raw) != LEGACY_SCOPE_SHA256:
        raise ValueError("phase7-window-legacy-scope-stale")
    old_scope = _json(old_raw, "phase7-window-legacy-scope-invalid")
    expected_scope = json.loads(json.dumps(old_scope))
    expected_scope["qualification_batch"].update(BUDGET)
    if scope != expected_scope:
        raise ValueError("phase7-window-scope-content-invalid")
    if scope["qualification_batch"] != {**old_scope["qualification_batch"], **BUDGET}:
        raise ValueError("phase7-window-scope-budget-invalid")
    return {"authority": authority, "authority_path": AUTH_PATH.as_posix(),
        "authority_sha256": AUTH_SHA256, "scope": scope,
        "scope_path": SCOPE_PATH.as_posix(), "scope_sha256": SCOPE_SHA256,
        "started_at": STARTED_AT, "runtime_cutoff": RUNTIME_CUTOFF,
        "package_cutoff": PACKAGE_CUTOFF, "global_cutoff": GLOBAL_CUTOFF,
        "attempt_namespace": ATTEMPT_NAMESPACE.as_posix(),
        "source_ancestor": SOURCE_ANCESTOR}


def check_window(window: dict[str, Any], *, phase: str,
        now: datetime.datetime | str | None = None,
        started_at: str | None = None,
        workflow_created_at: str | None = None) -> dict[str, Any]:
    """Enforce immutable phase cutoffs; queue delay spends the same original window."""
    if phase not in PHASE_CUTOFFS:
        raise ValueError("phase7-window-phase-invalid")
    if not isinstance(window, dict) or window.get("scope_sha256") != SCOPE_SHA256:
        raise ValueError("phase7-window-context-invalid")
    expected_start = _utc(STARTED_AT, "phase7-window-clock-invalid")
    supplied_start = _utc(started_at or window.get("started_at"),
        "phase7-window-start-invalid")
    if supplied_start != expected_start:
        raise ValueError("phase7-window-start-replaced")
    instant = (datetime.datetime.now(datetime.timezone.utc) if now is None else
        _utc(now, "phase7-window-clock-invalid") if isinstance(now, str) else now)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("phase7-window-clock-invalid")
    instant = instant.astimezone(datetime.timezone.utc)
    if instant < expected_start:
        raise ValueError("phase7-window-not-started")
    cutoff = _utc(PHASE_CUTOFFS[phase], "phase7-window-cutoff-invalid")
    if instant >= cutoff:
        raise ValueError("phase7-window-phase-expired")
    if workflow_created_at is not None:
        created = _utc(workflow_created_at, "phase7-window-workflow-clock-invalid")
        if created < expected_start or created > instant:
            raise ValueError("phase7-window-workflow-clock-invalid")
    remaining = (cutoff - instant).total_seconds()
    if remaining <= 0:
        raise ValueError("phase7-window-phase-expired")
    return {"phase": phase, "started_at": STARTED_AT,
        "phase_cutoff": cutoff.isoformat(), "remaining_seconds": remaining,
        "scope_path": SCOPE_PATH.as_posix(), "scope_sha256": SCOPE_SHA256,
        "hard_cutoff": GLOBAL_CUTOFF}


def validate_public_clock(root: Path, *, scope_path: str, scope_sha256: str,
        started_at: str, phase: str, now: str | datetime.datetime | None = None,
        workflow_created_at: str | None = None) -> dict[str, Any]:
    """Validate the public clock on hosted runners that cannot access private authority."""
    if scope_path != SCOPE_PATH.as_posix() or scope_sha256 != SCOPE_SHA256:
        raise ValueError("phase7-window-public-scope-pin-invalid")
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if supplied_root != root:
        raise ValueError("phase7-window-root-invalid")
    load_public_scope(root, scope_path=scope_path, scope_sha256=scope_sha256)
    clock = {"scope_sha256": SCOPE_SHA256, "started_at": STARTED_AT}
    return check_window(clock, phase=phase, now=now, started_at=started_at,
        workflow_created_at=workflow_created_at)


def select_public_event_window(root: Path, *, workflow_created_at: str,
        now: str | datetime.datetime | None = None) -> dict[str, Any]:
    """Select the prospective scope only for source runs created inside its window.

    Provider-created timestamps keep delayed jobs on the prospective clock. If a run
    was created during the window but reaches a runner after the preparation/runtime
    cutoff, validation fails instead of silently falling back to the legacy scope.
    """
    created = _utc(workflow_created_at, "phase7-window-workflow-clock-invalid")
    start = _utc(STARTED_AT, "phase7-window-clock-invalid")
    global_cutoff = _utc(GLOBAL_CUTOFF, "phase7-window-cutoff-invalid")
    if now is None:
        instant = datetime.datetime.now(datetime.timezone.utc)
    elif isinstance(now, datetime.datetime):
        instant = now
    else:
        instant = _utc(now, "phase7-window-clock-invalid")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("phase7-window-clock-invalid")
    if created > instant.astimezone(datetime.timezone.utc):
        raise ValueError("phase7-window-workflow-clock-invalid")
    if created < start or created >= global_cutoff:
        return {"selected": False, "scope_path": LEGACY_SCOPE_PATH.as_posix(),
            "scope_sha256": LEGACY_SCOPE_SHA256, "started_at": None}
    checked = validate_public_clock(root, scope_path=SCOPE_PATH.as_posix(),
        scope_sha256=SCOPE_SHA256, started_at=STARTED_AT, phase="preparation",
        now=now, workflow_created_at=workflow_created_at)
    return {"selected": True, "scope_path": SCOPE_PATH.as_posix(),
        "scope_sha256": SCOPE_SHA256, "started_at": STARTED_AT,
        "phase_cutoff": checked["phase_cutoff"], "remaining_seconds": checked["remaining_seconds"]}


def load_public_scope(root: Path, *, scope_path: str = SCOPE_PATH.as_posix(),
        scope_sha256: str = SCOPE_SHA256) -> dict[str, Any]:
    """Load the exact public scope on runners without private operator authority."""
    if scope_path != SCOPE_PATH.as_posix() or scope_sha256 != SCOPE_SHA256:
        raise ValueError("phase7-window-public-scope-pin-invalid")
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if supplied_root != root:
        raise ValueError("phase7-window-root-invalid")
    raw = _read_regular(root, SCOPE_PATH)
    if _sha(raw) != SCOPE_SHA256:
        raise ValueError("phase7-window-scope-stale")
    scope = _json(raw, "phase7-window-scope-invalid")
    old_raw = _read_regular(root, LEGACY_SCOPE_PATH)
    if _sha(old_raw) != LEGACY_SCOPE_SHA256:
        raise ValueError("phase7-window-legacy-scope-stale")
    old_scope = _json(old_raw, "phase7-window-legacy-scope-invalid")
    expected = json.loads(json.dumps(old_scope))
    expected["qualification_batch"].update(BUDGET)
    if scope != expected:
        raise ValueError("phase7-window-scope-content-invalid")
    return scope
