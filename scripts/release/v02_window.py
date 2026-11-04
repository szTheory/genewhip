#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the explicitly pinned prospective Phase 7 execution windows."""
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
AUTHORIZED_SCOPE_PATH = Path("evidence/v02-phase7-authorized-execution-scope.json")
AUTHORIZED_SCOPE_SHA256 = "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a"
CI_MEMORY_SCOPE_PATH = Path("evidence/v02-phase7-ci-memory-scope.json")
CI_MEMORY_SCOPE_SHA256 = "0aa84e06d689fba4593c6d52b3819c8954b941c3433c7f0ee502db0feda9efea"
AUTHORIZED_SCOPE_PROFILES = {
    AUTHORIZED_SCOPE_PATH: {
        "scope_sha256": AUTHORIZED_SCOPE_SHA256,
        "scope_content_sha256": "334f95fa3d9bfbe7c5b457099c44327cead593004450667b4b955d1f84be7f41",
        "max_rss_bytes": 4 * 1024**3,
    },
    CI_MEMORY_SCOPE_PATH: {
        "scope_sha256": CI_MEMORY_SCOPE_SHA256,
        "scope_content_sha256": "761deaa3f2bceec3610a6c9d9fb6770821a8b164e6098784e41478aea6c22048",
        "max_rss_bytes": 2 * 1024**3,
    },
}
AUTHORIZED_RUN_SCHEMA = "genewhip.phase7-execution-window.v1"
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

# The two-hour continuation is a second, independently pinned profile.  Keep the
# original constants/defaults above for historical four-hour artifacts.
TWO_HOUR_AUTH_PATH = Path("build/v02/phase7-qualification-20261102T220829Z/authorization.json")
TWO_HOUR_AUTH_SHA256 = "abe4ac195dfa2fb0cd851f3d022b503b31229a7d16481a0be9678cd112b2238a"
TWO_HOUR_SCOPE_PATH = Path("evidence/v02-phase7-two-hour-execution-scope.json")
TWO_HOUR_SCOPE_SHA256 = "a72453ee43bceeb16f03a5b023c6f94def38196e5ff23f36c7f2e4a35a99136c"
TWO_HOUR_SCHEMA = "genewhip.phase7-two-hour-authorization.v1"
TWO_HOUR_SOURCE_ANCESTOR = "208da236ecd5ef9cddd59556324fbb4b1deeabdf"
TWO_HOUR_STARTED_AT = "2026-11-02T22:08:29+00:00"
TWO_HOUR_RUNTIME_CUTOFF = "2026-11-02T23:43:29+00:00"
TWO_HOUR_PACKAGE_CUTOFF = "2026-11-03T00:03:29+00:00"
TWO_HOUR_GLOBAL_CUTOFF = "2026-11-03T00:08:29+00:00"
TWO_HOUR_ATTEMPT_NAMESPACE = Path("build/v02/phase7-qualification-20261102T220829Z/attempts")
TWO_HOUR_SELECTION_REF = {
    "path": "build/v02/phase7-qualification-20261102T220829Z/selection.json",
    "sha256": "d4d2573f284a2e62eb542b772e23894dbc5991ef4f65ce157421ee3de98b6be0",
}
TWO_HOUR_EVIDENCE_REF = {
    "path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-10-TWO-HOUR-WINDOW.md",
    "sha256": "c2e1c6f414c5aea3116b0620487d64c300e10b0d2bd8d75801cd3a9a30d7c7a2",
}
TWO_HOUR_PREDECESSOR_REF = {
    "path": "build/v02/phase7-qualification-20261102T165630Z/attempts/attempt-0002/operator/full-failure-observation.json",
    "sha256": "f78d82391b3b6dd30bfa0c3a63e65dd8050e75ffbdb1e36ca48181cbcc4fc98b",
}
TWO_HOUR_BUDGET = {"wall_seconds": 7200, "runtime_wall_seconds": 5700,
    "package_wall_seconds": 1200, "close_wall_seconds": 300}

# A renewed prospective window uses the same bounded two-hour budget and its
# own immutable identity. Earlier profiles remain available for frozen artifacts.
RENEWED_TWO_HOUR_AUTH_PATH = Path("build/v02/phase7-qualification-20261103T000225Z/authorization.json")
RENEWED_TWO_HOUR_AUTH_SHA256 = "c4e65420cca6bab3754702e12026610bf4e266175f7f2b6023e11acac0aaedbc"
RENEWED_TWO_HOUR_SCOPE_PATH = Path("evidence/v02-phase7-renewed-two-hour-execution-scope.json")
RENEWED_TWO_HOUR_SCOPE_SHA256 = "bda5c36ded9c6e1389e43eb089fd8c804e193917850d5a014b625ff3bbb0757c"
RENEWED_TWO_HOUR_SCHEMA = "genewhip.phase7-renewed-two-hour-authorization.v1"
RENEWED_TWO_HOUR_SOURCE_ANCESTOR = "27b67e6b92fba562603fac0aceffaa581236903a"
RENEWED_TWO_HOUR_STARTED_AT = "2026-11-03T00:02:25+00:00"
RENEWED_TWO_HOUR_RUNTIME_CUTOFF = "2026-11-03T01:37:25+00:00"
RENEWED_TWO_HOUR_PACKAGE_CUTOFF = "2026-11-03T01:57:25+00:00"
RENEWED_TWO_HOUR_GLOBAL_CUTOFF = "2026-11-03T02:02:25+00:00"
RENEWED_TWO_HOUR_ATTEMPT_NAMESPACE = Path("build/v02/phase7-qualification-20261103T000225Z/attempts")
RENEWED_TWO_HOUR_SELECTION_REF = {
    "path": "build/v02/phase7-qualification-20261103T000225Z/selection.json",
    "sha256": "efa12c7f0d74f3eacdcfa25d40f3a99b8c72dc454cd6df0e35e158d25a878c2c",
}
RENEWED_TWO_HOUR_EVIDENCE_REF = {
    "path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-10-RENEWED-TWO-HOUR-WINDOW.md",
    "sha256": "d55f3945bbfbc453eacd3053e35d9ecad6f9aff0862a8ed373031b439bfb7e1b",
}
RENEWED_TWO_HOUR_PREDECESSOR_REF = {
    "path": "build/v02/phase7-qualification-20261103T000225Z/operator/predecessor-observation.json",
    "sha256": "6bd1a5ba9ae45b2f7420efb1b7ddff928d09fa30a6838479bce8d2b4d81e0191",
}
RENEWED_TWO_HOUR_BUDGET = dict(TWO_HOUR_BUDGET)

_PROFILES = {
    "four-hour": {
        "authority_path": AUTH_PATH, "authority_sha256": AUTH_SHA256,
        "scope_path": SCOPE_PATH, "scope_sha256": SCOPE_SHA256,
        "schema": SCHEMA, "source_ancestor": SOURCE_ANCESTOR,
        "started_at": STARTED_AT, "runtime_cutoff": RUNTIME_CUTOFF,
        "package_cutoff": PACKAGE_CUTOFF, "global_cutoff": GLOBAL_CUTOFF,
        "attempt_namespace": ATTEMPT_NAMESPACE, "selection": SELECTION_REF,
        "evidence": EVIDENCE_REF, "predecessor": PREDECESSOR_REF,
        "budget": BUDGET,
        "selection_schema": "genewhip.phase7-four-hour-selection.v1",
        "selection_ancestor": "0de74de",
    },
    "two-hour": {
        "authority_path": TWO_HOUR_AUTH_PATH, "authority_sha256": TWO_HOUR_AUTH_SHA256,
        "scope_path": TWO_HOUR_SCOPE_PATH, "scope_sha256": TWO_HOUR_SCOPE_SHA256,
        "schema": TWO_HOUR_SCHEMA, "source_ancestor": TWO_HOUR_SOURCE_ANCESTOR,
        "started_at": TWO_HOUR_STARTED_AT, "runtime_cutoff": TWO_HOUR_RUNTIME_CUTOFF,
        "package_cutoff": TWO_HOUR_PACKAGE_CUTOFF, "global_cutoff": TWO_HOUR_GLOBAL_CUTOFF,
        "attempt_namespace": TWO_HOUR_ATTEMPT_NAMESPACE,
        "selection": TWO_HOUR_SELECTION_REF, "evidence": TWO_HOUR_EVIDENCE_REF,
        "predecessor": TWO_HOUR_PREDECESSOR_REF, "budget": TWO_HOUR_BUDGET,
        "selection_schema": "genewhip.phase7-two-hour-selection.v1",
        "selection_ancestor": TWO_HOUR_SOURCE_ANCESTOR,
    },
    "renewed-two-hour": {
        "authority_path": RENEWED_TWO_HOUR_AUTH_PATH,
        "authority_sha256": RENEWED_TWO_HOUR_AUTH_SHA256,
        "scope_path": RENEWED_TWO_HOUR_SCOPE_PATH,
        "scope_sha256": RENEWED_TWO_HOUR_SCOPE_SHA256,
        "schema": RENEWED_TWO_HOUR_SCHEMA,
        "source_ancestor": RENEWED_TWO_HOUR_SOURCE_ANCESTOR,
        "started_at": RENEWED_TWO_HOUR_STARTED_AT,
        "runtime_cutoff": RENEWED_TWO_HOUR_RUNTIME_CUTOFF,
        "package_cutoff": RENEWED_TWO_HOUR_PACKAGE_CUTOFF,
        "global_cutoff": RENEWED_TWO_HOUR_GLOBAL_CUTOFF,
        "attempt_namespace": RENEWED_TWO_HOUR_ATTEMPT_NAMESPACE,
        "selection": RENEWED_TWO_HOUR_SELECTION_REF,
        "evidence": RENEWED_TWO_HOUR_EVIDENCE_REF,
        "predecessor": RENEWED_TWO_HOUR_PREDECESSOR_REF,
        "budget": RENEWED_TWO_HOUR_BUDGET,
        "selection_schema": "genewhip.phase7-renewed-two-hour-selection.v1",
        "selection_ancestor": RENEWED_TWO_HOUR_SOURCE_ANCESTOR,
    },
}


def _profile_for_identity(*, authority_path: Path | None = None,
        authority_sha256: str | None = None, scope_path: Path | str | None = None,
        scope_sha256: str | None = None) -> tuple[str, dict[str, Any]]:
    supplied = (Path(authority_path) if authority_path is not None else None,
        authority_sha256, Path(scope_path) if scope_path is not None else None, scope_sha256)
    for name, profile in _PROFILES.items():
        expected = (profile["authority_path"], profile["authority_sha256"],
            profile["scope_path"], profile["scope_sha256"])
        actual = tuple(expected[i] if supplied[i] is None else supplied[i]
            for i in range(4))
        if actual == expected:
            return name, profile
    if supplied[0] is None and supplied[1] is None and any(
            value is not None for value in supplied[2:]):
        raise ValueError("phase7-window-public-scope-pin-invalid")
    raise ValueError("phase7-window-authority-or-scope-pin-invalid")


def _authorized_scope_profile(scope_path: Path | str,
        scope_sha256: str) -> dict[str, Any]:
    """Resolve only the two exact public scope identities for authorized runs."""
    path = Path(scope_path)
    profile = AUTHORIZED_SCOPE_PROFILES.get(path)
    if profile is None:
        raise ValueError("phase7-window-public-scope-pin-invalid")
    if scope_sha256 != profile["scope_sha256"]:
        raise ValueError("phase7-window-public-scope-pin-invalid")
    return profile


def _authorized_scope_content_matches(scope: dict[str, Any],
        profile: dict[str, Any]) -> bool:
    try:
        raw = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        return False
    return _sha(raw) == profile["scope_content_sha256"]


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


def _reference(root: Path, value: Any, expected: dict[str, str], label: str,
               *, cap: int = 65536) -> bytes:
    if (not isinstance(value, dict) or set(value) != {"path", "sha256"}
            or value != expected):
        raise ValueError(label)
    raw = _read_regular(root, Path(expected["path"]), cap=cap)
    if _sha(raw) != expected["sha256"]:
        raise ValueError(label)
    return raw


def load_window(root: Path, *, authority_path: Path = AUTH_PATH,
        authority_sha256: str = AUTH_SHA256, scope_path: Path = SCOPE_PATH,
        scope_sha256: str = SCOPE_SHA256) -> dict[str, Any]:
    """Reopen one exact user-authorized profile and its immutable basis refs.

    The no-argument form remains the frozen four-hour reader. Prospective profiles
    are accepted only when all four authority/scope identity values match pins.
    """
    profile_id, profile = _profile_for_identity(authority_path=authority_path,
        authority_sha256=authority_sha256, scope_path=scope_path,
        scope_sha256=scope_sha256)
    supplied = Path(os.path.abspath(root))
    root = supplied.resolve(strict=True)
    if supplied != root:
        raise ValueError("phase7-window-root-invalid")
    authority_path = profile["authority_path"]
    scope_path = profile["scope_path"]
    authority_raw = _read_regular(root, authority_path)
    if _sha(authority_raw) != profile["authority_sha256"]:
        raise ValueError("phase7-window-authority-stale")
    authority = _json(authority_raw, "phase7-window-authority-invalid")
    expected_authority = {
        "schema": profile["schema"], "repository": REPOSITORY,
        "source_ancestor": profile["source_ancestor"], "started_at": profile["started_at"],
        "runtime_cutoff": profile["runtime_cutoff"],
        "package_cutoff": profile["package_cutoff"],
        "global_cutoff": profile["global_cutoff"], "budget": profile["budget"],
        "scope_path": profile["scope_path"].as_posix(),
        "scope_sha256": profile["scope_sha256"],
        "attempt_namespace": profile["attempt_namespace"].as_posix(),
        "ordinary_ci_retries_approved": True, "per_attempt_user_approval": False,
        "per_child_limits_unchanged": True, "full_qualification_authorized": True,
        "merge_authorized": True, "release_authorized": True,
        "next_phase_authorized": False, "historical_risk_accepted": False,
        "safety_stop_required": True, "failure_stop_scope": "attempt",
        "selection": profile["selection"], "evidence": profile["evidence"],
        "predecessor": profile["predecessor"],
    }
    if set(authority) != AUTH_KEYS or authority != expected_authority:
        raise ValueError("phase7-window-authority-identity-invalid")
    selection = _json(_reference(root, authority["selection"], profile["selection"],
        "phase7-window-selection-invalid"), "phase7-window-selection-invalid")
    if (selection.get("schema") != profile["selection_schema"]
            or selection.get("source_ancestor") != profile["selection_ancestor"]
            or selection.get("started_at") != profile["started_at"]
            or selection.get("runtime_deadline") != profile["runtime_cutoff"]
            or selection.get("package_deadline") != profile["package_cutoff"]
            or selection.get("hard_deadline") != profile["global_cutoff"]
            or selection.get("retries_reset_clock") is not False
            or selection.get("phase_advance_authorized") is not False):
        raise ValueError("phase7-window-selection-invalid")
    _reference(root, authority["evidence"], profile["evidence"],
        "phase7-window-evidence-invalid")
    _reference(root, authority["predecessor"], profile["predecessor"],
        "phase7-window-predecessor-invalid", cap=256 * 1024)
    scope_raw = _read_regular(root, scope_path)
    if _sha(scope_raw) != profile["scope_sha256"]:
        raise ValueError("phase7-window-scope-stale")
    scope = _json(scope_raw, "phase7-window-scope-invalid")
    old_raw = _read_regular(root, LEGACY_SCOPE_PATH)
    if _sha(old_raw) != LEGACY_SCOPE_SHA256:
        raise ValueError("phase7-window-legacy-scope-stale")
    old_scope = _json(old_raw, "phase7-window-legacy-scope-invalid")
    expected_scope = json.loads(json.dumps(old_scope))
    expected_scope["qualification_batch"].update(profile["budget"])
    if scope != expected_scope:
        raise ValueError("phase7-window-scope-content-invalid")
    if scope["qualification_batch"] != {
            **old_scope["qualification_batch"], **profile["budget"]}:
        raise ValueError("phase7-window-scope-budget-invalid")
    return {"profile_id": profile_id, "authority": authority,
        "authority_path": authority_path.as_posix(),
        "authority_sha256": profile["authority_sha256"], "scope": scope,
        "scope_path": scope_path.as_posix(), "scope_sha256": profile["scope_sha256"],
        "started_at": profile["started_at"], "runtime_cutoff": profile["runtime_cutoff"],
        "package_cutoff": profile["package_cutoff"], "global_cutoff": profile["global_cutoff"],
        "attempt_namespace": profile["attempt_namespace"].as_posix(),
        "source_ancestor": profile["source_ancestor"], "budget": dict(profile["budget"])}


def _authorized_scope_budget(scope: dict[str, Any]) -> dict[str, int]:
    batch = scope.get("qualification_batch")
    keys = ("wall_seconds", "runtime_wall_seconds", "package_wall_seconds",
        "close_wall_seconds")
    if (not isinstance(batch, dict) or any(type(batch.get(key)) is not int or
            batch[key] <= 0 for key in keys)):
        raise ValueError("phase7-window-scope-budget-invalid")
    budget = {key: batch[key] for key in keys}
    if sum(budget[key] for key in keys[1:]) != budget["wall_seconds"]:
        raise ValueError("phase7-window-cutoff-partition-invalid")
    if (batch.get("benchmark_sub_batch_seconds") != 43200
            or batch.get("publication_reserve_seconds") != 7200):
        raise ValueError("phase7-window-scope-budget-invalid")
    return budget


def _authorized_cutoffs(started_at: str, budget: dict[str, int]) -> dict[str, str]:
    required = {"wall_seconds", "runtime_wall_seconds", "package_wall_seconds",
        "close_wall_seconds"}
    if (not isinstance(budget, dict) or set(budget) != required
            or any(type(budget[key]) is not int or budget[key] <= 0 for key in required)
            or sum(budget[key] for key in required - {"wall_seconds"}) != budget["wall_seconds"]):
        raise ValueError("phase7-window-cutoff-partition-invalid")
    start = _utc(started_at, "phase7-window-start-invalid")
    def plus(seconds: int) -> str:
        return (start + datetime.timedelta(seconds=seconds)).isoformat()
    return {"runtime_cutoff": plus(budget["runtime_wall_seconds"]),
        "package_cutoff": plus(budget["runtime_wall_seconds"] + budget["package_wall_seconds"]),
        "global_cutoff": plus(budget["wall_seconds"])}


def load_authorized_window(root: Path, *, authority_path: Path,
        authority_sha256: str, scope_path: Path | str,
        scope_sha256: str) -> dict[str, Any]:
    """Load an explicitly reviewed run authority over the reusable public 4h scope.

    The authority, rather than a date-specific product constant, selects the start,
    source ancestor, attempt namespace, and settled predecessor. The public scope
    itself must match the reviewed 4h execution policy exactly.
    """
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if supplied_root != root:
        raise ValueError("phase7-window-root-invalid")
    if (not re.fullmatch(r"[0-9a-f]{64}", authority_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", scope_sha256)):
        raise ValueError("phase7-window-authority-or-scope-pin-invalid")
    authority_path = Path(authority_path)
    scope_path = Path(scope_path)
    if (authority_path.is_absolute() or any(part in ("", ".", "..")
            for part in authority_path.parts) or authority_path.parts[:2] != ("build", "v02")
            or scope_path not in AUTHORIZED_SCOPE_PROFILES):
        raise ValueError("phase7-window-authority-or-scope-path-invalid")
    _authorized_scope_profile(scope_path, scope_sha256)
    authority_raw = _read_regular(root, authority_path, cap=256 * 1024)
    if _sha(authority_raw) != authority_sha256:
        raise ValueError("phase7-window-authority-stale")
    authority = _json(authority_raw, "phase7-window-authority-invalid")
    if set(authority) != AUTH_KEYS or authority.get("schema") != AUTHORIZED_RUN_SCHEMA:
        raise ValueError("phase7-window-authority-identity-invalid")
    if (authority.get("repository") != REPOSITORY
            or authority.get("scope_path") != scope_path.as_posix()
            or authority.get("scope_sha256") != scope_sha256
            or authority.get("ordinary_ci_retries_approved") is not True
            or authority.get("per_attempt_user_approval") is not False
            or authority.get("per_child_limits_unchanged") is not True
            or authority.get("full_qualification_authorized") is not True
            or authority.get("merge_authorized") is not True
            or authority.get("release_authorized") is not True
            or authority.get("next_phase_authorized") is not False
            or authority.get("historical_risk_accepted") is not False
            or authority.get("safety_stop_required") is not True
            or authority.get("failure_stop_scope") != "attempt"):
        raise ValueError("phase7-window-authority-identity-invalid")
    scope = load_public_scope(root, scope_path=scope_path.as_posix(),
        scope_sha256=scope_sha256)
    budget = _authorized_scope_budget(scope)
    if authority.get("budget") != budget:
        raise ValueError("phase7-window-authority-budget-invalid")
    started_at = authority.get("started_at")
    if not isinstance(started_at, str):
        raise ValueError("phase7-window-start-invalid")
    cutoffs = _authorized_cutoffs(started_at, budget)
    if any(authority.get(key) != value for key, value in cutoffs.items()):
        raise ValueError("phase7-window-authority-cutoff-invalid")
    attempt_namespace = Path(authority.get("attempt_namespace", ""))
    if (attempt_namespace.is_absolute() or attempt_namespace.parts[:2] != ("build", "v02")
            or any(part in ("", ".", "..") for part in attempt_namespace.parts)
            or attempt_namespace in {profile["attempt_namespace"] for profile in _PROFILES.values()}):
        raise ValueError("phase7-window-attempt-namespace-invalid")
    source_ancestor = authority.get("source_ancestor")
    if not isinstance(source_ancestor, str) or not re.fullmatch(r"[0-9a-f]{40}", source_ancestor):
        raise ValueError("phase7-window-source-ancestor-invalid")
    def reference(name: str) -> dict[str, str]:
        value = authority.get(name)
        if (not isinstance(value, dict) or set(value) != {"path", "sha256"}
                or not isinstance(value.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))):
            raise ValueError("phase7-window-" + name + "-invalid")
        return value
    selection = reference("selection")
    evidence = reference("evidence")
    predecessor = reference("predecessor")
    _reference(root, authority.get("selection"), selection,
        "phase7-window-selection-invalid", cap=256 * 1024)
    selection_value = _json(_read_regular(root, Path(selection["path"]), cap=256 * 1024),
        "phase7-window-selection-invalid")
    if (selection_value.get("schema") != "genewhip.phase7-execution-window-selection.v1"
            or selection_value.get("started_at") != started_at
            or selection_value.get("source_ancestor") != source_ancestor
            or selection_value.get("runtime_deadline") != cutoffs["runtime_cutoff"]
            or selection_value.get("package_deadline") != cutoffs["package_cutoff"]
            or selection_value.get("hard_deadline") != cutoffs["global_cutoff"]
            or selection_value.get("retries_reset_clock") is not False
            or selection_value.get("phase_advance_authorized") is not False):
        raise ValueError("phase7-window-selection-invalid")
    _reference(root, authority.get("evidence"), evidence,
        "phase7-window-evidence-invalid", cap=256 * 1024)
    _reference(root, authority.get("predecessor"), predecessor,
        "phase7-window-predecessor-invalid", cap=4 * 1024 * 1024)
    return {"profile_id": "authorized-run",
        "authority": authority, "authority_path": authority_path.as_posix(),
        "authority_sha256": authority_sha256,
        "scope": scope, "scope_path": scope_path.as_posix(),
        "scope_sha256": scope_sha256, "started_at": started_at,
        **cutoffs, "attempt_namespace": attempt_namespace.as_posix(),
        "source_ancestor": source_ancestor, "budget": budget}


def check_window(window: dict[str, Any], *, phase: str,
        now: datetime.datetime | str | None = None,
        started_at: str | None = None,
        workflow_created_at: str | None = None) -> dict[str, Any]:
    """Enforce immutable phase cutoffs; queue delay spends the same original window."""
    if phase not in PHASE_CUTOFFS:
        raise ValueError("phase7-window-phase-invalid")
    if not isinstance(window, dict):
        raise ValueError("phase7-window-context-invalid")
    profile_id = window.get("profile_id")
    if profile_id == "authorized-run":
        try:
            scope_profile = _authorized_scope_profile(
                window.get("scope_path", ""), window.get("scope_sha256", ""))
        except ValueError:
            raise ValueError("phase7-window-context-invalid")
        budget = window.get("budget")
        scope = window.get("scope")
        if (not isinstance(budget, dict) or not isinstance(scope, dict)
                or _authorized_scope_budget(scope) != budget
                or not _authorized_scope_content_matches(scope, scope_profile)):
            raise ValueError("phase7-window-context-invalid")
        cutoffs = _authorized_cutoffs(window.get("started_at"), budget)
        if any(window.get(key) != value for key, value in cutoffs.items()):
            raise ValueError("phase7-window-context-invalid")
        profile = {"started_at": window["started_at"],
            "scope_path": Path(window["scope_path"]),
            "scope_sha256": window["scope_sha256"],
            "runtime_cutoff": cutoffs["runtime_cutoff"],
            "package_cutoff": cutoffs["package_cutoff"],
            "global_cutoff": cutoffs["global_cutoff"]}
    else:
        profile = None
    if profile_id is None:
        # Preserve the small public-clock context used by existing callers.
        profile_id = next((name for name, profile in _PROFILES.items()
            if window.get("scope_sha256") == profile["scope_sha256"]), None)
    if profile_id != "authorized-run":
        profile = _PROFILES.get(profile_id)
        if (profile is None or window.get("scope_sha256") != profile["scope_sha256"]
                or (window.get("scope_path") is not None
                    and window.get("scope_path") != profile["scope_path"].as_posix())):
            raise ValueError("phase7-window-context-invalid")
    expected_start = _utc(profile["started_at"], "phase7-window-clock-invalid")
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
    cutoff_text = {"preparation": profile["runtime_cutoff"],
        "runtime": profile["runtime_cutoff"], "package": profile["package_cutoff"],
        "close": profile["global_cutoff"]}[phase]
    cutoff = _utc(cutoff_text, "phase7-window-cutoff-invalid")
    if instant >= cutoff:
        raise ValueError("phase7-window-phase-expired")
    if workflow_created_at is not None:
        created = _utc(workflow_created_at, "phase7-window-workflow-clock-invalid")
        if created < expected_start or created > instant:
            raise ValueError("phase7-window-workflow-clock-invalid")
    remaining = (cutoff - instant).total_seconds()
    if remaining <= 0:
        raise ValueError("phase7-window-phase-expired")
    return {"phase": phase, "profile_id": profile_id,
        "started_at": profile["started_at"],
        "phase_cutoff": cutoff.isoformat(), "remaining_seconds": remaining,
        "scope_path": profile["scope_path"].as_posix(),
        "scope_sha256": profile["scope_sha256"],
        "hard_cutoff": profile["global_cutoff"]}


def validate_public_clock(root: Path, *, scope_path: str, scope_sha256: str,
        started_at: str, phase: str, now: str | datetime.datetime | None = None,
        workflow_created_at: str | None = None) -> dict[str, Any]:
    """Validate the public clock on hosted runners that cannot access private authority."""
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if supplied_root != root:
        raise ValueError("phase7-window-root-invalid")
    if Path(scope_path) in AUTHORIZED_SCOPE_PROFILES:
        scope = load_public_scope(root, scope_path=scope_path, scope_sha256=scope_sha256)
        budget = _authorized_scope_budget(scope)
        cutoffs = _authorized_cutoffs(started_at, budget)
        clock = {"profile_id": "authorized-run", "scope_path": scope_path,
            "scope_sha256": scope_sha256, "started_at": started_at,
            "budget": budget, "scope": scope, **cutoffs}
        return check_window(clock, phase=phase, now=now, started_at=started_at,
            workflow_created_at=workflow_created_at)
    profile_id, profile = _profile_for_identity(scope_path=scope_path,
        scope_sha256=scope_sha256)
    load_public_scope(root, scope_path=scope_path, scope_sha256=scope_sha256)
    clock = {"profile_id": profile_id, "scope_path": profile["scope_path"].as_posix(),
        "scope_sha256": profile["scope_sha256"], "started_at": profile["started_at"]}
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
    if now is None:
        instant = datetime.datetime.now(datetime.timezone.utc)
    elif isinstance(now, datetime.datetime):
        instant = now
    else:
        instant = _utc(now, "phase7-window-clock-invalid")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("phase7-window-clock-invalid")
    instant = instant.astimezone(datetime.timezone.utc)
    if created > instant:
        raise ValueError("phase7-window-workflow-clock-invalid")
    matching = []
    for profile_id, profile in _PROFILES.items():
        start = _utc(profile["started_at"], "phase7-window-clock-invalid")
        global_cutoff = _utc(profile["global_cutoff"], "phase7-window-cutoff-invalid")
        if start <= created < global_cutoff:
            matching.append((start, profile_id, profile))
    if matching:
        # Overlapping prospective windows must select the newest authority. An
        # older active profile must not shadow a later retry window.
        _, profile_id, profile = max(matching, key=lambda item: item[0])
        checked = validate_public_clock(root,
            scope_path=profile["scope_path"].as_posix(),
            scope_sha256=profile["scope_sha256"], started_at=profile["started_at"],
            phase="preparation", now=now, workflow_created_at=workflow_created_at)
        return {"selected": True, "profile_id": profile_id,
            "scope_path": profile["scope_path"].as_posix(),
            "scope_sha256": profile["scope_sha256"],
            "started_at": profile["started_at"],
            "phase_cutoff": checked["phase_cutoff"],
            "remaining_seconds": checked["remaining_seconds"]}
    return {"selected": False, "profile_id": None,
        "scope_path": LEGACY_SCOPE_PATH.as_posix(),
        "scope_sha256": LEGACY_SCOPE_SHA256, "started_at": None}


def load_public_scope(root: Path, *, scope_path: str = SCOPE_PATH.as_posix(),
        scope_sha256: str = SCOPE_SHA256) -> dict[str, Any]:
    """Load one of the exact public scopes on runners without private authority."""
    authorized_path = Path(scope_path)
    if authorized_path in AUTHORIZED_SCOPE_PROFILES:
        supplied_root = Path(os.path.abspath(root))
        root = supplied_root.resolve(strict=True)
        if supplied_root != root:
            raise ValueError("phase7-window-root-invalid")
        profile = _authorized_scope_profile(authorized_path, scope_sha256)
        raw = _read_regular(root, authorized_path)
        if _sha(raw) != profile["scope_sha256"]:
            raise ValueError("phase7-window-scope-stale")
        scope = _json(raw, "phase7-window-scope-invalid")
        baseline_raw = _read_regular(root, SCOPE_PATH)
        if _sha(baseline_raw) != SCOPE_SHA256:
            raise ValueError("phase7-window-legacy-four-hour-scope-stale")
        baseline = _json(baseline_raw, "phase7-window-scope-invalid")
        expected = json.loads(json.dumps(baseline))
        expected["per_child_limits"]["max_rss_bytes"] = profile["max_rss_bytes"]
        if scope != expected:
            raise ValueError("phase7-window-scope-content-invalid")
        _authorized_scope_budget(scope)
        return scope
    _, profile = _profile_for_identity(scope_path=scope_path,
        scope_sha256=scope_sha256)
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if supplied_root != root:
        raise ValueError("phase7-window-root-invalid")
    raw = _read_regular(root, profile["scope_path"])
    if _sha(raw) != profile["scope_sha256"]:
        raise ValueError("phase7-window-scope-stale")
    scope = _json(raw, "phase7-window-scope-invalid")
    old_raw = _read_regular(root, LEGACY_SCOPE_PATH)
    if _sha(old_raw) != LEGACY_SCOPE_SHA256:
        raise ValueError("phase7-window-legacy-scope-stale")
    old_scope = _json(old_raw, "phase7-window-legacy-scope-invalid")
    expected = json.loads(json.dumps(old_scope))
    expected["qualification_batch"].update(profile["budget"])
    if scope != expected:
        raise ValueError("phase7-window-scope-content-invalid")
    return scope
