#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict authority and filesystem checks for the one-shot native diagnostic."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import datetime
import contextvars
import importlib.util
from typing import Any


AUTH_REL = Path("build/v02/native-capture-retest-20261102T034752Z-repair/authorization-contract.json")
AUTH_SHA256 = "ae44639cfea4e2b50cc70568ada998880529f81d010bb7c71f562973b06b975d"
AUTHORITY_CONTRACT = {
    "approval_observed_at": "2026-11-02T03:47:52+00:00",
    "authority_evidence_kind": "Private conversation evidence and independent scope review; no quotation is included in public fixtures.",
    "authority_evidence_sha256": "cf062c97a93818130cdcc580c2e63a8338e9a89bce0c18707d1ad45c85804241",
    "authorization_basis": "User approved one fresh hosted native prefix diagnostic after verified local renderer-capture reporting and malformed-report fixes:5400second overall controller including queue,2700second actual job including setup, unchanged cases and workload limits. Reviewed local preparation, publication and required exact-source CI precede the sole dispatch.",
    "case_order": ["full-route", "withhold-first-plate"],
    "clock_profile": "native-prefix-queue-v1",
    "controller_cleanup_seconds": 300,
    "controller_wall_seconds": 5400,
    "diagnostic_case": "recursion94-native-prefix",
    "diagnostic_only": True,
    "failure_action": "preserve result and stop; no automatic retry",
    "full_qualification_authorized": False,
    "historical_risk_accepted": False,
    "job_cleanup_seconds": 30,
    "job_wall_seconds": 2700,
    "max_dispatches": 1,
    "merge_authorized": False,
    "next_phase_authorized": False,
    "old_campaign_clocks_unchanged": True,
    "outer_wall_seconds": 1800,
    "per_child_limits": {"cleanup_grace_seconds": 30, "max_binary_file_bytes": 2147483648,
        "max_calls": 100000000, "max_capture_bytes": 2147483648, "max_fields": 7200,
        "max_json_bytes": 33554432, "max_retained_bytes": 4294967296, "max_rss_bytes": 4294967296,
        "max_scratch_bytes": 17179869184, "max_stdout_stderr_bytes": 16777216, "wall_seconds": 600},
    "phase": 7,
    "plan": 10,
    "preparation": "routine local checks, source fixes, privacy/code/security review and required exact-source PR CI within active Plan10; no native job starts during preparation",
    "qualification_accepted": False,
    "release_authorized": False,
    "repository": "szTheory/genewhip",
    "runtime_activation": "single immutable dispatch request after reviewed source, candidate and exact-head CI; no renewal after claim",
    "schema": "genewhip.phase7-single-native-authorization.v1",
    "scope_path": "evidence/v02-execution.json",
    "scope_sha256": "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5",
    "setup_wall_seconds": 600,
    "source_ancestor": "ad5f24316654fdb1b2044e751f1df9083811688f",
    "stage_wall_seconds": {"headless-reference": 600, "input-contract": 30, "native-comparison": 600},
}


def public_authority_fixture_bytes() -> bytes:
    """Exact public-safe projection bytes for positive CI fixtures; contains no user quote."""
    return json.dumps(AUTHORITY_CONTRACT, sort_keys=True, indent=2).encode("utf-8") + b"\n"


ITERATION_AUTH_REL = Path("build/v02/phase7-iterations/authorization-contract.json")
ITERATION_AUTH_SHA256 = "bf60746bf790ed11e9912c4d6136339d12f6235f6cd491f423209bca33ece9f8"
ITERATION_POLICY_ROOT_REL = ITERATION_AUTH_REL.parent
ITERATION_AUTHORITY_CONTRACT = {
    "approval_observed_at": "2026-11-02T14:18:56+00:00",
    "attempt_count_limit": None,
    "attempt_namespace": "build/v02/phase7-iterations/attempt-NNNN",
    "authority_evidence_kind": "Private conversation evidence and independent scope review; no quotation is included in public fixtures.",
    "authority_evidence_sha256": "0d4bb3b6d7565ca69595ebfe2785f7fd4c9ac8e104d465d5b32962c258647eac",
    "authorization_basis": "Standing user authorization for routine fixes, tests, CI and evidence-supported retests in the active phase; reassess unproductive repetition without per-attempt approval.",
    "case_order": ["full-route", "withhold-first-plate"],
    "claim_path": "dispatch-claim.json",
    "clock_profile": "native-prefix-queue-v1",
    "controller_cleanup_seconds": 300,
    "controller_wall_seconds": 5400,
    "diagnostic_case": "recursion94-native-prefix",
    "diagnostic_only": True,
    "failure_action": "Preserve the failed or uncertain attempt and assess its evidence; never replay a claim. A distinct justified iteration may follow only after current cleanup is settled.",
    "full_qualification_authorized": False,
    "historical_risk_accepted": False,
    "iteration_policy": "Record a concise evidence/change rationale for each next runtime attempt; reassess repeated equivalent failures. No arbitrary total-attempt approval gate.",
    "job_cleanup_seconds": 30,
    "job_wall_seconds": 2700,
    "max_dispatches_per_attempt": 1,
    "merge_authorized": False,
    "next_attempt_after_claim": "terminal-result-and-cleanup-confirmed",
    "next_phase_authorized": False,
    "old_campaign_clocks_unchanged": True,
    "outer_wall_seconds": 1800,
    "per_attempt_user_approval": False,
    "per_child_limits": {"cleanup_grace_seconds": 30, "max_binary_file_bytes": 2147483648,
        "max_calls": 100000000, "max_capture_bytes": 2147483648, "max_fields": 7200,
        "max_json_bytes": 33554432, "max_retained_bytes": 4294967296,
        "max_rss_bytes": 4294967296, "max_scratch_bytes": 17179869184,
        "max_stdout_stderr_bytes": 16777216, "wall_seconds": 600},
    "phase": 7,
    "plan": 10,
    "preparation": "Immutable source/candidate/CI preparation revisions within a numbered runtime attempt; no runtime clock before its exclusive claim.",
    "preparation_namespace": "preparations/revision-NNNN",
    "qualification_accepted": False,
    "release_authorized": False,
    "repository": "szTheory/genewhip",
    "retired_claims": {
        "build/v02/native-capture-retest-20261102T034752Z/native-dispatch-claim.json": "a5d7d815e9f34942d45dadc387d681fb706a3626c64673331fab04a0a75aebef",
        "build/v02/native-complete-setup-retest-20261102T000552Z/native-dispatch-claim.json": "800b314bdcecfc338b33d8a53e51a01d566c6cf54aa571ac7e55014b78e8fe0c",
        "build/v02/native-media-retest-20261101T143706Z/native-dispatch-claim.json": "7cefafb83e385fab415b311d1b6b1a42b8bc000fc2f8c46ec0d475b9ad6386de",
        "build/v02/native-prefix-one-shot-20261101T112701Z/native-dispatch-claim.json": "5ac3952023fbcb60be29d05e97ce8ddb9c0bfe703b692ba472ade1ac149f671b",
        "build/v02/native-queue-window-20261101T182756Z/native-dispatch-claim.json": "6b74bfd77c742b44e41c05bd1ba840e433a2e1be9ec630798732d6883e83dc6e",
        "build/v02/native-report-retest-20261102T020902Z/native-dispatch-claim.json": "f7d28aee60e6684dfb4ecc020d0ab80ed7a16aaaac96d61f28171aaa5e580fa2",
        "build/v02/native-setup-retest-20261101T211431Z/native-dispatch-claim.json": "b3285dbe40e07b0b5402572113cdb62c74c969a0e05dc83283c6be590ea50163",
        "build/v02/native-shared-setup-retest-20261101T224403Z/native-dispatch-claim.json": "df1020862a19a3aa4695130f8c444f55414de6a2a98a3766ecfbdc7d4028afe0",
        "build/v02/native-stop-context-20261101T161645Z/native-dispatch-claim.json": "ef04fa872e42a344ede6f94f34700846a5044d09d83771d2f3cff3d3c004579d",
    },
    "retry_before_claim": "reviewed-source-preparation-revision",
    "runtime_activation": "One exclusive descriptor-anchored claim per numbered attempt, binding its exact preparation revision and limits.",
    "schema": "genewhip.phase7-native-iteration-policy.v1",
    "scope_path": "evidence/v02-execution.json",
    "scope_sha256": "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5",
    "setup_wall_seconds": 600,
    "source_ancestor": "6316efea97679fe40587bb0e5ab4deb63397a87d",
    "stage_wall_seconds": {"headless-reference": 600, "input-contract": 30,
        "native-comparison": 600},
    "unknown_claim_or_cleanup": "stop",
}


def public_iteration_authority_fixture_bytes() -> bytes:
    """Exact public-safe bytes for the standing Phase 7 iteration policy."""
    return json.dumps(ITERATION_AUTHORITY_CONTRACT, sort_keys=True, indent=2).encode("utf-8") + b"\n"


ITERATION_CLAIM_LEAF = "dispatch-claim.json"
ITERATION_ATTEMPT_RE = re.compile(r"attempt-([0-9]{4,})\Z")
ITERATION_REVISION_RE = re.compile(r"revision-([0-9]{4,})\Z")
ITERATION_BASELINE_INPUT_REL = ITERATION_POLICY_ROOT_REL / "baseline-input.json"
ITERATION_BASELINE_INPUT_SHA256 = "4562d30b7d6c727c7ef08b04815b02743e05d49723681495ff09174a4cfdf30e"
ITERATION_BASELINE_REL = ITERATION_POLICY_ROOT_REL / "baseline.json"
ITERATION_TERMINAL_SCHEMA = "genewhip.phase7-native-iteration-terminal.v1"
ITERATION_ALLOCATION_SCHEMA = "genewhip.phase7-native-iteration-allocation.v1"
ITERATION_PREPARATION_SCHEMA = "genewhip.phase7-native-iteration-preparation.v1"
ITERATION_PREPARATION_TERMINAL_SCHEMA = "genewhip.phase7-native-iteration-preparation-terminal.v1"
ITERATION_SOURCE_CI_JOBS = frozenset({"safety", "gameplay", "desktop", "package",
    "performance", "product-smoke", "phase7-fast", "required-ci", "v02-runtime",
    "extended", "attestation", "v02-benchmark-control", "v02-benchmark-recursion94",
    "v02-benchmark-tank-battle", "v02-package", "v02-release-qualification"})
_TERMINAL_VALIDATION_CONTEXT = contextvars.ContextVar(
    "genewhip_single_native_terminal_validation_context", default=None)
LEGACY_ROOT_REL = AUTH_REL.parent / "attempt-0001"
RETIRED_ROOT_REL = Path("build/v02/native-prefix-one-shot-20261101T112701Z/attempt-0001")
ROOT_REL = AUTH_REL.parent / "attempt-0003"
# This is the original O_EXCL anchor for the unspent grant. Keep it pinned to
# the frozen preparation root while the accepted preparation moves forward.
CLAIM_REL = Path("build/v02/native-capture-retest-20261102T034752Z/native-dispatch-claim.json")
LOCAL_CLAIM_REL = AUTH_REL.parent / "native-dispatch-claim.json"
PREVIOUS_PREPARATION_REL = Path("build/v02/native-capture-retest-20261102T034752Z")
PREVIOUS_ATTEMPT_REL = PREVIOUS_PREPARATION_REL / "attempt-0003"
SCOPE_REL = Path("evidence/v02-execution.json")
SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"
PREDECESSOR_REL = AUTH_REL.parent / "predecessor-observation.json"
SCHEMA = "genewhip.phase7-single-native-admission.v1"
SOURCE_ROLES = {"code": "gsd-code-reviewer", "security": "gsd-security-auditor"}
MAX_RECORD = 8 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_ROSTER = 128 * 1024 * 1024
QUEUE_PROFILE = "native-prefix-queue-v1"
QUEUE_RECEIPT_SCHEMA = "genewhip.phase7-native-prefix-job-clock.v2"
NS = 1_000_000_000
PREVIEW_REQUIRED = {"safety", "gameplay", "desktop", "package", "performance",
    "product-smoke", "phase7-fast", "required-ci"}
PREVIEW_SKIPPED = {"v02-runtime", "extended", "v02-benchmark-control",
    "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package",
    "v02-release-qualification", "attestation"}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lineage_entry_present(root: Path, relative: Path) -> bool:
    """Treat a present or symlinked claim path component as a consumed route."""
    cursor = Path(root)
    parts = Path(relative).parts
    for index, part in enumerate(parts):
        cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode):
            return True
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            return True
    return True


def _validated_claim_path(root: Path, relative: Path) -> Path:
    """Resolve one fixed claim under owned, existing, non-symlink directories."""
    supplied_root = Path(os.path.abspath(root))
    try:
        root = supplied_root.resolve(strict=True)
        if supplied_root != root:
            raise ValueError("single-native-claim-parent-invalid")
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
            raise ValueError("single-native-claim-parent-invalid")
        if (relative.is_absolute() or not relative.parts
                or any(part in ("", ".", "..") or "\\" in part for part in relative.parts)):
            raise ValueError("single-native-claim-path-invalid")
        parent = root
        for part in relative.parts[:-1]:
            parent /= part
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()):
                raise ValueError("single-native-claim-parent-invalid")
        expected_parent = root.joinpath(*relative.parts[:-1])
        if parent.resolve(strict=True) != expected_parent:
            raise ValueError("single-native-claim-parent-invalid")
        return expected_parent / relative.parts[-1]
    except (OSError, RuntimeError):
        raise ValueError("single-native-claim-parent-invalid") from None


def _claim_directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise ValueError("single-native-claim-anchor-unavailable")
    return os.O_RDONLY | nofollow | directory


def _claim_identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid


def _close_claim_anchor(anchor: dict[str, Any]) -> None:
    """Close every retained descriptor, including after partial failures."""
    errors = []
    descriptors = []
    parent_fd = anchor.pop("parent_fd", None)
    if type(parent_fd) is int:
        descriptors.append(parent_fd)
    for descriptor in reversed(anchor.pop("dir_fds", [])):
        if type(descriptor) is int and descriptor not in descriptors:
            descriptors.append(descriptor)
    root_fd = anchor.pop("root_fd", None)
    if type(root_fd) is int and root_fd not in descriptors:
        descriptors.append(root_fd)
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError as exc:
            errors.append(exc)
    if errors:
        raise ValueError("single-native-claim-anchor-close-failed") from None


def _open_claim_anchor(root: Path, relative: Path) -> dict[str, Any]:
    """Pin a claim's existing parent chain with root-anchored no-follow descriptors."""
    supplied_root = Path(os.path.abspath(root))
    try:
        canonical_root = supplied_root.resolve(strict=True)
        if supplied_root != canonical_root:
            raise ValueError("single-native-claim-parent-invalid")
        if (relative.is_absolute() or not relative.parts
                or any(part in ("", ".", "..") or "\\" in part for part in relative.parts)):
            raise ValueError("single-native-claim-path-invalid")
        flags = _claim_directory_flags()
        root_info = canonical_root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
            raise ValueError("single-native-claim-parent-invalid")
        root_fd = os.open(os.fspath(canonical_root), flags)
        try:
            opened_root = os.fstat(root_fd)
            if (not stat.S_ISDIR(opened_root.st_mode) or opened_root.st_uid != os.getuid()
                    or _claim_identity(opened_root) != _claim_identity(root_info)):
                raise ValueError("single-native-claim-parent-invalid")
        except BaseException:
            os.close(root_fd)
            raise
        anchor: dict[str, Any] = {"root_path": canonical_root, "relative": relative,
            "leaf": relative.parts[-1], "root_fd": root_fd, "parent_fd": None,
            "dir_fds": [root_fd], "identities": [_claim_identity(opened_root)]}
        current_fd = root_fd
        try:
            for part in relative.parts[:-1]:
                next_fd = os.open(part, flags, dir_fd=current_fd)
                anchor["dir_fds"].append(next_fd)
                try:
                    next_info = os.fstat(next_fd)
                    named_info = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                    if (not stat.S_ISDIR(next_info.st_mode) or next_info.st_uid != os.getuid()
                            or stat.S_ISLNK(named_info.st_mode)
                            or _claim_identity(next_info) != _claim_identity(named_info)):
                        raise ValueError("single-native-claim-parent-invalid")
                except BaseException:
                    raise
                anchor["identities"].append(_claim_identity(next_info))
                current_fd = next_fd
            anchor["parent_fd"] = os.dup(current_fd) if current_fd == root_fd else current_fd
            if current_fd != root_fd:
                current_fd = -1
            _verify_claim_parent_binding(anchor)
            return anchor
        except BaseException:
            try:
                _close_claim_anchor(anchor)
            except ValueError:
                pass
            raise
    except ValueError:
        raise
    except OSError:
        raise ValueError("single-native-claim-parent-invalid") from None


def _verify_claim_parent_binding(anchor: dict[str, Any]) -> None:
    """Rewalk names from the held root and require each directory inode to match."""
    root_fd = anchor.get("root_fd")
    parent_fd = anchor.get("parent_fd")
    root_path = anchor.get("root_path")
    relative = anchor.get("relative")
    identities = anchor.get("identities")
    if (type(root_fd) is not int or type(parent_fd) is not int
            or not isinstance(root_path, Path) or not isinstance(relative, Path)
            or not isinstance(identities, list) or len(identities) != len(relative.parts)):
        raise ValueError("single-native-claim-parent-invalid")
    try:
        held_root = os.fstat(root_fd)
        root_info = root_path.lstat()
        reopened_root_fd = os.open(os.fspath(root_path), _claim_directory_flags())
        try:
            reopened_root = os.fstat(reopened_root_fd)
            if (not stat.S_ISDIR(held_root.st_mode) or held_root.st_uid != os.getuid()
                    or _claim_identity(held_root) != identities[0]
                    or stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
                    or _claim_identity(root_info) != identities[0]
                    or _claim_identity(reopened_root) != identities[0]):
                raise ValueError("single-native-claim-parent-invalid")
            current_fd = reopened_root_fd
            opened = []
            try:
                for index, part in enumerate(relative.parts[:-1], start=1):
                    next_fd = os.open(part, _claim_directory_flags(), dir_fd=current_fd)
                    opened.append(next_fd)
                    next_info = os.fstat(next_fd)
                    named_info = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                    if (not stat.S_ISDIR(next_info.st_mode) or next_info.st_uid != os.getuid()
                            or stat.S_ISLNK(named_info.st_mode)
                            or _claim_identity(next_info) != identities[index]
                            or _claim_identity(named_info) != identities[index]):
                        raise ValueError("single-native-claim-parent-invalid")
                    current_fd = next_fd
                if _claim_identity(os.fstat(current_fd)) != _claim_identity(os.fstat(parent_fd)):
                    raise ValueError("single-native-claim-parent-invalid")
            finally:
                for descriptor in reversed(opened):
                    os.close(descriptor)
        finally:
            os.close(reopened_root_fd)
    except ValueError:
        raise
    except OSError:
        raise ValueError("single-native-claim-parent-invalid") from None


def _verify_claim_at_anchor(anchor: dict[str, Any], *, expected_bytes: bytes | None = None) -> bytes:
    """Read and bind the exclusive regular claim through its pinned parent fd."""
    _verify_claim_parent_binding(anchor)
    parent_fd = anchor["parent_fd"]
    leaf = anchor["leaf"]
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > MAX_RECORD):
            raise ValueError("single-native-claim-file-invalid")
        descriptor = os.open(leaf, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if (_claim_identity(opened) != _claim_identity(info)
                    or not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                    or opened.st_nlink != 1 or opened.st_size > MAX_RECORD):
                raise ValueError("single-native-claim-file-invalid")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(MAX_RECORD + 1)
            if len(data) > MAX_RECORD or (expected_bytes is not None and data != expected_bytes):
                raise ValueError("single-native-claim-file-stale")
            after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if _claim_identity(after) != _claim_identity(opened) or not stat.S_ISREG(after.st_mode):
                raise ValueError("single-native-claim-file-stale")
        finally:
            os.close(descriptor)
    except ValueError:
        raise
    except FileNotFoundError:
        raise ValueError("single-native-claim-file-missing") from None
    except OSError:
        raise ValueError("single-native-claim-file-invalid") from None
    _verify_claim_parent_binding(anchor)
    return data


def _create_claim_at_anchor(anchor: dict[str, Any], payload_builder) -> tuple[bytes, str]:
    """Create a one-shot claim beneath its pinned parent and verify durable bytes."""
    _verify_claim_parent_binding(anchor)
    parent_fd = anchor["parent_fd"]
    leaf = anchor["leaf"]
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError:
        raise ValueError("single-native-claim-anchor-invalid") from None
    else:
        raise FileExistsError(leaf)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        raise
    except OSError:
        raise ValueError("single-native-claim-create-unconfirmed") from None
    try:
        payload = payload_builder()
        if not isinstance(payload, bytes) or len(payload) > MAX_RECORD:
            raise ValueError("single-native-claim-payload-invalid")
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent_fd)
        _verify_claim_at_anchor(anchor, expected_bytes=payload)
        return payload, _digest(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def publication_paths_from_names(root: Path, names: list[str]) -> list[str]:
    """Side-effect-free public roster filter used only after this module is pinned."""
    excluded = {".planning", "build", "artifacts", "node_modules", "target", "dist",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    history = {"phase5-baseline.json", "phase5-baseline-roster.json",
        "phase5-failure-inventory.json", "phase5-current-reference.json", "phase5-reference-d118.json"}
    result = []
    for name in names:
        path = Path(name)
        parts = path.parts
        if (not parts or path.is_absolute() or "\\" in name
                or any(part in excluded for part in parts)
                or path.name == ".DS_Store" or path.name.startswith(".env")
                or (parts[0] == "evidence" and path.name.startswith("phase5-") and path.name not in history)
                or name == "fixtures/candidate-screening-v2.json"
                or any(part.lower() in {"private-receipts", "private-receipt", "crosswalks"} for part in parts)
                or (path.name.startswith("raw-build-") and path.suffix.lower() == ".bin")
                or (path.suffix.lower() == ".json" and ("-red-" in path.name
                    or path.name.endswith("-red.json") or name == "evidence/phase6-repairs.json"))):
            continue
        target = root / name
        if target.is_symlink() or not target.is_file():
            raise ValueError("public-snapshot-source-entry-invalid")
        result.append(name)
    if not result:
        raise ValueError("public-snapshot-source-empty")
    return sorted(result)


def _safe_file(root: Path, relative: str, *, cap: int = MAX_RECORD) -> tuple[Path, bytes]:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("single-native-path-invalid")
    rel = Path(relative)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError("single-native-path-invalid")
    path = root / rel
    cursor = root
    for part in rel.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("single-native-path-symlink")
    try:
        info = path.lstat()
        if not path.is_file() or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_size > cap:
            raise ValueError("single-native-file-invalid")
        data = path.read_bytes()
    except OSError:
        raise ValueError("single-native-file-invalid") from None
    if len(data) > cap:
        raise ValueError("single-native-file-invalid")
    return path, data


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError(label) from None
    if not isinstance(value, dict):
        raise ValueError(label)
    return value


def _aware_utc(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError(label)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(label) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(label)
    return parsed.astimezone(datetime.timezone.utc)


def _utc_ns(value: Any, label: str) -> int:
    parsed = _aware_utc(value, label)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = parsed - epoch
    return (delta.days * 86_400 + delta.seconds) * NS + delta.microseconds * 1_000


def queue_clock_projection(*, claim_started_at: str, claim_deadline: str,
        job_started_at: str, server_date: str, round_trip_ns: int,
        response_received_monotonic_ns: int, local_request_started_at: str,
        local_response_at: str) -> dict[str, int]:
    """Project authenticated provider UTC to a frozen monotonic deadline, only conservatively.

    Date is second precision. Treat it as the earliest possible server time, then
    add the full request RTT and one second of precision uncertainty; also use
    the later captured local UTC response time as a conservative upper bound. Job
    started_at is interpreted at its earliest representable instant. This makes
    elapsed time an upper bound and every remaining window a lower bound.
    """
    if (type(round_trip_ns) is not int or round_trip_ns < 0 or round_trip_ns > 60 * NS
            or type(response_received_monotonic_ns) is not int
            or response_received_monotonic_ns <= 0):
        raise ValueError("single-native-job-clock-measurement-invalid")
    claim_start_ns = _utc_ns(claim_started_at, "single-native-job-clock-claim-invalid")
    claim_end_ns = _utc_ns(claim_deadline, "single-native-job-clock-claim-invalid")
    job_start_ns = _utc_ns(job_started_at, "single-native-job-clock-start-invalid")
    server_date_ns = _utc_ns(server_date, "single-native-job-clock-server-date-invalid")
    local_request_ns = _utc_ns(local_request_started_at, "single-native-job-clock-local-time-invalid")
    local_response_ns = _utc_ns(local_response_at, "single-native-job-clock-local-time-invalid")
    local_elapsed_ns = local_response_ns - local_request_ns
    if (local_elapsed_ns < 0 or abs(local_elapsed_ns - round_trip_ns) > 2 * NS
            or abs(local_response_ns - server_date_ns) > 60 * NS):
        raise ValueError("single-native-job-clock-provider-date-stale")
    if (claim_end_ns != claim_start_ns + 5400 * NS or job_start_ns < claim_start_ns
            or server_date_ns + NS < job_start_ns):
        raise ValueError("single-native-job-clock-order-invalid")
    # Use whichever trusted clock places response receipt later so a stale
    # provider Date can never grant time the runner clock says has elapsed.
    provider_now_upper_ns = max(server_date_ns + round_trip_ns + NS, local_response_ns)
    elapsed_upper_ns = provider_now_upper_ns - job_start_ns
    job_start_mono_ns = response_received_monotonic_ns - elapsed_upper_ns
    job_deadline_mono_ns = job_start_mono_ns + 2700 * NS
    controller_deadline_mono_ns = response_received_monotonic_ns + (claim_end_ns - provider_now_upper_ns)
    controller_cleanup_deadline_ns = controller_deadline_mono_ns - 300 * NS
    job_cleanup_deadline_ns = job_deadline_mono_ns - 30 * NS
    collector_deadline_ns = min(controller_cleanup_deadline_ns, job_cleanup_deadline_ns)
    collector_start_cutoff_ns = collector_deadline_ns - 1800 * NS
    setup_deadline_ns = min(job_start_mono_ns + 600 * NS, collector_start_cutoff_ns)
    if job_start_mono_ns <= 0:
        raise ValueError("single-native-job-clock-window-unavailable")
    return {"job_started_monotonic_ns": job_start_mono_ns,
        "job_deadline_monotonic_ns": job_deadline_mono_ns,
        "controller_deadline_monotonic_ns": controller_deadline_mono_ns,
        "controller_cleanup_deadline_monotonic_ns": controller_cleanup_deadline_ns,
        "job_cleanup_deadline_monotonic_ns": job_cleanup_deadline_ns,
        "collector_deadline_monotonic_ns": collector_deadline_ns,
        "collector_start_cutoff_monotonic_ns": collector_start_cutoff_ns,
        "setup_deadline_monotonic_ns": setup_deadline_ns}


def validate_job_clock_receipt(receipt: Any, *, claim_sha256: str, claim_nonce: str,
        source_sha: str, run_id: str, run_attempt: int, repository: str,
        branch: str, require_live: bool = False,
        live_monotonic_ns: int | None = None,
        live_window: str = "setup") -> dict[str, int]:
    """Validate the bounded actual-job receipt and optionally require setup or collector entry."""
    keys = {"schema", "clock_profile", "claim_sha256", "claim_nonce", "repository", "run_id",
        "run_attempt", "job_id", "job_name", "job_status_at_observation", "head_sha", "head_branch",
        "claim_started_at", "claim_deadline", "job_started_at", "server_date", "round_trip_ns", "timestamp_precision_seconds",
        "local_request_started_at", "local_response_at",
        "request_started_monotonic_ns", "response_received_monotonic_ns",
        "job_started_monotonic_ns", "job_deadline_monotonic_ns", "controller_deadline_monotonic_ns",
        "controller_cleanup_deadline_monotonic_ns", "job_cleanup_deadline_monotonic_ns",
        "collector_deadline_monotonic_ns", "collector_start_cutoff_monotonic_ns",
        "setup_deadline_monotonic_ns"}
    if (not isinstance(receipt, dict) or set(receipt) != keys
            or receipt.get("schema") != QUEUE_RECEIPT_SCHEMA
            or receipt.get("clock_profile") != QUEUE_PROFILE
            or receipt.get("claim_sha256") != claim_sha256
            or receipt.get("claim_nonce") != claim_nonce
            or receipt.get("repository") != repository or receipt.get("run_id") != run_id
            or receipt.get("run_attempt") != run_attempt or type(receipt.get("job_id")) is not int
            or receipt.get("job_id", 0) <= 0 or receipt.get("job_name") != "v02-runtime"
            or receipt.get("job_status_at_observation") != "in_progress"
            or receipt.get("head_sha") != source_sha or receipt.get("head_branch") != branch
            or receipt.get("timestamp_precision_seconds") != 1):
        raise ValueError("single-native-job-clock-receipt-invalid")
    request_start = receipt.get("request_started_monotonic_ns")
    response_end = receipt.get("response_received_monotonic_ns")
    round_trip = receipt.get("round_trip_ns")
    if (type(request_start) is not int or request_start <= 0 or type(response_end) is not int
            or response_end < request_start or type(round_trip) is not int
            or response_end - request_start != round_trip):
        raise ValueError("single-native-job-clock-receipt-invalid")
    claim_start = receipt.get("claim_started_at")
    claim_deadline = receipt.get("claim_deadline")
    # The immutable claim identity is included in the receipt and checked by its digest.
    if (not isinstance(claim_start, str) or not isinstance(claim_deadline, str)
            or receipt.get("claim_sha256") != claim_sha256):
        raise ValueError("single-native-job-clock-receipt-invalid")
    expected = queue_clock_projection(claim_started_at=claim_start,
        claim_deadline=claim_deadline, job_started_at=receipt.get("job_started_at"),
        server_date=receipt.get("server_date"), round_trip_ns=round_trip,
        response_received_monotonic_ns=response_end,
        local_request_started_at=receipt.get("local_request_started_at"),
        local_response_at=receipt.get("local_response_at"))
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("single-native-job-clock-projection-mismatch")
    if require_live:
        if type(live_monotonic_ns) is not int or live_monotonic_ns <= 0:
            raise ValueError("single-native-job-clock-live-time-invalid")
        if (live_window == "setup" and (live_monotonic_ns >= expected["setup_deadline_monotonic_ns"]
                or live_monotonic_ns >= expected["collector_start_cutoff_monotonic_ns"])):
            raise ValueError("single-native-job-clock-setup-window-unavailable")
        if (live_window == "collector" and (live_monotonic_ns >= expected["collector_start_cutoff_monotonic_ns"]
                or live_monotonic_ns >= expected["collector_deadline_monotonic_ns"])):
            raise ValueError("single-native-job-clock-collector-window-unavailable")
        if live_window not in ("setup", "collector"):
            raise ValueError("single-native-job-clock-live-window-invalid")
    return expected


def terminal_conclusion_matches(report_status: Any, workflow_conclusion: Any) -> bool:
    """Only pass/success and fail/failure are supported terminal report pairs."""
    return (report_status in ("pass", "fail")
        and workflow_conclusion in ("success", "failure")
        and ((report_status == "pass") == (workflow_conclusion == "success")))


def claim_payload(*, attempt_root: str, source_sha: str, base_sha: str, branch: str,
        nonce: str, started_at: str, deadline: str, readiness_sha256: str,
        authority_sha256: str = AUTH_SHA256,
        preparation_revision: str | None = None) -> dict[str, Any]:
    """Construct the exact immutable claim for a legacy or numbered attempt."""
    iteration = authority_sha256 == ITERATION_AUTH_SHA256
    attempt_match = ITERATION_ATTEMPT_RE.fullmatch(Path(attempt_root).name) if iteration else None
    revision_match = (ITERATION_REVISION_RE.fullmatch(Path(preparation_revision).name)
        if iteration and isinstance(preparation_revision, str) else None)
    if ((iteration and (attempt_match is None or int(attempt_match.group(1)) < 1
                or Path(attempt_root).parent != ITERATION_POLICY_ROOT_REL
                or revision_match is None or int(revision_match.group(1)) < 1
                or Path(preparation_revision).parent != Path(attempt_root) / "preparations"))
            or (not iteration and (attempt_root != ROOT_REL.as_posix()
                or authority_sha256 != AUTH_SHA256 or preparation_revision is not None))
            or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
            or not re.fullmatch(r"[0-9a-f]{40}", base_sha)
            or branch != "v0.2-source-" + source_sha[:12]
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not re.fullmatch(r"[0-9a-f]{64}", readiness_sha256)):
        raise ValueError("single-native-claim-identity-invalid")
    try:
        start = __import__("datetime").datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end = __import__("datetime").datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("single-native-claim-clock-invalid") from None
    if (start.tzinfo is None or end.tzinfo is None
            or end != start + __import__("datetime").timedelta(seconds=5400)):
        raise ValueError("single-native-claim-clock-invalid")
    claim = {"schema": ("genewhip.phase7-native-iteration-dispatch-claim.v1" if iteration
            else "genewhip.phase7-single-native-dispatch-claim.v1"),
        "authority_sha256": authority_sha256, "attempt_root": attempt_root,
        "clock_profile": "native-prefix-queue-v1",
        "source_sha": source_sha, "base_sha": base_sha, "branch": branch,
        "nonce": nonce, "started_at": started_at, "deadline": deadline,
        "readiness_sha256": readiness_sha256, "qualification_started_at": started_at,
        "dispatches": 1, "qualification_accepted": False}
    if iteration:
        claim["preparation_revision"] = preparation_revision
        claim["attempt_index"] = int(attempt_match.group(1))
        claim["revision_index"] = int(revision_match.group(1))
    return claim


def iteration_claim_payload(*, attempt_root: str, preparation_revision: str,
        source_sha: str, base_sha: str, branch: str, nonce: str, started_at: str,
        deadline: str, readiness_sha256: str) -> dict[str, Any]:
    """Named constructor for the standing policy's attempt-scoped O_EXCL claim."""
    return claim_payload(attempt_root=attempt_root, source_sha=source_sha, base_sha=base_sha,
        branch=branch, nonce=nonce, started_at=started_at, deadline=deadline,
        readiness_sha256=readiness_sha256, authority_sha256=ITERATION_AUTH_SHA256,
        preparation_revision=preparation_revision)


def readiness_payload(*, started_at: str, source_head: str, candidate_head: str,
        public_admission: dict[str, str], diagnostic_assessment: dict[str, str],
        assessment_reviews: dict[str, Any], attempt_root: str | None = None,
        preparation_revision: str | None = None,
        attempt_allocation_sha256: str | None = None) -> dict[str, Any]:
    """Construct the reviewed readiness packet, binding a numbered revision when supplied."""
    if (not isinstance(started_at, str)
            or not re.fullmatch(r"[0-9a-f]{40}", source_head)
            or not re.fullmatch(r"[0-9a-f]{40}", candidate_head)
            or not isinstance(public_admission, dict)
            or set(public_admission) != {"path", "sha256"}
            or not isinstance(diagnostic_assessment, dict)
            or set(diagnostic_assessment) != {"path", "sha256"}
            or not isinstance(assessment_reviews, dict)):
        raise ValueError("single-native-readiness-identity-invalid")
    ready = {"schema": "genewhip.phase7-native-prefix-diagnostic-readiness.v1",
        "diagnostic_only": True, "qualification_accepted": False,
        "plan": {"case": "recursion94-native-prefix", "workloads": [
            {"name": "input-contract", "wall_seconds": 30},
            {"name": "headless-reference", "wall_seconds": 600,
                "cases": ["full-route", "withhold-first-plate"]},
            {"name": "native-comparison", "wall_seconds": 600,
                "cases": ["full-route", "withhold-first-plate"]}],
            "outer_wall_seconds": 1800, "job_wall_seconds": 2700,
            "qualification_accepted": False, "stop_after_result": True},
        "started_at": started_at, "source_head": source_head,
        "candidate_head": candidate_head, "public_admission": dict(public_admission),
        "diagnostic_assessment": dict(diagnostic_assessment),
        "assessment_reviews": dict(assessment_reviews)}
    if attempt_root is not None or preparation_revision is not None or attempt_allocation_sha256 is not None:
        attempt_match = ITERATION_ATTEMPT_RE.fullmatch(Path(attempt_root).name) if isinstance(attempt_root, str) else None
        revision_match = (ITERATION_REVISION_RE.fullmatch(Path(preparation_revision).name)
            if isinstance(preparation_revision, str) else None)
        if (attempt_match is None or Path(attempt_root).parent != ITERATION_POLICY_ROOT_REL
                or revision_match is None or Path(preparation_revision).parent != Path(attempt_root) / "preparations"
                or not re.fullmatch(r"[0-9a-f]{64}", str(attempt_allocation_sha256))):
            raise ValueError("single-native-readiness-iteration-identity-invalid")
        ready.update({"authority_sha256": ITERATION_AUTH_SHA256,
            "attempt_root": attempt_root, "preparation_revision": preparation_revision,
            "attempt_allocation_sha256": attempt_allocation_sha256})
    return ready


def validate_preview_assessment(root: Path, assessment_ref: Any, *, attempt: Path,
        candidate: dict[str, Any], admission_path: Path, admission_sha256: str) -> dict[str, Any]:
    """Reopen and bind the complete assessed PR preview packet and its local references."""
    if (not isinstance(assessment_ref, dict) or set(assessment_ref) != {"path", "sha256"}
            or not isinstance(assessment_ref.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(assessment_ref.get("sha256", "")))):
        raise ValueError("single-native-readiness-assessment-reference-invalid")
    expected_prefix = attempt.relative_to(root).as_posix() + "/ci-failure/"
    rel = assessment_ref["path"]
    if not rel.startswith(expected_prefix):
        raise ValueError("single-native-readiness-assessment-path-invalid")
    _, raw = _safe_file(root, rel, cap=MAX_RECORD)
    if _digest(raw) != assessment_ref["sha256"]:
        raise ValueError("single-native-readiness-assessment-stale")
    packet = _json(raw, "single-native-readiness-assessment-invalid")
    table, gh, delivery = (packet.get("source_and_candidate"), packet.get("github"),
                           packet.get("hosted_source_delivery"))
    if (packet.get("disposition") != "diagnostic-preview-green-assessment-required"
            or packet.get("qualification_credit") is not False
            or not isinstance(table, dict) or not isinstance(gh, dict) or not isinstance(delivery, dict)):
        raise ValueError("single-native-readiness-assessment-invalid")
    public_rel = admission_path.relative_to(root).as_posix()
    source_rel = attempt.relative_to(root).as_posix() + "/source-admission.json"
    for name, path in (("source_admission", source_rel), ("public_admission", public_rel)):
        if table.get(name + "_path") != path:
            raise ValueError("single-native-readiness-assessment-admission-invalid")
        expected_hash = admission_sha256 if name == "public_admission" else table.get(name + "_sha256")
        _, ref_raw = _safe_file(root, path, cap=MAX_RECORD)
        if (not isinstance(expected_hash, str) or _digest(ref_raw) != expected_hash
                or table.get(name + "_sha256") != _digest(ref_raw)):
            raise ValueError("single-native-readiness-assessment-admission-stale")
    source = _json(_safe_file(root, source_rel, cap=MAX_RECORD)[1], "single-native-readiness-source-invalid")
    public = _json(_safe_file(root, public_rel, cap=MAX_RECORD)[1], "single-native-readiness-public-invalid")
    if (table.get("private_source_head") != source.get("source_head")
            or source.get("source_head") != public.get("source_head")
            or public.get("candidate") != candidate
            or table.get("candidate_head") != candidate.get("public_head")
            or table.get("public_head") != candidate.get("public_head")
            or table.get("public_base") != candidate.get("public_base")
            or table.get("public_tree") != candidate.get("public_tree")
            or table.get("manifest_sha256") != candidate.get("source_manifest_sha256")
            or table.get("preparation_sha256") != candidate.get("preparation_sha256")
            or table.get("candidate_review_payload_sha256") != candidate.get("candidate_payload_sha256")):
        raise ValueError("single-native-readiness-assessment-candidate-invalid")
    for key, filename in (("source_delivery", "source-delivery.json"),
                           ("journal", "hosted-delivery-journal.json")):
        path = attempt.relative_to(root).as_posix() + "/" + filename
        ref = {"path": delivery.get(key + "_path"), "sha256": delivery.get(key + "_sha256")}
        if ref["path"] != path or not re.fullmatch(r"[0-9a-f]{64}", str(ref["sha256"])):
            raise ValueError("single-native-readiness-assessment-delivery-invalid")
        _, data = _safe_file(root, path, cap=MAX_RECORD)
        if _digest(data) != ref["sha256"]:
            raise ValueError("single-native-readiness-assessment-delivery-stale")
        delivery[key] = _json(data, "single-native-readiness-assessment-delivery-invalid")
    source_delivery, journal = delivery["source_delivery"], delivery["journal"]
    if (source_delivery.get("status") != "diagnostic-ci-complete"
            or source_delivery.get("diagnostic_only") is not True
            or source_delivery.get("assessment_required") is not True
            or source_delivery.get("merge_attempted") is not False
            or source_delivery.get("repository") != "szTheory/genewhip"
            or source_delivery.get("candidate_sha") != candidate["public_head"]
            or source_delivery.get("public_base_sha") != candidate["public_base"]
            or journal.get("repository") != "szTheory/genewhip"
            or journal.get("source_head") != candidate["public_head"]
            or journal.get("public_base_sha") != candidate["public_base"]
            or journal.get("branch") != "v0.2-source-" + candidate["public_head"][:12]
            or journal.get("push_performed") is not True
            or journal.get("diagnostic_only") is not True
            or journal.get("diagnostic_ci_status") != "passed"
            or journal.get("assessment_required") is not True
            or journal.get("merge_attempted") is not False
            or _lineage_entry_present(root,
                attempt.relative_to(root) / "failure.json")):
        raise ValueError("single-native-readiness-assessment-delivery-identity-invalid")
    source_started = _aware_utc(source.get("started_at"),
        "single-native-readiness-source-clock-invalid")
    publication_started = _aware_utc(journal.get("started_at"),
        "single-native-readiness-publication-clock-invalid")
    if publication_started < source_started:
        raise ValueError("single-native-readiness-publication-clock-backdated")
    jobs = gh.get("jobs")
    run = gh.get("workflow_run")
    if (not isinstance(jobs, list) or len(jobs) != 16
            or not all(isinstance(row, dict) for row in jobs)):
        raise ValueError("single-native-readiness-preview-jobs-invalid")
    by_name = {row.get("name"): row for row in jobs}
    if (len(by_name) != 16 or set(by_name) != PREVIEW_REQUIRED | PREVIEW_SKIPPED
            or any(type(row.get("id")) is not int or row["id"] <= 0
                or row.get("status") != "completed" for row in jobs)
            or len({row["id"] for row in jobs}) != 16
            or any(by_name[name].get("conclusion") != "success" for name in PREVIEW_REQUIRED)
            or any(by_name[name].get("conclusion") != "skipped" for name in PREVIEW_SKIPPED)):
        raise ValueError("single-native-readiness-preview-jobs-invalid")
    pr_number = gh.get("pull_request")
    if (type(pr_number) is not int or pr_number <= 0 or not isinstance(run, dict)
            or type(run.get("id")) is not int or run["id"] <= 0
            or type(run.get("run_attempt")) is not int or run["run_attempt"] != 1
            or run.get("event") != "pull_request" or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("workflow_path") != ".github/workflows/ci.yml"
            or gh.get("repository") != "szTheory/genewhip" or gh.get("merged") is not False
            or gh.get("pull_request_state") != "open"
            or gh.get("head_sha") != candidate.get("public_head")
            or gh.get("base_sha") != candidate.get("public_base")
            or journal.get("pull_request") != str(pr_number)
            or source_delivery.get("pull_request") != str(pr_number)
            or any(key.startswith("qualification_dispatch") for key in journal)):
        raise ValueError("single-native-readiness-preview-identity-invalid")
    return {"packet": packet, "workflow_run": run, "jobs": by_name,
        "pull_request": pr_number, "source_delivery": source_delivery,
        "journal": journal}


def _validate_predecessor(root: Path, raw: bytes) -> None:
    value = _json(raw, "single-native-predecessor-invalid")
    expected = {"schema", "source_sha", "run_id", "run_attempt", "diagnostic_status",
        "first_headless_case", "input_contract", "remaining_cases", "inner_cleanup",
        "outer_cleanup", "outer_bound_violation", "hosted_exception", "full_qualification20_cause",
        "qualification_accepted", "retry_authority", "source_repair", "references"}
    refs_expected = {"dispatch", "result", "report", "workflow_run", "jobs_stdout",
        "retention_manifest", "runtime_log", "repair_payload", "repair_code_review",
        "repair_security_review", "result_code_review", "result_security_review"}
    if (set(value) != expected or value.get("schema") != "genewhip.phase7-single-native-predecessor-observation.v1"
            or value.get("diagnostic_status") != "fail"
            or value.get("first_headless_case") != "failed-process-and-route-facts-unavailable"
            or value.get("input_contract") != "pass-23-observations"
            or value.get("remaining_cases") != "unavailable"
            or value.get("inner_cleanup") != "unknown" or value.get("outer_cleanup") != "confirmed"
            or value.get("outer_bound_violation") is not False
            or value.get("hosted_exception") != "not-retained-unknown"
            or value.get("full_qualification20_cause") != "unknown"
            or value.get("qualification_accepted") is not False
            or value.get("run_attempt") != 1 or not re.fullmatch(r"[0-9]+", str(value.get("run_id", "")))
            or not re.fullmatch(r"[0-9a-f]{40}", str(value.get("source_sha", "")))):
        raise ValueError("single-native-predecessor-semantics-invalid")
    refs = value.get("references")
    if not isinstance(refs, dict) or set(refs) != refs_expected:
        raise ValueError("single-native-predecessor-references-invalid")
    files: dict[str, bytes] = {}
    for name, ref in refs.items():
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
            raise ValueError("single-native-predecessor-reference-invalid")
        rel = ref.get("path")
        if (not isinstance(rel, str) or ".." in Path(rel).parts
                or not (rel.startswith("build/v02/ci-continuation-20261031T124319Z/attempt-0021/")
                    or rel.startswith(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/"))
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))):
            raise ValueError("single-native-predecessor-reference-invalid")
        _, data = _safe_file(root, rel, cap=MAX_FILE)
        if _digest(data) != ref["sha256"]:
            raise ValueError("single-native-predecessor-reference-stale")
        files[name] = data
    dispatch = _json(files["dispatch"], "single-native-predecessor-dispatch-invalid")
    result = _json(files["result"], "single-native-predecessor-result-invalid")
    report = _json(files["report"], "single-native-predecessor-report-invalid")
    retained = _json(files["retention_manifest"], "single-native-predecessor-retention-invalid")
    workflow = _json(files["workflow_run"], "single-native-predecessor-workflow-invalid")
    selected = workflow.get("selected_run")
    if not isinstance(selected, dict):
        raise ValueError("single-native-predecessor-workflow-invalid")
    identity = report.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("single-native-predecessor-report-invalid")
    report_ref, result_ref, dispatch_ref = refs["report"], refs["result"], refs["dispatch"]
    if (dispatch.get("dispatches") != 1 or dispatch.get("qualification_accepted") is not False
            or dispatch.get("source_sha") != value["source_sha"]
            or str(dispatch.get("run_id")) != value["run_id"]
            or result.get("run_id") != value["run_id"] or result.get("run_attempt") != "1"
            or result.get("source_sha") != value["source_sha"] or result.get("status") != "fail"
            or result.get("qualification_accepted") is not False
            or result.get("report_sha256") != report_ref["sha256"]
            or result.get("report_path") != report_ref["path"]
            or report.get("schema") != "genewhip-phase7-native-prefix-diagnostic-v1"
            or report.get("status") != "fail" or report.get("diagnostic_only") is not True
            or report.get("qualification_accepted") is not False
            or report.get("fixture") != "recursion94"
            or report.get("case_order") != ["full-route", "withhold-first-plate"]
            or identity.get("source_sha") != value["source_sha"]
            or identity.get("head_sha") != value["source_sha"]
            or identity.get("run_id") != value["run_id"]
            or identity.get("run_attempt") != "1"
            or selected.get("id") != int(value["run_id"])
            or selected.get("run_attempt") != 1 or selected.get("head_sha") != value["source_sha"]
            or selected.get("event") != "workflow_dispatch" or selected.get("status") != "completed"
            or selected.get("conclusion") != "failure"
            or retained.get("run_id") != int(value["run_id"]) or retained.get("run_attempt") != 1
            or retained.get("dispatch_sha256") != dispatch_ref["sha256"]
            or retained.get("result_path") != result_ref["path"]
            or retained.get("result_sha256") != refs["result"]["sha256"]
            or retained.get("report_path") != report_ref["path"]
            or retained.get("report_sha256") != report_ref["sha256"]
            or hashlib.sha256(files["jobs_stdout"]).hexdigest() != retained.get("retained_receipts", {}).get("jobs", {}).get("stdout_sha256")
            or len(files["jobs_stdout"]) != retained.get("retained_receipts", {}).get("jobs", {}).get("stdout_bytes")):
        raise ValueError("single-native-predecessor-identity-join-invalid")


def _validate_candidate(root: Path, candidate: dict[str, Any], source_head: str) -> None:
    required = {"preparation_path", "preparation_sha256", "publication_path",
        "repository_policy_path", "repository_policy_sha256", "public_head", "public_base",
        "public_tree", "source_manifest_sha256", "candidate_payload_sha256"}
    if set(candidate) != required:
        raise ValueError("single-native-candidate-invalid")
    _, prep_raw = _safe_file(root, candidate["preparation_path"], cap=MAX_RECORD)
    _, policy_raw = _safe_file(root, candidate["repository_policy_path"], cap=MAX_RECORD)
    if (_digest(prep_raw) != candidate["preparation_sha256"]
            or _digest(policy_raw) != candidate["repository_policy_sha256"]):
        raise ValueError("single-native-candidate-pin-stale")
    prep, policy = _json(prep_raw, "single-native-preparation-invalid"), _json(policy_raw, "single-native-policy-invalid")
    manifest = prep.get("source_manifest")
    if (not isinstance(manifest, list) or not manifest or len(manifest) > 100000
            or prep.get("status") != "prepared"
            or prep.get("source_identity", {}).get("private_git_head") != source_head
            or prep.get("publication_copy") != candidate["publication_path"]
            or prep.get("repository_preflight") != candidate["repository_policy_path"]
            or prep.get("source_manifest_sha256") != candidate["source_manifest_sha256"]
            or prep.get("public_identity", {}).get("head_sha") != candidate["public_head"]
            or prep.get("public_identity", {}).get("base_sha") != candidate["public_base"]
            or prep.get("public_identity", {}).get("tree_sha") != candidate["public_tree"]
            or prep.get("privacy", {}).get("status") != "pass" or prep.get("blockers") != []
            or policy.get("repository_observations", {}).get("ready") is not True
            or policy.get("privacy_scan", {}).get("publication_copy", {}).get("status") != "pass"):
        raise ValueError("single-native-candidate-stale")
    canonical_manifest = _canonical(manifest)
    if _digest(canonical_manifest) != candidate["source_manifest_sha256"]:
        raise ValueError("single-native-public-manifest-invalid")
    publication_rel = Path(candidate["publication_path"])
    if (not candidate["publication_path"] or publication_rel.is_absolute()
            or "\\" in candidate["publication_path"]
            or any(part in ("", ".", "..") for part in publication_rel.parts)):
        raise ValueError("single-native-publication-directory-invalid")
    publication = root / publication_rel
    cursor = root
    for part in publication_rel.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("single-native-publication-directory-invalid")
    if publication.is_symlink() or not publication.is_dir():
        raise ValueError("single-native-publication-directory-invalid")
    actual: dict[str, tuple[int, str]] = {}
    total = 0
    for directory, dirs, files in os.walk(publication, followlinks=False):
        base = Path(directory)
        for name in list(dirs):
            item = base / name
            if name == ".git" and not (base == publication):
                raise ValueError("single-native-publication-entry-invalid")
            if item.is_symlink() or not item.is_dir():
                raise ValueError("single-native-publication-entry-invalid")
            if base == publication and name == ".git":
                dirs.remove(name)
                continue
        for name in files:
            item = base / name
            if base == publication and name == ".git":
                raise ValueError("single-native-publication-entry-invalid")
            info = item.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_size > MAX_FILE):
                raise ValueError("single-native-publication-entry-invalid")
            data = item.read_bytes()
            relative = item.relative_to(publication).as_posix()
            total += len(data)
            if total > MAX_ROSTER:
                raise ValueError("single-native-publication-over-limit")
            actual[relative] = (len(data), _digest(data))
    expected: dict[str, tuple[int, str]] = {}
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {"path", "size_bytes", "sha256"}:
            raise ValueError("single-native-public-manifest-invalid")
        path = row["path"]
        if (not isinstance(path, str) or path.startswith("/") or "\\" in path
                or any(part in ("", ".", "..") for part in Path(path).parts)
                or type(row["size_bytes"]) is not int or row["size_bytes"] < 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(row["sha256"]))
                or path in expected):
            raise ValueError("single-native-public-manifest-invalid")
        expected[path] = (row["size_bytes"], row["sha256"])
    if actual != expected:
        raise ValueError("single-native-publication-manifest-mismatch")


def canonical_root(root: Path, attempt_root: Path) -> Path:
    root = Path(os.path.abspath(root)).resolve(strict=True)
    candidate = attempt_root if attempt_root.is_absolute() else root / attempt_root
    candidate = Path(os.path.abspath(candidate))
    if candidate == root / ROOT_REL:
        relative = ROOT_REL
    else:
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            raise ValueError("single-native-attempt-root-invalid") from None
        if (relative.parent != ITERATION_POLICY_ROOT_REL
                or ITERATION_ATTEMPT_RE.fullmatch(relative.name) is None):
            raise ValueError("single-native-attempt-root-invalid")
    cursor = root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("single-native-attempt-root-invalid")
    if not candidate.is_dir():
        raise ValueError("single-native-attempt-root-missing")
    return candidate.resolve(strict=True)


def validate_route_paths(root: Path, paths: list[Path | None], *,
                         outputs: list[Path | None] | tuple[Path | None, ...] = (),
                         attempt_root: Path | None = None) -> None:
    """Require consumed paths to be unique and output targets to be genuinely new."""
    root = Path(os.path.abspath(root))
    selected_root = ROOT_REL if attempt_root is None else attempt_root
    attempt = canonical_root(root, selected_root)
    attempt_relative = attempt.relative_to(root)
    canonical: list[Path] = []
    existing_inodes: dict[tuple[int, int], Path] = {}
    for value in paths:
        if value is None:
            continue
        candidate = value if value.is_absolute() else root / value
        candidate = Path(os.path.abspath(candidate))
        try:
            relative = candidate.relative_to(attempt)
        except ValueError:
            raise ValueError("single-native-mixed-roots-rejected") from None
        cursor = root
        for part in attempt_relative.parts + relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise ValueError("single-native-route-path-symlink")
        resolved = candidate.resolve(strict=False)
        resolved_attempt = attempt.resolve(strict=False)
        if resolved != resolved_attempt and resolved_attempt not in resolved.parents:
            raise ValueError("single-native-mixed-roots-rejected")
        if resolved.exists():
            info = resolved.lstat()
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError("single-native-route-file-alias")
                inode = (info.st_dev, info.st_ino)
                if inode in existing_inodes:
                    raise ValueError("single-native-route-file-alias")
                existing_inodes[inode] = resolved
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError("single-native-route-file-alias")
        canonical.append(resolved)
    for i, left in enumerate(canonical):
        for right in canonical[i + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError("single-native-route-path-alias")
    output_paths: list[Path] = []
    for value in outputs:
        if value is None:
            continue
        candidate = value if value.is_absolute() else root / value
        candidate = Path(os.path.abspath(candidate))
        try:
            relative = candidate.relative_to(attempt)
        except ValueError:
            raise ValueError("single-native-mixed-roots-rejected") from None
        cursor = root
        for part in attempt_relative.parts + relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise ValueError("single-native-route-path-symlink")
        resolved = candidate.resolve(strict=False)
        resolved_attempt = attempt.resolve(strict=False)
        if (resolved != resolved_attempt and resolved_attempt not in resolved.parents):
            raise ValueError("single-native-mixed-roots-rejected")
        if resolved.exists():
            raise ValueError("single-native-route-output-stale")
        output_paths.append(resolved)
    for output in output_paths:
        for consumed in canonical:
            if output == consumed or output in consumed.parents or consumed in output.parents:
                raise ValueError("single-native-route-path-alias")
        for other in output_paths:
            if other != output and (output in other.parents or other in output.parents):
                raise ValueError("single-native-route-path-alias")


def write_failure(root: Path, *, stage: str, reason: str,
                  attempt_root: Path = ROOT_REL,
                  preparation_revision: Path | None = None,
                  authority_sha256: str = AUTH_SHA256) -> Path:
    """Write an exclusive fail-closed marker after a validated route fails."""
    if authority_sha256 == ITERATION_AUTH_SHA256:
        attempt = canonical_root(root, attempt_root)
        selected_root = attempt
        preparation_relative = None
        if preparation_revision is not None:
            revision = Path(preparation_revision)
            revision = revision if revision.is_absolute() else Path(root) / revision
            revision = Path(os.path.abspath(revision))
            if (revision.parent != attempt / "preparations" or not revision.is_dir()
                    or revision.is_symlink()):
                raise ValueError("single-native-failure-preparation-root-invalid")
            selected_root = revision
            preparation_relative = revision.relative_to(Path(root).resolve(strict=True)).as_posix()
        attempt_relative = attempt.relative_to(Path(root).resolve(strict=True)).as_posix()
        payload = {"schema": "genewhip.phase7-native-iteration-failure.v1",
            "stage": stage, "reason": reason, "authority_sha256": authority_sha256,
            "attempt_root": attempt_relative, "preparation_revision": preparation_relative,
            "observed_at_unix_ns": time.time_ns(), "qualification_accepted": False}
        relative = (Path(preparation_relative) if preparation_relative is not None
            else Path(attempt_relative)) / "failure.json"
        _write_iteration_record(Path(root).resolve(strict=True), relative, payload)
        return selected_root / "failure.json"
    if authority_sha256 != AUTH_SHA256 or preparation_revision is not None:
        raise ValueError("single-native-failure-authority-invalid")
    attempt = canonical_root(root, attempt_root)
    path = attempt / "failure.json"
    payload = {"schema": "genewhip.phase7-single-native-failure.v1", "stage": stage,
        "reason": reason, "authority_sha256": AUTH_SHA256,
        "observed_at_unix_ns": time.time_ns(), "qualification_accepted": False}
    raw = _canonical(payload) + b"\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ValueError("single-native-failure-latch-write-failed") from None
    return path


def authority_sha256_for_path(authority_path: Path | None) -> str:
    """Return the pinned digest for one supported legacy or iteration policy."""
    if authority_path is None:
        return AUTH_SHA256
    value = Path(authority_path)
    if (value == AUTH_REL or value.as_posix() == AUTH_REL.as_posix()
            or (value.is_absolute() and value.parts[-len(AUTH_REL.parts):] == AUTH_REL.parts)):
        return AUTH_SHA256
    if (value == ITERATION_AUTH_REL or value.as_posix() == ITERATION_AUTH_REL.as_posix()
            or (value.is_absolute()
                and value.parts[-len(ITERATION_AUTH_REL.parts):] == ITERATION_AUTH_REL.parts)):
        return ITERATION_AUTH_SHA256
    raise ValueError("single-native-authority-path-invalid")


def load_authority(root: Path, authority_path: Path | None = None,
                   authority_sha256: str | None = None) -> dict[str, Any]:
    root = Path(os.path.abspath(root)).resolve(strict=True)
    supplied_path = None if authority_path is None else Path(authority_path)
    if supplied_path is None:
        relative = AUTH_REL
    elif supplied_path.is_absolute():
        if supplied_path == root / AUTH_REL:
            relative = AUTH_REL
        elif supplied_path == root / ITERATION_AUTH_REL:
            relative = ITERATION_AUTH_REL
        else:
            raise ValueError("single-native-authority-path-invalid")
    else:
        relative = supplied_path
    expected_sha256 = authority_sha256_for_path(relative)
    expected = root / relative
    if Path(os.path.abspath(expected)) != expected or expected.is_symlink():
        raise ValueError("single-native-authority-path-invalid")
    _, raw = _safe_file(root, relative.as_posix(), cap=65536)
    if _digest(raw) != expected_sha256 or authority_sha256 != expected_sha256:
        raise ValueError("single-native-authority-pin-invalid")
    value = _json(raw, "single-native-authority-invalid")
    if relative == ITERATION_AUTH_REL:
        if _canonical(value) != _canonical(ITERATION_AUTHORITY_CONTRACT):
            raise ValueError("single-native-iteration-policy-invalid")
    elif (value.get("schema") != "genewhip.phase7-single-native-authorization.v1"
            or value.get("phase") != 7 or value.get("plan") != 10
            or value.get("repository") != "szTheory/genewhip"
            or value.get("source_ancestor") != "ad5f24316654fdb1b2044e751f1df9083811688f"
            or value.get("diagnostic_case") != "recursion94-native-prefix"
            or value.get("case_order") != ["full-route", "withhold-first-plate"]
            or value.get("clock_profile") != "native-prefix-queue-v1"
            or value.get("controller_wall_seconds") != 5400
            or value.get("job_wall_seconds") != 2700
            or value.get("setup_wall_seconds") != 600
            or value.get("controller_cleanup_seconds") != 300
            or value.get("job_cleanup_seconds") != 30
            or value.get("max_dispatches") != 1
            or value.get("full_qualification_authorized") is not False
            or value.get("merge_authorized") is not False
            or value.get("release_authorized") is not False
            or value.get("next_phase_authorized") is not False
            or value.get("historical_risk_accepted") is not False
            or value.get("scope_path") != SCOPE_REL.as_posix()
            or value.get("scope_sha256") != SCOPE_SHA256):
        raise ValueError("single-native-authority-scope-invalid")
    _, scope_raw = _safe_file(root, SCOPE_REL.as_posix(), cap=65536)
    if _digest(scope_raw) != SCOPE_SHA256:
        raise ValueError("single-native-scope-pin-invalid")
    return value


def source_payload(*, source_head: str, started_at: str, attempt_root: str,
                   source_pins: dict[str, str], predecessor_sha256: str,
                   authority_sha256: str = AUTH_SHA256,
                   preparation_revision: str | None = None,
                   attempt_allocation_sha256: str | None = None) -> dict[str, Any]:
    payload = {"schema": SCHEMA, "stage": "source-preparation", "authority_sha256": authority_sha256,
        "scope_sha256": SCOPE_SHA256, "attempt_root": attempt_root, "started_at": started_at,
        "source_head": source_head, "source_pins": dict(sorted(source_pins.items())),
        "predecessor_sha256": predecessor_sha256}
    if preparation_revision is not None:
        payload["preparation_revision"] = preparation_revision
    if attempt_allocation_sha256 is not None:
        payload["attempt_allocation_sha256"] = attempt_allocation_sha256
    return payload


def candidate_payload(source: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    return {"schema": SCHEMA, "stage": "public-effects", "source_payload_sha256": _digest(_canonical(source)),
        "preparation_sha256": candidate["preparation_sha256"],
        "repository_policy_sha256": candidate["repository_policy_sha256"],
        "public_head": candidate["public_head"], "public_base": candidate["public_base"],
        "public_tree": candidate["public_tree"], "source_manifest_sha256": candidate["source_manifest_sha256"]}


def _owned_directory(path: Path, *, label: str) -> Path:
    try:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or path.resolve(strict=True) != path):
            raise ValueError(label)
    except (OSError, RuntimeError):
        raise ValueError(label) from None
    return path


def iteration_context(root: Path, authority_path: Path,
                      admission_path: Path, *, allow_claim: bool = False,
                      allow_historical: bool = False) -> dict[str, Any]:
    """Resolve one immutable numbered attempt and preparation revision from its admission path."""
    supplied_root = Path(os.path.abspath(root))
    canonical = supplied_root.resolve(strict=True)
    if supplied_root != canonical:
        raise ValueError("single-native-iteration-root-invalid")
    authority = load_authority(canonical, authority_path,
        authority_sha256_for_path(authority_path))
    if authority.get("schema") != "genewhip.phase7-native-iteration-policy.v1":
        raise ValueError("single-native-iteration-policy-required")
    supplied = Path(admission_path)
    absolute = supplied if supplied.is_absolute() else canonical / supplied
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(canonical)
    except ValueError:
        raise ValueError("single-native-iteration-admission-path-invalid") from None
    parts = relative.parts
    prefix = ITERATION_POLICY_ROOT_REL.parts
    if (len(parts) != len(prefix) + 4 or parts[:len(prefix)] != prefix
            or parts[len(prefix) + 1] != "preparations"
            or parts[-1] not in {"source-admission.json", "public-admission.json"}):
        raise ValueError("single-native-iteration-admission-path-invalid")
    attempt_name = parts[len(prefix)]
    revision_name = parts[len(prefix) + 2]
    attempt_match = ITERATION_ATTEMPT_RE.fullmatch(attempt_name)
    revision_match = ITERATION_REVISION_RE.fullmatch(revision_name)
    if (attempt_match is None or revision_match is None
            or int(attempt_match.group(1)) < 1 or int(revision_match.group(1)) < 1):
        raise ValueError("single-native-iteration-admission-path-invalid")
    policy_root = _owned_directory(canonical / ITERATION_POLICY_ROOT_REL,
        label="single-native-iteration-policy-root-invalid")
    if _lineage_entry_present(canonical, LOCAL_CLAIM_REL):
        raise ValueError("single-native-iteration-retired-route-present")
    attempt_relative = ITERATION_POLICY_ROOT_REL / attempt_name
    revision_relative = attempt_relative / "preparations" / revision_name
    cursor = canonical
    for part in attempt_relative.parts:
        cursor = cursor / part
        _owned_directory(cursor, label="single-native-iteration-attempt-root-invalid")
    preparations_root = _owned_directory(canonical / attempt_relative / "preparations",
        label="single-native-iteration-preparations-root-invalid")
    revision_root = _owned_directory(canonical / revision_relative,
        label="single-native-iteration-revision-root-invalid")
    if absolute.parent != revision_root or absolute.is_symlink():
        raise ValueError("single-native-iteration-admission-path-invalid")

    def numbered_directories(parent: Path, pattern: re.Pattern[str], label: str) -> list[int]:
        values = []
        try:
            children = list(parent.iterdir())
        except OSError:
            raise ValueError(label) from None
        for child in children:
            match = pattern.fullmatch(child.name)
            if match is None:
                continue
            _owned_directory(child, label=label)
            values.append(int(match.group(1)))
        values.sort()
        if values != list(range(1, len(values) + 1)):
            raise ValueError(label)
        return values

    attempts = numbered_directories(policy_root, ITERATION_ATTEMPT_RE,
        "single-native-iteration-attempt-sequence-invalid")
    attempt_index = int(attempt_match.group(1))
    if not attempts or (not allow_historical and attempts[-1] != attempt_index):
        raise ValueError("single-native-iteration-attempt-not-current")
    revisions = numbered_directories(preparations_root, ITERATION_REVISION_RE,
        "single-native-iteration-revision-sequence-invalid")
    revision_index = int(revision_match.group(1))
    if not revisions or (not allow_historical and revisions[-1] != revision_index):
        raise ValueError("single-native-iteration-revision-not-current")
    claim_path = attempt_relative / ITERATION_CLAIM_LEAF
    claim_absolute = canonical / claim_path
    if not allow_claim and _lineage_entry_present(canonical, claim_path):
        raise ValueError("single-native-iteration-claim-already-created")
    _validate_iteration_baseline(canonical, authority)
    attempt_allocation, attempt_allocation_raw = _iteration_allocation(canonical, attempt_relative)
    previous_attempt_rel = None
    if attempt_index == 1:
        expected_prior_path = ITERATION_BASELINE_REL.as_posix()
        expected_prior_sha = _digest(_safe_file(canonical, expected_prior_path, cap=MAX_RECORD)[1])
    else:
        previous_attempt_rel = ITERATION_POLICY_ROOT_REL / f"attempt-{attempt_index - 1:04d}"
        _, terminal_sha = _checked_terminal_assessment(canonical, previous_attempt_rel)
        expected_prior_path = (previous_attempt_rel / "terminal-assessment.json").as_posix()
        expected_prior_sha = terminal_sha
    if attempt_allocation.get("predecessor") != {
            "path": expected_prior_path, "sha256": expected_prior_sha}:
        raise ValueError("single-native-iteration-attempt-predecessor-invalid")
    if revision_index == 1:
        expected_revision_prior_path = (attempt_relative / "allocation.json").as_posix()
        expected_revision_prior_sha = _digest(attempt_allocation_raw)
    else:
        previous_revision_rel = (attempt_relative / "preparations"
            / f"revision-{revision_index - 1:04d}")
        _, prior_revision_sha = _checked_preparation_terminal(canonical,
            attempt_relative, previous_revision_rel)
        expected_revision_prior_path = (previous_revision_rel / "preparation-terminal.json").as_posix()
        expected_revision_prior_sha = prior_revision_sha
    revision_allocation, revision_allocation_raw = _iteration_allocation(
        canonical, attempt_relative, revision_relative)
    if (revision_allocation.get("predecessor") != {
            "path": expected_revision_prior_path, "sha256": expected_revision_prior_sha}
            or revision_allocation.get("attempt_allocation_sha256") != _digest(attempt_allocation_raw)):
        raise ValueError("single-native-iteration-revision-predecessor-invalid")
    return {"policy_kind": "iteration", "authority": authority,
        "authority_path": ITERATION_AUTH_REL.as_posix(),
        "authority_sha256": ITERATION_AUTH_SHA256,
        "policy_root": policy_root, "attempt_root": canonical / attempt_relative,
        "attempt_root_rel": attempt_relative.as_posix(), "attempt_index": attempt_index,
        "preparation_revision": revision_root,
        "preparation_revision_rel": revision_relative.as_posix(),
        "revision_index": revision_index, "admission_path": absolute,
        "claim_rel": claim_path, "claim_path": claim_absolute,
        "attempt_allocation": attempt_allocation,
        "attempt_allocation_sha256": _digest(attempt_allocation_raw),
        "preparation_allocation": revision_allocation,
        "preparation_allocation_sha256": _digest(revision_allocation_raw),
        "predecessor_ref": {"path": (revision_relative / "allocation.json").as_posix(),
            "sha256": _digest(revision_allocation_raw)}}


def validate_admission(root: Path, attempt_root: Path, admission_path: Path, *, stage: str,
                       source_head: str, source_roster: set[str],
                       authority_path: Path | None = None, authority_sha256: str | None = None,
                       admission_sha256: str | None = None,
                       readiness_path: Path | None = None, readiness_sha256: str | None = None,
                       _terminal_reopen: bool = False,
                       _historical: bool = False,
                       _source_snapshot_only: bool = False) -> dict[str, Any]:
    """Validate real source pins/reviews and candidate bindings for one of three stages.

    Records are source-admission.json and public-admission.json. Both include schema,
    stage, authority_path/digest, scope_path/digest, attempt_root, started_at,
    source_head, source_pins, source_payload_sha256, source_reviews. Public stages
    also include candidate and candidate_reviews. Review references use path, sha256,
    reviewer_role, status, payload_sha256 and Markdown frontmatter with the same role,
    accepted status and payload digest.
    """
    if stage not in {"source-preparation", "public-effects", "native-prefix-diagnostic"}:
        raise ValueError("single-native-stage-invalid")
    supplied_root = Path(os.path.abspath(root))
    root = supplied_root.resolve(strict=True)
    if stage == "native-prefix-diagnostic" and supplied_root != root:
        raise ValueError("single-native-claim-parent-invalid")
    iteration = authority_path is not None and authority_sha256_for_path(authority_path) == ITERATION_AUTH_SHA256
    iteration_ctx = None
    if iteration:
        iteration_ctx = iteration_context(root, authority_path, admission_path,
            allow_claim=((_terminal_reopen and stage == "native-prefix-diagnostic")
                or (_historical and stage != "native-prefix-diagnostic")),
            allow_historical=_historical)
        if Path(os.path.abspath(attempt_root if attempt_root.is_absolute()
                else root / attempt_root)) != iteration_ctx["attempt_root"]:
            raise ValueError("single-native-attempt-root-invalid")
        attempt = iteration_ctx["attempt_root"]
        revision = iteration_ctx["preparation_revision"]
        claim_path = iteration_ctx["claim_path"]
    else:
        if stage == "native-prefix-diagnostic":
            _validated_claim_path(root, CLAIM_REL)
            _validated_claim_path(root, LOCAL_CLAIM_REL)
            lineage_conflicts = (LOCAL_CLAIM_REL,
                PREVIOUS_ATTEMPT_REL / "native-prefix-diagnostic")
            if any(_lineage_entry_present(root, relative) for relative in lineage_conflicts):
                raise ValueError("single-native-lineage-conflict")
            if not _terminal_reopen:
                spent_claims = (CLAIM_REL,
                    LEGACY_ROOT_REL / "native-prefix-diagnostic",
                    RETIRED_ROOT_REL / "native-prefix-diagnostic")
                if any(_lineage_entry_present(root, relative) for relative in spent_claims):
                    raise ValueError("single-native-one-shot-already-claimed")
        attempt = canonical_root(root, attempt_root)
        revision = attempt
        claim_path = attempt / "native-prefix-diagnostic"
    if not iteration and stage == "native-prefix-diagnostic":
        pass
    failure = revision / "failure.json"
    if _lineage_entry_present(root, failure.relative_to(root)):
        raise ValueError("single-native-failure-latch-present")
    claim = claim_path
    if stage == "native-prefix-diagnostic":
        if _terminal_reopen:
            if iteration:
                if claim.is_symlink() or not claim.is_file():
                    raise ValueError("single-native-terminal-claim-invalid")
            elif claim.is_symlink() or not claim.is_dir():
                raise ValueError("single-native-terminal-claim-invalid")
        elif claim.exists() or claim.is_symlink():
            raise ValueError("single-native-one-shot-already-claimed")
    elif _terminal_reopen:
        raise ValueError("single-native-terminal-stage-invalid")
    auth = load_authority(root, authority_path, authority_sha256)
    path = admission_path if admission_path.is_absolute() else root / admission_path
    expected = revision / ("source-admission.json" if stage == "source-preparation" else "public-admission.json")
    if Path(os.path.abspath(path)).resolve(strict=False) != expected:
        raise ValueError("single-native-admission-path-invalid")
    _, raw = _safe_file(root, expected.relative_to(root).as_posix(), cap=MAX_RECORD)
    if not isinstance(admission_sha256, str) or _digest(raw) != admission_sha256:
        raise ValueError("single-native-admission-pin-invalid")
    record = _json(raw, "single-native-admission-invalid")
    admitted_stage = "public-effects" if stage == "native-prefix-diagnostic" else stage
    base = {"schema", "stage", "authority_path", "authority_sha256", "scope_path", "scope_sha256",
        "attempt_root", "started_at", "source_head", "source_pins", "source_payload_sha256", "source_reviews",
        "predecessor"}
    public = stage != "source-preparation"
    keys = base | ({"candidate", "candidate_reviews"} if public else set())
    if iteration:
        base |= {"preparation_revision", "attempt_allocation_sha256"}
        keys = base | ({"candidate", "candidate_reviews"} if public else set())
    expected_authority_path = ITERATION_AUTH_REL.as_posix() if iteration else AUTH_REL.as_posix()
    expected_authority_sha = ITERATION_AUTH_SHA256 if iteration else AUTH_SHA256
    expected_attempt_root = (iteration_ctx["attempt_root_rel"] if iteration else ROOT_REL.as_posix())
    if (set(record) != keys or record.get("schema") != SCHEMA or record.get("stage") != admitted_stage
            or record.get("authority_path") != expected_authority_path
            or record.get("authority_sha256") != expected_authority_sha
            or record.get("scope_path") != SCOPE_REL.as_posix()
            or record.get("scope_sha256") != SCOPE_SHA256
            or record.get("attempt_root") != expected_attempt_root
            or (iteration and (record.get("preparation_revision") != iteration_ctx["preparation_revision_rel"]
                or record.get("attempt_allocation_sha256") != iteration_ctx["attempt_allocation_sha256"]))
            or record.get("source_head") != source_head
            or not re.fullmatch(r"[0-9a-f]{40}", str(source_head))):
        raise ValueError("single-native-admission-identity-invalid")
    if not isinstance(record.get("started_at"), str):
        raise ValueError("single-native-start-invalid")
    predecessor = record.get("predecessor")
    if iteration:
        if predecessor != iteration_ctx["predecessor_ref"]:
            raise ValueError("single-native-iteration-predecessor-reference-invalid")
        _, _, predecessor_raw = _iteration_reference(root, predecessor)
    else:
        if (not isinstance(predecessor, dict) or set(predecessor) != {"path", "sha256"}
                or predecessor.get("path") != PREDECESSOR_REL.as_posix()
                or not re.fullmatch(r"[0-9a-f]{64}", str(predecessor.get("sha256", "")))):
            raise ValueError("single-native-predecessor-reference-invalid")
        _, predecessor_raw = _safe_file(root, PREDECESSOR_REL.as_posix(), cap=MAX_RECORD)
        if _digest(predecessor_raw) != predecessor["sha256"]:
            raise ValueError("single-native-predecessor-stale")
        _validate_predecessor(root, predecessor_raw)
    if _source_snapshot_only and not _historical:
        raise ValueError("single-native-source-snapshot-mode-invalid")
    pins = record.get("source_pins")
    if not isinstance(pins, dict) or set(pins) != source_roster or not pins:
        raise ValueError("single-native-source-roster-invalid")
    total = 0
    checked = {}
    for rel, digest in pins.items():
        if (not isinstance(rel, str) or Path(rel).is_absolute() or "\\" in rel
                or any(part in ("", ".", "..") for part in Path(rel).parts)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("single-native-source-roster-over-limit")
        if not _source_snapshot_only:
            _, data = _safe_file(root, rel, cap=MAX_FILE)
            total += len(data)
            if total > MAX_ROSTER:
                raise ValueError("single-native-source-roster-over-limit")
            if _digest(data) != digest:
                raise ValueError("single-native-source-pin-stale")
        checked[rel] = digest
    source = source_payload(source_head=source_head, started_at=record["started_at"],
        attempt_root=expected_attempt_root, source_pins=checked,
        predecessor_sha256=predecessor["sha256"], authority_sha256=expected_authority_sha,
        preparation_revision=(iteration_ctx["preparation_revision_rel"] if iteration else None),
        attempt_allocation_sha256=(iteration_ctx["attempt_allocation_sha256"] if iteration else None))
    source_hash = _digest(_canonical(source))
    if record.get("source_payload_sha256") != source_hash:
        raise ValueError("single-native-source-payload-stale")
    _check_reviews(root, record.get("source_reviews"), SOURCE_ROLES, source_hash)
    if public:
        candidate = record.get("candidate")
        if not isinstance(candidate, dict):
            raise ValueError("single-native-candidate-invalid")
        _validate_candidate(root, candidate, source_head)
        for field in ("public_head", "public_base", "public_tree", "source_manifest_sha256"):
            if not isinstance(candidate.get(field), str) or not re.fullmatch(r"[0-9a-f]{40}" if field != "source_manifest_sha256" else r"[0-9a-f]{64}", candidate[field]):
                raise ValueError("single-native-candidate-identity-invalid")
        payload = candidate_payload(source, candidate)
        if candidate.get("candidate_payload_sha256") != _digest(_canonical(payload)):
            raise ValueError("single-native-candidate-payload-stale")
        candidate_hash = _digest(_canonical(payload))
        _check_reviews(root, record.get("candidate_reviews"), SOURCE_ROLES, candidate_hash)
    artifact_root = revision if iteration else attempt
    ready = None
    if stage == "native-prefix-diagnostic":
        expected_ready = artifact_root / "native-prefix-diagnostic-readiness.json"
        if (not isinstance(readiness_path, Path) or not isinstance(readiness_sha256, str)
                or Path(os.path.abspath(readiness_path if readiness_path.is_absolute()
                    else root / readiness_path)).resolve(strict=False) != expected_ready):
            raise ValueError("single-native-readiness-reference-invalid")
        _, ready_raw = _safe_file(root, expected_ready.relative_to(root).as_posix(), cap=MAX_RECORD)
        if _digest(ready_raw) != readiness_sha256:
            raise ValueError("single-native-readiness-stale")
        ready = _json(ready_raw, "single-native-readiness-invalid")
        ready_keys = {"schema", "diagnostic_only", "qualification_accepted", "plan", "started_at",
            "source_head", "candidate_head", "public_admission", "diagnostic_assessment", "assessment_reviews"}
        if iteration:
            ready_keys |= {"authority_sha256", "attempt_root", "preparation_revision",
                "attempt_allocation_sha256"}
        if (set(ready) != ready_keys or ready.get("schema") != "genewhip.phase7-native-prefix-diagnostic-readiness.v1"
                or ready.get("diagnostic_only") is not True or ready.get("qualification_accepted") is not False
                or ready.get("started_at") != record.get("started_at")
                or ready.get("source_head") != source_head
                or ready.get("candidate_head") != candidate.get("public_head")
                or (iteration and (ready.get("authority_sha256") != ITERATION_AUTH_SHA256
                    or ready.get("attempt_root") != iteration_ctx["attempt_root_rel"]
                    or ready.get("preparation_revision") != iteration_ctx["preparation_revision_rel"]
                    or ready.get("attempt_allocation_sha256") != iteration_ctx["attempt_allocation_sha256"]))
                or not isinstance(ready.get("diagnostic_assessment"), dict)):
            raise ValueError("single-native-readiness-identity-invalid")
        expected_plan = {"case": "recursion94-native-prefix", "workloads": [
            {"name": "input-contract", "wall_seconds": 30},
            {"name": "headless-reference", "wall_seconds": 600,
             "cases": ["full-route", "withhold-first-plate"]},
            {"name": "native-comparison", "wall_seconds": 600,
             "cases": ["full-route", "withhold-first-plate"]}],
            "outer_wall_seconds": 1800, "job_wall_seconds": 2700,
            "qualification_accepted": False, "stop_after_result": True}
        if _canonical(ready.get("plan")) != _canonical(expected_plan):
            raise ValueError("single-native-readiness-plan-invalid")
        pub_rel = expected.relative_to(root).as_posix()
        if ready.get("public_admission") != {"path": pub_rel, "sha256": _digest(raw)}:
            raise ValueError("single-native-readiness-admission-stale")
        ready_payload = {key: val for key, val in ready.items() if key != "assessment_reviews"}
        _check_reviews(root, ready.get("assessment_reviews"), SOURCE_ROLES,
                       _digest(_canonical(ready_payload)))
        journal_path = artifact_root / "hosted-delivery-journal.json"
        public_path = expected
        validate_preview_assessment(root, ready["diagnostic_assessment"], attempt=artifact_root,
            candidate=candidate, admission_path=public_path, admission_sha256=_digest(raw))
    return {"authority": auth, "batch_root": attempt, "attempt_root": attempt,
        "preparation_root": revision, "iteration_context": iteration_ctx,
        "repository": auth["repository"], "native_prefix_readiness": ready,
        "admission": record, "source_payload": source, "candidate": record.get("candidate")}


def validate_historical_admission(root: Path, attempt_root: Path, admission_path: Path, *,
        stage: str, source_head: str, source_roster: set[str], authority_path: Path,
        authority_sha256: str, admission_sha256: str) -> dict[str, Any]:
    """Read an earlier immutable source/public admission without reopening dispatch."""
    if stage not in {"source-preparation", "public-effects"}:
        raise ValueError("single-native-historical-admission-stage-invalid")
    ctx = iteration_context(root, authority_path, admission_path,
        allow_claim=True, allow_historical=True)
    key = "source_admission" if stage == "source-preparation" else "public_admission"
    canonical = Path(os.path.abspath(root)).resolve(strict=True)
    supplied = Path(admission_path)
    absolute = supplied if supplied.is_absolute() else canonical / supplied
    expected_ref = {"path": Path(os.path.abspath(absolute)).relative_to(canonical).as_posix(),
        "sha256": admission_sha256}
    prep_terminal = ctx["preparation_revision"] / "preparation-terminal.json"
    if _lineage_entry_present(root, prep_terminal.relative_to(root)):
        body, _ = _checked_preparation_terminal(root,
            Path(ctx["attempt_root_rel"]), Path(ctx["preparation_revision_rel"]))
        if body.get(key) != expected_ref:
            raise ValueError("single-native-historical-admission-closure-mismatch")
    else:
        terminal_rel = Path(ctx["attempt_root_rel"]) / "terminal-assessment.json"
        body, _ = _checked_terminal_assessment(root, Path(ctx["attempt_root_rel"]))
        ref = body.get(key)
        if ref != expected_ref:
            raise ValueError("single-native-historical-admission-closure-mismatch")
    return validate_admission(root, attempt_root, admission_path, stage=stage,
        source_head=source_head, source_roster=source_roster,
        authority_path=authority_path, authority_sha256=authority_sha256,
        admission_sha256=admission_sha256, _historical=True,
        _source_snapshot_only=True)


def _check_reviews(root: Path, refs: Any, roles: dict[str, str], payload_sha256: str) -> None:
    if not isinstance(refs, dict) or set(refs) != set(roles):
        raise ValueError("single-native-reviews-missing")
    for name, role in roles.items():
        ref = refs[name]
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256", "reviewer_role", "status", "payload_sha256"}:
            raise ValueError("single-native-review-reference-invalid")
        review_path, raw = _safe_file(root, ref["path"], cap=1024 * 1024)
        if not review_path.relative_to(root).as_posix().startswith(".planning/phases/GW-07-"):
            raise ValueError("single-native-review-path-invalid")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("single-native-review-invalid") from None
        front = {}
        if text.startswith("---\n") and "\n---\n" in text[4:]:
            block = text[4:text.index("\n---\n", 4)]
            for line in block.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    front[k.strip()] = v.strip()
        if (ref.get("sha256") != _digest(raw) or ref.get("reviewer_role") != role
                or ref.get("status") != "accepted" or ref.get("payload_sha256") != payload_sha256
                or front.get("status") != "accepted" or front.get("reviewer_role") != role
                or front.get("payload_sha256") != payload_sha256):
            raise ValueError("single-native-review-stale-or-rejected")


def _iteration_reason(value: Any) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 2048
            or any(ord(char) < 32 and char not in "\t" for char in value)):
        raise ValueError("single-native-iteration-reason-invalid")
    return value.strip()


def _iteration_reference(root: Path, value: Any, *, expected_path: str | None = None) -> tuple[str, str, bytes]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("single-native-iteration-reference-invalid")
    relative = value.get("path")
    if (not isinstance(relative, str) or Path(relative).is_absolute()
            or any(part in ("", ".", "..") for part in Path(relative).parts)
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))
            or (expected_path is not None and relative != expected_path)):
        raise ValueError("single-native-iteration-reference-invalid")
    _, raw = _safe_file(root, relative, cap=MAX_RECORD)
    if _digest(raw) != value["sha256"]:
        raise ValueError("single-native-iteration-reference-stale")
    return relative, value["sha256"], raw


def _write_iteration_record(root: Path, relative: Path, value: dict[str, Any]) -> tuple[Path, bytes]:
    """Write an immutable record through a root-anchored O_EXCL directory descriptor."""
    raw = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"
    anchor = _open_claim_anchor(root, relative)
    try:
        _create_claim_at_anchor(anchor, lambda: raw)
    finally:
        _close_claim_anchor(anchor)
    return Path(root) / relative, raw


def _retired_claims_unchanged(root: Path, authority: dict[str, Any]) -> None:
    """Reopen every immutable retired claim against the policy pin."""
    expected = ITERATION_AUTHORITY_CONTRACT["retired_claims"]
    if authority.get("retired_claims") != expected:
        raise ValueError("single-native-retired-claim-policy-invalid")
    for relative, digest in expected.items():
        _, raw = _safe_file(root, relative, cap=MAX_RECORD)
        if _digest(raw) != digest:
            raise ValueError("single-native-retired-claim-changed")


def _validate_iteration_baseline_bytes(root: Path, authority: dict[str, Any],
                                       raw: bytes) -> dict[str, Any]:
    if _digest(raw) != ITERATION_BASELINE_INPUT_SHA256:
        raise ValueError("single-native-iteration-baseline-changed")
    baseline = _json(raw, "single-native-iteration-baseline-invalid")
    required = {"schema", "policy_sha256", "previous_attempt", "retired_claims",
        "review_payload", "reviews"}
    previous = baseline.get("previous_attempt")
    review_payload = baseline.get("review_payload")
    if (set(baseline) != required
            or baseline.get("schema") != "genewhip.phase7-native-iteration-baseline.v1"
            or baseline.get("policy_sha256") != ITERATION_AUTH_SHA256
            or baseline.get("retired_claims") != authority["retired_claims"]
            or not isinstance(previous, dict)
            or previous.get("name") != "native-capture-retest-20261102T034752Z-repair/attempt-0003"
            or previous.get("status") != "fail"
            or previous.get("qualification_accepted") is not False
            or previous.get("remote_cleanup_status") != "confirmed"
            or previous.get("result_path") != "build/v02/native-capture-retest-20261102T034752Z-repair/operator/actual-result-reader.json"
            or previous.get("result_sha256") != "22f7368a07fa7be536bee797f4006de3f3625039fc5411c5a7f86741150e0de5"
            or not isinstance(review_payload, dict)
            or set(review_payload) != {"path", "payload_sha256", "sha256"}
            or review_payload.get("path") != "build/v02/native-capture-retest-20261102T034752Z-repair/operator/actual-result-review-payload-v2.json"
            or review_payload.get("payload_sha256") != "ddb80b6b842512529c18a9988b3d44470d409014482fc24938ee18f05f1ff8f0"
            or review_payload.get("sha256") != "9931be2065f74e2f0a8e01b7bb827dbdb0e40636a0fa74408b4ddf2076d2be16"):
        raise ValueError("single-native-iteration-baseline-identity-invalid")
    _, _, result_raw = _iteration_reference(root, {
        "path": previous.get("result_path"), "sha256": previous.get("result_sha256")})
    result = _json(result_raw, "single-native-iteration-baseline-result-invalid")
    if (result.get("status") != "fail" or result.get("diagnostic_status") != "fail"
            or result.get("qualification_accepted") is not False
            or result.get("remote_cleanup_status") != "confirmed"):
        raise ValueError("single-native-iteration-baseline-result-invalid")
    payload_path, payload_sha, payload_raw = _iteration_reference(root, {
        "path": review_payload.get("path"), "sha256": review_payload.get("sha256")})
    payload = _json(payload_raw, "single-native-iteration-baseline-review-payload-invalid")
    if (_digest(_canonical(payload)) != review_payload.get("payload_sha256")
            or payload.get("status") != "fail"
            or payload.get("qualification_accepted") is not False):
        raise ValueError("single-native-iteration-baseline-review-payload-invalid")
    _check_reviews(root, baseline.get("reviews"), SOURCE_ROLES,
        review_payload["payload_sha256"])
    _retired_claims_unchanged(root, authority)
    return baseline


def _validate_iteration_baseline(root: Path, authority: dict[str, Any]) -> tuple[Path, bytes]:
    baseline_path = Path(root) / ITERATION_BASELINE_REL
    try:
        _, raw = _safe_file(root, ITERATION_BASELINE_REL.as_posix(), cap=MAX_RECORD)
    except ValueError:
        raise ValueError("single-native-iteration-baseline-missing-or-invalid") from None
    _validate_iteration_baseline_bytes(root, authority, raw)
    return baseline_path, raw


def write_iteration_baseline(root: Path, input_path: Path | None = None,
                             input_sha256: str = ITERATION_BASELINE_INPUT_SHA256) -> dict[str, str]:
    """Validate the reviewed R8 baseline and preserve it as the iteration root's first record."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    authority = load_authority(root, ITERATION_AUTH_REL, ITERATION_AUTH_SHA256)
    source = ITERATION_BASELINE_INPUT_REL if input_path is None else Path(input_path)
    supplied = source if source.is_absolute() else root / source
    if Path(os.path.abspath(supplied)) != root / ITERATION_BASELINE_INPUT_REL:
        raise ValueError("single-native-iteration-baseline-input-invalid")
    _, raw = _safe_file(root, ITERATION_BASELINE_INPUT_REL.as_posix(), cap=MAX_RECORD)
    if _digest(raw) != input_sha256 or input_sha256 != ITERATION_BASELINE_INPUT_SHA256:
        raise ValueError("single-native-iteration-baseline-input-pin-invalid")
    # Validate every referenced claim, result, payload and review before copying the baseline.
    parsed = _validate_iteration_baseline_bytes(root, authority, raw)
    baseline_relative = ITERATION_BASELINE_REL
    target = root / baseline_relative
    if target.exists() or target.is_symlink():
        existing = _validate_iteration_baseline(root, authority)[1]
        if existing != raw:
            raise ValueError("single-native-iteration-baseline-conflict")
    else:
        _write_iteration_record(root, baseline_relative, parsed)
        stored = _safe_file(root, baseline_relative.as_posix(), cap=MAX_RECORD)[1]
        if stored != raw:
            raise ValueError("single-native-iteration-baseline-write-unconfirmed")
    return {"path": baseline_relative.as_posix(), "sha256": _digest(raw)}


def _sealed_iteration_record(body: dict[str, Any]) -> dict[str, Any]:
    return {**body, "record_sha256": _digest(_canonical(body))}


def _check_sealed_iteration_record(value: dict[str, Any], *, schema: str) -> dict[str, Any]:
    if value.get("schema") != schema or not isinstance(value.get("record_sha256"), str):
        raise ValueError("single-native-iteration-record-invalid")
    body = {key: item for key, item in value.items() if key != "record_sha256"}
    if _digest(_canonical(body)) != value["record_sha256"]:
        raise ValueError("single-native-iteration-record-digest-invalid")
    return body


def _read_iteration_json(root: Path, relative: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    _, raw = _safe_file(root, relative.as_posix(), cap=MAX_RECORD)
    return _json(raw, label), raw


def _native_prefix_process_cleanup_is_confirmed(report: Any) -> bool:
    """Require cleanup evidence for every launched child in a strict public report."""
    if not isinstance(report, dict):
        return False
    outer = report.get("outer_process")
    stages = report.get("stages")
    if (not isinstance(outer, dict) or not isinstance(stages, list) or len(stages) != 3
            or outer.get("status") not in ("completed", "failed", "timeout")
            or outer.get("cleanup") != "confirmed" or outer.get("bound_violation") is not False):
        return False
    processes = []
    first = stages[0]
    if not isinstance(first, dict):
        return False
    processes.append(first.get("process"))
    for stage in stages[1:]:
        if not isinstance(stage, dict) or not isinstance(stage.get("cases"), list):
            return False
        for case in stage["cases"]:
            if not isinstance(case, dict):
                return False
            processes.append(case.get("process"))
    for process in processes:
        if not isinstance(process, dict):
            return False
        if (process.get("status") not in ("completed", "failed", "timeout")
                or process.get("return_code") not in ("zero", "nonzero", "signaled")
                or process.get("cleanup") != "confirmed"
                or process.get("bound_violation") is not False):
            return False
    return True


def _validate_native_prefix_public_report(root: Path, report: Any,
        identity: dict[str, str], expected_clock: dict[str, Any]) -> None:
    """Reopen the strict runtime report contract and require settled process cleanup."""
    runtime_path = root / "scripts/evidence/v02_run.py"
    try:
        info = runtime_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_size > 1024 * 1024):
            raise ValueError("single-native-strict-report-validator-missing")
    except OSError:
        raise ValueError("single-native-strict-report-validator-missing") from None
    spec = importlib.util.spec_from_file_location("gw_single_native_result_runtime", runtime_path)
    if spec is None or spec.loader is None:
        raise ValueError("single-native-strict-report-validator-missing")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if runtime.validate_native_prefix_diagnostic_public(report, identity,
            expected_clock=expected_clock) is not True:
        raise ValueError("single-native-strict-report-consumer-rejected")
    if not _native_prefix_process_cleanup_is_confirmed(report):
        raise ValueError("single-native-process-cleanup-unconfirmed")


def _checked_terminal_assessment(root: Path, attempt_root_rel: Path) -> tuple[dict[str, Any], str]:
    context = _TERMINAL_VALIDATION_CONTEXT.get()
    owns_context = context is None
    if owns_context:
        context = {"memo": {}, "active": set()}
        token = _TERMINAL_VALIDATION_CONTEXT.set(context)
    try:
        canonical = Path(os.path.abspath(root)).resolve(strict=True)
        relative = Path(attempt_root_rel)
        if relative.is_absolute():
            relative = relative.relative_to(canonical)
        if any(part in ("", ".", "..") for part in relative.parts):
            raise ValueError("single-native-iteration-terminal-path-invalid")
        key = (canonical.as_posix(), relative.as_posix())
        if key in context["active"]:
            raise ValueError("single-native-iteration-terminal-lineage-cycle")
        cached = context["memo"].get(key)
        if cached is not None:
            body, terminal_sha = cached
            terminal_raw = _safe_file(canonical,
                (relative / "terminal-assessment.json").as_posix(), cap=MAX_RECORD)[1]
            if _digest(terminal_raw) != terminal_sha:
                raise ValueError("single-native-iteration-terminal-reference-stale")
            cache_refs = [(body.get("claim_path"), body.get("claim_sha256")),
                (body.get("dispatch_path"), body.get("dispatch_sha256")),
                (body.get("result_path"), body.get("result_sha256"))]
            for name in ("source_admission", "public_admission", "readiness", "report",
                         "job_clock_receipt", "workflow", "jobs"):
                ref = body.get(name)
                if isinstance(ref, dict):
                    cache_refs.append((ref.get("path"), ref.get("sha256")))
            for path, expected_sha in cache_refs:
                if not isinstance(path, str) or not isinstance(expected_sha, str):
                    raise ValueError("single-native-iteration-terminal-reference-stale")
                referenced_raw = _safe_file(canonical, path, cap=MAX_RECORD)[1]
                if _digest(referenced_raw) != expected_sha:
                    raise ValueError("single-native-iteration-terminal-reference-stale")
            return cached
        context["active"].add(key)
        try:
            result = _checked_terminal_assessment_uncached(canonical, relative)
            context["memo"][key] = result
            return result
        finally:
            context["active"].discard(key)
    finally:
        if owns_context:
            _TERMINAL_VALIDATION_CONTEXT.reset(token)


def _checked_terminal_assessment_uncached(root: Path, attempt_root_rel: Path) -> tuple[dict[str, Any], str]:
    relative = attempt_root_rel / "terminal-assessment.json"
    value, raw = _read_iteration_json(root, relative, label="single-native-iteration-terminal-invalid")
    body = _check_sealed_iteration_record(value, schema=ITERATION_TERMINAL_SCHEMA)
    match = ITERATION_ATTEMPT_RE.fullmatch(attempt_root_rel.name)
    required = {"schema", "policy_sha256", "attempt_root", "attempt_index",
        "preparation_revision", "status", "qualification_accepted", "remote_cleanup_status",
        "claim_path", "claim_sha256", "dispatch_path", "dispatch_sha256",
        "result_path", "result_sha256", "source_admission", "public_admission",
        "readiness", "report", "job_clock_receipt", "workflow", "jobs",
        "source_sha", "base_sha", "branch", "nonce", "run_id", "report_status",
        "assessed_at"}
    if (match is None or body.get("policy_sha256") != ITERATION_AUTH_SHA256
            or set(body) != required
            or body.get("attempt_root") != attempt_root_rel.as_posix()
            or body.get("attempt_index") != int(match.group(1))
            or body.get("status") not in ("pass", "fail")
            or body.get("qualification_accepted") is not False
            or body.get("remote_cleanup_status") != "confirmed"
            or not re.fullmatch(r"[0-9a-f]{64}", str(body.get("claim_sha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(body.get("dispatch_sha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(body.get("result_sha256", "")))
            or not isinstance(body.get("preparation_revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", str(body.get("source_sha", "")))
            or not re.fullmatch(r"[0-9a-f]{40}", str(body.get("base_sha", "")))
            or not re.fullmatch(r"[0-9a-f]{32}", str(body.get("nonce", "")))
            or not str(body.get("run_id", "")).isdigit()
            or body.get("report_status") != body.get("status")):
        raise ValueError("single-native-iteration-terminal-not-settled")
    claim_rel = attempt_root_rel / ITERATION_CLAIM_LEAF
    dispatch_rel = attempt_root_rel / "native-prefix-diagnostic/dispatch.json"
    result_rel = attempt_root_rel / "native-prefix-diagnostic/result.json"
    preparation_rel = Path(body["preparation_revision"])
    if (preparation_rel.parent != attempt_root_rel / "preparations"
            or ITERATION_REVISION_RE.fullmatch(preparation_rel.name) is None):
        raise ValueError("single-native-iteration-terminal-preparation-invalid")
    if (body.get("claim_path") != claim_rel.as_posix()
            or body.get("dispatch_path") != dispatch_rel.as_posix()
            or body.get("result_path") != result_rel.as_posix()):
        raise ValueError("single-native-iteration-terminal-reference-invalid")
    claim_raw = _safe_file(root, claim_rel.as_posix(), cap=MAX_RECORD)[1]
    dispatch_raw = _safe_file(root, dispatch_rel.as_posix(), cap=MAX_RECORD)[1]
    result_raw = _safe_file(root, result_rel.as_posix(), cap=MAX_RECORD)[1]
    claim = _json(claim_raw, "single-native-iteration-terminal-claim-invalid")
    dispatch = _json(dispatch_raw, "single-native-iteration-terminal-dispatch-invalid")
    result = _json(result_raw, "single-native-iteration-terminal-result-invalid")
    if (_digest(claim_raw) != body["claim_sha256"]
            or _digest(dispatch_raw) != body["dispatch_sha256"]
            or _digest(result_raw) != body["result_sha256"]):
        raise ValueError("single-native-iteration-terminal-reference-stale")
    fixed_refs = {
        "source_admission": preparation_rel / "source-admission.json",
        "public_admission": preparation_rel / "public-admission.json",
        "readiness": preparation_rel / "native-prefix-diagnostic-readiness.json",
        "workflow": attempt_root_rel / "native-prefix-diagnostic/workflow_run.json",
        "jobs": attempt_root_rel / "native-prefix-diagnostic/jobs.json"}
    artifacts: dict[str, dict[str, Any]] = {}
    for name, expected_path in fixed_refs.items():
        ref = body.get(name)
        if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or ref.get("path") != expected_path.as_posix()
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))):
            raise ValueError("single-native-iteration-terminal-reference-invalid")
        artifact_raw = _safe_file(root, expected_path.as_posix(), cap=MAX_RECORD)[1]
        if _digest(artifact_raw) != ref["sha256"]:
            raise ValueError("single-native-iteration-terminal-reference-stale")
        artifacts[name] = _json(artifact_raw,
            "single-native-iteration-terminal-artifact-invalid")
    variable_refs = {"report": result.get("report_path"),
        "job_clock_receipt": result.get("job_clock_receipt_path")}
    for name, expected_path in variable_refs.items():
        ref = body.get(name)
        if (not isinstance(expected_path, str) or not isinstance(ref, dict)
                or set(ref) != {"path", "sha256"} or ref.get("path") != expected_path
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))):
            raise ValueError("single-native-iteration-terminal-reference-invalid")
        artifact_raw = _safe_file(root, expected_path, cap=MAX_RECORD)[1]
        if _digest(artifact_raw) != ref["sha256"]:
            raise ValueError("single-native-iteration-terminal-reference-stale")
        artifacts[name] = _json(artifact_raw,
            "single-native-iteration-terminal-artifact-invalid")
    source_record = artifacts["source_admission"]
    public_record = artifacts["public_admission"]
    ready = artifacts["readiness"]
    workflow = artifacts["workflow"]
    jobs = artifacts["jobs"]
    report = artifacts["report"]
    public_candidate = public_record.get("candidate")
    report_identity = report.get("identity")
    rows = jobs.get("jobs")
    try:
        expected_claim = claim_payload(attempt_root=attempt_root_rel.as_posix(),
            source_sha=body["source_sha"], base_sha=body["base_sha"],
            branch=body["branch"], nonce=body["nonce"],
            started_at=dispatch["native_diagnostic_started_at"],
            deadline=dispatch["native_diagnostic_deadline"],
            readiness_sha256=body["readiness"]["sha256"],
            authority_sha256=ITERATION_AUTH_SHA256,
            preparation_revision=preparation_rel.as_posix())
    except (KeyError, TypeError, ValueError):
        raise ValueError("single-native-iteration-terminal-claim-invalid") from None
    expected_job_names = {"safety", "gameplay", "desktop", "package", "performance",
        "product-smoke", "phase7-fast", "v02-runtime", "extended", "attestation",
        "required-ci", "v02-benchmark-control", "v02-benchmark-recursion94",
        "v02-benchmark-tank-battle", "v02-package", "v02-release-qualification"}
    shared_admission_fields = ("authority_path", "authority_sha256", "scope_path",
        "scope_sha256", "attempt_root", "preparation_revision",
        "attempt_allocation_sha256", "started_at", "source_head", "source_pins",
        "source_payload_sha256", "source_reviews", "predecessor")
    if (not isinstance(public_candidate, dict) or not isinstance(report_identity, dict)
            or claim != expected_claim
            or claim.get("authority_sha256") != ITERATION_AUTH_SHA256
            or claim.get("attempt_root") != attempt_root_rel.as_posix()
            or claim.get("preparation_revision") != preparation_rel.as_posix()
            or claim.get("source_sha") != body["source_sha"]
            or claim.get("base_sha") != body["base_sha"]
            or claim.get("branch") != body["branch"]
            or claim.get("nonce") != body["nonce"]
            or claim.get("readiness_sha256") != body["readiness"]["sha256"]
            or dispatch.get("nonce") != body["nonce"]
            or dispatch.get("run_id") != int(body["run_id"])
            or dispatch.get("source_sha") != body["source_sha"]
            or dispatch.get("base_sha") != body["base_sha"]
            or dispatch.get("branch") != body["branch"]
            or dispatch.get("status") != "completed-assessment-required"
            or dispatch.get("qualification_accepted") is not False
            or dispatch.get("readiness_sha256") != body["readiness"]["sha256"]
            or dispatch.get("remote_cleanup_status") != "confirmed"
            or result.get("status") != body.get("status")
            or result.get("qualification_accepted") is not False
            or result.get("assessment_required") is not True
            or result.get("source_sha") != body["source_sha"]
            or result.get("branch") != body["branch"]
            or str(result.get("run_id")) != str(body["run_id"])
            or result.get("report_sha256") != body["report"]["sha256"]
            or result.get("job_clock_receipt_sha256") != body["job_clock_receipt"]["sha256"]
            or report.get("status") != body["status"]
            or report.get("qualification_accepted") is not False
            or report.get("schema") != "genewhip-phase7-native-prefix-diagnostic-v2"
            or report.get("diagnostic_only") is not True
            or report.get("fixture") != "recursion94"
            or report.get("case_order") != ["full-route", "withhold-first-plate"]
            or report_identity.get("source_sha") != body["source_sha"]
            or report_identity.get("head_sha") != body["source_sha"]
            or report_identity.get("base_sha") != body["base_sha"]
            or report_identity.get("run_id") != str(body["run_id"])
            or report_identity.get("run_attempt") != "1"
            or workflow.get("head_sha") != body["source_sha"]
            or workflow.get("head_branch") != body["branch"]
            or str(workflow.get("id")) != str(body["run_id"])
            or workflow.get("status") != "completed"
            or workflow.get("conclusion") != ("success" if body["status"] == "pass" else "failure")
            or workflow.get("display_title") != "Plan10 native prefix diagnostic " + body["nonce"]
            or not isinstance(rows, list) or len(rows) != 16
            or jobs.get("total_count") != 16
            or {row.get("name") for row in rows if isinstance(row, dict)} != expected_job_names
            or any(not isinstance(row, dict) or row.get("status") != "completed"
                or row.get("conclusion") != (workflow.get("conclusion")
                    if row.get("name") == "v02-runtime" else "skipped") for row in rows)
            or any(source_record.get(field) != public_record.get(field)
                for field in shared_admission_fields)
            or ready.get("source_head") != source_record.get("source_head")
            or public_candidate.get("public_head") != body["source_sha"]
            or public_candidate.get("public_base") != body["base_sha"]
            or ready.get("candidate_head") != body["source_sha"]):
        raise ValueError("single-native-iteration-terminal-reference-stale")
    clock = artifacts["job_clock_receipt"]
    job_projection = validate_job_clock_receipt(clock, claim_sha256=_digest(claim_raw),
        claim_nonce=body["nonce"], source_sha=body["source_sha"],
        run_id=str(body["run_id"]), run_attempt=1, repository="szTheory/genewhip",
        branch=body["branch"])
    _validate_native_prefix_public_report(root, report,
        {"source_sha": body["source_sha"], "head_sha": body["source_sha"],
            "base_sha": body["base_sha"], "run_id": str(body["run_id"]),
            "run_attempt": "1"},
        {"receipt_sha256": body["job_clock_receipt"]["sha256"],
            "collector_deadline_monotonic_ns": job_projection["collector_deadline_monotonic_ns"]})
    pins = public_record.get("source_pins")
    if not isinstance(pins, dict) or not pins:
        raise ValueError("single-native-iteration-terminal-admission-invalid")
    validate_admission(root, root / attempt_root_rel,
        root / fixed_refs["source_admission"], stage="source-preparation",
        source_head=source_record["source_head"], source_roster=set(pins),
        authority_path=ITERATION_AUTH_REL, authority_sha256=ITERATION_AUTH_SHA256,
        admission_sha256=body["source_admission"]["sha256"],
        _historical=True, _source_snapshot_only=True)
    validate_admission(root, root / attempt_root_rel,
        root / fixed_refs["public_admission"], stage="native-prefix-diagnostic",
        source_head=source_record["source_head"], source_roster=set(pins),
        authority_path=ITERATION_AUTH_REL, authority_sha256=ITERATION_AUTH_SHA256,
        admission_sha256=body["public_admission"]["sha256"],
        readiness_path=root / fixed_refs["readiness"],
        readiness_sha256=body["readiness"]["sha256"], _terminal_reopen=True,
        _historical=True, _source_snapshot_only=True)
    return body, _digest(raw)


def write_terminal_assessment(root: Path, attempt_root: Path) -> dict[str, str]:
    """Seal one fully reopened native result only after actual cleanup is confirmed."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    attempt = canonical_root(root, attempt_root)
    attempt_rel = attempt.relative_to(root)
    assessment = validate_result(root, attempt_root=attempt,
        authority_path=ITERATION_AUTH_REL)
    if (assessment.get("status") not in ("pass", "fail")
            or assessment.get("remote_cleanup_status") != "confirmed"
            or assessment.get("qualification_accepted") is not False):
        raise ValueError("single-native-iteration-terminal-result-not-settled")
    claim_rel = attempt_rel / ITERATION_CLAIM_LEAF
    dispatch_rel = attempt_rel / "native-prefix-diagnostic/dispatch.json"
    result_rel = attempt_rel / "native-prefix-diagnostic/result.json"
    claim_raw = _safe_file(root, claim_rel.as_posix(), cap=MAX_RECORD)[1]
    dispatch_raw = _safe_file(root, dispatch_rel.as_posix(), cap=MAX_RECORD)[1]
    result_raw = _safe_file(root, result_rel.as_posix(), cap=MAX_RECORD)[1]
    claim = _json(claim_raw, "single-native-iteration-terminal-claim-invalid")
    dispatch = _json(dispatch_raw, "single-native-iteration-terminal-dispatch-invalid")
    result = _json(result_raw, "single-native-iteration-terminal-result-invalid")
    match = ITERATION_ATTEMPT_RE.fullmatch(attempt_rel.name)
    preparation_rel = Path(claim.get("preparation_revision", ""))
    if (match is None or claim.get("attempt_root") != attempt_rel.as_posix()
            or preparation_rel.parent != attempt_rel / "preparations"
            or ITERATION_REVISION_RE.fullmatch(preparation_rel.name) is None):
        raise ValueError("single-native-iteration-terminal-claim-invalid")
    def reference(path: Path | str) -> dict[str, str]:
        relative = Path(path)
        if relative.is_absolute():
            relative = relative.relative_to(root)
        data = _safe_file(root, relative.as_posix(), cap=MAX_RECORD)[1]
        return {"path": relative.as_posix(), "sha256": _digest(data)}

    source_sha = claim["source_sha"]
    base_sha = claim["base_sha"]
    branch = claim["branch"]
    nonce = claim["nonce"]
    report_ref = reference(result["report_path"])
    job_clock_ref = reference(result["job_clock_receipt_path"])
    body = {"schema": ITERATION_TERMINAL_SCHEMA,
        "policy_sha256": ITERATION_AUTH_SHA256,
        "attempt_root": attempt_rel.as_posix(), "attempt_index": int(match.group(1)),
        "preparation_revision": preparation_rel.as_posix(),
        "status": assessment["status"], "qualification_accepted": False,
        "remote_cleanup_status": "confirmed",
        "claim_path": claim_rel.as_posix(), "claim_sha256": _digest(claim_raw),
        "dispatch_path": dispatch_rel.as_posix(), "dispatch_sha256": _digest(dispatch_raw),
        "result_path": result_rel.as_posix(), "result_sha256": _digest(result_raw),
        "source_admission": reference(preparation_rel / "source-admission.json"),
        "public_admission": reference(preparation_rel / "public-admission.json"),
        "readiness": reference(preparation_rel / "native-prefix-diagnostic-readiness.json"),
        "report": report_ref, "job_clock_receipt": job_clock_ref,
        "workflow": reference(attempt_rel / "native-prefix-diagnostic/workflow_run.json"),
        "jobs": reference(attempt_rel / "native-prefix-diagnostic/jobs.json"),
        "source_sha": source_sha, "base_sha": base_sha, "branch": branch,
        "nonce": nonce, "run_id": str(result["run_id"]),
        "report_status": assessment["status"],
        "assessed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    relative = attempt_rel / "terminal-assessment.json"
    _, raw = _write_iteration_record(root, relative, _sealed_iteration_record(body))
    _checked_terminal_assessment(root, attempt_rel)
    return {"path": relative.as_posix(), "sha256": _digest(raw)}


def _checked_preparation_terminal(root: Path, attempt_root_rel: Path,
                                  revision_root_rel: Path) -> tuple[dict[str, Any], str]:
    relative = revision_root_rel / "preparation-terminal.json"
    value, raw = _read_iteration_json(root, relative,
        label="single-native-iteration-preparation-terminal-invalid")
    body = _check_sealed_iteration_record(value, schema=ITERATION_PREPARATION_TERMINAL_SCHEMA)
    expected_keys = {"schema", "policy_sha256", "attempt_root", "preparation_revision",
        "status", "qualification_accepted", "dispatch_claim_absent", "reason", "source_head",
        "evidence_path", "evidence_sha256", "source_admission", "public_admission"}
    if body.get("status") == "source-ci-failed":
        expected_keys |= {"candidate_head", "pull_request", "pull_request_state", "merged",
            "required_ci_status", "required_ci_conclusion", "remote_cleanup_status",
            "source_ci_workflow", "source_ci_jobs", "source_ci_pull_request"}
    if (body.get("policy_sha256") != ITERATION_AUTH_SHA256
            or body.get("attempt_root") != attempt_root_rel.as_posix()
            or body.get("preparation_revision") != revision_root_rel.as_posix()
            or body.get("status") not in ("preparation-failed", "pre-publication-failed", "source-ci-failed")
            or body.get("qualification_accepted") is not False
            or body.get("dispatch_claim_absent") is not True
            or not isinstance(body.get("reason"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", str(body.get("source_head", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(body.get("evidence_sha256", "")))
            or set(body) != expected_keys):
        raise ValueError("single-native-iteration-preparation-not-retryable")
    if _lineage_entry_present(root, attempt_root_rel / ITERATION_CLAIM_LEAF):
        raise ValueError("single-native-iteration-preparation-claim-conflict")
    _, _, evidence = _iteration_reference(root, {"path": body.get("evidence_path"),
        "sha256": body.get("evidence_sha256")})
    try:
        Path(body["evidence_path"]).relative_to(revision_root_rel)
    except (KeyError, ValueError):
        raise ValueError("single-native-iteration-preparation-evidence-path-invalid") from None
    for name, filename in (("source_admission", "source-admission.json"),
                           ("public_admission", "public-admission.json")):
        ref = body.get(name)
        relative = revision_root_rel / filename
        if ref is None:
            if _lineage_entry_present(root, relative):
                raise ValueError("single-native-iteration-preparation-admission-reference-invalid")
            continue
        if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or ref.get("path") != relative.as_posix()
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))):
            raise ValueError("single-native-iteration-preparation-admission-reference-invalid")
        raw_admission = _safe_file(root, relative.as_posix(), cap=MAX_RECORD)[1]
        if _digest(raw_admission) != ref["sha256"]:
            raise ValueError("single-native-iteration-preparation-admission-stale")
    source, public = _validate_preparation_admissions(root, attempt_root_rel,
        revision_root_rel, body["source_head"], reopen_source=False)
    if body.get("status") in ("preparation-failed", "pre-publication-failed"):
        local = _json(evidence, "single-native-iteration-local-failure-evidence-invalid")
        if (set(local) != {"schema", "attempt_root", "preparation_revision", "source_head",
                "stage", "reason", "publication_attempted", "dispatch_claim_absent",
                "qualification_accepted"}
                or local.get("schema") != "genewhip.phase7-native-iteration-local-failure.v1"
                or local.get("attempt_root") != attempt_root_rel.as_posix()
                or local.get("preparation_revision") != revision_root_rel.as_posix()
                or local.get("source_head") != body.get("source_head")
                or local.get("publication_attempted") is not False
                or local.get("dispatch_claim_absent") is not True
                or local.get("qualification_accepted") is not False
                or local.get("reason") != body.get("reason")
                or not isinstance(local.get("stage"), str) or not local["stage"].strip()
                or (body.get("status") == "preparation-failed" and source is None)
                or (body.get("status") == "pre-publication-failed" and source is not None)):
            raise ValueError("single-native-iteration-local-failure-evidence-invalid")
        for side_effect in ("source-delivery.json", "hosted-delivery-journal.json"):
            if _lineage_entry_present(root, revision_root_rel / side_effect):
                raise ValueError("single-native-iteration-local-failure-side-effect-present")
        if _lineage_entry_present(root, attempt_root_rel / "native-prefix-diagnostic"):
            raise ValueError("single-native-iteration-local-failure-dispatch-present")
    if body.get("status") == "source-ci-failed":
        candidate_sha = body.get("candidate_head")
        pr_number = body.get("pull_request")
        if (not re.fullmatch(r"[0-9a-f]{40}", str(candidate_sha or ""))
                or not isinstance(pr_number, str) or not pr_number.isdigit()
                or body.get("pull_request_state") != "open"
                or body.get("merged") is not False
                or body.get("required_ci_status") != "COMPLETED"
                or body.get("required_ci_conclusion") != "FAILURE"
                or body.get("remote_cleanup_status") != "confirmed"):
            raise ValueError("single-native-iteration-preparation-not-retryable")
        ci = _json(evidence, "single-native-iteration-source-ci-evidence-invalid")
        public_raw = _safe_file(root,
            (revision_root_rel / "public-admission.json").as_posix(), cap=MAX_RECORD)[1]
        public = _json(public_raw, "single-native-iteration-preparation-public-invalid")
        if (public.get("candidate", {}).get("public_head") != candidate_sha
                or public.get("source_head") != body.get("source_head")):
            raise ValueError("single-native-iteration-preparation-candidate-invalid")
        _validate_source_ci_settlement(root, revision_root_rel, body, ci, public)
    return body, _digest(raw)


def _validate_preparation_admissions(root: Path, attempt_root_rel: Path,
        revision_root_rel: Path, source_head: str, *,
        reopen_source: bool = True) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    source_rel = revision_root_rel / "source-admission.json"
    public_rel = revision_root_rel / "public-admission.json"
    source = public = None
    if _lineage_entry_present(root, source_rel):
        source_raw = _safe_file(root, source_rel.as_posix(), cap=MAX_RECORD)[1]
        source = _json(source_raw, "single-native-iteration-preparation-source-invalid")
        if (source.get("source_head") != source_head
                or source.get("attempt_root") != attempt_root_rel.as_posix()
                or source.get("preparation_revision") != revision_root_rel.as_posix()
                or source.get("authority_sha256") != ITERATION_AUTH_SHA256):
            raise ValueError("single-native-iteration-preparation-source-invalid")
        source_pins = source.get("source_pins")
        if not isinstance(source_pins, dict) or not source_pins:
            raise ValueError("single-native-iteration-preparation-source-invalid")
        validate_admission(root, root / attempt_root_rel,
            root / source_rel, stage="source-preparation", source_head=source_head,
            source_roster=set(source_pins), authority_path=ITERATION_AUTH_REL,
            authority_sha256=ITERATION_AUTH_SHA256, admission_sha256=_digest(source_raw),
            _historical=True, _source_snapshot_only=not reopen_source)
    if _lineage_entry_present(root, public_rel):
        if source is None:
            raise ValueError("single-native-iteration-preparation-public-without-source")
        public_raw = _safe_file(root, public_rel.as_posix(), cap=MAX_RECORD)[1]
        public = _json(public_raw, "single-native-iteration-preparation-public-invalid")
        public_pins = public.get("source_pins")
        if not isinstance(public_pins, dict) or not public_pins:
            raise ValueError("single-native-iteration-preparation-public-invalid")
        validate_admission(root, root / attempt_root_rel, root / public_rel,
            stage="public-effects", source_head=source_head, source_roster=set(public_pins),
            authority_path=ITERATION_AUTH_REL, authority_sha256=ITERATION_AUTH_SHA256,
            admission_sha256=_digest(public_raw), _historical=True,
            _source_snapshot_only=not reopen_source)
    return source, public


def preparation_terminal_payload(*, attempt_root: str, preparation_revision: str,
        status: str, reason: str, source_head: str, evidence_path: str,
        evidence_sha256: str, candidate_head: str | None = None,
        pull_request: str | None = None,
        source_admission: dict[str, str] | None = None,
        public_admission: dict[str, str] | None = None,
        source_ci_workflow: dict[str, str] | None = None,
        source_ci_jobs: dict[str, str] | None = None,
        source_ci_pull_request: dict[str, str] | None = None) -> dict[str, Any]:
    """Build a no-claim preparation failure record that can authorize a new revision."""
    attempt_match = ITERATION_ATTEMPT_RE.fullmatch(Path(attempt_root).name)
    revision_match = ITERATION_REVISION_RE.fullmatch(Path(preparation_revision).name)
    if (attempt_match is None or Path(attempt_root).parent != ITERATION_POLICY_ROOT_REL
            or revision_match is None
            or Path(preparation_revision).parent != Path(attempt_root) / "preparations"
            or status not in ("preparation-failed", "pre-publication-failed", "source-ci-failed")
            or not re.fullmatch(r"[0-9a-f]{40}", source_head)
            or not isinstance(evidence_path, str)
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_sha256)
            or (source_admission is not None and (set(source_admission) != {"path", "sha256"}
                or not re.fullmatch(r"[0-9a-f]{64}", str(source_admission.get("sha256", "")))))
            or (public_admission is not None and (set(public_admission) != {"path", "sha256"}
                or not re.fullmatch(r"[0-9a-f]{64}", str(public_admission.get("sha256", "")))))):
        raise ValueError("single-native-iteration-preparation-terminal-identity-invalid")
    body = {"schema": ITERATION_PREPARATION_TERMINAL_SCHEMA,
        "policy_sha256": ITERATION_AUTH_SHA256, "attempt_root": attempt_root,
        "preparation_revision": preparation_revision, "status": status,
        "qualification_accepted": False, "dispatch_claim_absent": True,
        "reason": _iteration_reason(reason), "source_head": source_head,
        "evidence_path": evidence_path, "evidence_sha256": evidence_sha256,
        "source_admission": source_admission, "public_admission": public_admission}
    if status == "source-ci-failed":
        if (not isinstance(candidate_head, str)
                or not re.fullmatch(r"[0-9a-f]{40}", candidate_head)
                or not isinstance(pull_request, str) or not pull_request.isdigit()):
            raise ValueError("single-native-iteration-preparation-ci-identity-invalid")
        expected_ci_paths = {
            "source_ci_workflow": (Path(preparation_revision) / "ci-failure/workflow_run.json").as_posix(),
            "source_ci_jobs": (Path(preparation_revision) / "ci-failure/jobs.json").as_posix(),
            "source_ci_pull_request": (Path(preparation_revision) / "ci-failure/pull_request.json").as_posix()}
        ci_refs = {"source_ci_workflow": source_ci_workflow,
            "source_ci_jobs": source_ci_jobs, "source_ci_pull_request": source_ci_pull_request}
        if any(not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or ref.get("path") != expected_ci_paths[name]
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))
                for name, ref in ci_refs.items()):
            raise ValueError("single-native-iteration-preparation-ci-reference-invalid")
        body.update({"candidate_head": candidate_head, "pull_request": pull_request,
            "pull_request_state": "open", "merged": False,
            "required_ci_status": "COMPLETED", "required_ci_conclusion": "FAILURE",
            "remote_cleanup_status": "confirmed", **ci_refs})
    return body


def local_preparation_failure_payload(*, attempt_root: str, preparation_revision: str,
        source_head: str, stage: str, reason: str) -> dict[str, Any]:
    """Describe a local failure before any source publication or native claim."""
    attempt_match = ITERATION_ATTEMPT_RE.fullmatch(Path(attempt_root).name)
    revision_match = ITERATION_REVISION_RE.fullmatch(Path(preparation_revision).name)
    if (attempt_match is None or Path(attempt_root).parent != ITERATION_POLICY_ROOT_REL
            or revision_match is None
            or Path(preparation_revision).parent != Path(attempt_root) / "preparations"
            or not re.fullmatch(r"[0-9a-f]{40}", source_head)
            or not isinstance(stage, str) or not stage.strip() or len(stage) > 128):
        raise ValueError("single-native-iteration-local-failure-identity-invalid")
    return {"schema": "genewhip.phase7-native-iteration-local-failure.v1",
        "attempt_root": attempt_root, "preparation_revision": preparation_revision,
        "source_head": source_head, "stage": stage.strip(),
        "reason": _iteration_reason(reason), "publication_attempted": False,
        "dispatch_claim_absent": True, "qualification_accepted": False}


def write_preparation_terminal(root: Path, attempt_root: Path, preparation_revision: Path,
        *, status: str, reason: str, evidence_path: str,
        source_head: str | None = None,
        candidate_head: str | None = None, pull_request: str | None = None,
        source_ci_workflow: dict[str, str] | None = None,
        source_ci_jobs: dict[str, str] | None = None,
        source_ci_pull_request: dict[str, str] | None = None) -> dict[str, str]:
    """Seal evidence for a settled pre-claim failure; never create a retry or claim."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    attempt = canonical_root(root, attempt_root)
    attempt_rel = attempt.relative_to(root)
    revision = Path(preparation_revision)
    revision = revision if revision.is_absolute() else root / revision
    revision = Path(os.path.abspath(revision))
    if revision.parent != attempt / "preparations" or not revision.is_dir() or revision.is_symlink():
        raise ValueError("single-native-iteration-preparation-root-invalid")
    revision_rel = revision.relative_to(root)
    if (attempt_rel.parent != ITERATION_POLICY_ROOT_REL
            or _lineage_entry_present(root, attempt_rel / ITERATION_CLAIM_LEAF)):
        raise ValueError("single-native-iteration-preparation-claim-conflict")
    has_source = _lineage_entry_present(root, revision_rel / "source-admission.json")
    if source_head is None and has_source:
        source_raw = _safe_file(root,
            (revision_rel / "source-admission.json").as_posix(), cap=MAX_RECORD)[1]
        source = _json(source_raw, "single-native-iteration-preparation-source-invalid")
        source_head = source.get("source_head")
    source, public = (_validate_preparation_admissions(root, attempt_rel,
        revision_rel, source_head) if source_head is not None else (None, None))
    if source is None and status != "pre-publication-failed":
        raise ValueError("single-native-iteration-preparation-source-required")
    if not isinstance(source_head, str) or not re.fullmatch(r"[0-9a-f]{40}", source_head):
        raise ValueError("single-native-iteration-preparation-source-head-required")
    if status == "source-ci-failed":
        if public is None or public.get("candidate", {}).get("public_head") != candidate_head:
            raise ValueError("single-native-iteration-preparation-candidate-invalid")
    if status == "pre-publication-failed" and source is not None:
        raise ValueError("single-native-iteration-preparation-status-mismatch")
    try:
        Path(evidence_path).relative_to(revision_rel)
    except (TypeError, ValueError):
        raise ValueError("single-native-iteration-preparation-evidence-path-invalid") from None
    _, evidence_sha, evidence_raw = _iteration_reference(root,
        {"path": evidence_path,
            "sha256": _digest(_safe_file(root, evidence_path, cap=MAX_RECORD)[1])})
    evidence_value = (_json(evidence_raw, "single-native-iteration-source-ci-evidence-invalid")
        if status == "source-ci-failed" else None)
    if status == "source-ci-failed" and all(value is None for value in
            (source_ci_workflow, source_ci_jobs, source_ci_pull_request)):
        source_ci_workflow = evidence_value.get("source_ci_workflow")
        source_ci_jobs = evidence_value.get("source_ci_jobs")
        source_ci_pull_request = evidence_value.get("source_ci_pull_request")
    source_ref = (None if source is None else {"path": (revision_rel / "source-admission.json").as_posix(),
        "sha256": _digest(_safe_file(root,
            (revision_rel / "source-admission.json").as_posix(), cap=MAX_RECORD)[1])})
    public_ref = (None if public is None else {"path": (revision_rel / "public-admission.json").as_posix(),
        "sha256": _digest(_safe_file(root,
            (revision_rel / "public-admission.json").as_posix(), cap=MAX_RECORD)[1])})
    body = preparation_terminal_payload(attempt_root=attempt_rel.as_posix(),
        preparation_revision=revision_rel.as_posix(), status=status, reason=reason,
        source_head=source_head,
        evidence_path=evidence_path, evidence_sha256=evidence_sha,
        candidate_head=candidate_head, pull_request=pull_request,
        source_admission=source_ref, public_admission=public_ref,
        source_ci_workflow=source_ci_workflow, source_ci_jobs=source_ci_jobs,
        source_ci_pull_request=source_ci_pull_request)
    if status == "source-ci-failed":
        _validate_source_ci_settlement(root, revision_rel, body, evidence_value, public)
    _iteration_reference(root, {"path": evidence_path, "sha256": body["evidence_sha256"]})
    relative = revision_rel / "preparation-terminal.json"
    _, raw = _write_iteration_record(root, relative, _sealed_iteration_record(body))
    _checked_preparation_terminal(root, attempt_rel, revision_rel)
    return {"path": relative.as_posix(), "sha256": _digest(raw)}


def write_local_preparation_failure(root: Path, attempt_root: Path,
        preparation_revision: Path, *, source_head: str, stage: str,
        reason: str) -> dict[str, str]:
    """Record a local pre-publication failure without fabricating a hosted result."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    attempt = canonical_root(root, attempt_root)
    attempt_rel = attempt.relative_to(root)
    revision = Path(preparation_revision)
    revision = revision if revision.is_absolute() else root / revision
    revision = Path(os.path.abspath(revision))
    if revision.parent != attempt / "preparations" or not revision.is_dir() or revision.is_symlink():
        raise ValueError("single-native-iteration-preparation-root-invalid")
    revision_rel = revision.relative_to(root)
    if _lineage_entry_present(root, attempt_rel / ITERATION_CLAIM_LEAF):
        raise ValueError("single-native-iteration-preparation-claim-conflict")
    source, public = _validate_preparation_admissions(root, attempt_rel,
        revision_rel, source_head)
    for side_effect in ("source-delivery.json", "hosted-delivery-journal.json"):
        if _lineage_entry_present(root, revision_rel / side_effect):
            raise ValueError("single-native-iteration-local-failure-side-effect-present")
    if _lineage_entry_present(root, attempt_rel / "native-prefix-diagnostic"):
        raise ValueError("single-native-iteration-local-failure-dispatch-present")
    evidence = local_preparation_failure_payload(attempt_root=attempt_rel.as_posix(),
        preparation_revision=revision_rel.as_posix(), source_head=source_head,
        stage=stage, reason=reason)
    evidence_path = revision_rel / "local-preparation-failure.json"
    _, evidence_raw = _write_iteration_record(root, evidence_path, evidence)
    return write_preparation_terminal(root, attempt, revision,
        status="preparation-failed" if source is not None else "pre-publication-failed",
        reason=reason, source_head=source_head, evidence_path=evidence_path.as_posix())


def _validate_source_ci_settlement(root: Path, revision_root_rel: Path,
        body: dict[str, Any], evidence: dict[str, Any], public: dict[str, Any] | None) -> None:
    """Require actual completed candidate PR, workflow, and every job before rollover."""
    if not isinstance(public, dict) or not isinstance(public.get("candidate"), dict):
        raise ValueError("single-native-iteration-source-ci-candidate-invalid")
    expected_evidence_keys = {"schema", "candidate_head", "pull_request", "pull_request_state",
        "merged", "required_ci_status", "required_ci_conclusion", "remote_cleanup_status",
        "source_ci_workflow", "source_ci_jobs", "source_ci_pull_request"}
    if (not isinstance(evidence, dict) or set(evidence) != expected_evidence_keys
            or evidence.get("schema") != "genewhip.phase7-native-iteration-source-ci-failure.v1"):
        raise ValueError("single-native-iteration-source-ci-evidence-invalid")
    candidate = public["candidate"]
    candidate_sha = candidate.get("public_head")
    candidate_base = candidate.get("public_base")
    pr_number = body.get("pull_request")
    if (body.get("remote_cleanup_status") != "confirmed"
            or evidence.get("remote_cleanup_status") != "confirmed"
            or evidence.get("candidate_head") != candidate_sha
            or evidence.get("pull_request") != pr_number
            or evidence.get("pull_request_state") != "open"
            or evidence.get("merged") is not False
            or evidence.get("required_ci_status") != "COMPLETED"
            or evidence.get("required_ci_conclusion") != "FAILURE"):
        raise ValueError("single-native-iteration-source-ci-evidence-invalid")
    expected_paths = {
        "source_ci_workflow": revision_root_rel / "ci-failure/workflow_run.json",
        "source_ci_jobs": revision_root_rel / "ci-failure/jobs.json",
        "source_ci_pull_request": revision_root_rel / "ci-failure/pull_request.json"}
    records: dict[str, dict[str, Any]] = {}
    for name, relative in expected_paths.items():
        ref = body.get(name)
        if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or ref.get("path") != relative.as_posix()
                or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", "")))
                or evidence.get(name) != ref):
            raise ValueError("single-native-iteration-source-ci-reference-invalid")
        raw = _safe_file(root, relative.as_posix(), cap=MAX_RECORD)[1]
        if _digest(raw) != ref["sha256"]:
            raise ValueError("single-native-iteration-source-ci-reference-stale")
        records[name] = _json(raw, "single-native-iteration-source-ci-record-invalid")
    workflow = records["source_ci_workflow"]
    jobs = records["source_ci_jobs"]
    pull_request = records["source_ci_pull_request"]
    branch = "v0.2-source-" + str(candidate_sha)[:12]
    workflow_id = workflow.get("id")
    workflow_repo = workflow.get("repository")
    if (type(workflow_id) is not int or workflow_id <= 0
            or workflow.get("run_attempt") != 1
            or workflow.get("event") != "pull_request"
            or not isinstance(workflow.get("path"), str)
            or workflow["path"].split("@", 1)[0] != ".github/workflows/ci.yml"
            or not isinstance(workflow_repo, dict)
            or workflow_repo.get("full_name") != "szTheory/genewhip"
            or workflow.get("head_sha") != candidate_sha
            or workflow.get("head_branch") != branch
            or workflow.get("status") != "completed"
            or workflow.get("conclusion") != "failure"):
        raise ValueError("single-native-iteration-source-ci-workflow-unsettled")
    pr_head = pull_request.get("head") if isinstance(pull_request, dict) else None
    pr_base = pull_request.get("base") if isinstance(pull_request, dict) else None
    if (not isinstance(pr_head, dict) or not isinstance(pr_base, dict)
            or type(pull_request.get("number")) is not int
            or str(pull_request.get("number")) != pr_number
            or pull_request.get("state") != "open"
            or pull_request.get("merged") is not False
            or pr_head.get("sha") != candidate_sha
            or pr_head.get("ref") != branch
            or not isinstance(pr_head.get("repo"), dict)
            or pr_head["repo"].get("full_name") != "szTheory/genewhip"
            or pr_base.get("ref") != "main"
            or pr_base.get("sha") != candidate_base):
        raise ValueError("single-native-iteration-source-ci-pull-request-invalid")
    rows = jobs.get("jobs")
    if (jobs.get("total_count") != len(ITERATION_SOURCE_CI_JOBS)
            or not isinstance(rows, list) or len(rows) != len(ITERATION_SOURCE_CI_JOBS)
            or {row.get("name") for row in rows if isinstance(row, dict)} != ITERATION_SOURCE_CI_JOBS
            or any(not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] <= 0
                or row.get("run_id") != workflow_id or row.get("run_attempt") != 1
                or row.get("head_sha") != candidate_sha or row.get("head_branch") != branch
                or row.get("status") != "completed"
                or row.get("conclusion") not in ("success", "failure", "cancelled", "skipped",
                    "timed_out", "action_required", "neutral", "stale", "startup_failure")
                for row in rows)
            or len({row["id"] for row in rows if isinstance(row, dict)}) != len(ITERATION_SOURCE_CI_JOBS)):
        raise ValueError("single-native-iteration-source-ci-jobs-unsettled")


def _attempt_numbers(policy_root: Path) -> list[int]:
    numbers = []
    try:
        entries = list(policy_root.iterdir())
    except OSError:
        raise ValueError("single-native-iteration-policy-root-invalid") from None
    for entry in entries:
        match = ITERATION_ATTEMPT_RE.fullmatch(entry.name)
        if match is None:
            continue
        _owned_directory(entry, label="single-native-iteration-attempt-root-invalid")
        numbers.append(int(match.group(1)))
    numbers.sort()
    if numbers != list(range(1, len(numbers) + 1)):
        raise ValueError("single-native-iteration-attempt-sequence-invalid")
    return numbers


def _revision_numbers(preparations_root: Path) -> list[int]:
    numbers = []
    try:
        entries = list(preparations_root.iterdir())
    except OSError:
        raise ValueError("single-native-iteration-preparations-root-invalid") from None
    for entry in entries:
        match = ITERATION_REVISION_RE.fullmatch(entry.name)
        if match is None:
            continue
        _owned_directory(entry, label="single-native-iteration-revision-root-invalid")
        numbers.append(int(match.group(1)))
    numbers.sort()
    if numbers != list(range(1, len(numbers) + 1)):
        raise ValueError("single-native-iteration-revision-sequence-invalid")
    return numbers


def _iteration_allocation(root: Path, attempt_root_rel: Path,
                           revision_root_rel: Path | None = None) -> tuple[dict[str, Any], bytes]:
    if revision_root_rel is None:
        relative = attempt_root_rel / "allocation.json"
        schema = ITERATION_ALLOCATION_SCHEMA
    else:
        relative = revision_root_rel / "allocation.json"
        schema = ITERATION_PREPARATION_SCHEMA
    value, raw = _read_iteration_json(root, relative,
        label="single-native-iteration-allocation-invalid")
    body = _check_sealed_iteration_record(value, schema=schema)
    attempt_match = ITERATION_ATTEMPT_RE.fullmatch(attempt_root_rel.name)
    if (attempt_match is None or body.get("policy_sha256") != ITERATION_AUTH_SHA256
            or body.get("attempt_root") != attempt_root_rel.as_posix()
            or body.get("attempt_index") != int(attempt_match.group(1))
            or not isinstance(body.get("reason"), str)
            or not body["reason"].strip()
            or not isinstance(body.get("allocated_at"), str)):
        raise ValueError("single-native-iteration-allocation-invalid")
    if revision_root_rel is not None:
        revision_match = ITERATION_REVISION_RE.fullmatch(revision_root_rel.name)
        if (revision_match is None
                or body.get("preparation_revision") != revision_root_rel.as_posix()
                or body.get("revision_index") != int(revision_match.group(1))):
            raise ValueError("single-native-iteration-preparation-allocation-invalid")
    return body, raw


def allocate_attempt(root: Path, *, reason: str) -> dict[str, Any]:
    """Atomically allocate exactly the next runtime attempt under the standing policy."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    authority = load_authority(root, ITERATION_AUTH_REL, ITERATION_AUTH_SHA256)
    reason_text = _iteration_reason(reason)
    policy_root = _owned_directory(root / ITERATION_POLICY_ROOT_REL,
        label="single-native-iteration-policy-root-invalid")
    _validate_iteration_baseline(root, authority)
    numbers = _attempt_numbers(policy_root)
    attempt_index = numbers[-1] + 1 if numbers else 1
    predecessor_rel = (ITERATION_BASELINE_REL if attempt_index == 1 else
        ITERATION_POLICY_ROOT_REL / f"attempt-{attempt_index - 1:04d}" / "terminal-assessment.json")
    if attempt_index > 1:
        _checked_terminal_assessment(root,
            ITERATION_POLICY_ROOT_REL / f"attempt-{attempt_index - 1:04d}")
    else:
        _, baseline_raw = _validate_iteration_baseline(root, authority)
        if _digest(baseline_raw) != ITERATION_BASELINE_INPUT_SHA256:
            raise ValueError("single-native-iteration-baseline-invalid")
    predecessor_sha = _digest(_safe_file(root, predecessor_rel.as_posix(), cap=MAX_RECORD)[1])
    attempt_rel = ITERATION_POLICY_ROOT_REL / f"attempt-{attempt_index:04d}"
    attempt = root / attempt_rel
    try:
        attempt.mkdir(mode=0o700)
        (attempt / "preparations").mkdir(mode=0o700)
    except OSError:
        # Never remove a partial allocation: its name remains consumed and must be reconciled.
        raise ValueError("single-native-iteration-attempt-allocation-unconfirmed") from None
    body = {"schema": ITERATION_ALLOCATION_SCHEMA,
        "policy_sha256": ITERATION_AUTH_SHA256,
        "attempt_root": attempt_rel.as_posix(), "attempt_index": attempt_index,
        "reason": reason_text,
        "predecessor": {"path": predecessor_rel.as_posix(), "sha256": predecessor_sha},
        "allocated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    record = _sealed_iteration_record(body)
    _, raw = _write_iteration_record(root, attempt_rel / "allocation.json", record)
    return {"attempt_root": attempt, "attempt_root_rel": attempt_rel.as_posix(),
        "attempt_index": attempt_index, "allocation": record,
        "allocation_path": (attempt_rel / "allocation.json").as_posix(),
        "allocation_sha256": _digest(raw), "preparations_root": attempt / "preparations"}


def allocate_revision(root: Path, attempt_root: Path, *, reason: str) -> dict[str, Any]:
    """Allocate one immutable source/candidate preparation revision before the attempt claim."""
    root = Path(os.path.abspath(root)).resolve(strict=True)
    authority = load_authority(root, ITERATION_AUTH_REL, ITERATION_AUTH_SHA256)
    reason_text = _iteration_reason(reason)
    attempt = canonical_root(root, attempt_root)
    attempt_rel = attempt.relative_to(root)
    if attempt_rel.parent != ITERATION_POLICY_ROOT_REL:
        raise ValueError("single-native-iteration-attempt-root-invalid")
    attempt_body, attempt_raw = _iteration_allocation(root, attempt_rel)
    _validate_iteration_baseline(root, authority)
    attempt_index = int(ITERATION_ATTEMPT_RE.fullmatch(attempt_rel.name).group(1))
    if _attempt_numbers(root / ITERATION_POLICY_ROOT_REL)[-1:] != [attempt_index]:
        raise ValueError("single-native-iteration-attempt-not-current")
    if attempt_index == 1:
        expected_attempt_prior = {"path": ITERATION_BASELINE_REL.as_posix(),
            "sha256": _digest(_validate_iteration_baseline(root, authority)[1])}
    else:
        prior_attempt = ITERATION_POLICY_ROOT_REL / f"attempt-{attempt_index - 1:04d}"
        _, prior_terminal_sha = _checked_terminal_assessment(root, prior_attempt)
        expected_attempt_prior = {"path": (prior_attempt / "terminal-assessment.json").as_posix(),
            "sha256": prior_terminal_sha}
    if attempt_body.get("predecessor") != expected_attempt_prior:
        raise ValueError("single-native-iteration-attempt-predecessor-invalid")
    claim = attempt / ITERATION_CLAIM_LEAF
    if _lineage_entry_present(root, attempt_rel / ITERATION_CLAIM_LEAF):
        raise ValueError("single-native-iteration-claim-already-created")
    preparations = _owned_directory(attempt / "preparations",
        label="single-native-iteration-preparations-root-invalid")
    revisions = _revision_numbers(preparations)
    revision_index = revisions[-1] + 1 if revisions else 1
    if revision_index == 1:
        predecessor_rel = attempt_rel / "allocation.json"
        predecessor_raw = attempt_raw
    else:
        previous_revision = attempt_rel / "preparations" / f"revision-{revision_index - 1:04d}"
        _checked_preparation_terminal(root, attempt_rel, previous_revision)
        predecessor_rel = previous_revision / "preparation-terminal.json"
        predecessor_raw = _safe_file(root, predecessor_rel.as_posix(), cap=MAX_RECORD)[1]
    revision_rel = attempt_rel / "preparations" / f"revision-{revision_index:04d}"
    revision = root / revision_rel
    try:
        revision.mkdir(mode=0o700)
    except OSError:
        raise ValueError("single-native-iteration-revision-allocation-unconfirmed") from None
    body = {"schema": ITERATION_PREPARATION_SCHEMA,
        "policy_sha256": ITERATION_AUTH_SHA256,
        "attempt_root": attempt_rel.as_posix(),
        "attempt_index": attempt_index,
        "preparation_revision": revision_rel.as_posix(), "revision_index": revision_index,
        "attempt_allocation_sha256": _digest(attempt_raw),
        "reason": reason_text,
        "predecessor": {"path": predecessor_rel.as_posix(), "sha256": _digest(predecessor_raw)},
        "allocated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    record = _sealed_iteration_record(body)
    _, raw = _write_iteration_record(root, revision_rel / "allocation.json", record)
    return {"attempt_root": attempt, "attempt_root_rel": attempt_rel.as_posix(),
        "attempt_index": body["attempt_index"], "preparation_revision": revision,
        "preparation_revision_rel": revision_rel.as_posix(), "revision_index": revision_index,
        "attempt_allocation_sha256": _digest(attempt_raw),
        "preparation_allocation": record,
        "preparation_allocation_path": (revision_rel / "allocation.json").as_posix(),
        "preparation_allocation_sha256": _digest(raw),
        "predecessor_ref": {"path": (revision_rel / "allocation.json").as_posix(),
            "sha256": _digest(raw)}}


def validate_result(root: Path, *, attempt_root: Path | None = None,
                    authority_path: Path | None = None) -> dict[str, Any]:
    """Reopen one terminal diagnostic; missing or partial evidence remains UNKNOWN."""
    supplied = Path(os.path.abspath(root))
    iteration = (authority_path is not None
        and authority_sha256_for_path(authority_path) == ITERATION_AUTH_SHA256)
    if iteration:
        if attempt_root is None:
            raise ValueError("single-native-iteration-attempt-root-required")
        root_input = supplied
    else:
        if len(supplied.parts) >= len(ROOT_REL.parts) and supplied.parts[-len(ROOT_REL.parts):] == ROOT_REL.parts:
            root_input = Path(*supplied.parts[:-len(ROOT_REL.parts)])
        else:
            root_input = supplied
    root = root_input.resolve(strict=True)
    selected_authority_path = ITERATION_AUTH_REL if iteration else AUTH_REL
    selected_authority_sha = ITERATION_AUTH_SHA256 if iteration else AUTH_SHA256
    load_authority(root, authority_path or selected_authority_path, selected_authority_sha)
    def unknown(reason: str) -> dict[str, Any]:
        return {"schema": "genewhip.phase7-single-native-result-assessment.v1",
            "status": "unknown", "diagnostic_status": "unavailable",
            "qualification_accepted": False, "reason": reason}

    if root_input != root:
        return unknown("global-dispatch-claim-parent-invalid")

    if iteration:
        try:
            selected_attempt = canonical_root(root, attempt_root)
        except ValueError:
            return unknown("attempt-root-invalid")
        selected_attempt_rel = selected_attempt.relative_to(root)
        selected_claim_rel = selected_attempt_rel / ITERATION_CLAIM_LEAF
        if _lineage_entry_present(root, LOCAL_CLAIM_REL):
            return unknown("terminal-lineage-conflict")
        if _lineage_entry_present(root,
                selected_attempt_rel / "terminal-assessment.json"):
            try:
                closure, closure_sha = _checked_terminal_assessment(root, selected_attempt_rel)
                return {"schema": "genewhip.phase7-single-native-result-assessment.v1",
                    "status": closure["status"], "diagnostic_status": closure["status"],
                    "qualification_accepted": False, "run_id": str(closure["run_id"]),
                    "source_sha": closure["source_sha"], "run_attempt": "1",
                    "report_sha256": closure["report"]["sha256"],
                    "report_path": closure["report"]["path"],
                    "remote_cleanup_status": "confirmed",
                    "terminal_assessment_sha256": closure_sha,
                    "reason": "immutable-terminal-closure-reopened"}
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                return unknown("iteration-terminal-closure-invalid")
    else:
        try:
            _validated_claim_path(root, CLAIM_REL)
            _validated_claim_path(root, LOCAL_CLAIM_REL)
        except ValueError:
            return unknown("global-dispatch-claim-parent-invalid")
        if any(_lineage_entry_present(root, relative) for relative in (
                LOCAL_CLAIM_REL, PREVIOUS_ATTEMPT_REL / "native-prefix-diagnostic")):
            return unknown("terminal-lineage-conflict")
        selected_attempt_rel = ROOT_REL
        selected_claim_rel = CLAIM_REL
        selected_attempt = root / ROOT_REL
    attempt_path = root / selected_attempt_rel
    if attempt_path.is_symlink():
        return unknown("attempt-root-invalid")
    if not attempt_path.is_dir():
        return unknown("attempt-root-missing")
    try:
        attempt = selected_attempt
    except ValueError:
        return unknown("attempt-root-invalid")
    base = attempt / "native-prefix-diagnostic"

    dispatch_path = base / "dispatch.json"
    result_path = base / "result.json"
    download = base / "download"
    report_path = download / "native-prefix-diagnostic.json"
    job_clock_path = download / "native-prefix-job-clock.json"
    if (not dispatch_path.is_file() or dispatch_path.is_symlink()
            or not result_path.is_file() or result_path.is_symlink()
            or not download.is_dir() or download.is_symlink()
            or not report_path.is_file() or report_path.is_symlink()
            or not job_clock_path.is_file() or job_clock_path.is_symlink()):
        return unknown("terminal-artifact-missing")
    try:
        _, dispatch_raw = _safe_file(root, dispatch_path.relative_to(root).as_posix(), cap=65536)
        _, result_raw = _safe_file(root, result_path.relative_to(root).as_posix(), cap=65536)
        _, report_raw = _safe_file(root, report_path.relative_to(root).as_posix(), cap=65536)
        _, job_clock_raw = _safe_file(root, job_clock_path.relative_to(root).as_posix(), cap=65536)
        dispatch, result, report = (_json(dispatch_raw, "single-native-dispatch-invalid"),
            _json(result_raw, "single-native-result-invalid"),
            _json(report_raw, "single-native-report-invalid"))
        job_clock = _json(job_clock_raw, "single-native-job-clock-invalid")
        if sorted(item.name for item in download.iterdir()) != sorted(
                [report_path.name, job_clock_path.name]):
            return unknown("terminal-download-roster-invalid")
        expected_dispatch_keys = {"schema", "source_sha", "base_sha", "branch", "repository", "nonce", "requested_at",
            "started_at", "readiness_sha256", "qualification_accepted", "status", "dispatches",
            "native_diagnostic_started_at", "native_diagnostic_deadline", "qualification_started_at",
            "run_id", "clock_profile", "job_clock_receipt_sha256"}
        if iteration or "remote_cleanup_status" in dispatch:
            expected_dispatch_keys.add("remote_cleanup_status")
        start = dispatch.get("native_diagnostic_started_at")
        deadline = dispatch.get("native_diagnostic_deadline")
        try:
            started = __import__("datetime").datetime.fromisoformat(start.replace("Z", "+00:00"))
            ends = __import__("datetime").datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return unknown("claim-clock-invalid")
        if (set(dispatch) != expected_dispatch_keys
                or dispatch.get("schema") != "genewhip.phase7-native-prefix-diagnostic-dispatch.v1"
                or dispatch.get("dispatches") != 1 or dispatch.get("status") != "completed-assessment-required"
                or dispatch.get("qualification_accepted") is not False
                or dispatch.get("repository") != "szTheory/genewhip"
                or dispatch.get("clock_profile") != QUEUE_PROFILE
                or dispatch.get("job_clock_receipt_sha256") != _digest(job_clock_raw)
                or dispatch.get("branch") != "v0.2-source-" + str(dispatch.get("source_sha", ""))[:12]
                or not re.fullmatch(r"[0-9a-f]{40}", str(dispatch.get("source_sha", "")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(dispatch.get("base_sha", "")))
                or dispatch.get("started_at") != start or dispatch.get("qualification_started_at") != start
                or started.tzinfo is None or ends.tzinfo is None
                or ends != started + __import__("datetime").timedelta(seconds=5400)
                or ((iteration or "remote_cleanup_status" in dispatch)
                    and dispatch.get("remote_cleanup_status") != "confirmed")):
            return unknown("dispatch-claim-or-terminal-state-invalid")
        try:
            claim_anchor = _open_claim_anchor(root, selected_claim_rel)
            try:
                claim_raw = _verify_claim_at_anchor(claim_anchor)
            finally:
                _close_claim_anchor(claim_anchor)
        except ValueError as exc:
            if str(exc) == "single-native-claim-file-missing":
                return unknown("global-dispatch-claim-missing")
            return unknown("global-dispatch-claim-invalid")
        claim = _json(claim_raw, "single-native-global-claim-invalid")
        try:
            expected_claim = claim_payload(attempt_root=selected_attempt_rel.as_posix(),
                source_sha=dispatch["source_sha"], base_sha=dispatch["base_sha"],
                branch=dispatch["branch"], nonce=dispatch["nonce"],
                started_at=dispatch["native_diagnostic_started_at"],
                deadline=dispatch["native_diagnostic_deadline"],
                readiness_sha256=dispatch["readiness_sha256"],
                authority_sha256=selected_authority_sha,
                preparation_revision=(claim.get("preparation_revision") if iteration else None))
        except ValueError:
            return unknown("global-dispatch-claim-identity-invalid")
        if claim != expected_claim or claim.get("clock_profile") != QUEUE_PROFILE:
            return unknown("global-dispatch-claim-mismatch")
        try:
            rows = json.loads(_safe_file(root, (base / "jobs.json").relative_to(root).as_posix(), cap=MAX_RECORD)[1]).get("jobs")
            runtime_jobs = [row for row in rows if isinstance(row, dict) and row.get("name") == "v02-runtime"]
            if len(runtime_jobs) != 1:
                return unknown("native-job-clock-runtime-job-ambiguous")
            job = runtime_jobs[0]
            projection = validate_job_clock_receipt(job_clock, claim_sha256=_digest(claim_raw),
                claim_nonce=dispatch["nonce"], source_sha=dispatch["source_sha"],
                run_id=str(dispatch["run_id"]), run_attempt=1,
                repository="szTheory/genewhip", branch=dispatch["branch"])
        except (ValueError, TypeError, KeyError):
            return unknown("native-job-clock-receipt-invalid")
        if (job.get("id") != job_clock.get("job_id")
                or job.get("run_id") != int(dispatch["run_id"])
                or job.get("run_attempt") != 1 or job.get("status") != "completed"
                or job.get("head_sha") != dispatch["source_sha"]
                or job.get("head_branch") != dispatch["branch"]
                or job.get("started_at") != job_clock.get("job_started_at")):
            return unknown("native-job-clock-provider-join-invalid")
        expected_result_keys = {"schema", "status", "qualification_accepted", "assessment_required",
            "run_id", "source_sha", "run_attempt", "report_sha256", "report_path", "branch",
            "job_clock_receipt_sha256", "job_clock_receipt_path"}
        if (set(result) != expected_result_keys
                or result.get("schema") != "genewhip.phase7-native-prefix-diagnostic-result.v1"
                or result.get("qualification_accepted") is not False
                or result.get("assessment_required") is not True
                or result.get("report_sha256") != _digest(report_raw)
                or result.get("report_path") != report_path.relative_to(root).as_posix()
                or result.get("job_clock_receipt_sha256") != _digest(job_clock_raw)
                or result.get("job_clock_receipt_path") != job_clock_path.relative_to(root).as_posix()
                or str(result.get("run_id")) != str(dispatch.get("run_id"))
                or result.get("run_attempt") != "1"
                or result.get("source_sha") != dispatch.get("source_sha")
                or result.get("branch") != dispatch.get("branch")):
            return unknown("result-report-join-invalid")
        workflow_path, jobs_path = base / "workflow_run.json", base / "jobs.json"
        _, workflow_raw = _safe_file(root, workflow_path.relative_to(root).as_posix(), cap=MAX_RECORD)
        _, jobs_raw = _safe_file(root, jobs_path.relative_to(root).as_posix(), cap=MAX_RECORD)
        workflow, jobs = _json(workflow_raw, "single-native-workflow-invalid"), _json(jobs_raw, "single-native-jobs-invalid")
        expected_jobs = {"safety", "gameplay", "desktop", "package", "performance", "product-smoke", "phase7-fast",
            "v02-runtime", "extended", "attestation", "required-ci", "v02-benchmark-control",
            "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package", "v02-release-qualification"}
        rows = jobs.get("jobs")
        workflow_repository = workflow.get("repository")
        if (workflow.get("id") != int(dispatch["run_id"])
                or workflow.get("run_attempt") != 1 or workflow.get("event") != "workflow_dispatch"
                or not isinstance(workflow.get("path"), str)
                or workflow["path"].split("@", 1)[0] != ".github/workflows/ci.yml"
                or not isinstance(workflow_repository, dict)
                or workflow_repository.get("full_name") != "szTheory/genewhip"
                or workflow.get("head_sha") != dispatch["source_sha"]
                or workflow.get("head_branch") != dispatch["branch"]
                or workflow.get("status") != "completed"
                or workflow.get("conclusion") not in ("success", "failure")
                or workflow.get("display_title") != "Plan10 native prefix diagnostic " + dispatch["nonce"]
                or jobs.get("total_count") != 16 or not isinstance(rows, list) or len(rows) != 16
                or {row.get("name") for row in rows if isinstance(row, dict)} != expected_jobs
                or any(not isinstance(row, dict) or row.get("status") != "completed"
                    or row.get("conclusion") != (workflow.get("conclusion") if row.get("name") == "v02-runtime" else "skipped")
                    for row in rows)):
            return unknown("workflow-or-job-roster-join-invalid")
        if iteration:
            preparation_revision = Path(claim.get("preparation_revision", ""))
            try:
                if (preparation_revision.parent != selected_attempt_rel / "preparations"
                        or ITERATION_REVISION_RE.fullmatch(preparation_revision.name) is None):
                    return unknown("single-native-claim-preparation-invalid")
                cursor = root
                for part in preparation_revision.parts:
                    cursor = cursor / part
                    _owned_directory(cursor, label="single-native-claim-preparation-invalid")
                preparation = root / preparation_revision
            except ValueError:
                return unknown("single-native-claim-preparation-invalid")
        else:
            preparation = attempt
        admission_path = preparation / "public-admission.json"
        readiness_path = preparation / "native-prefix-diagnostic-readiness.json"
        admission_raw = _safe_file(root, admission_path.relative_to(root).as_posix(), cap=MAX_RECORD)[1]
        admission = _json(admission_raw, "single-native-terminal-admission-invalid")
        pins = admission.get("source_pins")
        if not isinstance(pins, dict) or not pins:
            return unknown("terminal-source-admission-invalid")
        validate_admission(root, selected_attempt_rel, admission_path,
            stage="native-prefix-diagnostic", source_head=admission.get("source_head"),
            source_roster=set(pins), authority_path=selected_authority_path,
            authority_sha256=selected_authority_sha,
            admission_sha256=_digest(admission_raw), readiness_path=readiness_path,
            readiness_sha256=dispatch.get("readiness_sha256"), _terminal_reopen=True,
            _historical=iteration)
        candidate = admission.get("candidate")
        expected_branch = ("v0.2-source-" + candidate.get("public_head", "")[:12]
            if isinstance(candidate, dict) else None)
        if (not isinstance(candidate, dict)
                or dispatch.get("source_sha") != candidate.get("public_head")
                or dispatch.get("base_sha") != candidate.get("public_base")
                or dispatch.get("branch") != expected_branch
                or claim.get("source_sha") != candidate.get("public_head")
                or claim.get("base_sha") != candidate.get("public_base")
                or claim.get("branch") != expected_branch
                or claim.get("attempt_root") != selected_attempt_rel.as_posix()):
            return unknown("dispatch-candidate-identity-mismatch")
        identity = {"source_sha": dispatch["source_sha"], "head_sha": dispatch["source_sha"],
            "base_sha": dispatch["base_sha"],
            "run_id": str(dispatch["run_id"]), "run_attempt": "1"}
        expected_clock = {"receipt_sha256": _digest(job_clock_raw),
            "collector_deadline_monotonic_ns": projection["collector_deadline_monotonic_ns"]}
        _validate_native_prefix_public_report(root, report, identity, expected_clock)
        if (not terminal_conclusion_matches(report.get("status"), workflow.get("conclusion"))
                or result.get("status") != report.get("status")):
            return unknown("diagnostic-status-mismatch")
        return {"schema": "genewhip.phase7-single-native-result-assessment.v1",
            "status": report["status"], "diagnostic_status": report["status"],
            "qualification_accepted": False, "run_id": str(dispatch["run_id"]),
            "source_sha": dispatch["source_sha"], "run_attempt": "1",
            "report_sha256": _digest(report_raw), "report_path": report_path.relative_to(root).as_posix(),
            "remote_cleanup_status": dispatch["remote_cleanup_status"] if iteration else
                dispatch.get("remote_cleanup_status", "confirmed"),
            "reason": "strict-terminal-report-reopened"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError):
        return unknown("terminal-evidence-invalid")


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-authority", action="store_true")
    parser.add_argument("--validate-result", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2] / ROOT_REL,
        help="repository root or exact attempt-0001 root")
    parser.add_argument("--attempt-root", type=Path,
        help="numbered iteration attempt root for --validate-result")
    parser.add_argument("--authority-path", type=Path,
        help="explicit authority contract path")
    args = parser.parse_args(argv)
    if args.validate_authority:
        selected = args.authority_path or AUTH_REL
        load_authority(args.root, selected, authority_sha256_for_path(selected))
        print("single-native-authority: valid")
        return 0
    if args.validate_result:
        print(json.dumps(validate_result(args.root, attempt_root=args.attempt_root,
            authority_path=args.authority_path), sort_keys=True))
        return 0
    parser.error("select --validate-authority or --validate-result")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
