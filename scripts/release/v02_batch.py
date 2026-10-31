#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow authorization and admission checks for the fresh Phase 7 batch."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable


AUTH_PATH = Path("build/v02/ci-continuation-20261031T124319Z/authorization.json")
AUTH_SHA256 = "51ea5e62bca6ad2cb153f060dfc97ff3c74b75eb2b36b55f7dccf48c5c780cbc"
POLICY_ROOT = AUTH_PATH.parent
SCOPE_PATH = Path("evidence/v02-execution.json")
SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"
OLD_CAMPAIGN_PATH = Path("build/v02/campaign15/campaign.json")
OLD_CAMPAIGN_SHA256 = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"
OLD_JOURNAL_PATH = Path("build/v02/campaign15/hosted-delivery-journal.json")
OLD_JOURNAL_SHA256 = "085a769ceefe2dbaae88b0fd911fb777213d37ff142c85b2ca9f9ac912a18826"
SCHEMA = "genewhip.phase7-fresh-batch-admission.v2"
MAX_AUTH_BYTES = 65536
MAX_ADMISSION_BYTES = 262144
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_REVIEW_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
FAILURE_FILENAME = "failure.json"
SOURCE_ROLES = {"code": "gsd-code-reviewer", "security": "gsd-security-auditor"}
CANDIDATE_ROLES = SOURCE_ROLES
DISPOSITIONS = {"routine-source-repair", "evidence-backed-infrastructure-retry"}
PREVIEW_REQUIRED_LANES = {"safety", "gameplay", "desktop", "package", "performance",
    "product-smoke", "phase7-fast", "required-ci"}
PREVIEW_CONDITIONAL_SKIPS = {"v02-runtime", "extended", "v02-benchmark-control",
    "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package",
    "v02-release-qualification", "attestation"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_review_payload(*, source_head: str, started_at: str, attempt_root: str,
                          attempt_index: int, predecessor: dict[str, Any],
                          disposition: str, source_pins: dict[str, str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "stage": "source-preparation",
        "authorization_sha256": AUTH_SHA256, "scope_sha256": SCOPE_SHA256,
        "batch_root": attempt_root, "attempt_index": attempt_index,
        "predecessor_sha256": _digest(_canonical(predecessor)),
        "disposition": disposition, "started_at": started_at,
        "source_head": source_head, "source_pins": dict(sorted(source_pins.items()))}


def candidate_review_payload(source_payload: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    return {**source_payload, "stage": "public-effects",
        "preparation_sha256": candidate["preparation_sha256"],
        "repository_policy_sha256": candidate["repository_policy_sha256"],
        "public_head": candidate["public_head"], "public_base": candidate["public_base"],
        "public_tree": candidate["public_tree"],
        "source_manifest_sha256": candidate["source_manifest_sha256"]}


def _safe_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(label)
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(label)
    return path


def _path(root: Path, value: Path) -> Path:
    candidate = root / value
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise ValueError("fresh-batch-path-outside-root") from None
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("fresh-batch-path-symlink")
    resolved = candidate.resolve(strict=True)
    root_resolved = root.resolve(strict=True)
    if root_resolved not in resolved.parents:
        raise ValueError("fresh-batch-path-outside-root")
    return resolved


def _resolve_no_symlink(root: Path, value: Path, *, label: str) -> Path:
    """Resolve a project path while rejecting symlinks in every existing component."""
    root_lexical = Path(os.path.abspath(root))
    candidate = value if value.is_absolute() else root_lexical / value
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root_lexical)
    except ValueError:
        raise ValueError(label) from None
    cursor = root_lexical
    for part in relative.parts:
        cursor = cursor / part
        try:
            if cursor.is_symlink():
                raise ValueError(label)
        except OSError:
            raise ValueError(label) from None
    resolved = candidate.resolve(strict=False)
    root_resolved = root.resolve(strict=True)
    if resolved == root_resolved or root_resolved not in resolved.parents:
        raise ValueError(label)
    return resolved


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _attempt_location(root: Path, admission_path: Path) -> tuple[Path, int, str]:
    policy_root = _path(root, POLICY_ROOT)
    admission = _resolve_no_symlink(root, admission_path,
                                    label="fresh-batch-admission-path-invalid")
    try:
        relative = admission.relative_to(policy_root)
    except ValueError:
        raise ValueError("fresh-batch-admission-path-invalid") from None
    if len(relative.parts) != 2 or relative.parts[1] not in (
            "source-admission.json", "public-admission.json"):
        raise ValueError("fresh-batch-admission-path-invalid")
    match = re.fullmatch(r"attempt-([0-9]{4})", relative.parts[0])
    if match is None or int(match.group(1)) < 1:
        raise ValueError("fresh-batch-attempt-namespace-invalid")
    return policy_root / relative.parts[0], int(match.group(1)), relative.parts[0]


def _read_reference(root: Path, reference: Any, *, label: str,
                    cap: int = MAX_ADMISSION_BYTES) -> tuple[dict[str, Any], bytes]:
    required = {"path", "sha256"}
    if not isinstance(reference, dict) or set(reference) != required:
        raise ValueError(label)
    relative = _safe_relative(reference.get("path"), label)
    path = _path(root, relative)
    raw = _read_regular(path, cap=cap, label=label)
    if not isinstance(reference.get("sha256"), str) or _digest(raw) != reference["sha256"]:
        raise ValueError(label)
    return _json_object(raw, label), raw


def _validate_current_target_reconciliation(root: Path, *, expected_root: str,
                                            cleanup: Any, failure: Any) -> None:
    label = "fresh-batch-current-target-reconciliation-invalid"
    required = {"schema", "confirmation_type", "original_cleanup", "pid", "pgid",
                "process_receipt", "snapshot"}
    if (not isinstance(cleanup, dict) or set(cleanup) != required
            or cleanup.get("schema") != "genewhip.phase7-current-target-reconciliation.v1"
            or cleanup.get("confirmation_type") != "post-failure-current-target-inactive"
            or cleanup.get("original_cleanup") != "unconfirmed"):
        raise ValueError(label)
    pid, pgid = cleanup.get("pid"), cleanup.get("pgid")
    if (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
            or isinstance(pgid, bool) or not isinstance(pgid, int) or pgid <= 0):
        raise ValueError(label)
    receipt_prefix = f"{expected_root}/coordinator-external-attempts/process-receipts/"
    snapshot_path = f"{expected_root}/monitor-failure/process-snapshot.json"
    receipt_ref, snapshot_ref = cleanup.get("process_receipt"), cleanup.get("snapshot")
    receipt_name = receipt_ref.get("path", "").removeprefix(receipt_prefix) \
        if isinstance(receipt_ref, dict) and isinstance(receipt_ref.get("path"), str) else ""
    if (not isinstance(receipt_ref, dict)
            or not receipt_ref.get("path", "").startswith(receipt_prefix)
            or re.fullmatch(r"[0-9a-f]{32}\.json", receipt_name) is None
            or not isinstance(snapshot_ref, dict) or snapshot_ref.get("path") != snapshot_path):
        raise ValueError(label)
    receipt, _ = _read_reference(root, receipt_ref, label=label)
    processes = receipt.get("processes")
    if (not isinstance(processes, list) or len(processes) != 1
            or not isinstance(processes[0], dict)):
        raise ValueError(label)
    row = processes[0]
    if (row.get("pid") != pid or row.get("pgid") != pgid
            or row.get("process_group_cleanup") != "unconfirmed"
            or row.get("cleanup_reason") != "cleanup-permission-denied"
            or row.get("cleanup_status_observation") != "not-observed"
            or row.get("bound_violation_reason") != "phase7-rss-observation-unavailable"):
        raise ValueError(label)
    snapshot, _ = _read_reference(root, snapshot_ref, label=label)
    target_ids = sorted({pid, pgid})
    row_count, validated_rows, row_cap = (snapshot.get("row_count_observed"),
        snapshot.get("validated_rows"), snapshot.get("row_cap"))
    observed_bytes, stdout_cap = snapshot.get("observed_bytes"), snapshot.get("stdout_cap_bytes")
    if (snapshot.get("schema") != "genewhip.original10-readonly-process-snapshot.v1"
            or snapshot.get("complete") is not True or snapshot.get("returncode") != 0
            or snapshot.get("reason") is not None or snapshot.get("matching_rows") != []
            or snapshot.get("signals_to_target_processes") is not False
            or snapshot.get("target_numeric_ids") != target_ids
            or any(isinstance(value, bool) or not isinstance(value, int)
                   for value in (row_count, validated_rows, row_cap, observed_bytes, stdout_cap))
            or row_cap <= 0 or row_cap > 4096 or row_count < 0 or row_count > row_cap
            or validated_rows != row_count or observed_bytes < 0 or stdout_cap <= 0
            or stdout_cap > 1024 * 1024 or observed_bytes > stdout_cap):
        raise ValueError(label)
    try:
        failure_time = _utc(failure.get("observed_at"))
        finished_time = _utc(snapshot.get("finished_at_utc"))
    except (AttributeError, ValueError):
        raise ValueError(label) from None
    if finished_time < failure_time:
        raise ValueError(label)


def _validate_predecessor(root: Path, authorization: dict[str, Any], *,
                          attempt_index: int, predecessor: Any) -> tuple[dict[str, Any], str]:
    required = {"attempt_index", "attempt_root", "failure", "journal",
        "terminal_observation", "repair_evidence", "cleanup_evidence", "source_admission", "disposition",
        "all_ci_terminal", "safety_status", "cleanup_status", "unknown_high_findings"}
    if not isinstance(predecessor, dict) or set(predecessor) != required:
        raise ValueError("fresh-batch-predecessor-shape-invalid")
    expected_index = attempt_index - 1
    if predecessor.get("attempt_index") != expected_index:
        raise ValueError("fresh-batch-predecessor-index-invalid")
    if predecessor.get("disposition") not in DISPOSITIONS:
        raise ValueError("fresh-batch-predecessor-disposition-invalid")
    if (predecessor.get("all_ci_terminal") is not True
            or predecessor.get("safety_status") != "clear"
            or predecessor.get("unknown_high_findings") is not False):
        raise ValueError("fresh-batch-predecessor-stop-condition")
    cleanup_status = predecessor.get("cleanup_status")
    cleanup_reference = predecessor.get("cleanup_evidence")
    cleanup_value = None
    if cleanup_status == "not-applicable":
        if cleanup_reference is not None:
            raise ValueError("fresh-batch-predecessor-cleanup-evidence-invalid")
    elif cleanup_status == "confirmed":
        cleanup_value, _ = _read_reference(root, cleanup_reference,
            label="fresh-batch-predecessor-cleanup-evidence-invalid")
        processes = cleanup_value.get("processes")
        if (not isinstance(processes, list) or not processes
                or any(not isinstance(row, dict) or row.get("cleanup_confirmed") is not True
                       for row in processes)):
            raise ValueError("fresh-batch-predecessor-cleanup-evidence-invalid")
    elif cleanup_status == "current-target-inactive":
        if attempt_index <= 1:
            raise ValueError("fresh-batch-predecessor-cleanup-evidence-invalid")
        cleanup_value, _ = _read_reference(root, cleanup_reference,
            label="fresh-batch-predecessor-cleanup-evidence-invalid")
    else:
        raise ValueError("fresh-batch-predecessor-stop-condition")
    if attempt_index == 1:
        expected = authorization.get("initial_predecessor")
        if not isinstance(expected, dict):
            raise ValueError("fresh-batch-initial-predecessor-invalid")
        expected_root = expected.get("attempt_root")
        for key in ("failure", "journal", "terminal_observation", "repair_evidence"):
            if predecessor.get(key) != expected.get(key):
                raise ValueError("fresh-batch-initial-predecessor-mismatch")
        if predecessor.get("source_admission") is not None:
            raise ValueError("fresh-batch-initial-predecessor-mismatch")
        if predecessor.get("cleanup_evidence") is not None:
            raise ValueError("fresh-batch-initial-predecessor-mismatch")
        expected_paths = {key: expected[key]["path"] for key in
            ("failure", "journal", "terminal_observation", "repair_evidence")}
    else:
        expected_root = (POLICY_ROOT / f"attempt-{expected_index:04d}").as_posix()
        source_ref = predecessor.get("source_admission")
        if not isinstance(source_ref, dict) or set(source_ref) != {"path", "sha256"}:
            raise ValueError("fresh-batch-predecessor-source-admission-invalid")
        if source_ref.get("path") != f"{expected_root}/source-admission.json":
            raise ValueError("fresh-batch-predecessor-source-admission-invalid")
        prior_admission, _ = _read_reference(root, source_ref,
            label="fresh-batch-predecessor-source-admission-invalid")
        _validate_prior_source_admission(root, prior_admission,
            expected_root=expected_root, expected_index=expected_index,
            authorization=authorization)
        _validate_predecessor(root, authorization, attempt_index=expected_index,
                              predecessor=prior_admission.get("predecessor"))
        expected_paths = {
            "failure": f"{expected_root}/{FAILURE_FILENAME}",
            "journal": f"{expected_root}/hosted-delivery-journal.json",
            "terminal_observation": f"{expected_root}/terminal-observation.json",
            "repair_evidence": f"{expected_root}/repair-evidence.json"}
        cleanup_ref = predecessor.get("cleanup_evidence")
        if predecessor.get("cleanup_status") == "confirmed":
            if (not isinstance(cleanup_ref, dict)
                    or cleanup_ref.get("path") != f"{expected_root}/cleanup-evidence.json"):
                raise ValueError("fresh-batch-predecessor-cleanup-evidence-invalid")
            expected_paths["cleanup_evidence"] = f"{expected_root}/cleanup-evidence.json"
        elif predecessor.get("cleanup_status") == "current-target-inactive":
            if (not isinstance(cleanup_ref, dict)
                    or cleanup_ref.get("path") != f"{expected_root}/cleanup-evidence.json"):
                raise ValueError("fresh-batch-predecessor-cleanup-evidence-invalid")
            expected_paths["cleanup_evidence"] = f"{expected_root}/cleanup-evidence.json"
    if predecessor.get("attempt_root") != expected_root:
        raise ValueError("fresh-batch-predecessor-root-invalid")
    terminal_value = None
    repair_value = None
    failure_value = None
    for key, expected_path in expected_paths.items():
        reference = predecessor.get(key)
        if not isinstance(reference, dict) or reference.get("path") != expected_path:
            raise ValueError("fresh-batch-predecessor-artifact-path-invalid")
        value, _ = _read_reference(root, reference,
                                   label="fresh-batch-predecessor-artifact-invalid")
        if key == "failure" and value.get("schema") != "genewhip.phase7-fresh-batch-failure.v1":
            raise ValueError("fresh-batch-predecessor-failure-invalid")
        if key == "failure":
            failure_value = value
        if key == "terminal_observation":
            terminal_value = value
            jobs = value.get("jobs")
            no_ci = (value.get("ci_dispatch_state") == "not-dispatched"
                     and value.get("source_preparation_terminal") is True
                     and jobs == [])
            jobs_terminal = (value.get("all_jobs_terminal") is True
                and isinstance(jobs, list) and bool(jobs)
                and all(isinstance(row, dict) and row.get("status") == "completed"
                    and row.get("conclusion") in ("success", "failure", "cancelled", "skipped")
                    for row in jobs))
            event = ("pull_request" if isinstance(value.get("pull_request"), dict)
                     else value.get("event"))
            expected_jobs = PREVIEW_REQUIRED_LANES | PREVIEW_CONDITIONAL_SKIPS
            if event == "push":
                expected_jobs.remove("attestation")
                expected_jobs.add("attestation")
            by_name = {row.get("name"): row for row in jobs
                       if isinstance(row, dict) and isinstance(row.get("name"), str)} \
                if isinstance(jobs, list) else {}
            roster_valid = (event in ("pull_request", "push")
                and len(by_name) == len(jobs) if isinstance(jobs, list) else False)
            if not no_ci:
                roster_valid = (roster_valid and set(by_name) == expected_jobs
                    and all(by_name[name].get("conclusion") in
                        ("success", "failure", "cancelled") for name in PREVIEW_REQUIRED_LANES)
                    and all(by_name[name].get("conclusion") in ("skipped", "cancelled")
                        for name in PREVIEW_CONDITIONAL_SKIPS - ({"attestation"} if event == "push" else set()))
                    and (event != "push" or by_name["attestation"].get("conclusion")
                         in ("success", "cancelled")))
            if (not (no_ci or jobs_terminal)
                    or (not no_ci and not roster_valid)
                    or value.get("safety_job_failed") is True
                    or any(row.get("name") == "safety" and row.get("conclusion") == "failure"
                           for row in jobs if isinstance(row, dict))
                    or value.get("qualification_accepted") is True
                    or not isinstance(value.get("full_qualification_dispatched"), bool)):
                raise ValueError("fresh-batch-predecessor-terminal-observation-invalid")
            if no_ci and value.get("full_qualification_dispatched") is not False:
                raise ValueError("fresh-batch-predecessor-terminal-observation-invalid")
            if value.get("full_qualification_dispatched") is True:
                qualification_run = value.get("qualification_run")
                if (not isinstance(qualification_run, dict)
                        or qualification_run.get("status") != "completed"
                        or qualification_run.get("conclusion") not in ("failure", "cancelled")):
                    raise ValueError("fresh-batch-predecessor-qualification-not-terminal")
            if attempt_index > 1 and not no_ci and (
                    value.get("safety_job_failed") is not False
                    or value.get("qualification_accepted") is not False):
                raise ValueError("fresh-batch-predecessor-terminal-classification-missing")
            if (predecessor.get("cleanup_status") == "current-target-inactive"
                    and value.get("local_monitor_safety_issue") is not True):
                raise ValueError("fresh-batch-predecessor-terminal-observation-invalid")
        if key == "repair_evidence":
            common_invalid = value.get("live_retry_authorized") is not False
            if predecessor.get("cleanup_status") == "current-target-inactive":
                if (not common_invalid and value.get("had_cleanup_issue") is True
                        and value.get("unresolved_current_safety_or_cleanup_issue") is False
                        and value.get("qualification_accepted") is False):
                    pass
                else:
                    raise ValueError("fresh-batch-predecessor-repair-evidence-invalid")
            elif (common_invalid or value.get("safety_or_cleanup_issue") is True
                    or attempt_index > 1 and value.get("safety_or_cleanup_issue") is not False
                    or attempt_index > 1 and value.get("qualification_accepted") is not False):
                raise ValueError("fresh-batch-predecessor-repair-evidence-invalid")
        if key == "repair_evidence":
            repair_value = value
        if key in ("terminal_observation", "repair_evidence"):
            if (predecessor.get("cleanup_status") == "not-applicable"
                    and attempt_index > 1
                    and value.get("cleanup_disposition") != "not-applicable"):
                raise ValueError("fresh-batch-predecessor-cleanup-classification-missing")
    if predecessor.get("cleanup_status") == "current-target-inactive":
        if not isinstance(terminal_value, dict) or not isinstance(repair_value, dict):
            raise ValueError("fresh-batch-current-target-reconciliation-invalid")
        _validate_current_target_reconciliation(root, expected_root=expected_root,
            cleanup=cleanup_value, failure=failure_value)
    if (isinstance(terminal_value, dict)
            and terminal_value.get("ci_dispatch_state") == "not-dispatched"
            and (not isinstance(repair_value, dict)
                or repair_value.get("ci_dispatch_state") != "not-dispatched"
                or repair_value.get("source_preparation_terminal") is not True)):
        raise ValueError("fresh-batch-predecessor-no-ci-settlement-invalid")
    predecessor_sha = _digest(_canonical(predecessor))
    return predecessor, predecessor_sha


def _claim_successor(root: Path, *, predecessor_sha256: str,
                     predecessor_record_sha256: str,
                     attempt_root: str, source_payload_sha256: str) -> Path:
    policy_root = _path(root, POLICY_ROOT)
    if not re.fullmatch(r"[0-9a-f]{64}", predecessor_sha256):
        raise ValueError("fresh-batch-successor-claim-invalid")
    claim_dir = policy_root / "successors"
    if claim_dir.is_symlink() or (claim_dir.exists() and not claim_dir.is_dir()):
        raise ValueError("fresh-batch-successor-claim-path-invalid")
    claim_dir.mkdir(mode=0o700, exist_ok=True)
    claim_path = claim_dir / f"{predecessor_sha256}.json"
    body = _canonical({"schema": "genewhip.phase7-successor-claim.v1",
        "predecessor_sha256": predecessor_sha256, "attempt_root": attempt_root,
        "predecessor_record_sha256": predecessor_record_sha256,
        "source_payload_sha256": source_payload_sha256}) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(claim_path, flags, 0o600)
    except FileExistsError:
        existing = _read_regular(claim_path, cap=MAX_AUTH_BYTES,
                                 label="fresh-batch-successor-claim-invalid")
        if existing != body:
            raise ValueError("fresh-batch-successor-already-claimed") from None
        return claim_path
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(claim_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            claim_path.unlink()
        except OSError:
            pass
        raise
    return claim_path


def _predecessor_identity_sha256(predecessor: dict[str, Any]) -> str:
    """Use immutable failed-attempt identity so metadata edits cannot mint a new claim."""
    failure = predecessor.get("failure")
    journal = predecessor.get("journal")
    value = {"authorization_sha256": AUTH_SHA256,
        "attempt_index": predecessor.get("attempt_index"),
        "attempt_root": predecessor.get("attempt_root"),
        "failure_sha256": failure.get("sha256") if isinstance(failure, dict) else None,
        "journal_sha256": journal.get("sha256") if isinstance(journal, dict) else None}
    return _digest(_canonical(value))


def _validate_prior_source_admission(root: Path, value: dict[str, Any], *,
                                     expected_root: str, expected_index: int,
                                     authorization: dict[str, Any]) -> None:
    required = {"schema", "status", "authorization_path", "authorization_sha256",
        "scope_path", "scope_sha256", "batch_root", "attempt_index", "attempt_root",
        "predecessor", "disposition", "started_at", "source_head", "source_pins",
        "source_payload_sha256", "source_reviews"}
    if (set(value) != required or value.get("schema") != SCHEMA
            or value.get("status") != "source-preparation"
            or value.get("authorization_path") != AUTH_PATH.as_posix()
            or value.get("authorization_sha256") != AUTH_SHA256
            or value.get("scope_path") != SCOPE_PATH.as_posix()
            or value.get("scope_sha256") != SCOPE_SHA256
            or value.get("batch_root") != expected_root
            or value.get("attempt_root") != expected_root
            or value.get("attempt_index") != expected_index
            or value.get("started_at") != authorization.get("started_at")
            or value.get("disposition") not in DISPOSITIONS
            or not isinstance(value.get("source_head"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["source_head"])
            or not isinstance(value.get("source_pins"), dict)
            or not value["source_pins"]):
        raise ValueError("fresh-batch-predecessor-source-admission-invalid")
    for path, digest in value["source_pins"].items():
        _safe_relative(path, "fresh-batch-predecessor-source-pins-invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("fresh-batch-predecessor-source-pins-invalid")
    predecessor = value.get("predecessor")
    if not isinstance(predecessor, dict):
        raise ValueError("fresh-batch-predecessor-source-admission-invalid")
    payload = source_review_payload(source_head=value["source_head"],
        started_at=value["started_at"], attempt_root=expected_root,
        attempt_index=expected_index, predecessor=predecessor,
        disposition=value["disposition"], source_pins=value["source_pins"])
    payload_sha = _digest(_canonical(payload))
    if value.get("source_payload_sha256") != payload_sha:
        raise ValueError("fresh-batch-predecessor-source-payload-invalid")
    reviews = value.get("source_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError("fresh-batch-predecessor-source-reviews-invalid")
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=payload_sha)
    claim_identity = _predecessor_identity_sha256(predecessor)
    claim_path = POLICY_ROOT / "successors" / f"{claim_identity}.json"
    claim = _read_regular(_path(root, claim_path), cap=MAX_AUTH_BYTES,
                          label="fresh-batch-predecessor-successor-claim-invalid")
    expected_claim = _canonical({"schema": "genewhip.phase7-successor-claim.v1",
        "predecessor_sha256": claim_identity, "attempt_root": expected_root,
        "predecessor_record_sha256": _digest(_canonical(predecessor)),
        "source_payload_sha256": payload_sha}) + b"\n"
    if claim != expected_claim:
        raise ValueError("fresh-batch-predecessor-successor-claim-invalid")


def _read_regular(path: Path, *, cap: int, label: str) -> bytes:
    try:
        info = path.lstat()
        if (not path.is_file() or path.is_symlink() or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > cap):
            raise ValueError(label)
        data = path.read_bytes()
    except (OSError, ValueError):
        raise ValueError(label) from None
    if len(data) > cap:
        raise ValueError(label)
    return data


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(label) from None
    if not isinstance(value, dict):
        raise ValueError(label)
    return value


def _frontmatter(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    result: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line or line.startswith("#"):
            continue
        if line[0].isspace() or ":" not in line:
            return {}
        key, value = line.split(":", 1)
        value = value.strip()
        if key != key.strip() or not value or key in result:
            return {}
        result[key] = value
    return result


def _check_review(root: Path, reference: Any, *, role: str,
                  payload_sha256: str) -> None:
    required = {"path", "sha256", "reviewer_role", "status", "payload_sha256"}
    if not isinstance(reference, dict) or set(reference) != required:
        raise ValueError("fresh-batch-review-reference-invalid")
    review_rel = _safe_relative(reference.get("path"), "fresh-batch-review-path-invalid")
    if not review_rel.as_posix().startswith(
            ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/"):
        raise ValueError("fresh-batch-review-path-invalid")
    review_path = _path(root, review_rel)
    raw = _read_regular(review_path, cap=MAX_REVIEW_BYTES,
                        label="fresh-batch-review-file-invalid")
    fields = _frontmatter(raw)
    if (not re.fullmatch(r"[0-9a-f]{64}", str(reference.get("sha256", "")))
            or _digest(raw) != reference["sha256"]
            or reference.get("reviewer_role") != role
            or reference.get("status") != "accepted"
            or reference.get("payload_sha256") != payload_sha256
            or fields.get("status") != "accepted"
            or fields.get("reviewer_role") != role
            or fields.get("payload_sha256") != payload_sha256):
        raise ValueError("fresh-batch-review-stale-or-rejected")


def _check_pins(root: Path, pins: Any, *, required_paths: set[str]) -> dict[str, str]:
    if not isinstance(pins, dict) or not required_paths.issubset(pins):
        raise ValueError("fresh-batch-source-pins-incomplete")
    checked: dict[str, str] = {}
    total = 0
    for name, expected in pins.items():
        relative = _safe_relative(name, "fresh-batch-source-pin-path-invalid")
        # The caller supplies the complete, independently enumerated publication
        # roster. This path check validates syntax and containment; filtering to a
        # guessed directory subset would silently omit workflow/docs assets.
        data = _read_regular(_path(root, relative), cap=MAX_SOURCE_BYTES,
                             label="fresh-batch-source-pin-file-invalid")
        total += len(data)
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise ValueError("fresh-batch-source-pins-over-limit")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("fresh-batch-source-pin-digest-invalid")
        actual = _digest(data)
        if actual != expected:
            raise ValueError("fresh-batch-source-pin-stale")
        checked[relative.as_posix()] = actual
    return checked


def _utc(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError("fresh-batch-clock-invalid")
    try:
        result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("fresh-batch-clock-invalid") from None
    if result.tzinfo is None:
        raise ValueError("fresh-batch-clock-invalid")
    return result.astimezone(datetime.timezone.utc)


def validate_batch(root: Path, authorization_path: Path, authorization_sha256: str,
                   admission_path: Path, admission_sha256: str, *, stage: str,
                   source_head: str, now: datetime.datetime,
                   scope_path: Path, journal_path: Path, publication_copy: Path,
                   preflight_path: Path, output_path: Path,
                   source_is_ancestor: Callable[[str, str], bool],
                   expected_source_paths: set[str]) -> dict[str, Any]:
    """Validate fixed authority and a review-bound source/candidate before effects.

    Admission JSON schema fields:
      schema, status, authorization_path, authorization_sha256, scope_path,
      scope_sha256, batch_root, attempt_index, attempt_root, predecessor,
      disposition, started_at, source_head, source_pins, source_payload_sha256,
      source_reviews{code,security}, candidate(optional).
    The predecessor contains attempt_index/root; exact failure, journal, terminal,
    repair and (when confirmed) cleanup-evidence references; source_admission for
    attempts after one; disposition; and terminal/safety/cleanup/new-high enums.
    Review refs contain path, sha256, reviewer_role, status and payload_sha256.
    Candidate fields: preparation_path, preparation_sha256, publication_path,
      repository_policy_path, repository_policy_sha256, public_head, public_base,
      public_tree, source_manifest_sha256, candidate_payload_sha256,
      candidate_reviews{code,security}.
    """
    root = Path(os.path.abspath(root)).resolve(strict=True)
    policy_root = _path(root, POLICY_ROOT)
    batch_root, attempt_index, attempt_name = _attempt_location(root, admission_path)
    if batch_root.parent != policy_root or batch_root.is_symlink() or not batch_root.is_dir():
        raise ValueError("fresh-batch-attempt-namespace-invalid")
    expected_auth = _path(root, AUTH_PATH)
    expected_scope = _path(root, SCOPE_PATH)
    expected_journal = batch_root / "hosted-delivery-journal.json"
    expected_publication = publication_copy if publication_copy.is_absolute() else root / publication_copy
    expected_preflight = preflight_path if preflight_path.is_absolute() else root / preflight_path
    expected_output = output_path if output_path.is_absolute() else root / output_path
    expected_admission = batch_root / (
        "source-admission.json" if stage == "source-preparation" else "public-admission.json")
    if stage not in ("source-preparation", "public-effects"):
        raise ValueError("fresh-batch-stage-invalid")
    if (authorization_path.is_symlink() or authorization_path.resolve(strict=False) != expected_auth
            or authorization_sha256 != AUTH_SHA256):
        raise ValueError("fresh-batch-authorization-path-or-pin-invalid")
    scope_resolved = _resolve_no_symlink(root, scope_path, label="fresh-batch-scope-path-invalid")
    journal_resolved = _resolve_no_symlink(root, journal_path, label="fresh-batch-journal-path-invalid")
    publication_resolved = _resolve_no_symlink(root, expected_publication,
                                               label="fresh-batch-publication-path-invalid")
    preflight_resolved = _resolve_no_symlink(root, expected_preflight,
                                             label="fresh-batch-preflight-path-invalid")
    output_resolved = _resolve_no_symlink(root, expected_output,
                                          label="fresh-batch-output-layout-invalid")
    if (scope_resolved != expected_scope or journal_resolved != expected_journal
            or batch_root not in publication_resolved.parents
            or batch_root not in preflight_resolved.parents
            or output_resolved == expected_auth
            or batch_root not in output_resolved.parents):
        raise ValueError("fresh-batch-output-layout-invalid")
    admission_resolved = _resolve_no_symlink(root, admission_path,
                                             label="fresh-batch-admission-path-invalid")
    if admission_resolved != expected_admission:
        raise ValueError("fresh-batch-admission-path-invalid")
    expected_output_resolved = output_resolved
    protected_inputs = (expected_admission, expected_auth, expected_scope, expected_journal)
    if stage == "public-effects":
        protected_inputs += (preflight_resolved,)
    if (_paths_overlap(expected_output_resolved, publication_resolved)
            or any(_paths_overlap(expected_output_resolved, protected) for protected in protected_inputs)
            or any(_paths_overlap(publication_resolved, protected) for protected in protected_inputs)):
        raise ValueError("fresh-batch-output-aliases-input")
    if expected_output_resolved.exists():
        raise ValueError("fresh-batch-output-already-exists")
    failure_path = batch_root / FAILURE_FILENAME
    if failure_path.exists() or failure_path.is_symlink():
        raise ValueError("fresh-batch-terminal-failure-present")
    auth_bytes = _read_regular(expected_auth, cap=MAX_AUTH_BYTES,
                               label="fresh-batch-authorization-invalid")
    if _digest(auth_bytes) != AUTH_SHA256:
        raise ValueError("fresh-batch-authorization-stale")
    authorization = _json_object(auth_bytes, "fresh-batch-authorization-invalid")
    scope_bytes = _read_regular(expected_scope, cap=MAX_AUTH_BYTES,
                                label="fresh-batch-scope-invalid")
    if _digest(scope_bytes) != SCOPE_SHA256:
        raise ValueError("fresh-batch-scope-stale")
    scope = _json_object(scope_bytes, "fresh-batch-scope-invalid")
    old_campaign = _read_regular(_path(root, OLD_CAMPAIGN_PATH), cap=MAX_AUTH_BYTES,
                                 label="fresh-batch-old-campaign-invalid")
    old_journal = _read_regular(_path(root, OLD_JOURNAL_PATH), cap=MAX_AUTH_BYTES,
                                label="fresh-batch-old-journal-invalid")
    if (_digest(old_campaign) != OLD_CAMPAIGN_SHA256
            or _digest(old_journal) != OLD_JOURNAL_SHA256):
        raise ValueError("fresh-batch-old-history-changed")
    historical_records = authorization.get("historical_records")
    if not isinstance(historical_records, list) or len(historical_records) != 6:
        raise ValueError("fresh-batch-historical-records-invalid")
    for reference in historical_records:
        _read_reference(root, reference, label="fresh-batch-historical-record-changed",
                        cap=MAX_AUTH_BYTES)
    if (authorization.get("schema") != "genewhip.phase7-continuing-ci-authorization.v1"
            or authorization.get("source_head") != "0baeedeab8aadbf09bb2c3a2726c2a05c45eea36"
            or authorization.get("source_fix_head") != "f18a30842ad73bb29de18a0fdcdba86ded292f19"
            or authorization.get("scope_path") != SCOPE_PATH.as_posix()
            or authorization.get("scope_sha256") != SCOPE_SHA256
            or authorization.get("ci_before_full_qualification") is not True
            or authorization.get("stop_on_failure") is not True
            or authorization.get("historical_risk_accepted") is not False
            or authorization.get("next_phase_authorized") is not False
            or authorization.get("ordinary_ci_retries_approved") is not True
            or authorization.get("resource_limits_unchanged") is not True
            or authorization.get("reviewed_public_updates_approved") is not True
            or authorization.get("safety_stop_required") is not True
            or authorization.get("failure_stop_scope") != "attempt"
            or authorization.get("package_cutoff") is None
            or authorization.get("global_cutoff") is None
            or authorization.get("repository") != "szTheory/genewhip"):
        raise ValueError("fresh-batch-authorization-identity-invalid")
    started_at = authorization.get("started_at")
    start = _utc(started_at)
    runtime_cutoff = _utc(authorization.get("runtime_cutoff"))
    package_cutoff = _utc(authorization.get("package_cutoff"))
    global_cutoff = _utc(authorization.get("global_cutoff"))
    expected_cutoffs = (start + datetime.timedelta(hours=18),
                        start + datetime.timedelta(hours=22),
                        start + datetime.timedelta(hours=24))
    if (runtime_cutoff, package_cutoff, global_cutoff) != expected_cutoffs:
        raise ValueError("fresh-batch-cutoff-identity-invalid")
    current = now.astimezone(datetime.timezone.utc)
    if current < start or current >= runtime_cutoff:
        raise ValueError("fresh-batch-runtime-window-expired-or-future")
    if (scope.get("qualification_batch", {}).get("wall_seconds") != 86400
            or scope.get("qualification_batch", {}).get("runtime_wall_seconds") != 64800
            or scope.get("qualification_batch", {}).get("package_wall_seconds") != 14400
            or scope.get("qualification_batch", {}).get("close_wall_seconds") != 7200):
        raise ValueError("fresh-batch-scope-budget-invalid")
    if (not isinstance(source_head, str) or not re.fullmatch(r"[0-9a-f]{40}", source_head)
            or not source_is_ancestor(authorization["source_head"], source_head)):
        raise ValueError("fresh-batch-source-head-not-authorized-descendant")
    if os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT") not in (None, started_at):
        raise ValueError("fresh-batch-environment-clock-conflict")

    admission_bytes = _read_regular(admission_path.resolve(strict=True), cap=MAX_ADMISSION_BYTES,
                                    label="fresh-batch-admission-invalid")
    if (not re.fullmatch(r"[0-9a-f]{64}", admission_sha256)
            or _digest(admission_bytes) != admission_sha256):
        raise ValueError("fresh-batch-admission-digest-invalid")
    admission = _json_object(admission_bytes, "fresh-batch-admission-invalid")
    expected_admission_keys = {"schema", "status", "authorization_path", "authorization_sha256",
        "scope_path", "scope_sha256", "batch_root", "attempt_index", "attempt_root",
        "predecessor", "disposition", "started_at", "source_head", "source_pins",
        "source_payload_sha256", "source_reviews"}
    if stage == "public-effects":
        expected_admission_keys.add("candidate")
    if (set(admission) != expected_admission_keys
            or admission.get("schema") != SCHEMA or admission.get("status") != stage
            or admission.get("authorization_path") != AUTH_PATH.as_posix()
            or admission.get("authorization_sha256") != AUTH_SHA256
            or admission.get("scope_path") != SCOPE_PATH.as_posix()
            or admission.get("scope_sha256") != SCOPE_SHA256
            or admission.get("batch_root") != batch_root.relative_to(root).as_posix()
            or admission.get("attempt_root") != batch_root.relative_to(root).as_posix()
            or admission.get("attempt_index") != attempt_index
            or admission.get("disposition") not in DISPOSITIONS
            or admission.get("started_at") != started_at
            or admission.get("source_head") != source_head):
        raise ValueError("fresh-batch-admission-identity-invalid")
    predecessor, predecessor_sha = _validate_predecessor(root, authorization,
        attempt_index=attempt_index, predecessor=admission.get("predecessor"))
    if not isinstance(admission.get("source_pins"), dict) or set(admission["source_pins"]) != expected_source_paths:
        raise ValueError("fresh-batch-source-pin-roster-stale")
    pins = _check_pins(root, admission.get("source_pins"), required_paths={
        "scripts/release/v02_batch.py", "scripts/release/v02_qualification.py",
        "tests/evidence/phase7_fresh_batch_contract.py", "scripts/ci/required-gate.sh"})
    source_payload = source_review_payload(source_head=source_head, started_at=started_at,
        attempt_root=batch_root.relative_to(root).as_posix(), attempt_index=attempt_index,
        predecessor=predecessor, disposition=admission["disposition"], source_pins=pins)
    source_payload_sha = _digest(_canonical(source_payload))
    if admission.get("source_payload_sha256") != source_payload_sha:
        raise ValueError("fresh-batch-source-review-payload-stale")
    reviews = admission.get("source_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError("fresh-batch-source-reviews-missing")
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=source_payload_sha)
    predecessor_evidence, _ = _read_reference(root, predecessor["repair_evidence"],
        label="fresh-batch-predecessor-repair-evidence-invalid")
    if admission["disposition"] == "routine-source-repair":
        if attempt_index == 1:
            changed_file_sha = predecessor_evidence.get("file_sha256")
            if (not isinstance(changed_file_sha, str)
                    or changed_file_sha not in pins.values()):
                raise ValueError("fresh-batch-source-repair-change-unproven")
        else:
            prior_ref = predecessor.get("source_admission")
            prior_admission, _ = _read_reference(root, prior_ref,
                label="fresh-batch-predecessor-source-admission-invalid")
            prior_pins = prior_admission.get("source_pins")
            if (not isinstance(prior_pins, dict)
                    or not any(pins.get(name) != digest for name, digest in prior_pins.items())):
                raise ValueError("fresh-batch-source-repair-change-unproven")
    elif predecessor_evidence.get("infrastructure_retry_reason") not in (
            "runner-transient", "observation-reconciliation"):
        raise ValueError("fresh-batch-infrastructure-retry-justification-required")

    if stage == "public-effects":
        candidate = admission.get("candidate")
        if not isinstance(candidate, dict):
            raise ValueError("fresh-batch-candidate-admission-missing")
        preparation_rel = _safe_relative(candidate.get("preparation_path"),
                                          "fresh-batch-preparation-path-invalid")
        policy_rel = _safe_relative(candidate.get("repository_policy_path"),
                                     "fresh-batch-policy-path-invalid")
        root_resolved = root.resolve(strict=True)
        expected_preflight_rel = preflight_resolved.relative_to(root_resolved)
        expected_publication_rel = publication_resolved.relative_to(root_resolved)
        if (preparation_rel != expected_preflight_rel
                or _safe_relative(candidate.get("publication_path"),
                    "fresh-batch-publication-path-invalid") != expected_publication_rel):
            raise ValueError("fresh-batch-candidate-layout-invalid")
        prep_bytes = _read_regular(_path(root, preparation_rel), cap=MAX_CANDIDATE_BYTES,
                                   label="fresh-batch-preparation-invalid")
        prep = _json_object(prep_bytes, "fresh-batch-preparation-invalid")
        policy_bytes = _read_regular(_path(root, policy_rel), cap=MAX_CANDIDATE_BYTES,
                                     label="fresh-batch-policy-invalid")
        policy = _json_object(policy_bytes, "fresh-batch-policy-invalid")
        policy_resolved = _path(root, policy_rel)
        if _paths_overlap(publication_resolved, policy_resolved):
            raise ValueError("fresh-batch-policy-overlaps-publication-candidate")
        publication = expected_publication.resolve(strict=False)
        if (candidate.get("preparation_sha256") != _digest(prep_bytes)
                or prep.get("status") != "prepared"
                or prep.get("source_identity", {}).get("private_git_head") != source_head
                or prep.get("publication_copy") != expected_publication_rel.as_posix()
                or prep.get("repository_preflight") != policy_rel.as_posix()
                or prep.get("public_identity", {}).get("head_sha") != candidate.get("public_head")
                or prep.get("public_identity", {}).get("base_sha") != candidate.get("public_base")
                or prep.get("public_identity", {}).get("tree_sha") != candidate.get("public_tree")
                or prep.get("source_manifest_sha256") != candidate.get("source_manifest_sha256")
                or prep.get("privacy", {}).get("status") != "pass"
                or prep.get("blockers") != []
                or candidate.get("repository_policy_sha256") != _digest(policy_bytes)
                or policy.get("repository_observations", {}).get("ready") is not True
                or policy.get("privacy_scan", {}).get("publication_copy", {}).get("status") != "pass"
                or not publication.is_dir() or publication.is_symlink()):
            raise ValueError("fresh-batch-candidate-or-policy-stale")
        expected_candidate_keys = {"preparation_path", "preparation_sha256", "publication_path",
            "repository_policy_path", "repository_policy_sha256", "public_head", "public_base",
            "public_tree", "source_manifest_sha256", "candidate_payload_sha256", "candidate_reviews"}
        if set(candidate) != expected_candidate_keys:
            raise ValueError("fresh-batch-candidate-admission-invalid")
        candidate_payload = candidate_review_payload(source_payload, candidate)
        candidate_payload_sha = _digest(_canonical(candidate_payload))
        if candidate.get("candidate_payload_sha256") != candidate_payload_sha:
            raise ValueError("fresh-batch-candidate-review-payload-stale")
        candidate_reviews = candidate.get("candidate_reviews")
        if not isinstance(candidate_reviews, dict) or set(candidate_reviews) != set(CANDIDATE_ROLES):
            raise ValueError("fresh-batch-candidate-reviews-missing")
        for key, role in CANDIDATE_ROLES.items():
            _check_review(root, candidate_reviews[key], role=role,
                          payload_sha256=candidate_payload_sha)
    claim_identity_sha = _predecessor_identity_sha256(predecessor)
    claim_path = _claim_successor(root, predecessor_sha256=claim_identity_sha,
        predecessor_record_sha256=predecessor_sha,
        attempt_root=batch_root.relative_to(root).as_posix(),
        source_payload_sha256=source_payload_sha)
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    os.environ["GENEWHIP_FRESH_BATCH_ROOT"] = batch_root.relative_to(root).as_posix()
    return {"authorization": authorization, "admission": admission,
            "started_at": started_at, "batch_root": batch_root,
            "attempt_index": attempt_index, "predecessor_sha256": predecessor_sha,
            "predecessor_identity_sha256": claim_identity_sha,
            "source_payload_sha256": source_payload_sha, "successor_claim": claim_path}


def require_output_under_batch(root: Path, value: Path, *, attempt_root: Path,
                               allow_existing: bool = False) -> Path:
    """Resolve a mutable batch output without allowing aliases or symlinks."""
    root = root.resolve(strict=True)
    resolved = _resolve_no_symlink(root, value, label="fresh-batch-output-symlink")
    attempt = _resolve_no_symlink(root, attempt_root,
                                  label="fresh-batch-attempt-namespace-invalid")
    policy_root = (root / POLICY_ROOT).resolve(strict=True)
    if (attempt.parent != policy_root or not re.fullmatch(r"attempt-[0-9]{4}", attempt.name)
            or int(attempt.name[-4:]) < 1):
        raise ValueError("fresh-batch-attempt-namespace-invalid")
    batch_root = attempt.resolve(strict=True)
    if resolved == batch_root or batch_root not in resolved.parents:
        raise ValueError("fresh-batch-output-outside-root")
    if not allow_existing and resolved.exists():
        raise ValueError("fresh-batch-output-already-exists")
    cursor = batch_root
    try:
        relative = resolved.relative_to(batch_root)
    except ValueError:
        raise ValueError("fresh-batch-output-outside-root") from None
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("fresh-batch-output-symlink")
    return resolved


def write_failure_sentinel(root: Path, *, attempt_root: Path, stage: str, reason: str,
                           observed_at: str) -> Path:
    """Durably consume this batch after a terminal CI/qualification failure."""
    if (stage not in ("preparation", "publication", "preview-ci", "qualification", "package")
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", reason)):
        raise ValueError("fresh-batch-failure-sentinel-input-invalid")
    _utc(observed_at)
    root = root.resolve(strict=True)
    batch_root = _resolve_no_symlink(root, attempt_root,
                                     label="fresh-batch-failure-root-invalid")
    policy_root = (root / POLICY_ROOT).resolve(strict=True)
    if (batch_root.parent != policy_root or not re.fullmatch(r"attempt-[0-9]{4}", batch_root.name)
            or int(batch_root.name[-4:]) < 1):
        raise ValueError("fresh-batch-failure-root-invalid")
    cursor = root
    for part in batch_root.relative_to(root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("fresh-batch-failure-root-invalid")
    batch_root.mkdir(parents=True, exist_ok=True)
    path = batch_root / FAILURE_FILENAME
    payload = {"schema": "genewhip.phase7-fresh-batch-failure.v1",
        "authorization_sha256": AUTH_SHA256, "stage": stage,
        "reason": reason, "observed_at": observed_at}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_fd = os.open(batch_root, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise ValueError("fresh-batch-failure-sentinel-write-failed") from None
    return path
