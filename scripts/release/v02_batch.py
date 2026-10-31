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


AUTH_PATH = Path("build/v02/batch-20261031T124319Z-retry1/authorization.json")
AUTH_SHA256 = "b9f6b7fe4b242ec866f04e8c36d5228b0f5af0cc19c78e0af6afc51514684def"
SCOPE_PATH = Path("evidence/v02-execution.json")
SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"
OLD_CAMPAIGN_PATH = Path("build/v02/campaign15/campaign.json")
OLD_CAMPAIGN_SHA256 = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"
OLD_JOURNAL_PATH = Path("build/v02/campaign15/hosted-delivery-journal.json")
OLD_JOURNAL_SHA256 = "085a769ceefe2dbaae88b0fd911fb777213d37ff142c85b2ca9f9ac912a18826"
PREVIOUS_AUTH_SHA256 = "ed71b6afb5c0defbeaba4e358c1f4dd635e1fb9ce0b2faf052c567551801ef1f"
PREVIOUS_BATCH_ROOT = Path("build/v02/batch-20261031T124319Z")
PREVIOUS_FAILURE_PATH = PREVIOUS_BATCH_ROOT / "failure.json"
PREVIOUS_FAILURE_SHA256 = "e85af97622af00d4968cb9cd2e1f000dfb0a3bab3f453d1f5ac7f7f315d1d95b"
PREVIOUS_JOURNAL_PATH = PREVIOUS_BATCH_ROOT / "hosted-delivery-journal.json"
PREVIOUS_JOURNAL_SHA256 = "f8af02bf4ae791a70552fcfd728200c6578db9466d88a9487fd07d2cb09baf70"
PREVIOUS_CI_RUN_ID = 41206052510
PREVIOUS_PULL_REQUEST = 26
SCHEMA = "genewhip.phase7-fresh-batch-admission.v1"
MAX_AUTH_BYTES = 65536
MAX_ADMISSION_BYTES = 262144
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_REVIEW_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
FAILURE_PATH = AUTH_PATH.parent / "failure.json"
SOURCE_ROLES = {"code": "gsd-code-reviewer", "security": "gsd-security-auditor"}
CANDIDATE_ROLES = SOURCE_ROLES


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_review_payload(*, source_head: str, started_at: str,
                          source_pins: dict[str, str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "stage": "source-preparation",
        "authorization_sha256": AUTH_SHA256, "scope_sha256": SCOPE_SHA256,
        "batch_root": AUTH_PATH.parent.as_posix(), "started_at": started_at,
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
      scope_sha256, batch_root, started_at, source_head, source_pins,
      source_payload_sha256, source_reviews{code,security}, candidate(optional).
    Review refs contain path, sha256, reviewer_role, status and payload_sha256.
    Candidate fields: preparation_path, preparation_sha256, publication_path,
      repository_policy_path, repository_policy_sha256, public_head, public_base,
      public_tree, source_manifest_sha256, candidate_payload_sha256,
      candidate_reviews{code,security}.
    """
    root = Path(os.path.abspath(root))
    batch_root = _path(root, AUTH_PATH.parent)
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
    failure_path = batch_root / FAILURE_PATH.name
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
    previous_failure = _read_regular(_path(root, PREVIOUS_FAILURE_PATH), cap=MAX_AUTH_BYTES,
        label="fresh-batch-previous-failure-invalid")
    previous_journal = _read_regular(_path(root, PREVIOUS_JOURNAL_PATH), cap=MAX_AUTH_BYTES,
        label="fresh-batch-previous-journal-invalid")
    expected_retry = {"authorization_sha256": PREVIOUS_AUTH_SHA256,
        "batch_root": PREVIOUS_BATCH_ROOT.as_posix(),
        "failed_ci_run_id": PREVIOUS_CI_RUN_ID,
        "failure_path": PREVIOUS_FAILURE_PATH.as_posix(),
        "failure_sha256": PREVIOUS_FAILURE_SHA256,
        "journal_path": PREVIOUS_JOURNAL_PATH.as_posix(),
        "journal_sha256": PREVIOUS_JOURNAL_SHA256,
        "limit_one_further_ci_first_attempt": True,
        "pull_request": PREVIOUS_PULL_REQUEST}
    if (_digest(previous_failure) != PREVIOUS_FAILURE_SHA256
            or _digest(previous_journal) != PREVIOUS_JOURNAL_SHA256):
        raise ValueError("fresh-batch-retry-predecessor-changed")
    if (authorization.get("schema") != "genewhip.phase7-ci-first-authorization.v1"
            or authorization.get("source_head") != "0baeedeab8aadbf09bb2c3a2726c2a05c45eea36"
            or authorization.get("previous_campaign_sha256") != OLD_CAMPAIGN_SHA256
            or authorization.get("previous_failed_journal_sha256") != OLD_JOURNAL_SHA256
            or authorization.get("retry_of") != expected_retry
            or authorization.get("scope_path") != SCOPE_PATH.as_posix()
            or authorization.get("scope_sha256") != SCOPE_SHA256
            or authorization.get("ci_before_full_qualification") is not True
            or authorization.get("stop_on_failure") is not True
            or authorization.get("historical_risk_accepted") is not False
            or authorization.get("next_phase_authorized") is not False):
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
        "scope_path", "scope_sha256", "batch_root", "started_at", "source_head",
        "source_pins", "source_payload_sha256", "source_reviews"}
    if stage == "public-effects":
        expected_admission_keys.add("candidate")
    if (set(admission) != expected_admission_keys
            or admission.get("schema") != SCHEMA or admission.get("status") != stage
            or admission.get("authorization_path") != AUTH_PATH.as_posix()
            or admission.get("authorization_sha256") != AUTH_SHA256
            or admission.get("scope_path") != SCOPE_PATH.as_posix()
            or admission.get("scope_sha256") != SCOPE_SHA256
            or admission.get("batch_root") != AUTH_PATH.parent.as_posix()
            or admission.get("started_at") != started_at
            or admission.get("source_head") != source_head):
        raise ValueError("fresh-batch-admission-identity-invalid")
    if not isinstance(admission.get("source_pins"), dict) or set(admission["source_pins"]) != expected_source_paths:
        raise ValueError("fresh-batch-source-pin-roster-stale")
    pins = _check_pins(root, admission.get("source_pins"), required_paths={
        "scripts/release/v02_batch.py", "scripts/release/v02_qualification.py",
        "tests/evidence/phase7_fresh_batch_contract.py", "scripts/ci/required-gate.sh"})
    source_payload = source_review_payload(source_head=source_head, started_at=started_at,
                                           source_pins=pins)
    source_payload_sha = _digest(_canonical(source_payload))
    if admission.get("source_payload_sha256") != source_payload_sha:
        raise ValueError("fresh-batch-source-review-payload-stale")
    reviews = admission.get("source_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError("fresh-batch-source-reviews-missing")
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=source_payload_sha)

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
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    return {"authorization": authorization, "admission": admission,
            "started_at": started_at, "batch_root": batch_root}


def require_output_under_batch(root: Path, value: Path, *, allow_existing: bool = False) -> Path:
    """Resolve a mutable batch output without allowing aliases or symlinks."""
    root = root.resolve(strict=True)
    resolved = _resolve_no_symlink(root, value, label="fresh-batch-output-symlink")
    batch_root = (root / AUTH_PATH.parent).resolve(strict=True)
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


def write_failure_sentinel(root: Path, *, stage: str, reason: str,
                           observed_at: str) -> Path:
    """Durably consume this batch after a terminal CI/qualification failure."""
    if (stage not in ("preparation", "publication", "preview-ci", "qualification", "package")
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", reason)):
        raise ValueError("fresh-batch-failure-sentinel-input-invalid")
    _utc(observed_at)
    root = root.resolve(strict=True)
    batch_root = root / AUTH_PATH.parent
    cursor = root
    for part in AUTH_PATH.parent.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("fresh-batch-failure-root-invalid")
    batch_root.mkdir(parents=True, exist_ok=True)
    path = batch_root / FAILURE_PATH.name
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
