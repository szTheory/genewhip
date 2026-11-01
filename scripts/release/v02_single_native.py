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
from typing import Any


AUTH_REL = Path("build/v02/native-queue-window-20261101T182756Z/authorization-contract.json")
AUTH_SHA256 = "4478ba94764a30b33f9ba05b29b1efbb650cb0cef2015dab7c0f424de0764f7c"
AUTHORITY_CONTRACT = {
    "approval_observed_at": "2026-11-01T18:27:56+00:00",
    "authority_evidence_kind": "Private conversation evidence and independent scope review; no quotation is included in public fixtures.",
    "authority_evidence_sha256": "a35580a2be6bc8a82ea43eb0aa5127dc51f95ad5cf84ec51254df72a8094e388",
    "authorization_basis": "User approved one queue-aware hosted native prefix diagnostic:5400second overall controller including queue,2700second actual job including setup, unchanged workload limits. Implementation, reviewed local preparation and required exact-source PR CI are in scope.",
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
LEGACY_ROOT_REL = AUTH_REL.parent / "attempt-0001"
RETIRED_ROOT_REL = Path("build/v02/native-prefix-one-shot-20261101T112701Z/attempt-0001")
ROOT_REL = AUTH_REL.parent / "attempt-0003"
CLAIM_REL = AUTH_REL.parent / "native-dispatch-claim.json"
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
        nonce: str, started_at: str, deadline: str, readiness_sha256: str) -> dict[str, Any]:
    """Construct the exact immutable one-shot claim recorded at dispatch boundary."""
    if (attempt_root != ROOT_REL.as_posix()
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
    return {"schema": "genewhip.phase7-single-native-dispatch-claim.v1",
        "authority_sha256": AUTH_SHA256, "attempt_root": attempt_root,
        "clock_profile": "native-prefix-queue-v1",
        "source_sha": source_sha, "base_sha": base_sha, "branch": branch,
        "nonce": nonce, "started_at": started_at, "deadline": deadline,
        "readiness_sha256": readiness_sha256, "qualification_started_at": started_at,
        "dispatches": 1, "qualification_accepted": False}


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
            or (attempt / "failure.json").exists() or (attempt / "failure.json").is_symlink()):
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
    if candidate != root / ROOT_REL:
        raise ValueError("single-native-attempt-root-invalid")
    cursor = root
    for part in ROOT_REL.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("single-native-attempt-root-invalid")
    if not candidate.is_dir():
        raise ValueError("single-native-attempt-root-missing")
    return candidate.resolve(strict=True)


def validate_route_paths(root: Path, paths: list[Path | None], *,
                         outputs: list[Path | None] | tuple[Path | None, ...] = ()) -> None:
    """Require consumed paths to be unique and output targets to be genuinely new."""
    root = Path(os.path.abspath(root))
    attempt = root / ROOT_REL
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
        for part in ROOT_REL.parts + relative.parts:
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
        for part in ROOT_REL.parts + relative.parts:
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


def write_failure(root: Path, *, stage: str, reason: str) -> Path:
    """Write an exclusive fail-closed marker after a validated route fails."""
    attempt = canonical_root(root, ROOT_REL)
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


def load_authority(root: Path, authority_path: Path | None = None,
                   authority_sha256: str | None = None) -> dict[str, Any]:
    root = Path(os.path.abspath(root)).resolve(strict=True)
    expected = root / AUTH_REL
    supplied = expected if authority_path is None else (
        authority_path if authority_path.is_absolute() else root / authority_path)
    if Path(os.path.abspath(supplied)) != expected or supplied.is_symlink():
        raise ValueError("single-native-authority-path-invalid")
    _, raw = _safe_file(root, AUTH_REL.as_posix(), cap=65536)
    if _digest(raw) != AUTH_SHA256 or authority_sha256 != AUTH_SHA256:
        raise ValueError("single-native-authority-pin-invalid")
    value = _json(raw, "single-native-authority-invalid")
    if (value.get("schema") != "genewhip.phase7-single-native-authorization.v1"
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
                   authority_sha256: str = AUTH_SHA256) -> dict[str, Any]:
    return {"schema": SCHEMA, "stage": "source-preparation", "authority_sha256": authority_sha256,
        "scope_sha256": SCOPE_SHA256, "attempt_root": attempt_root, "started_at": started_at,
        "source_head": source_head, "source_pins": dict(sorted(source_pins.items())),
        "predecessor_sha256": predecessor_sha256}


def candidate_payload(source: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    return {"schema": SCHEMA, "stage": "public-effects", "source_payload_sha256": _digest(_canonical(source)),
        "preparation_sha256": candidate["preparation_sha256"],
        "repository_policy_sha256": candidate["repository_policy_sha256"],
        "public_head": candidate["public_head"], "public_base": candidate["public_base"],
        "public_tree": candidate["public_tree"], "source_manifest_sha256": candidate["source_manifest_sha256"]}


def validate_admission(root: Path, attempt_root: Path, admission_path: Path, *, stage: str,
                       source_head: str, source_roster: set[str],
                       authority_path: Path | None = None, authority_sha256: str | None = None,
                       admission_sha256: str | None = None,
                       readiness_path: Path | None = None, readiness_sha256: str | None = None,
                       _terminal_reopen: bool = False) -> dict[str, Any]:
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
    root = Path(os.path.abspath(root)).resolve(strict=True)
    if stage == "native-prefix-diagnostic" and not _terminal_reopen:
        claim_path = root / CLAIM_REL
        legacy_claim = root / LEGACY_ROOT_REL / "native-prefix-diagnostic"
        retired_claim = root / RETIRED_ROOT_REL / "native-prefix-diagnostic"
        if (claim_path.exists() or claim_path.is_symlink()
                or legacy_claim.exists() or legacy_claim.is_symlink()
                or retired_claim.exists() or retired_claim.is_symlink()):
            raise ValueError("single-native-one-shot-already-claimed")
    attempt = canonical_root(root, attempt_root)
    failure = attempt / "failure.json"
    if failure.exists() or failure.is_symlink():
        raise ValueError("single-native-failure-latch-present")
    claim = attempt / "native-prefix-diagnostic"
    if stage == "native-prefix-diagnostic":
        if _terminal_reopen:
            if claim.is_symlink() or not claim.is_dir():
                raise ValueError("single-native-terminal-claim-invalid")
        elif claim.exists() or claim.is_symlink():
            raise ValueError("single-native-one-shot-already-claimed")
    elif _terminal_reopen:
        raise ValueError("single-native-terminal-stage-invalid")
    auth = load_authority(root, authority_path, authority_sha256)
    path = admission_path if admission_path.is_absolute() else root / admission_path
    expected = attempt / ("source-admission.json" if stage == "source-preparation" else "public-admission.json")
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
    if (set(record) != keys or record.get("schema") != SCHEMA or record.get("stage") != admitted_stage
            or record.get("authority_path") != AUTH_REL.as_posix()
            or record.get("authority_sha256") != AUTH_SHA256
            or record.get("scope_path") != SCOPE_REL.as_posix()
            or record.get("scope_sha256") != SCOPE_SHA256
            or record.get("attempt_root") != ROOT_REL.as_posix()
            or record.get("source_head") != source_head
            or not re.fullmatch(r"[0-9a-f]{40}", str(source_head))):
        raise ValueError("single-native-admission-identity-invalid")
    if not isinstance(record.get("started_at"), str):
        raise ValueError("single-native-start-invalid")
    predecessor = record.get("predecessor")
    if (not isinstance(predecessor, dict) or set(predecessor) != {"path", "sha256"}
            or predecessor.get("path") != PREDECESSOR_REL.as_posix()
            or not re.fullmatch(r"[0-9a-f]{64}", str(predecessor.get("sha256", "")))):
        raise ValueError("single-native-predecessor-reference-invalid")
    _, predecessor_raw = _safe_file(root, PREDECESSOR_REL.as_posix(), cap=MAX_RECORD)
    if _digest(predecessor_raw) != predecessor["sha256"]:
        raise ValueError("single-native-predecessor-stale")
    _validate_predecessor(root, predecessor_raw)
    pins = record.get("source_pins")
    if not isinstance(pins, dict) or set(pins) != source_roster or not pins:
        raise ValueError("single-native-source-roster-invalid")
    total = 0
    checked = {}
    for rel, digest in pins.items():
        _, data = _safe_file(root, rel, cap=MAX_FILE)
        total += len(data)
        if total > MAX_ROSTER or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("single-native-source-roster-over-limit")
        if _digest(data) != digest:
            raise ValueError("single-native-source-pin-stale")
        checked[rel] = digest
    source = source_payload(source_head=source_head, started_at=record["started_at"],
        attempt_root=ROOT_REL.as_posix(), source_pins=checked,
        predecessor_sha256=predecessor["sha256"])
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
    ready = None
    if stage == "native-prefix-diagnostic":
        expected_ready = attempt / "native-prefix-diagnostic-readiness.json"
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
        if (set(ready) != ready_keys or ready.get("schema") != "genewhip.phase7-native-prefix-diagnostic-readiness.v1"
                or ready.get("diagnostic_only") is not True or ready.get("qualification_accepted") is not False
                or ready.get("started_at") != record.get("started_at")
                or ready.get("source_head") != source_head
                or ready.get("candidate_head") != candidate.get("public_head")
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
        journal_path = attempt / "hosted-delivery-journal.json"
        public_path = expected
        validate_preview_assessment(root, ready["diagnostic_assessment"], attempt=attempt,
            candidate=candidate, admission_path=public_path, admission_sha256=_digest(raw))
    return {"authority": auth, "batch_root": attempt, "attempt_root": attempt,
        "repository": auth["repository"], "native_prefix_readiness": ready,
        "admission": record, "source_payload": source, "candidate": record.get("candidate")}


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


def validate_result(root: Path) -> dict[str, Any]:
    """Reopen one terminal diagnostic; missing or partial evidence remains UNKNOWN."""
    supplied = Path(os.path.abspath(root))
    if len(supplied.parts) >= len(ROOT_REL.parts) and supplied.parts[-len(ROOT_REL.parts):] == ROOT_REL.parts:
        root = Path(*supplied.parts[:-len(ROOT_REL.parts)]).resolve(strict=True)
    else:
        root = supplied.resolve(strict=True)
    load_authority(root, AUTH_REL, AUTH_SHA256)
    def unknown(reason: str) -> dict[str, Any]:
        return {"schema": "genewhip.phase7-single-native-result-assessment.v1",
            "status": "unknown", "diagnostic_status": "unavailable",
            "qualification_accepted": False, "reason": reason}

    attempt_path = root / ROOT_REL
    if attempt_path.is_symlink():
        return unknown("attempt-root-invalid")
    if not attempt_path.is_dir():
        return unknown("attempt-root-missing")
    try:
        attempt = canonical_root(root, ROOT_REL)
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
        if "remote_cleanup_status" in dispatch:
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
                or ("remote_cleanup_status" in dispatch and dispatch["remote_cleanup_status"] != "confirmed")):
            return unknown("dispatch-claim-or-terminal-state-invalid")
        claim_path = root / CLAIM_REL
        if claim_path.is_symlink() or not claim_path.is_file():
            return unknown("global-dispatch-claim-missing")
        _, claim_raw = _safe_file(root, CLAIM_REL.as_posix(), cap=65536)
        claim = _json(claim_raw, "single-native-global-claim-invalid")
        try:
            expected_claim = claim_payload(attempt_root=ROOT_REL.as_posix(),
                source_sha=dispatch["source_sha"], base_sha=dispatch["base_sha"],
                branch=dispatch["branch"], nonce=dispatch["nonce"],
                started_at=dispatch["native_diagnostic_started_at"],
                deadline=dispatch["native_diagnostic_deadline"],
                readiness_sha256=dispatch["readiness_sha256"])
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
        admission_path = attempt / "public-admission.json"
        readiness_path = attempt / "native-prefix-diagnostic-readiness.json"
        admission_raw = _safe_file(root, admission_path.relative_to(root).as_posix(), cap=MAX_RECORD)[1]
        admission = _json(admission_raw, "single-native-terminal-admission-invalid")
        pins = admission.get("source_pins")
        if not isinstance(pins, dict) or not pins:
            return unknown("terminal-source-admission-invalid")
        validate_admission(root, ROOT_REL, admission_path,
            stage="native-prefix-diagnostic", source_head=admission.get("source_head"),
            source_roster=set(pins), authority_path=AUTH_REL, authority_sha256=AUTH_SHA256,
            admission_sha256=_digest(admission_raw), readiness_path=readiness_path,
            readiness_sha256=dispatch.get("readiness_sha256"), _terminal_reopen=True)
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
                or claim.get("attempt_root") != ROOT_REL.as_posix()):
            return unknown("dispatch-candidate-identity-mismatch")
        runtime_path = root / "scripts/evidence/v02_run.py"
        if runtime_path.is_symlink() or not runtime_path.is_file():
            return unknown("strict-report-validator-missing")
        import importlib.util
        spec = importlib.util.spec_from_file_location("gw_single_native_result_runtime", runtime_path)
        if spec is None or spec.loader is None:
            return unknown("strict-report-validator-missing")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        identity = {"source_sha": dispatch["source_sha"], "head_sha": dispatch["source_sha"],
            "base_sha": dispatch["base_sha"],
            "run_id": str(dispatch["run_id"]), "run_attempt": "1"}
        expected_clock = {"receipt_sha256": _digest(job_clock_raw),
            "collector_deadline_monotonic_ns": projection["collector_deadline_monotonic_ns"]}
        if runtime.validate_native_prefix_diagnostic_public(report, identity,
                expected_clock=expected_clock) is not True:
            return unknown("strict-report-consumer-rejected")
        if (not terminal_conclusion_matches(report.get("status"), workflow.get("conclusion"))
                or result.get("status") != report.get("status")):
            return unknown("diagnostic-status-mismatch")
        return {"schema": "genewhip.phase7-single-native-result-assessment.v1",
            "status": report["status"], "diagnostic_status": report["status"],
            "qualification_accepted": False, "run_id": str(dispatch["run_id"]),
            "source_sha": dispatch["source_sha"], "run_attempt": "1",
            "report_sha256": _digest(report_raw), "report_path": report_path.relative_to(root).as_posix(),
            "remote_cleanup_status": dispatch.get("remote_cleanup_status", "confirmed"),
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
    args = parser.parse_args(argv)
    if args.validate_authority:
        load_authority(args.root, AUTH_REL, AUTH_SHA256)
        print("single-native-authority: valid")
        return 0
    if args.validate_result:
        print(json.dumps(validate_result(args.root), sort_keys=True))
        return 0
    parser.error("select --validate-authority or --validate-result")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
