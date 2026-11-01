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
MAX_CONNECTOR_CAPTURE_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_REVIEW_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
FAILURE_FILENAME = "failure.json"
SOURCE_ROLES = {"code": "gsd-code-reviewer", "security": "gsd-security-auditor"}
CANDIDATE_ROLES = SOURCE_ROLES
DISPOSITIONS = {"routine-source-repair", "evidence-backed-infrastructure-retry",
                "bounded-diagnostic-followup", "reviewed-diagnostic-resumption"}
DIAGNOSTIC_CASE = "BaselineRecordContract.test_real_process_output_cap_timeout_and_status"
RSS_DIAGNOSTIC_CASE = "smoke/tank-battle/full-route"
RSS_DIAGNOSTIC_SOURCE_PATHS = {
    "tests/session/phase6_route_contract.py",
    "tests/evidence/phase7_rss_contract.py",
    "scripts/evidence/v02_run.py",
    "tests/evidence/v02_execution_contract.py",
}
PHASE5_CLEANUP_DIAGNOSTIC_SOURCE_PATHS = {
    "tests/evidence/phase5_baseline_contract.py",
    "scripts/evidence/phase4_report.py",
    "tests/evidence/phase4_report_contract.py",
    "tests/session/phase6_route_contract.py",
    "scripts/evidence/phase5_process.py",
    "tests/evidence/phase7_cleanup_diagnostic_contract.py",
}
FIRST_PARTY_CLEANUP_CONTROL_CASE = (
    "NativeParserContract.test_phase7_launcher_keeps_shorter_caller_deadline")
FIRST_PARTY_CLEANUP_CONTROL_METADATA = {
    "control_id": "darwin-caller-deadline-sleeper-v1",
    "child_seconds": 30,
    "caller_timeout_seconds": 0.3,
    "child_wall_seconds": 5,
    "cleanup_grace_seconds": 1,
    "rss_limit_bytes": 1073741824,
    "other_caps_bytes": 4096,
    "field_limit": 10,
    "call_limit": 10,
}
FIRST_PARTY_CLEANUP_CONTROL_SOURCE_PATHS = {
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
    "tests/session/phase6_route_contract.py",
    "scripts/evidence/phase5_process.py",
    "tests/evidence/phase5_baseline_contract.py",
    "tests/evidence/phase7_cleanup_diagnostic_contract.py",
    "scripts/evidence/phase4_report.py",
    "tests/evidence/phase4_report_contract.py",
    ".github/workflows/ci.yml",
    "tests/evidence/phase7_process_admission_contract.py",
}
NATIVE_HOST_RUNTIME_CASE = "runtime/native/recursion94/withhold-first-plate"
NATIVE_HOST_RUNTIME_PROFILE = "native-host-runtime"
NATIVE_CASE_PREPARATION = "prepare/native/recursion94/withhold-first-plate"
NATIVE_CASE_PREPARATION_PATHS = {
    ".github/workflows/ci.yml", "scripts/evidence/v02_run.py",
    "scripts/release/v02_qualification.py", "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
    "tests/evidence/v02_qualification_contract.py",
    "tests/evidence/phase7_native_diagnostic_contract.py",
    "tests/evidence/phase7_diagnostic_contract.py",
}
NATIVE_RESULT_HANDOFF_CASE = "native-diagnostic/collector-handoff"
NATIVE_RESULT_HANDOFF_PROFILE = "native-collector-handoff"
NATIVE_RESULT_HANDOFF_SOURCE_PATHS = {
    "scripts/evidence/v02_run.py",
    "scripts/release/v02_qualification.py",
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_native_diagnostic_contract.py",
    "tests/evidence/v02_qualification_contract.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
}
NATIVE_RESULT_HANDOFF_PAYLOAD_SHA256 = (
    "0c8a7db417e652880dfa4af8f00cde55b861ad67d6070b845c93301eece2ae35")
NATIVE_RESULT_HANDOFF_REPORT_SHA256 = (
    "b61770428f6c3bf4bd5f20d3b441fa9a309460df537305e4f6f29733246cc8f2")
NATIVE_RESULT_HANDOFF_RESULT_SHA256 = (
    "31e4e290553233234d03557fb6378402781ec2484b6d900c1fe04d11c70faaae")
NATIVE_RESULT_HANDOFF_PUBLIC_ADMISSION_SHA256 = (
    "2bd0d46190b1b1f2e11af63e66adb31869055eac8620cb8124f29cd99e8c8e13")
NATIVE_RESULT_HANDOFF_READINESS_SHA256 = (
    "5eabf2de3ddc887311eeb43e73750a4f1379ec6eb62745e8a6cbac24a9ac144a")
NATIVE_RESULT_HANDOFF_RUN_ID = 41260650010
NATIVE_RESULT_HANDOFF_SOURCE_SHA = "122852cf824b176b8395bbc2a8592b393a4b450e"
NATIVE_RESULT_HANDOFF_NONCE = "1a52bdb0adab4486becf69d85df060e0"
NATIVE_INPUT_MASK_ALIGNMENT_CASE = "native-diagnostic/input-mask-alignment"
NATIVE_INPUT_MASK_ALIGNMENT_PROFILE = "native-input-mask-alignment"
NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_PATHS = {
    "scripts/evidence/v02_run.py",
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
    "tests/evidence/phase7_native_diagnostic_contract.py",
}
NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID = 41265690437
NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA = "ff937606a779b7275ce2f58163e1102a8e93a307"
NATIVE_INPUT_MASK_ALIGNMENT_NONCE = "8857dd76adad4b578a793631b9d7306d"
NATIVE_INPUT_MASK_ALIGNMENT_DISPATCH_SHA256 = (
    "d639e0bbc25a8c7b607fae3b845d5aaa5ea3deb7f13e3e42e5ddf10a869d2a95")
NATIVE_INPUT_MASK_ALIGNMENT_RESULT_SHA256 = (
    "c0cdcfd4dff498ef90f520b69a105b383be0b7e6849113eff0d400a568f192b2")
NATIVE_INPUT_MASK_ALIGNMENT_REPORT_SHA256 = (
    "059186cf9702d48c560ffe08b61c034a41e6f899bb9f8d230fb25cfc2d4eb933")
NATIVE_INPUT_MASK_ALIGNMENT_RUN_SHA256 = (
    "85c2efc5652e7dfd5602c717c496260430d1b4abb9c504cc93de6f4b6b003333")
NATIVE_INPUT_MASK_ALIGNMENT_JOBS_SHA256 = (
    "32d111eb1d2974deaeec672e13c94952994f28286607bbff7fe141410091cf57")
NATIVE_INPUT_MASK_ALIGNMENT_EXTRACTION_SHA256 = (
    "e665a8ba4574a644138e8d317d80198e7134bc0522b31e33c26513f05c3aa070")
NATIVE_INPUT_MASK_ALIGNMENT_LOG_SHA256 = (
    "b78495bd92c2c815f4f0c455cde3d79a113fa927e7cca05b7cd633d770e4c446")
NATIVE_INPUT_MASK_ALIGNMENT_ASSESSMENT_SHA256 = (
    "04b7bc6bfa44cf1ce5d986b28ab7d08fffcaa2f849a0db647b6e1621d092f5b0")
NATIVE_INPUT_MASK_ALIGNMENT_FAILURE_PAYLOAD_SHA256 = (
    "82d3764a7ff879bde85e9224f687e5bbe0d2b425588d129960de044a6c05a5b8")
NATIVE_INPUT_MASK_ALIGNMENT_JOURNAL_PAYLOAD_SHA256 = (
    "535f4abf517f4e59a75c33ce5dfe377ccc85cb307a0a3bb8453683773ac26411")
NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_DELIVERY_SHA256 = (
    "3dca679590f43c84c3097090c5bd8ebbf9ad333e6c4bc78f1de5779c9cb57672")
NATIVE_INPUT_MASK_ALIGNMENT_PREPARATION_SHA256 = (
    "9e789b4650116eacc499223c2bb61161787bdc4a58b11560f4b800e5cf73b85d")
NATIVE_INPUT_MASK_ALIGNMENT_MANIFEST_SHA256 = (
    "b7e5a95dbd0590433d23cfbbac0f6b4324df170411dac0efb94345ad79f02cfd")
NATIVE_INPUT_MASK_ALIGNMENT_PUBLIC_ADMISSION_SHA256 = (
    "874be5313611c31cc41b53d1bd49e8b837b0badfb8d286fe5cd4e514f78515bf")
NATIVE_INPUT_MASK_ALIGNMENT_READINESS_SHA256 = (
    "f3d1a900e1db2946dfa304b40bd0c9bdaaf6c120a5ce200a7f1c6f7ee84008a4")
NATIVE_INPUT_MASK_ALIGNMENT_RESULT_PAYLOAD_SHA256 = (
    "f175946ef06b672be9546f6361483daaccf94d27682f148a4d67e15ed6491988")
NATIVE_DIAGNOSTIC_RESUMPTION_CASE = "native-diagnostic/accepted-revalidation"
NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE = "native-diagnostic-accepted-resumption"
WORKFLOW_TIMEOUT_CONTRACT_CASE = (
    "QualificationCoordinatorContract.test_workflow_wires_real_product_smoke_and_serial_full_jobs")
WORKFLOW_TIMEOUT_CONTRACT_PROFILE = "workflow-timeout-contract"
WORKFLOW_TIMEOUT_CONTRACT_SOURCE_PATHS = {
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
    "tests/evidence/v02_qualification_contract.py",
}
PUBLICATION_RSS_OBSERVATION_CASE = "coordinator/gh-pr-view/rss-observation"
PUBLICATION_RSS_OBSERVATION_PROFILE = "publication-rss-observation-reconciliation"
PUBLICATION_RSS_OBSERVATION_SOURCE_PATHS = {
    "tests/session/phase6_route_contract.py",
    "tests/evidence/phase7_rss_contract.py",
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
}


def native_diagnostic_plan() -> dict[str, Any]:
    return {"case": "recursion94-withhold-first-plate", "workloads": [
        {"name": "input-contract", "wall_seconds": 30},
        {"name": "headless-reference", "wall_seconds": 600},
        {"name": "native-sdl-comparison", "wall_seconds": 600}],
        "outer_wall_seconds": 1800, "job_wall_seconds": 2700,
        "qualification_accepted": False, "stop_after_result": True}


def _validate_assessed_preview(root: Path, expected_root: str, packet_ref: Any,
        reviews: Any, journal: dict[str, Any], failure: dict[str, Any],
        *, review_payload_sha: str | None = None) -> dict[str, Any]:
    """Reopen one successful diagnostic PR and its distinct intentional stop."""
    label = "native-diagnostic-assessed-preview-invalid"
    if (not isinstance(packet_ref, dict)
            or not isinstance(packet_ref.get("path"), str)
            or not packet_ref["path"].startswith(expected_root + "/ci-failure/")):
        raise ValueError(label)
    packet, _ = _read_reference(root, packet_ref, label=label)
    table, gh = packet.get("source_and_candidate"), packet.get("github")
    if (packet.get("qualification_credit") is not False
            or packet.get("disposition") != "diagnostic-preview-green-assessment-required"
            or not isinstance(table, dict) or not isinstance(gh, dict)):
        raise ValueError(label)
    values = {}
    for key, filename in (("source_admission", "source-admission.json"),
                          ("public_admission", "public-admission.json")):
        path = table.get(key + "_path")
        if path != expected_root + "/" + filename:
            raise ValueError(label)
        values[key], _ = _read_reference(root, {"path": path,
            "sha256": table.get(key + "_sha256")}, label=label)
    source, public = values["source_admission"], values["public_admission"]
    candidate = public.get("candidate")
    if (not isinstance(candidate, dict) or public.get("disposition") != "bounded-diagnostic-followup"
            or source.get("source_head") != table.get("private_source_head")
            or public.get("source_head") != source.get("source_head")
            or public.get("source_payload_sha256") != source.get("source_payload_sha256")):
        raise ValueError(label)
    delivery_meta = packet.get("hosted_source_delivery")
    if not isinstance(delivery_meta, dict):
        raise ValueError(label)
    documents = {}
    for key, filename in (("source_delivery", "source-delivery.json"),
                           ("journal", "hosted-delivery-journal.json"),
                           ("failure_latch", FAILURE_FILENAME)):
        if delivery_meta.get(key + "_path") != expected_root + "/" + filename:
            raise ValueError(label)
        documents[key], _ = _read_reference(root, {"path": delivery_meta[key + "_path"],
            "sha256": delivery_meta.get(key + "_sha256")}, label=label)
    if (documents["journal"] != journal or documents["failure_latch"] != failure
            or documents["source_delivery"].get("status") != "diagnostic-ci-complete"
            or documents["source_delivery"].get("diagnostic_only") is not True
            or documents["source_delivery"].get("assessment_required") is not True
            or documents["source_delivery"].get("merge_attempted") is not False
            or documents["source_delivery"].get("candidate_sha") != candidate.get("public_head")):
        raise ValueError(label)
    for field, key in (("public_head", "candidate_head"), ("public_base", "public_base"),
                       ("public_tree", "public_tree"), ("source_manifest_sha256", "manifest_sha256"),
                       ("preparation_sha256", "preparation_sha256"),
                       ("candidate_payload_sha256", "candidate_review_payload_sha256")):
        if candidate.get(field) != table.get(key):
            raise ValueError(label)
    _, prep_bytes = _read_reference(root, {"path": candidate.get("preparation_path"),
        "sha256": candidate.get("preparation_sha256")}, label=label, cap=MAX_CANDIDATE_BYTES)
    if _digest(prep_bytes) != table["preparation_sha256"]:
        raise ValueError(label)
    jobs = gh.get("jobs")
    if (not isinstance(jobs, list) or len(jobs) != 16
            or not all(isinstance(row, dict) and type(row.get("id")) is int
                       and row["id"] > 0 and row.get("status") == "completed" for row in jobs)):
        raise ValueError(label)
    by_name = {row.get("name"): row for row in jobs}
    if (set(by_name) != PREVIEW_REQUIRED_LANES | PREVIEW_CONDITIONAL_SKIPS
            or len({row["id"] for row in jobs}) != 16
            or any(by_name[name].get("conclusion") != "success" for name in PREVIEW_REQUIRED_LANES)
            or any(by_name[name].get("conclusion") != "skipped" for name in PREVIEW_CONDITIONAL_SKIPS)):
        raise ValueError(label)
    run = gh.get("workflow_run")
    if (not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] <= 0
            or run.get("event") != "pull_request" or run.get("status") != "completed"
            or run.get("conclusion") != "success" or run.get("workflow_path") != ".github/workflows/ci.yml"
            or gh.get("repository") != "szTheory/genewhip" or gh.get("merged") is not False
            or gh.get("pull_request_state") != "open"
            or gh.get("head_sha") != candidate["public_head"]
            or gh.get("base_sha") != candidate["public_base"]):
        raise ValueError(label)
    if (journal.get("repository") != "szTheory/genewhip"
            or journal.get("source_head") != candidate["public_head"]
            or journal.get("public_base_sha") != candidate["public_base"]
            or journal.get("started_at") != source.get("started_at")
            or journal.get("diagnostic_only") is not True
            or journal.get("diagnostic_ci_status") != "passed"
            or journal.get("assessment_required") is not True
            or journal.get("merge_attempted") is not False
            or journal.get("pull_request") != str(gh.get("pull_request"))
            or any(key.startswith("qualification_dispatch") for key in journal)
            or failure.get("authorization_sha256") != AUTH_SHA256
            or failure.get("stage") != "preview-ci"
            or failure.get("reason") != "diagnostic-ci-complete-assessment-required"):
        raise ValueError(label)
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError(label)
    payload_sha = review_payload_sha or _digest(_canonical(packet))
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=payload_sha)
        raw = _read_regular(_path(root, _safe_relative(reviews[key]["path"], label)),
                            cap=MAX_REVIEW_BYTES, label=label)
        if _frontmatter(raw).get("source_head") != source["source_head"]:
            raise ValueError(label)
    return public


def _validate_native_readiness(root: Path, batch_root: Path, admission: dict[str, Any],
        admission_sha: str, path: Path, expected_sha: str) -> dict[str, Any]:
    label = "native-diagnostic-readiness-invalid"
    if path.is_symlink() or path.resolve(strict=False) != batch_root / "native-diagnostic-readiness.json":
        raise ValueError(label)
    data = _read_regular(path, cap=MAX_ADMISSION_BYTES, label=label)
    if _digest(data) != expected_sha:
        raise ValueError(label)
    ready = _json_object(data, label)
    required = {"schema", "diagnostic_only", "qualification_accepted", "plan", "started_at",
        "source_head", "candidate_head", "public_admission", "diagnostic_assessment", "assessment_reviews"}
    if (set(ready) != required or ready.get("schema") != "genewhip.phase7-native-diagnostic-readiness.v1"
            or ready.get("diagnostic_only") is not True or ready.get("qualification_accepted") is not False
            or _canonical(ready.get("plan")) != _canonical(native_diagnostic_plan())
            or ready.get("started_at") != admission.get("started_at")
            or ready.get("source_head") != admission.get("source_head")
            or ready.get("candidate_head") != admission.get("candidate", {}).get("public_head")
            or ready.get("public_admission") != {"path": (batch_root / "public-admission.json").relative_to(root).as_posix(),
                "sha256": admission_sha}
            or admission.get("disposition") != "bounded-diagnostic-followup"):
        raise ValueError(label)
    repair, _ = _read_reference(root, admission["predecessor"]["repair_evidence"], label=label)
    if repair.get("diagnostic_case") not in (
            NATIVE_CASE_PREPARATION, WORKFLOW_TIMEOUT_CONTRACT_CASE,
            PUBLICATION_RSS_OBSERVATION_CASE, NATIVE_RESULT_HANDOFF_CASE,
            NATIVE_INPUT_MASK_ALIGNMENT_CASE):
        raise ValueError(label)
    journal = _json_object(_read_regular(batch_root / "hosted-delivery-journal.json",
                                       cap=MAX_ADMISSION_BYTES, label=label), label)
    failure = _json_object(_read_regular(batch_root / FAILURE_FILENAME, cap=MAX_AUTH_BYTES, label=label), label)
    payload = {key: value for key, value in ready.items() if key != "assessment_reviews"}
    public = _validate_assessed_preview(root, batch_root.relative_to(root).as_posix(),
        ready["diagnostic_assessment"], ready["assessment_reviews"], journal, failure,
        review_payload_sha=_digest(_canonical(payload)))
    if public != admission:
        raise ValueError(label)
    return ready
NATIVE_HOST_RUNTIME_SOURCE_PATHS = {
    "scripts/release/v02_qualification.py",
    "tests/evidence/v02_qualification_contract.py",
    "scripts/evidence/v02_run.py",
    "tests/desktop/phase6_routes.py",
    "tests/evidence/phase7_host_failure_diagnostic_contract.py",
    "scripts/release/v02_batch.py",
    "tests/evidence/phase7_fresh_batch_contract.py",
}
PREVIEW_REQUIRED_LANES = {"safety", "gameplay", "desktop", "package", "performance",
    "product-smoke", "phase7-fast", "required-ci"}
PREVIEW_CONDITIONAL_SKIPS = {"v02-runtime", "extended", "v02-benchmark-control",
    "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package",
    "v02-release-qualification", "attestation"}
NATIVE_HOST_RUNTIME_JOBS = (PREVIEW_REQUIRED_LANES | PREVIEW_CONDITIONAL_SKIPS)
NATIVE_HOST_RUNTIME_OUTCOMES = {
    "phase7-fast": "success", "gameplay": "success", "performance": "success",
    "package": "success", "safety": "success", "desktop": "success",
    "product-smoke": "success", "v02-runtime": "failure", "required-ci": "failure",
    "extended": "skipped", "v02-benchmark-recursion94": "skipped",
    "v02-benchmark-control": "skipped", "v02-benchmark-tank-battle": "skipped",
    "v02-package": "skipped", "v02-release-qualification": "skipped",
    "attestation": "skipped",
}


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


def _validate_rss_diagnostic_artifacts(root: Path, *, expected_root: str,
                                       terminal: dict[str, Any], repair: dict[str, Any],
                                       journal: dict[str, Any]) -> None:
    label = "fresh-batch-rss-diagnostic-evidence-invalid"
    receipt_ref = repair.get("local_monitor_receipt")
    log_ref = repair.get("hosted_log")
    receipt_prefix = f"{expected_root}/coordinator-external-attempts/"
    receipt_path = (receipt_ref.get("path", "")
                    if isinstance(receipt_ref, dict) and isinstance(receipt_ref.get("path"), str)
                    else "")
    receipt_name = receipt_path[len(receipt_prefix):] if receipt_path.startswith(receipt_prefix) else ""
    log_path = log_ref.get("path", "") if isinstance(log_ref, dict) else ""
    pull_request = terminal.get("pull_request")
    pr_number = pull_request.get("number") if isinstance(pull_request, dict) else None
    if (not receipt_path.startswith(receipt_prefix)
            or re.fullmatch(r"external-[0-9]+-[0-9]+\.attempt\.json", receipt_name) is None
            or isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0
            or not isinstance(log_ref, dict)
            or set(log_ref) != {"path", "sha256"}):
        raise ValueError(label)
    receipt, _ = _read_reference(root, receipt_ref, label=label)
    processes = receipt.get("processes")
    expected_argv = ["gh", "pr", "view", str(pr_number), "--repo", "szTheory/genewhip",
                     "--json", "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"]
    if (receipt.get("schema") != "genewhip.v02-coordinator-child-attempt.v1"
            or receipt.get("argv") != expected_argv
            or receipt.get("returncode") != -15
            or receipt.get("process_group_cleanup") != "confirmed"
            or not isinstance(processes, list) or not processes
            or any(not isinstance(row, dict)
                or row.get("status") != "failed"
                or row.get("return_code") != -15
                or row.get("process_group_cleanup") != "confirmed"
                or row.get("bound_violation") is not True
                or row.get("bound_violation_reason") != "phase7-rss-observation-unavailable"
                or isinstance(row.get("pid"), bool) or not isinstance(row.get("pid"), int)
                or row.get("pid") <= 0
                or isinstance(row.get("pgid"), bool) or not isinstance(row.get("pgid"), int)
                or row.get("pgid") <= 0 or row.get("pid") != row.get("pgid")
                for row in processes)):
        raise ValueError(label)
    product_job = next((row for row in terminal.get("jobs", [])
                        if isinstance(row, dict) and row.get("name") == "product-smoke"), None)
    job_id = product_job.get("id") if isinstance(product_job, dict) else None
    if (isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0
            or log_path != f"{expected_root}/ci-failure/product-smoke-{job_id}.log"):
        raise ValueError(label)
    log_relative = _safe_relative(log_path, label)
    raw_log = _read_regular(_path(root, log_relative), cap=MAX_ADMISSION_BYTES, label=label)
    if not isinstance(log_ref.get("sha256"), str) or _digest(raw_log) != log_ref["sha256"]:
        raise ValueError(label)
    text = raw_log.decode("utf-8", errors="replace")
    if ("tank-battle/full-route: process failed" not in text
            or "BOUND: phase7-rss-observation-unavailable" not in text):
        raise ValueError(label)
    if (journal.get("repository") != "szTheory/genewhip"
            or not isinstance(journal.get("source_head"), str)
            or re.fullmatch(r"[0-9a-f]{40}", journal["source_head"]) is None
            or not isinstance(journal.get("public_base_sha"), str)
            or re.fullmatch(r"[0-9a-f]{40}", journal["public_base_sha"]) is None
            or not isinstance(pull_request, dict)
            or pull_request.get("state") != "open"
            or pull_request.get("merged") is not False
            or pull_request.get("head_sha") != journal.get("source_head")
            or pull_request.get("base_sha") != journal.get("public_base_sha")):
        raise ValueError(label)


def _validate_publication_rss_observation_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any],
        failure: dict[str, Any]) -> None:
    """Bind a publication-stage gh observer failure without attributing CI failure to it."""
    label = "fresh-batch-publication-rss-observation-invalid"
    receipt_ref = repair.get("local_monitor_receipt")
    prefix = f"{expected_root}/coordinator-external-attempts/"
    receipt_path = (receipt_ref.get("path", "") if isinstance(receipt_ref, dict)
                    and isinstance(receipt_ref.get("path"), str) else "")
    receipt_name = receipt_path[len(prefix):] if receipt_path.startswith(prefix) else ""
    if (not receipt_path.startswith(prefix)
            or re.fullmatch(r"external-[0-9]+-[0-9]+\.attempt\.json", receipt_name) is None
            or not isinstance(receipt_ref, dict) or set(receipt_ref) != {"path", "sha256"}):
        raise ValueError(label)
    receipt, _ = _read_reference(root, receipt_ref, label=label)
    pull_request = terminal.get("pull_request")
    pr_number = pull_request.get("number") if isinstance(pull_request, dict) else None
    run_id = terminal.get("workflow_run_id")
    jobs = terminal.get("jobs")
    if (type(pr_number) is not int or pr_number <= 0 or type(run_id) is not int or run_id <= 0
            or not isinstance(jobs, list) or len(jobs) != 16):
        raise ValueError(label)
    names = [row.get("name") for row in jobs if isinstance(row, dict)]
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    if (len(names) != 16 or not all(isinstance(name, str) for name in names)
            or len(set(names)) != 16
            or set(names) != PREVIEW_REQUIRED_LANES | PREVIEW_CONDITIONAL_SKIPS
            or any(type(row.get("id")) is not int or row["id"] <= 0 for row in jobs)
            or len({row["id"] for row in jobs}) != 16
            or any(type(row.get("run_id")) is not int or row.get("run_id") != run_id for row in jobs)
            or any(row.get("status") != "completed" for row in jobs)
            or any(by_name[name].get("conclusion") != "success" for name in PREVIEW_REQUIRED_LANES)
            or any(by_name[name].get("conclusion") != "skipped" for name in PREVIEW_CONDITIONAL_SKIPS)):
        raise ValueError(label)
    workflow_run = terminal.get("workflow_run")
    queried_source_sha = terminal.get("queried_source_sha")
    captures = terminal.get("connector_captures")
    if (not isinstance(workflow_run, dict)
            or set(workflow_run) != {"id", "status", "conclusion", "workflow_id"}
            or terminal.get("event") != "pull_request"
            or terminal.get("event_basis") != "github_fetch_commit_workflow_runs:pull-request-filter"
            or workflow_run.get("id") != run_id
            or workflow_run.get("status") != "completed"
            or workflow_run.get("conclusion") != "success"
            or type(workflow_run.get("workflow_id")) is not int
            or workflow_run["workflow_id"] <= 0
            or not isinstance(queried_source_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40}", queried_source_sha)
            or queried_source_sha != journal.get("source_head")
            or not isinstance(captures, dict)
            or set(captures) != {"pr", "workflow_runs", "jobs"}):
        raise ValueError(label)
    expected_capture_paths = {
        "pr": f"{expected_root}/ci-failure/pull-request-{pr_number}.json",
        "workflow_runs": f"{expected_root}/ci-failure/commit-workflow-runs-{queried_source_sha[:12]}.json",
        "jobs": f"{expected_root}/ci-failure/jobs-{run_id}.json",
    }
    capture_values: dict[str, dict[str, Any]] = {}
    for name, expected_path in expected_capture_paths.items():
        reference = captures[name]
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                or reference.get("path") != expected_path):
            raise ValueError(label)
        capture_values[name], _ = _read_reference(root, reference, label=label,
                                                   cap=MAX_CONNECTOR_CAPTURE_BYTES)
    captured_pr = capture_values["pr"]
    if (captured_pr.get("number") != pr_number
            or captured_pr.get("state") != "open"
            or captured_pr.get("merged") is not False
            or captured_pr.get("head_sha") != queried_source_sha
            or captured_pr.get("base_sha") != journal.get("public_base_sha")):
        raise ValueError(label)
    workflow_envelope = capture_values["workflow_runs"]
    captured_runs = workflow_envelope.get("workflow_runs")
    if (workflow_envelope.get("provider") != "github_fetch_commit_workflow_runs"
            or workflow_envelope.get("repo_full_name") != "szTheory/genewhip"
            or workflow_envelope.get("commit_sha") != queried_source_sha
            or not isinstance(captured_runs, list)):
        raise ValueError(label)
    selected_runs = [row for row in captured_runs
                     if isinstance(row, dict) and row.get("id") == run_id]
    if (len(selected_runs) != 1
            or selected_runs[0].get("status") != workflow_run.get("status")
            or selected_runs[0].get("conclusion") != workflow_run.get("conclusion")
            or selected_runs[0].get("workflow_id") != workflow_run.get("workflow_id")):
        raise ValueError(label)
    captured_jobs = capture_values["jobs"].get("jobs")
    if not isinstance(captured_jobs, list) or len(captured_jobs) != 16:
        raise ValueError(label)
    captured_job_index = {row.get("id"): row for row in captured_jobs if isinstance(row, dict)}
    if len(captured_job_index) != 16:
        raise ValueError(label)
    for row in jobs:
        actual = captured_job_index.get(row["id"])
        if (not isinstance(actual, dict)
                or any(actual.get(field) != row.get(field)
                       for field in ("id", "run_id", "name", "status", "conclusion"))):
            raise ValueError(label)
    public_ref = terminal.get("public_admission")
    expected_public_path = f"{expected_root}/public-admission.json"
    if (not isinstance(public_ref, dict) or set(public_ref) != {"path", "sha256"}
            or public_ref.get("path") != expected_public_path):
        raise ValueError(label)
    public, _ = _read_reference(root, public_ref, label=label)
    # The prior source-admission was already recursively validated. Reopen its
    # bounded bytes here to cryptographically compose the accepted candidate review.
    source_path = _path(root, _safe_relative(f"{expected_root}/source-admission.json", label))
    source = _json_object(_read_regular(source_path, cap=MAX_ADMISSION_BYTES, label=label), label)
    if (public.get("schema") != SCHEMA or public.get("status") != "public-effects"
            or public.get("authorization_sha256") != AUTH_SHA256
            or public.get("scope_sha256") != SCOPE_SHA256
            or public.get("attempt_root") != expected_root
            or public.get("batch_root") != expected_root
            or public.get("attempt_index") != source.get("attempt_index")
            or public.get("started_at") != source.get("started_at")
            or public.get("source_head") != source.get("source_head")
            or public.get("source_pins") != source.get("source_pins")
            or public.get("source_reviews") != source.get("source_reviews")
            or public.get("source_payload_sha256") != source.get("source_payload_sha256")
            or public.get("predecessor") != source.get("predecessor")
            or public.get("disposition") != "bounded-diagnostic-followup"):
        raise ValueError(label)
    source_payload = source_review_payload(source_head=source["source_head"],
        started_at=source["started_at"], attempt_root=expected_root,
        attempt_index=source["attempt_index"], predecessor=source["predecessor"],
        disposition=source["disposition"], source_pins=source["source_pins"])
    candidate = public.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError(label)
    candidate_payload = candidate_review_payload(source_payload, candidate)
    if candidate.get("candidate_payload_sha256") != _digest(_canonical(candidate_payload)):
        raise ValueError(label)
    candidate_reviews = candidate.get("candidate_reviews")
    if not isinstance(candidate_reviews, dict) or set(candidate_reviews) != set(CANDIDATE_ROLES):
        raise ValueError(label)
    for role_key, role in CANDIDATE_ROLES.items():
        _check_review(root, candidate_reviews[role_key], role=role,
                      payload_sha256=candidate["candidate_payload_sha256"])
        review_raw = _read_regular(_path(root, _safe_relative(candidate_reviews[role_key]["path"], label)),
                                   cap=MAX_REVIEW_BYTES, label=label)
        if _frontmatter(review_raw).get("source_head") != source.get("source_head"):
            raise ValueError(label)
    if (candidate.get("public_head") != journal.get("source_head")
            or candidate.get("public_base") != journal.get("public_base_sha")
            or public.get("source_head") != source.get("source_head")):
        raise ValueError(label)
    jobs_run_ids = [row.get("run_id") for row in jobs]
    if any(type(value) is not int or value != run_id for value in jobs_run_ids):
        raise ValueError(label)
    expected_argv = ["gh", "pr", "view", str(pr_number), "--repo", "szTheory/genewhip",
        "--json", "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"]
    processes = receipt.get("processes")
    if (receipt.get("schema") != "genewhip.v02-coordinator-child-attempt.v1"
            or receipt.get("argv") != expected_argv or receipt.get("returncode") != -15
            or receipt.get("process_group_cleanup") != "confirmed"
            or not isinstance(processes, list) or len(processes) != 1):
        raise ValueError(label)
    row = processes[0]
    if (not isinstance(row, dict) or row.get("status") != "failed"
            or type(row.get("return_code")) is not int or row["return_code"] != -15
            or row.get("process_group_cleanup") != "confirmed"
            or row.get("bound_violation") is not True
            or row.get("bound_violation_reason") != "phase7-rss-observation-unavailable"
            or type(row.get("pid")) is not int or row["pid"] <= 0
            or type(row.get("pgid")) is not int or row["pgid"] != row["pid"]
            or type(row.get("rss_bytes_peak")) is not int
            or not 0 < row["rss_bytes_peak"] <= 4 * 1024**3
            or type(row.get("rss_bytes_observed")) is not int or row["rss_bytes_observed"] != 0
            or row.get("rss_observation_reason") != "task-info-unavailable"
            or row.get("rss_observation_errno") != "esrch"
            or row.get("rss_observation_result") != "missing"
            or type(row.get("stdout_bytes")) is not int or row["stdout_bytes"] != 0
            or type(row.get("stderr_bytes")) is not int or row["stderr_bytes"] != 42
            or type(row.get("wall_seconds")) not in (int, float)
            or not 0 < row["wall_seconds"] <= 30
            or not isinstance(receipt.get("stderr_tail"), str)
            or "BOUND: phase7-rss-observation-unavailable" not in receipt["stderr_tail"]):
        raise ValueError(label)
    if (failure.get("schema") != "genewhip.phase7-fresh-batch-failure.v1"
            or failure.get("stage") != "publication"
            or failure.get("reason") != "fresh-batch-publication-failed"
            or failure.get("authorization_sha256") != AUTH_SHA256
            or journal.get("schema") != "genewhip.v02-delivery-journal.v1"
            or journal.get("repository") != "szTheory/genewhip"
            or journal.get("push_performed") is not True
            or journal.get("source_head") != pull_request.get("head_sha")
            or journal.get("public_base_sha") != pull_request.get("base_sha")
            or pull_request.get("state") != "open" or pull_request.get("merged") is not False
            or type(pull_request.get("number")) is not int
            or pull_request.get("head_sha") != queried_source_sha
            or any(key.startswith("qualification_dispatch") for key in journal)
            or any(key in journal for key in ("qualification_run", "qualification_accepted",
                "public_source_sha", "pull_request", "merge_attempted"))
            or not isinstance(journal.get("started_at"), str)
            or (root / expected_root / "source-delivery.json").exists()):
        raise ValueError(label)
def _validate_phase5_cleanup_diagnostic_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any]) -> None:
    """Bind the narrowly classified stdout-cap cleanup diagnostic to its saved CI log."""
    label = "fresh-batch-phase5-cleanup-diagnostic-evidence-invalid"
    log_ref = repair.get("hosted_log")
    jobs = terminal.get("jobs")
    safety_job = next((row for row in jobs if isinstance(row, dict)
                       and row.get("name") == "safety"), None) if isinstance(jobs, list) else None
    job_id = safety_job.get("id") if isinstance(safety_job, dict) else None
    expected_path = (f"{expected_root}/ci-failure/safety-job-{job_id}.log"
                     if isinstance(job_id, int) and not isinstance(job_id, bool) and job_id > 0
                     else None)
    if (not isinstance(log_ref, dict) or set(log_ref) != {"path", "sha256"}
            or log_ref.get("path") != expected_path):
        raise ValueError(label)
    raw = _read_regular(_path(root, _safe_relative(log_ref["path"], label)),
                        cap=MAX_ADMISSION_BYTES, label=label)
    if not isinstance(log_ref.get("sha256"), str) or _digest(raw) != log_ref["sha256"]:
        raise ValueError(label)
    text = raw.decode("utf-8", errors="replace")
    required = (
        "CTest process subcase: BaselineRecordContract.test_real_process_output_cap_timeout_and_status "
        "[stdout-cap; failure; exception=ValueError; status=failed; cleanup=unconfirmed; "
        "cleanup_error=PermissionError; return=missing; result=cleanup-unconfirmed]",
    )
    if any(item not in text for item in required):
        raise ValueError(label)


def _validate_first_party_cleanup_control_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any]) -> None:
    """Bind the fixed caller-deadline failure to its exact CI jobs and private logs."""
    label = "fresh-batch-first-party-cleanup-control-invalid"
    hosted_logs = repair.get("hosted_logs")
    if not isinstance(hosted_logs, dict) or set(hosted_logs) != {"safety", "phase7-fast"}:
        raise ValueError(label)
    jobs = terminal.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError(label)
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    safety_job = by_name.get("safety")
    fast_job = by_name.get("phase7-fast")
    if (not isinstance(safety_job, dict) or not isinstance(fast_job, dict)
            or type(safety_job.get("id")) is not int or safety_job["id"] <= 0
            or type(fast_job.get("id")) is not int or fast_job["id"] <= 0):
        raise ValueError(label)
    expected_paths = {
        "safety": f"{expected_root}/ci-failure/safety-job-{safety_job['id']}.log",
        "phase7-fast": f"{expected_root}/ci-failure/phase7-fast-{fast_job['id']}.log",
    }
    log_text: dict[str, str] = {}
    for lane, expected_path in expected_paths.items():
        reference = hosted_logs.get(lane)
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                or reference.get("path") != expected_path):
            raise ValueError(label)
        raw = _read_regular(_path(root, _safe_relative(reference["path"], label)),
                            cap=MAX_ADMISSION_BYTES, label=label)
        if not isinstance(reference.get("sha256"), str) or _digest(raw) != reference["sha256"]:
            raise ValueError(label)
        log_text[lane] = raw.decode("utf-8", errors="replace")

    safety = log_text["safety"]
    safety_failure = (
        "CTest subtest failure: NativeParserContract.test_phase7_launcher_keeps_shorter_caller_deadline "
        "[error; exception=RuntimeError; cleanup=unconfirmed; bound=other; "
        "cleanup_reason=cleanup-permission-denied; status_observation=group-status-unavailable; cleanup_queries=3]")
    if ("100% tests passed out of 146" not in safety
            or "99% tests passed, 1 tests failed out of 146" not in safety
            or safety.count(safety_failure) != 1):
        raise ValueError(label)

    fast = log_text["phase7-fast"]
    fast_failure = terminal.get("fast_job_failure")
    if (not isinstance(fast_failure, dict)
            or fast_failure.get("cases") != [
                "ProcessAdmissionContract.test_baseline_fake_cancel_and_setup_failure_always_cleanup",
                "ProcessAdmissionContract.test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler"]
            or fast_failure.get("exception") != "AssertionError"
            or fast_failure.get("classification") != "old mocked argument expectations"
            or fast_failure.get("real_child_in_failing_cases") is not False):
        raise ValueError(label)
    failure_headers = re.findall(
        r"^.*FAIL: (test_[A-Za-z0-9_]+) \(__main__\.([A-Za-z_][A-Za-z0-9_]*)\.(test_[A-Za-z0-9_]+)\)$",
        fast, flags=re.MULTILINE)
    status_budget = (r"status_budget=\{'remaining': 16, 'attempted': 0, "
                     r"'last_reason': 'cleanup-unclassified', 'status_reason': 'not-observed'\}")
    call_shape = re.compile(
        r"^.*Expected: _terminate_process_group\(<Mock id='(?P<id>[0-9]+)'>\)$\n"
        r"^.*Actual: _terminate_process_group\(<Mock id='(?P=id)'>, " + status_budget + r"\)$",
        flags=re.MULTILINE)
    expected_method_names = (
        "test_baseline_fake_cancel_and_setup_failure_always_cleanup",
        "test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler",
    )
    per_test_shape_valid = True
    for method_name in expected_method_names:
        marker = f"FAIL: {method_name} (__main__.ProcessAdmissionContract.{method_name})"
        start = fast.find(marker)
        if start < 0:
            per_test_shape_valid = False
            break
        next_failure = fast.find("\n", start)
        next_failure = fast.find("FAIL: ", next_failure + 1) if next_failure >= 0 else -1
        end = next_failure if next_failure >= 0 else len(fast)
        block = fast[start:end]
        if len(call_shape.findall(block)) != 1:
            per_test_shape_valid = False
            break
    expected_headers = [(name, "ProcessAdmissionContract", name)
                        for name in expected_method_names]
    if (failure_headers != expected_headers
            or fast.count("FAILED (failures=2)") != 1
            or "ERROR:" in fast
            or not per_test_shape_valid):
        raise ValueError(label)
    # The failure lane is eligible only for the source-owned finite control.
    control = repair.get("control")
    if (not isinstance(control, dict)
            or _canonical(control) != _canonical(FIRST_PARTY_CLEANUP_CONTROL_METADATA)):
        raise ValueError(label)
    pull_request = terminal.get("pull_request")
    if (not isinstance(pull_request, dict)
            or pull_request.get("head_sha") != journal.get("source_head")
            or pull_request.get("base_sha") != journal.get("public_base_sha")
            or type(pull_request.get("number")) is not int or pull_request["number"] <= 0):
        raise ValueError(label)



def _validate_workflow_timeout_contract_artifact(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any]) -> None:
    """Bind this one fixed pure contract failure to its exact private fast-lane log."""
    label = "fresh-batch-workflow-timeout-contract-invalid"
    jobs = terminal.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError(label)
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    fast = by_name.get("phase7-fast")
    if (not isinstance(fast, dict) or type(fast.get("id")) is not int or fast["id"] <= 0):
        raise ValueError(label)
    reference = repair.get("hosted_log")
    expected_path = f"{expected_root}/ci-failure/phase7-fast-{fast['id']}.log"
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or reference.get("path") != expected_path):
        raise ValueError(label)
    raw = _read_regular(_path(root, _safe_relative(expected_path, label)),
        cap=MAX_ADMISSION_BYTES, label=label)
    if not isinstance(reference.get("sha256"), str) or _digest(raw) != reference["sha256"]:
        raise ValueError(label)
    text = raw.decode("utf-8", errors="replace")
    failure = terminal.get("fast_job_failure")
    expected_failure = {
        "outer_case": "test_default_unittest_suites_do_not_reach_any_os_process_seam",
        "inner_case": WORKFLOW_TIMEOUT_CONTRACT_CASE,
        "exception": "AssertionError",
        "expected_literal": "timeout-minutes: 360",
        "classification": "workflow-timeout-expression-updated",
        "real_child_in_failing_cases": False,
    }
    if failure != expected_failure:
        raise ValueError(label)
    outer_header = ("FAIL: test_default_unittest_suites_do_not_reach_any_os_process_seam "
        "(__main__.ProcessAdmissionContract.test_default_unittest_suites_do_not_reach_any_os_process_seam)")
    nested_case = ("QualificationCoordinatorContract testMethod="
        "test_workflow_wires_real_product_smoke_and_serial_full_jobs")
    failed_assertion = 'self.assertIn("timeout-minutes: 360", text)'
    if (text.count(outer_header) != 1
            or text.count(nested_case) != 2
            or text.count(failed_assertion) != 2
            or text.count("not found in") != 2
            or text.count("FAILED (failures=1)") != 1
            or "AssertionError: Lists differ:" not in text
            or re.search(r"^.*(?:FAIL|ERROR): (?!test_default_unittest_suites_do_not_reach_any_os_process_seam ).+$",
                text, flags=re.MULTILINE)):
        raise ValueError(label)

def _validate_native_host_runtime_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any],
        source_delivery: dict[str, Any], failure: dict[str, Any]) -> None:
    """Bind one exact failed full-run case without resolving outer cleanup/cause."""
    label = "fresh-batch-native-host-runtime-evidence-invalid"
    run_id = terminal.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0:
        raise ValueError(label)
    run_dir = f"{expected_root}/terminal-record-{run_id}"
    paths = {
        "terminal_packet": f"{run_dir}/terminal-packet.json",
        "qualification_run_snapshot": f"{run_dir}/run.json",
        "qualification_jobs_snapshot": f"{run_dir}/jobs.json",
        "hosted_log": f"{run_dir}/v02-runtime-job.log",
        "source_delivery": f"{expected_root}/source-delivery.json",
        "hosted_delivery_journal": f"{expected_root}/hosted-delivery-journal.json",
    }
    values: dict[str, Any] = {}
    raw_by_key: dict[str, bytes] = {}
    for key, expected_path in paths.items():
        reference = terminal.get(key)
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                or reference.get("path") != expected_path):
            raise ValueError(label)
        raw = _read_regular(_path(root, _safe_relative(expected_path, label)),
                            cap=MAX_ADMISSION_BYTES, label=label)
        if not isinstance(reference.get("sha256"), str) or _digest(raw) != reference["sha256"]:
            raise ValueError(label)
        raw_by_key[key] = raw
        if key != "hosted_log":
            if key == "qualification_jobs_snapshot":
                try:
                    parsed = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ValueError(label) from None
                if not isinstance(parsed, list):
                    raise ValueError(label)
                values[key] = parsed
            else:
                values[key] = _json_object(raw, label)

    run = values["qualification_run_snapshot"]
    snapshot_jobs = values["qualification_jobs_snapshot"]
    packet = values["terminal_packet"]
    if (terminal.get("qualification_run") != run
            or terminal.get("qualification_jobs") != snapshot_jobs
            or not isinstance(snapshot_jobs, list)
            or not isinstance(terminal.get("jobs"), list)):
        raise ValueError(label)
    if (repair.get("diagnostic_profile") != NATIVE_HOST_RUNTIME_PROFILE
            or repair.get("diagnostic_case") != NATIVE_HOST_RUNTIME_CASE
            or repair.get("diagnostic_only") is not True
            or repair.get("live_retry_authorized") is not False
            or repair.get("safety_job_failed") is not False
            or repair.get("had_safety_job_failure") is not False
            or repair.get("full_qualification_dispatched") is not True
            or repair.get("qualification_accepted") is not False
            or repair.get("unknown_high_findings") is not False
            or repair.get("hosted_cleanup_outcome") != "unknown"
            or repair.get("outer_runtime_cleanup") != "unknown"
            or repair.get("inner_row_cleanup") != "confirmed"
            or repair.get("inner_row_bound") != "none"
            or type(repair.get("batch_return")) is not int
            or repair.get("batch_return") != 1
            or repair.get("desktop_child_return") != "unknown"
            or repair.get("original_failure_cause") != "unknown"):
        raise ValueError(label)
    nonce = journal.get("qualification_dispatch_nonce")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (run.get("id") != run_id or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed" or run.get("conclusion") != "failure"
            or run.get("path") != ".github/workflows/ci.yml"
            or run.get("head_branch") != "main"
            or run.get("name") != f"Plan10 qualification {nonce}"
            or run.get("head_sha") != journal.get("public_source_sha")
            or run.get("created_at") != journal.get("selected_run_created_at")
            or type(run.get("run_attempt")) is not int or run.get("run_attempt") <= 0
            or run.get("run_attempt") != terminal.get("run_attempt")
            or run.get("display_title") != f"Plan10 qualification {nonce}"
            or not isinstance(repository, dict)
            or repository.get("full_name") != "szTheory/genewhip"
            or repository.get("private") is not False
            or not isinstance(repository.get("owner"), dict)
            or repository["owner"].get("login") != "szTheory"
            or not isinstance(head_repository, dict)
            or head_repository.get("full_name") != "szTheory/genewhip"
            or head_repository.get("private") is not False
            or not isinstance(run.get("head_commit"), dict)
            or run["head_commit"].get("id") != journal.get("public_source_sha")
            or run["head_commit"].get("tree_id") != journal.get("tree_sha")):
        raise ValueError(label)
    if (terminal.get("event") != "workflow_dispatch"
            or terminal.get("run_status") != "completed"
            or terminal.get("run_conclusion") != "failure"
            or terminal.get("head_sha") != journal.get("public_source_sha")
            or terminal.get("created_at") != run.get("created_at")
            or terminal.get("qualification_dispatch_nonce") != nonce
            or terminal.get("started_at") != journal.get("started_at")
            or terminal.get("attempt_root") != expected_root):
        raise ValueError(label)
    rows = terminal["jobs"]
    names = [row.get("name") for row in rows if isinstance(row, dict)]
    snapshot_names = [row.get("name") for row in snapshot_jobs if isinstance(row, dict)]
    by_name = {row.get("name"): row for row in rows if isinstance(row, dict)}
    normalized_snapshot = [{key: row.get(key) for key in ("id", "name", "status", "conclusion")}
                           for row in snapshot_jobs if isinstance(row, dict)]
    packet_jobs = packet.get("jobs") if isinstance(packet, dict) else None
    raw_jobs_by_name = {row.get("name"): row for row in snapshot_jobs if isinstance(row, dict)}
    packet_jobs_by_name = {row.get("name"): row for row in packet_jobs
                           if isinstance(row, dict)} if isinstance(packet_jobs, list) else {}
    failed_steps_by_name: dict[str, list[str]] = {}
    for name in NATIVE_HOST_RUNTIME_JOBS:
        steps = raw_jobs_by_name.get(name, {}).get("steps")
        if steps is None:
            steps = []
        if not isinstance(steps, list):
            raise ValueError(label)
        failed_steps_by_name[name] = [step.get("name") for step in steps
            if isinstance(step, dict) and step.get("conclusion") == "failure"]
    if (len(rows) != 16 or len(names) != 16 or len(set(names)) != 16
            or set(names) != NATIVE_HOST_RUNTIME_JOBS
            or len(snapshot_jobs) != 16 or len(snapshot_names) != 16
            or len(set(snapshot_names)) != 16 or set(snapshot_names) != NATIVE_HOST_RUNTIME_JOBS
            or normalized_snapshot != rows
            or not isinstance(packet_jobs, list) or len(packet_jobs) != 16
            or len(packet_jobs_by_name) != 16 or set(packet_jobs_by_name) != NATIVE_HOST_RUNTIME_JOBS
            or {name: by_name[name].get("conclusion") for name in NATIVE_HOST_RUNTIME_JOBS}
                != NATIVE_HOST_RUNTIME_OUTCOMES
            or any(by_name[name].get("status") != "completed"
                or type(by_name[name].get("id")) is not int or by_name[name]["id"] <= 0
                for name in NATIVE_HOST_RUNTIME_JOBS)
            or len({by_name[name]["id"] for name in NATIVE_HOST_RUNTIME_JOBS}) != 16
            or any(any(packet_jobs_by_name[name].get(key) != by_name[name].get(key)
                    for key in ("id", "name", "status", "conclusion"))
                or packet_jobs_by_name[name].get("failed_steps") != failed_steps_by_name[name]
                for name in NATIVE_HOST_RUNTIME_JOBS)):
        raise ValueError(label)
    runtime_job = by_name["v02-runtime"]
    packet_failure = packet.get("runtime_failure")
    coordinator_terminal = packet.get("coordinator_terminal")
    if (not isinstance(packet_failure, dict) or not isinstance(coordinator_terminal, dict)
            or coordinator_terminal.get("exit_code") != 1
            or coordinator_terminal.get("failure_record_reason") != "fresh-batch-qualification-failed"
            or coordinator_terminal.get("failure_record_stage") != "qualification"
            or runtime_job.get("id") != packet_failure.get("job_id")
            or packet_jobs_by_name["v02-runtime"].get("failed_steps") != [
                "Run complete current-source product safety and chunk roster"]
            or packet_jobs_by_name["required-ci"].get("failed_steps") != [
                "Reject incomplete or stale required lanes"]
            or packet.get("workflow_run") != {key: run.get(key) for key in (
                "id", "name", "event", "status", "conclusion", "created_at",
                "head_sha", "path", "run_attempt", "display_title", "html_url")}
            or packet.get("job_totals") != {"conclusions": {
                "failure": 2, "skipped": 7, "success": 7}, "total": 16}
            or packet.get("attempt_root") != expected_root
            or packet.get("nonce") != nonce
            or packet.get("source_commit") != journal.get("public_source_sha")
            or packet.get("public_tree") != journal.get("tree_sha")
            or packet.get("qualification_state") !=
                "failed/nonqualifying; no acceptance, inventory, or release claim"):
        raise ValueError(label)
    safe_line = ("REJECT: qualification-child-failed:runtime:1:BLOCKED: "
        "phase7-host-batch-failed:backend=native;report=fail;"
        "case=recursion94/withhold-first-plate;row=fail;return=1;"
        "cleanup=confirmed;bound=none;cleanup_reason=missing;"
        "status_observation=missing;cleanup_queries=other")
    log_bytes = raw_by_key["hosted_log"]
    if (not isinstance(packet_failure, dict)
            or packet_failure.get("bounded_failure_line") != safe_line
            or packet_failure.get("cause_limit") !=
                "Retained hosted log has no underlying assertion/test traceback; do not infer cause."
            or packet_failure.get("failed_step") !=
                "Run complete current-source product safety and chunk roster"
            or packet_failure.get("job_id") != runtime_job["id"]
            or packet_failure.get("log") != {"bytes": len(log_bytes), "path": paths["hosted_log"],
                "sha256": terminal["hosted_log"]["sha256"]}
            or safe_line.encode("utf-8") not in log_bytes):
        raise ValueError(label)
    pr = terminal.get("pull_request")
    if (not isinstance(pr, dict)
            or terminal.get("diagnostic_profile") != NATIVE_HOST_RUNTIME_PROFILE
            or terminal.get("owning_case") != NATIVE_HOST_RUNTIME_CASE
            or terminal.get("failed_lane") != "v02-runtime"
            or terminal.get("inner_row_cleanup") != "confirmed"
            or terminal.get("inner_row_bound") != "none"
            or type(terminal.get("batch_return")) is not int
            or terminal.get("batch_return") != 1
            or terminal.get("outer_runtime_cleanup") != "unknown"
            or terminal.get("hosted_cleanup_outcome") != "unknown"
            or terminal.get("desktop_child_return") != "unknown"
            or terminal.get("original_failure_cause") != "unknown"
            or terminal.get("local_monitor_safety_issue") is not False
            or terminal.get("local_monitor_cleanup") != "confirmed"
            or terminal.get("safety_job_failed") is not False
            or terminal.get("qualification_accepted") is not False
            or terminal.get("full_qualification_dispatched") is not True
            or terminal.get("merge_attempted") is not True
            or pr.get("merged") is not True or pr.get("state") != "closed"
            or type(pr.get("number")) is not int or pr["number"] <= 0):
        raise ValueError(label)
    packet_pr = packet.get("pull_request")
    if (not isinstance(packet_pr, dict)
            or any(packet_pr.get(key) != pr.get(key) for key in
                ("number", "state", "merged", "head_sha", "base_sha", "merge_commit_sha"))):
        raise ValueError(label)
    if (journal.get("schema") != "genewhip.v02-delivery-journal.v1"
            or journal.get("repository") != "szTheory/genewhip"
            or journal.get("source_head") != pr.get("head_sha")
            or journal.get("public_base_sha") != pr.get("base_sha")
            or journal.get("public_source_sha") != pr.get("merge_commit_sha")
            or journal.get("started_at") != terminal.get("started_at")
            or journal.get("qualification_started_at") != journal.get("started_at")
            or journal.get("qualification_dispatch_requested") is not True
            or journal.get("qualification_dispatch_submitted") is not True
            or journal.get("qualification_dispatch_nonce") != terminal.get("qualification_dispatch_nonce")
            or journal.get("public_source_sha") != terminal.get("head_sha")
            or journal.get("tree_sha") != packet.get("public_tree")
            or journal.get("pull_request") != str(pr.get("number"))
            or journal.get("merge_parents") != [journal.get("public_base_sha")]
            or journal.get("merge_strategy") != "squash"):
        raise ValueError(label)
    if (source_delivery.get("status") != "merged"
            or source_delivery.get("schema") != "genewhip.v02-public-source-delivery.v1"
            or source_delivery.get("public_source_sha") != journal.get("public_source_sha")
            or source_delivery.get("public_base_sha") != journal.get("public_base_sha")
            or source_delivery.get("candidate_sha") != journal.get("candidate_sha")
            or source_delivery.get("tree_sha") != journal.get("tree_sha")
            or source_delivery.get("pull_request") != journal.get("pull_request")
            or source_delivery.get("merge_parents") != journal.get("merge_parents")
            or source_delivery.get("merge_strategy") != journal.get("merge_strategy")):
        raise ValueError(label)
    if (failure.get("schema") != "genewhip.phase7-fresh-batch-failure.v1"
            or failure.get("authorization_sha256") != AUTH_SHA256
            or failure.get("stage") != "qualification"
            or failure.get("reason") != "fresh-batch-qualification-failed"
            or failure.get("observed_at") != coordinator_terminal.get("failure_record_observed_at")):
        raise ValueError(label)


def _validate_native_result_handoff_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any],
        failure: dict[str, Any]) -> None:
    """Bind attempt17's failed collector handoff without inferring its private cause."""
    label = "fresh-batch-native-result-handoff-invalid"
    expected_paths = {
        "workflow_run": f"{expected_root}/ci-failure/native-workflow-run-{NATIVE_RESULT_HANDOFF_RUN_ID}.json",
        "jobs": f"{expected_root}/ci-failure/native-jobs-{NATIVE_RESULT_HANDOFF_RUN_ID}.json",
        "workflow_extraction": f"{expected_root}/ci-failure/native-workflow-run-extraction.json",
        "workflow_log": f"{expected_root}/ci-failure/native-job-124713044938.log",
        "diagnostic_assessment": f"{expected_root}/ci-failure/native-diagnostic-assessment-input.json",
        "public_admission": f"{expected_root}/public-admission.json",
        "readiness": f"{expected_root}/native-diagnostic-readiness.json",
        "dispatch": f"{expected_root}/native-diagnostic/dispatch.json",
        "result": f"{expected_root}/native-diagnostic/result.json",
        "downloaded_report": f"{expected_root}/native-diagnostic/download/native-diagnostic.json",
    }
    refs = terminal.get("diagnostic_artifacts")
    if not isinstance(refs, dict) or set(refs) != set(expected_paths):
        raise ValueError(label)
    caps = {"workflow_run": 65536, "jobs": MAX_ADMISSION_BYTES,
        "workflow_extraction": MAX_REVIEW_BYTES, "workflow_log": 256 * 1024,
        "diagnostic_assessment": MAX_ADMISSION_BYTES, "public_admission": MAX_ADMISSION_BYTES,
        "readiness": MAX_ADMISSION_BYTES, "dispatch": MAX_REVIEW_BYTES,
        "result": 65536, "downloaded_report": 65536}
    raw_values: dict[str, bytes] = {}
    values: dict[str, Any] = {}
    for key, path in expected_paths.items():
        ref = refs.get(key)
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or ref.get("path") != path:
            raise ValueError(label)
        raw = _read_regular(_path(root, _safe_relative(path, label)), cap=caps[key], label=label)
        if not isinstance(ref.get("sha256"), str) or _digest(raw) != ref["sha256"]:
            raise ValueError(label)
        raw_values[key] = raw
        if key == "workflow_log":
            continue
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(label) from None
        if key == "jobs":
            if not isinstance(parsed, dict) or set(parsed) != {"jobs"} or not isinstance(parsed["jobs"], list):
                raise ValueError(label)
            values[key] = parsed["jobs"]
        else:
            values[key] = _json_object(raw, label)

    run, jobs = values["workflow_run"], values["jobs"]
    extraction, dispatch = values["workflow_extraction"], values["dispatch"]
    result, report = values["result"], values["downloaded_report"]
    if (run.get("id") != NATIVE_RESULT_HANDOFF_RUN_ID
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
            or run.get("conclusion") != "failure" or run.get("run_attempt") != 1
            or run.get("path") != ".github/workflows/ci.yml"
            or run.get("head_sha") != NATIVE_RESULT_HANDOFF_SOURCE_SHA
            or run.get("head_branch") != "v0.2-source-122852cf824b"
            or run.get("name") != "Plan10 native diagnostic " + NATIVE_RESULT_HANDOFF_NONCE
            or run.get("display_title") != run.get("name")
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != "szTheory/genewhip"
            or run["repository"].get("private") is not False):
        raise ValueError(label)
    names = set(NATIVE_HOST_RUNTIME_JOBS)
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    if (len(jobs) != 16 or len(by_name) != 16 or set(by_name) != names
            or any(not isinstance(row, dict) or row.get("status") != "completed"
                or type(row.get("id")) is not int or row.get("id") <= 0
                or row.get("run_id") != NATIVE_RESULT_HANDOFF_RUN_ID for row in jobs)
            or len({row["id"] for row in jobs}) != 16
            or by_name["v02-runtime"].get("conclusion") != "failure"
            or any(by_name[name].get("conclusion") != "skipped" for name in names - {"v02-runtime"})):
        raise ValueError(label)
    if (extraction.get("selected_run_id") != NATIVE_RESULT_HANDOFF_RUN_ID
            or extraction.get("source_receipt_sha256") !=
                "5bcc27d0678a06ddae652b317d889aa8b4db63bc6ce61a079fed99087b9b98f3"):
        raise ValueError(label)
    if (dispatch.get("schema") != "genewhip.phase7-native-diagnostic-dispatch.v1"
            or dispatch.get("run_id") != NATIVE_RESULT_HANDOFF_RUN_ID
            or dispatch.get("dispatches") != 1 or dispatch.get("nonce") != NATIVE_RESULT_HANDOFF_NONCE
            or dispatch.get("source_sha") != NATIVE_RESULT_HANDOFF_SOURCE_SHA
            or dispatch.get("status") != "completed-assessment-required"
            or dispatch.get("qualification_accepted") is not False
            or dispatch.get("started_at") != journal.get("started_at")):
        raise ValueError(label)
    if (_digest(raw_values["result"]) != NATIVE_RESULT_HANDOFF_RESULT_SHA256
            or _digest(_canonical(result)) != NATIVE_RESULT_HANDOFF_PAYLOAD_SHA256
            or result.get("schema") != "genewhip.phase7-native-diagnostic-result.v1"
            or result.get("status") != "fail" or result.get("qualification_accepted") is not False
            or result.get("assessment_required") is not True
            or result.get("run_id") != str(NATIVE_RESULT_HANDOFF_RUN_ID)
            or result.get("run_attempt") != "1"
            or result.get("source_sha") != NATIVE_RESULT_HANDOFF_SOURCE_SHA
            or result.get("report_sha256") != NATIVE_RESULT_HANDOFF_REPORT_SHA256
            or result.get("report_path") != expected_paths["downloaded_report"]):
        raise ValueError(label)
    identity = report.get("identity")
    stages = report.get("stages")
    if (report.get("schema") != "genewhip-phase7-one-case-diagnostic-v1"
            or report.get("status") != "fail" or report.get("diagnostic_only") is not True
            or report.get("qualification_accepted") is not False
            or report.get("fixture") != "recursion94" or report.get("case") != "withhold-first-plate"
            or report.get("failure_category") is not None or report.get("outer_rejection") is not None
            or report.get("outer_process") != {"status": "completed", "return_code": "zero",
                "cleanup": "confirmed", "bound_violation": False}
            or not isinstance(identity, dict)
            or identity != {"source_sha": NATIVE_RESULT_HANDOFF_SOURCE_SHA,
                "head_sha": NATIVE_RESULT_HANDOFF_SOURCE_SHA,
                "base_sha": "d4865061f524a8637342562710af72dd2d583ae3",
                "run_id": str(NATIVE_RESULT_HANDOFF_RUN_ID), "run_attempt": "1"}
            or not isinstance(stages, list) or len(stages) != 3
            or [row.get("name") for row in stages if isinstance(row, dict)] !=
                ["input-contract", "headless-reference", "native-sdl-comparison"]
            or any(not isinstance(row, dict) or row.get("status") != "not-run"
                for row in stages)):
        raise ValueError(label)
    log = raw_values["workflow_log"]
    if (b"native-diagnostic: fail; qualification_accepted=false" not in log
            or b"Process completed with exit code 1." not in log
            or b"Run python3 -I scripts/release/v02_qualification.py --mode native-diagnostic" not in log):
        raise ValueError(label)

    source_path = f"{expected_root}/source-admission.json"
    source_admission, _ = _read_reference(root, {"path": source_path,
        "sha256": terminal.get("source_admission_sha256")}, label=label)
    source_keys = set(source_admission)
    if (_digest(raw_values["public_admission"]) != NATIVE_RESULT_HANDOFF_PUBLIC_ADMISSION_SHA256
            or _digest(raw_values["readiness"]) != NATIVE_RESULT_HANDOFF_READINESS_SHA256
            or source_keys != set(values["public_admission"]) - {"candidate"}
            or source_admission.get("status") != "source-preparation"
            or values["public_admission"].get("status") != "public-effects"
            or any(source_admission[key] != values["public_admission"][key]
                   for key in source_keys - {"status"})):
        raise ValueError(label)
    _validate_native_readiness(root, root / expected_root, values["public_admission"],
        NATIVE_RESULT_HANDOFF_PUBLIC_ADMISSION_SHA256,
        _path(root, _safe_relative(expected_paths["readiness"], label)),
        NATIVE_RESULT_HANDOFF_READINESS_SHA256)

    if (terminal.get("owning_case") != NATIVE_RESULT_HANDOFF_CASE
            or terminal.get("diagnostic_profile") != NATIVE_RESULT_HANDOFF_PROFILE
            or terminal.get("diagnostic_outer_cleanup") != "confirmed"
            or terminal.get("diagnostic_outer_return") != "zero"
            or terminal.get("diagnostic_outer_bound_violation") is not False
            or terminal.get("diagnostic_outer_rejection") is not None
            or terminal.get("diagnostic_workload_outcome") != "unavailable"
            or terminal.get("private_collector_rejection_cause") != "unknown"
            or terminal.get("private_collector_bytes") != "unknown"
            or repair.get("diagnostic_case") != NATIVE_RESULT_HANDOFF_CASE
            or repair.get("diagnostic_profile") != NATIVE_RESULT_HANDOFF_PROFILE
            or repair.get("diagnostic_only") is not True
            or repair.get("live_retry_authorized") is not False
            or repair.get("qualification_accepted") is not False
            or repair.get("unknown_high_findings") is not False
            or repair.get("safety_job_failed") is not False
            or repair.get("had_safety_job_failure") is not False
            or repair.get("hosted_cleanup_outcome") != "unknown"
            or repair.get("diagnostic_outer_cleanup") != "confirmed"
            or repair.get("diagnostic_outer_return") != "zero"
            or repair.get("diagnostic_outer_bound_violation") is not False
            or repair.get("diagnostic_outer_rejection") is not None
            or repair.get("diagnostic_workload_outcome") != "unavailable"
            or repair.get("private_collector_rejection_cause") != "unknown"
            or repair.get("private_collector_bytes") != "unknown"
            or repair.get("original_failure_cause") != "unknown"
            or repair.get("full_qualification_dispatched") is not False
            or repair.get("merge_attempted") is not False
            or not isinstance(terminal.get("pull_request"), dict)
            or terminal["pull_request"].get("number") != 42
            or terminal["pull_request"].get("merged") is not False
            or terminal["pull_request"].get("state") != "open"
            or terminal["pull_request"].get("head_sha") != NATIVE_RESULT_HANDOFF_SOURCE_SHA
            or terminal["pull_request"].get("base_sha") != "d4865061f524a8637342562710af72dd2d583ae3"):
        raise ValueError(label)
    reviews = repair.get("result_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError(label)
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=NATIVE_RESULT_HANDOFF_PAYLOAD_SHA256)
        review_path = _path(root, _safe_relative(reviews[key]["path"], label))
        frontmatter = _frontmatter(_read_regular(review_path, cap=MAX_REVIEW_BYTES, label=label))
        if frontmatter.get("source_head") != "d85ac14471964cbde5109b3587b781ab997b9446":
            raise ValueError(label)


def _validate_native_input_mask_alignment_artifacts(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any],
        failure: dict[str, Any]) -> None:
    """Bind attempt18's failed input-mask handoff without assigning an unproven cause."""
    label = "fresh-batch-native-input-mask-alignment-invalid"
    expected_paths = {
        "workflow_run": f"{expected_root}/ci-failure/native-workflow-run-{NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID}.json",
        "jobs": f"{expected_root}/ci-failure/native-jobs-{NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID}.json",
        "workflow_extraction": f"{expected_root}/ci-failure/native-workflow-run-extraction.json",
        "workflow_log": f"{expected_root}/ci-failure/native-job-124727922235.log",
        "diagnostic_assessment": f"{expected_root}/ci-failure/native-diagnostic-assessment-input.json",
        "public_admission": f"{expected_root}/public-admission.json",
        "readiness": f"{expected_root}/native-diagnostic-readiness.json",
        "dispatch": f"{expected_root}/native-diagnostic/dispatch.json",
        "result": f"{expected_root}/native-diagnostic/result.json",
        "downloaded_report": f"{expected_root}/native-diagnostic/download/native-diagnostic.json",
        "source_delivery": f"{expected_root}/source-delivery.json",
        "pull_request_receipt": f"{expected_root}/ci-failure/pull-request-43.json",
    }
    refs = terminal.get("diagnostic_artifacts")
    if not isinstance(refs, dict) or set(refs) != set(expected_paths):
        raise ValueError(label)
    caps = {"workflow_run": 65536, "jobs": MAX_ADMISSION_BYTES,
        "workflow_extraction": MAX_REVIEW_BYTES, "workflow_log": 256 * 1024,
        "diagnostic_assessment": MAX_ADMISSION_BYTES, "public_admission": MAX_ADMISSION_BYTES,
        "readiness": MAX_ADMISSION_BYTES, "dispatch": MAX_REVIEW_BYTES,
        "result": 65536, "downloaded_report": 65536,
        "source_delivery": MAX_ADMISSION_BYTES, "pull_request_receipt": MAX_ADMISSION_BYTES}
    expected_hashes = {
        "workflow_run": NATIVE_INPUT_MASK_ALIGNMENT_RUN_SHA256,
        "jobs": NATIVE_INPUT_MASK_ALIGNMENT_JOBS_SHA256,
        "workflow_extraction": NATIVE_INPUT_MASK_ALIGNMENT_EXTRACTION_SHA256,
        "workflow_log": NATIVE_INPUT_MASK_ALIGNMENT_LOG_SHA256,
        "diagnostic_assessment": NATIVE_INPUT_MASK_ALIGNMENT_ASSESSMENT_SHA256,
        "public_admission": NATIVE_INPUT_MASK_ALIGNMENT_PUBLIC_ADMISSION_SHA256,
        "readiness": NATIVE_INPUT_MASK_ALIGNMENT_READINESS_SHA256,
        "dispatch": NATIVE_INPUT_MASK_ALIGNMENT_DISPATCH_SHA256,
        "result": NATIVE_INPUT_MASK_ALIGNMENT_RESULT_SHA256,
        "downloaded_report": NATIVE_INPUT_MASK_ALIGNMENT_REPORT_SHA256,
        "source_delivery": NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_DELIVERY_SHA256,
        "pull_request_receipt": "556a4d9dee1b585c9c18285da21d115cdb8f14891fa869617feded000ef8a387",
    }
    raw_values: dict[str, bytes] = {}
    values: dict[str, Any] = {}
    for key, path in expected_paths.items():
        ref = refs.get(key)
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or ref.get("path") != path:
            raise ValueError(label)
        raw = _read_regular(_path(root, _safe_relative(path, label)), cap=caps[key], label=label)
        if _digest(raw) != expected_hashes[key] or ref.get("sha256") != expected_hashes[key]:
            raise ValueError(label)
        raw_values[key] = raw
        if key == "workflow_log":
            continue
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(label) from None
        if key == "jobs":
            if not isinstance(parsed, dict) or set(parsed) != {"jobs"} or not isinstance(parsed["jobs"], list):
                raise ValueError(label)
            values[key] = parsed["jobs"]
        else:
            values[key] = _json_object(raw, label)

    run, jobs = values["workflow_run"], values["jobs"]
    extraction, dispatch = values["workflow_extraction"], values["dispatch"]
    result, report = values["result"], values["downloaded_report"]
    if (run.get("id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
            or run.get("conclusion") != "failure" or run.get("run_attempt") != 1
            or run.get("path") != ".github/workflows/ci.yml"
            or run.get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or run.get("head_branch") != "v0.2-source-ff937606a779"
            or run.get("name") != "Plan10 native diagnostic " + NATIVE_INPUT_MASK_ALIGNMENT_NONCE
            or run.get("display_title") != run.get("name")
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != "szTheory/genewhip"
            or run["repository"].get("private") is not False):
        raise ValueError(label)
    names = set(NATIVE_HOST_RUNTIME_JOBS)
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    if (len(jobs) != 16 or len(by_name) != 16 or set(by_name) != names
            or any(not isinstance(row, dict) or row.get("status") != "completed"
                or type(row.get("id")) is not int or row.get("id") <= 0
                or row.get("run_id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID for row in jobs)
            or len({row["id"] for row in jobs}) != 16
            or by_name["v02-runtime"].get("id") != 124727922235
            or by_name["v02-runtime"].get("conclusion") != "failure"
            or any(by_name[name].get("conclusion") != "skipped"
                for name in names - {"v02-runtime"})):
        raise ValueError(label)
    if (extraction.get("selected_run_id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID
            or not isinstance(extraction.get("source_receipt_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", extraction["source_receipt_sha256"]) is None):
        raise ValueError(label)
    if (_digest(_canonical(failure)) != NATIVE_INPUT_MASK_ALIGNMENT_FAILURE_PAYLOAD_SHA256
            or failure.get("schema") != "genewhip.phase7-fresh-batch-failure.v1"
            or failure.get("authorization_sha256") != AUTH_SHA256
            or failure.get("stage") != "preview-ci"
            or failure.get("reason") != "diagnostic-ci-complete-assessment-required"
            or journal.get("schema") != "genewhip.v02-delivery-journal.v1"
            or journal.get("repository") != "szTheory/genewhip"
            or journal.get("source_head") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or journal.get("public_base_sha") != "d4865061f524a8637342562710af72dd2d583ae3"
            or journal.get("push_performed") is not True
            or journal.get("started_at") != dispatch.get("started_at")
            or journal.get("diagnostic_ci_status") != "passed"
            or journal.get("merge_attempted") is not False):
        raise ValueError(label)
    if (dispatch.get("schema") != "genewhip.phase7-native-diagnostic-dispatch.v1"
            or dispatch.get("run_id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID
            or dispatch.get("dispatches") != 1 or dispatch.get("nonce") != NATIVE_INPUT_MASK_ALIGNMENT_NONCE
            or dispatch.get("source_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or dispatch.get("status") != "completed-assessment-required"
            or dispatch.get("qualification_accepted") is not False
            or dispatch.get("started_at") != journal.get("started_at")):
        raise ValueError(label)
    if (_digest(raw_values["result"]) != NATIVE_INPUT_MASK_ALIGNMENT_RESULT_SHA256
            or _digest(_canonical(result)) != NATIVE_INPUT_MASK_ALIGNMENT_RESULT_PAYLOAD_SHA256
            or result.get("schema") != "genewhip.phase7-native-diagnostic-result.v1"
            or result.get("status") != "fail" or result.get("qualification_accepted") is not False
            or result.get("assessment_required") is not True
            or result.get("run_id") != str(NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID)
            or result.get("run_attempt") != "1"
            or result.get("source_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or result.get("report_sha256") != NATIVE_INPUT_MASK_ALIGNMENT_REPORT_SHA256
            or result.get("report_path") != expected_paths["downloaded_report"]):
        raise ValueError(label)
    identity = report.get("identity")
    stages = report.get("stages")
    if (report.get("schema") != "genewhip-phase7-one-case-diagnostic-v2"
            or report.get("status") != "fail" or report.get("diagnostic_only") is not True
            or report.get("qualification_accepted") is not False
            or report.get("fixture") != "recursion94" or report.get("case") != "withhold-first-plate"
            or report.get("collector_read_status") != "invalid"
            or report.get("failure_category") != "collector-handoff-invalid"
            or report.get("outer_rejection") is not None
            or report.get("outer_process") != {"status": "completed", "return_code": "zero",
                "cleanup": "confirmed", "bound_violation": False}
            or not isinstance(identity, dict)
            or identity != {"source_sha": NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA,
                "head_sha": NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA,
                "base_sha": "d4865061f524a8637342562710af72dd2d583ae3",
                "run_id": str(NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID), "run_attempt": "1"}
            or not isinstance(stages, list) or len(stages) != 3
            or [row.get("name") for row in stages if isinstance(row, dict)] !=
                ["input-contract", "headless-reference", "native-sdl-comparison"]
            or any(not isinstance(row, dict) or row.get("status") != "unavailable"
                for row in stages)):
        raise ValueError(label)
    log = raw_values["workflow_log"]
    if (b"native-diagnostic: fail; qualification_accepted=false" not in log
            or b"Process completed with exit code 1." not in log
            or b"Run python3 -I scripts/release/v02_qualification.py --mode native-diagnostic" not in log):
        raise ValueError(label)

    source_path = f"{expected_root}/source-admission.json"
    source_admission, _ = _read_reference(root, {"path": source_path,
        "sha256": terminal.get("source_admission_sha256")}, label=label)
    source_keys = set(source_admission)
    public_admission = values["public_admission"]
    if (source_keys != set(public_admission) - {"candidate"}
            or source_admission.get("status") != "source-preparation"
            or public_admission.get("status") != "public-effects"
            or any(source_admission[key] != public_admission[key] for key in source_keys - {"status"})
            or not isinstance(public_admission.get("candidate"), dict)
            or public_admission["candidate"].get("public_head") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or public_admission["candidate"].get("public_base") != "d4865061f524a8637342562710af72dd2d583ae3"):
        raise ValueError(label)
    _validate_native_readiness(root, root / expected_root, public_admission,
        NATIVE_INPUT_MASK_ALIGNMENT_PUBLIC_ADMISSION_SHA256,
        _path(root, _safe_relative(expected_paths["readiness"], label)),
        NATIVE_INPUT_MASK_ALIGNMENT_READINESS_SHA256)
    assessment = values["diagnostic_assessment"]
    if (assessment.get("schema") != "genewhip.phase7-diagnostic-assessment-input.v1"
            or assessment.get("disposition") != "diagnostic-preview-green-assessment-required"
            or assessment.get("qualification_credit") is not False
            or assessment.get("source_and_candidate", {}).get("private_source_head") != source_admission.get("source_head")
            or assessment.get("source_and_candidate", {}).get("candidate_head") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or assessment.get("source_and_candidate", {}).get("public_admission_sha256") !=
                NATIVE_INPUT_MASK_ALIGNMENT_PUBLIC_ADMISSION_SHA256
            or assessment.get("source_and_candidate", {}).get("preparation_sha256") !=
                NATIVE_INPUT_MASK_ALIGNMENT_PREPARATION_SHA256
            or assessment.get("source_and_candidate", {}).get("manifest_sha256") !=
                NATIVE_INPUT_MASK_ALIGNMENT_MANIFEST_SHA256):
        raise ValueError(label)
    github = assessment.get("github")
    preview_jobs = github.get("jobs") if isinstance(github, dict) else None
    preview_by_name = {row.get("name"): row for row in preview_jobs if isinstance(row, dict)} \
        if isinstance(preview_jobs, list) else {}
    if (not isinstance(preview_jobs, list) or len(preview_jobs) != 16
            or set(preview_by_name) != NATIVE_HOST_RUNTIME_JOBS
            or len(preview_by_name) != 16
            or github.get("workflow_run", {}).get("conclusion") != "success"
            or github.get("workflow_run", {}).get("event") != "pull_request"
            or github.get("workflow_run", {}).get("id") != 41264591599
            or github.get("merged") is not False or github.get("pull_request") != 43
            or github.get("pull_request_state") != "open"
            or github.get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or github.get("base_sha") != "d4865061f524a8637342562710af72dd2d583ae3"
            or any(preview_by_name[name].get("status") != "completed"
                or preview_by_name[name].get("conclusion") != "success"
                for name in PREVIEW_REQUIRED_LANES)
            or any(preview_by_name[name].get("status") != "completed"
                or preview_by_name[name].get("conclusion") != "skipped"
                for name in PREVIEW_CONDITIONAL_SKIPS)):
        raise ValueError(label)
    pr = values["pull_request_receipt"]
    if (pr.get("number") != 43 or pr.get("state") != "open"
            or pr.get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or pr.get("base_sha") != "d4865061f524a8637342562710af72dd2d583ae3"):
        raise ValueError(label)
    if (_digest(raw_values["source_delivery"]) != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_DELIVERY_SHA256
            or values["source_delivery"].get("status") != "diagnostic-ci-complete"
            or values["source_delivery"].get("candidate_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or values["source_delivery"].get("public_base_sha") != "d4865061f524a8637342562710af72dd2d583ae3"
            or values["source_delivery"].get("merge_attempted") is not False):
        raise ValueError(label)
    if (terminal.get("owning_case") != NATIVE_INPUT_MASK_ALIGNMENT_CASE
            or terminal.get("diagnostic_profile") != NATIVE_INPUT_MASK_ALIGNMENT_PROFILE
            or terminal.get("run_status") != "completed" or terminal.get("run_conclusion") != "failure"
            or terminal.get("workflow_run_id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID
            or terminal.get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or terminal.get("diagnostic_nonce") != NATIVE_INPUT_MASK_ALIGNMENT_NONCE
            or terminal.get("diagnostic_outer_cleanup") != "confirmed"
            or terminal.get("diagnostic_outer_return") != "zero"
            or terminal.get("diagnostic_outer_bound_violation") is not False
            or terminal.get("diagnostic_outer_rejection") is not None
            or terminal.get("diagnostic_workload_outcome") != "unavailable"
            or terminal.get("hosted_cleanup_outcome") != "unknown"
            or terminal.get("original_failure_cause") != "unknown"
            or terminal.get("private_collector_rejection_cause") != "unknown"
            or terminal.get("private_collector_bytes") != "unknown"
            or terminal.get("qualification_accepted") is not False
            or terminal.get("full_qualification_dispatched") is not False
            or terminal.get("merge_attempted") is not False
            or terminal.get("safety_job_failed") is not False
            or not isinstance(terminal.get("pull_request"), dict)
            or terminal["pull_request"].get("number") != 43
            or terminal["pull_request"].get("state") != "open"
            or terminal["pull_request"].get("merged") is not False
            or terminal["pull_request"].get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
            or repair.get("diagnostic_case") != NATIVE_INPUT_MASK_ALIGNMENT_CASE
            or repair.get("diagnostic_profile") != NATIVE_INPUT_MASK_ALIGNMENT_PROFILE
            or repair.get("diagnostic_only") is not True
            or repair.get("live_retry_authorized") is not False
            or repair.get("diagnostic_workload_outcome") != "unavailable"
            or repair.get("hosted_cleanup_outcome") != "unknown"
            or repair.get("original_failure_cause") != "unknown"
            or repair.get("private_collector_rejection_cause") != "unknown"
            or repair.get("private_collector_bytes") != "unknown"
            or repair.get("qualification_accepted") is not False
            or repair.get("full_qualification_dispatched") is not False
            or repair.get("merge_attempted") is not False
            or repair.get("unknown_high_findings") is not False):
        raise ValueError(label)
    reviews = repair.get("result_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError(label)
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role,
            payload_sha256=NATIVE_INPUT_MASK_ALIGNMENT_RESULT_PAYLOAD_SHA256)
        review_path = _path(root, _safe_relative(reviews[key]["path"], label))
        if _frontmatter(_read_regular(review_path, cap=MAX_REVIEW_BYTES, label=label)).get("source_head") != \
                source_admission.get("source_head"):
            raise ValueError(label)


def _validate_accepted_native_diagnostic(root: Path, *, expected_root: str,
        terminal: dict[str, Any], repair: dict[str, Any], journal: dict[str, Any],
        failure: dict[str, Any]) -> dict[str, Any]:
    """Accept only a fully reviewed successful one-case diagnostic as a continuation boundary."""
    label = "fresh-batch-accepted-native-diagnostic-invalid"
    run_id = terminal.get("workflow_run_id")
    source = terminal.get("head_sha")
    nonce = terminal.get("diagnostic_nonce")
    pr = terminal.get("pull_request")
    if (type(run_id) is not int or run_id <= 0
            or not isinstance(source, str) or re.fullmatch(r"[0-9a-f]{40}", source) is None
            or not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
            or not isinstance(pr, dict) or type(pr.get("number")) is not int or pr["number"] <= 0):
        raise ValueError(label)
    expected_paths = {
        "workflow_run": f"{expected_root}/ci-failure/native-workflow-run-{run_id}.json",
        "jobs": f"{expected_root}/ci-failure/native-jobs-{run_id}.json",
        "workflow_extraction": f"{expected_root}/ci-failure/native-workflow-run-extraction.json",
        "workflow_log": f"{expected_root}/ci-failure/native-job-{terminal.get('runtime_job_id')}.log",
        "dispatch": f"{expected_root}/native-diagnostic/dispatch.json",
        "result": f"{expected_root}/native-diagnostic/result.json",
        "downloaded_report": f"{expected_root}/native-diagnostic/download/native-diagnostic.json",
        "public_admission": f"{expected_root}/public-admission.json",
        "readiness": f"{expected_root}/native-diagnostic-readiness.json",
    }
    refs = terminal.get("diagnostic_artifacts")
    if (type(terminal.get("runtime_job_id")) is not int
            or terminal.get("runtime_job_id") <= 0
            or not isinstance(refs, dict) or set(refs) != set(expected_paths)):
        raise ValueError(label)
    caps = {"workflow_run": 65536, "jobs": MAX_ADMISSION_BYTES,
        "workflow_extraction": MAX_REVIEW_BYTES, "workflow_log": 256 * 1024,
        "dispatch": MAX_REVIEW_BYTES, "result": 65536, "downloaded_report": 65536,
        "public_admission": MAX_ADMISSION_BYTES, "readiness": MAX_ADMISSION_BYTES}
    raw_values: dict[str, bytes] = {}
    values: dict[str, Any] = {}
    for key, path in expected_paths.items():
        ref = refs.get(key)
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or ref.get("path") != path:
            raise ValueError(label)
        raw = _read_regular(_path(root, _safe_relative(path, label)), cap=caps[key], label=label)
        if not isinstance(ref.get("sha256"), str) or _digest(raw) != ref["sha256"]:
            raise ValueError(label)
        raw_values[key] = raw
        if key == "workflow_log":
            continue
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(label) from None
        if key == "jobs":
            if not isinstance(parsed, dict) or set(parsed) != {"jobs"} or not isinstance(parsed["jobs"], list):
                raise ValueError(label)
            values[key] = parsed["jobs"]
        else:
            values[key] = _json_object(raw, label)

    run, jobs = values["workflow_run"], values["jobs"]
    dispatch, result, report = values["dispatch"], values["result"], values["downloaded_report"]
    public_admission = values["public_admission"]
    source_path = f"{expected_root}/source-admission.json"
    source_admission, _ = _read_reference(root, {"path": source_path,
        "sha256": terminal.get("source_admission_sha256")}, label=label)
    source_keys = set(source_admission)
    if (source_keys != set(public_admission) - {"candidate"}
            or source_admission.get("status") != "source-preparation"
            or public_admission.get("status") != "public-effects"
            or any(source_admission[key] != public_admission[key] for key in source_keys - {"status"})
            or not isinstance(public_admission.get("candidate"), dict)
            or terminal.get("diagnostic_public_tree") != public_admission["candidate"].get("public_tree")):
        raise ValueError(label)
    base = pr.get("base_sha")
    if (type(base) is not str or re.fullmatch(r"[0-9a-f]{40}", base) is None
            or run.get("id") != run_id or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or type(run.get("run_attempt")) is not int or run["run_attempt"] != 1
            or run.get("path") != ".github/workflows/ci.yml"
            or run.get("head_sha") != source
            or run.get("head_branch") != "v0.2-source-" + source[:12]
            or run.get("name") != "Plan10 native diagnostic " + nonce
            or run.get("display_title") != run.get("name")
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != "szTheory/genewhip"
            or run["repository"].get("private") is not False):
        raise ValueError(label)
    names = set(NATIVE_HOST_RUNTIME_JOBS)
    by_name = {row.get("name"): row for row in jobs if isinstance(row, dict)}
    if (len(jobs) != 16 or len(by_name) != 16 or set(by_name) != names
            or any(not isinstance(row, dict) or row.get("status") != "completed"
                or type(row.get("id")) is not int or row["id"] <= 0
                or row.get("run_id") != run_id for row in jobs)
            or len({row["id"] for row in jobs}) != 16
            or by_name["v02-runtime"].get("id") != terminal.get("runtime_job_id")
            or by_name["v02-runtime"].get("conclusion") != "success"
            or any(by_name[name].get("conclusion") != "skipped" for name in names - {"v02-runtime"})):
        raise ValueError(label)
    extraction = values["workflow_extraction"]
    if (type(extraction.get("selected_run_id")) is not int
            or extraction.get("selected_run_id") != run_id
            or not isinstance(extraction.get("source_receipt_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", extraction["source_receipt_sha256"]) is None):
        raise ValueError(label)
    if (dispatch.get("schema") != "genewhip.phase7-native-diagnostic-dispatch.v1"
            or dispatch.get("run_id") != run_id or dispatch.get("dispatches") != 1
            or dispatch.get("nonce") != nonce or dispatch.get("source_sha") != source
            or dispatch.get("status") != "completed-assessment-required"
            or dispatch.get("qualification_accepted") is not False
            or dispatch.get("started_at") != journal.get("started_at")
            or dispatch.get("readiness_sha256") != refs["readiness"]["sha256"]):
        raise ValueError(label)
    try:
        failure_observed_at = _utc(failure.get("observed_at"))
    except (AttributeError, ValueError):
        raise ValueError(label) from None
    if (failure.get("schema") != "genewhip.phase7-fresh-batch-failure.v1"
            or failure.get("authorization_sha256") != AUTH_SHA256
            or failure.get("stage") != "preview-ci"
            or failure.get("reason") != "diagnostic-ci-complete-assessment-required"
            or failure_observed_at < _utc(journal.get("started_at"))):
        raise ValueError(label)
    if (not isinstance(result, dict)
            or set(result) != {"schema", "status", "qualification_accepted", "assessment_required",
                "run_id", "source_sha", "run_attempt", "report_sha256", "report_path", "branch"}
            or result.get("schema") != "genewhip.phase7-native-diagnostic-result.v1"
            or result.get("status") != "pass" or result.get("qualification_accepted") is not False
            or result.get("assessment_required") is not True or result.get("run_id") != str(run_id)
            or result.get("source_sha") != source or result.get("run_attempt") != "1"
            or result.get("report_sha256") != refs["downloaded_report"]["sha256"]
            or result.get("report_path") != expected_paths["downloaded_report"]
            or result.get("branch") != run.get("head_branch")):
        raise ValueError(label)
    identity = {"source_sha": source, "head_sha": source, "base_sha": base,
        "run_id": str(run_id), "run_attempt": "1"}
    # The public admission is not an authority for code to import. The exact
    # reviewed source admission is; require its join before executing validator
    # bytes from the temporary/public candidate tree.
    source_pins = source_admission.get("source_pins")
    runtime_validator_path = root / "scripts/evidence/v02_run.py"
    runtime_validator_bytes = _read_regular(_path(root, Path("scripts/evidence/v02_run.py")),
        cap=MAX_SOURCE_BYTES, label=label)
    if (not isinstance(source_pins, dict)
            or source_pins.get("scripts/evidence/v02_run.py") != _digest(runtime_validator_bytes)):
        raise ValueError(label)
    _validate_native_readiness(root, root / expected_root, public_admission,
        _digest(raw_values["public_admission"]),
        _path(root, _safe_relative(expected_paths["readiness"], label)),
        _digest(raw_values["readiness"]))
    try:
        import sys
        import types
        module_name = "gw_phase7_native_report_validator"
        module = types.ModuleType(module_name)
        module.__file__ = str(runtime_validator_path)
        sys.modules[module_name] = module
        try:
            # Execute only the exact bytes just matched to the recursively
            # reviewed private source pin; importing from the path again would
            # reopen a mutable file after that check.
            code = compile(runtime_validator_bytes, str(runtime_validator_path), "exec")
            exec(code, module.__dict__)
            if module.validate_native_diagnostic_public(report, identity) is not True:
                raise ValueError(label)
        finally:
            sys.modules.pop(module_name, None)
    except Exception:
        raise ValueError(label) from None
    if (report.get("status") != "pass" or report.get("collector_read_status") != "valid"
            or report.get("failure_category") is not None or report.get("outer_rejection") is not None
            or report.get("outer_process") != {"return_code": "zero", "status": "completed",
                "cleanup": "confirmed", "bound_violation": False}):
        raise ValueError(label)
    log = raw_values["workflow_log"]
    if b"native-diagnostic: pass; qualification_accepted=false" not in log:
        raise ValueError(label)

    if (terminal.get("owning_case") != NATIVE_DIAGNOSTIC_RESUMPTION_CASE
            or terminal.get("diagnostic_profile") != NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
            or terminal.get("qualification_accepted") is not False
            or terminal.get("full_qualification_dispatched") is not False
            or terminal.get("merge_attempted") is not False
            or terminal.get("cleanup_disposition") != "confirmed"
            or terminal.get("diagnostic_outer_cleanup") != "confirmed"
            or terminal.get("diagnostic_outer_return") != "zero"
            or terminal.get("diagnostic_outer_bound_violation") is not False
            or terminal.get("diagnostic_outer_rejection") is not None
            or terminal.get("safety_job_failed") is not False
            or terminal.get("diagnostic_workload_outcome") != "pass"
            or terminal.get("hosted_cleanup_outcome") != "confirmed"
            or terminal.get("original_failure_cause") != "unknown"
            or terminal.get("diagnostic_public_base") != public_admission["candidate"].get("public_base")
            or repair.get("diagnostic_case") != NATIVE_DIAGNOSTIC_RESUMPTION_CASE
            or repair.get("diagnostic_profile") != NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
            or repair.get("diagnostic_only") is not True
            or repair.get("live_retry_authorized") is not False
            or repair.get("qualification_accepted") is not False
            or repair.get("full_qualification_dispatched") is not False
            or repair.get("merge_attempted") is not False
            or repair.get("cleanup_disposition") != "confirmed"
            or repair.get("diagnostic_outer_cleanup") != "confirmed"
            or repair.get("diagnostic_outer_return") != "zero"
            or repair.get("diagnostic_outer_bound_violation") is not False
            or repair.get("diagnostic_outer_rejection") is not None
            or repair.get("safety_job_failed") is not False
            or repair.get("had_safety_job_failure") is not False
            or repair.get("diagnostic_workload_outcome") != "pass"
            or repair.get("hosted_cleanup_outcome") != "confirmed"
            or repair.get("diagnostic_public_tree") != public_admission["candidate"].get("public_tree")
            or repair.get("diagnostic_public_base") != public_admission["candidate"].get("public_base")
            or not isinstance(pr, dict) or type(pr.get("number")) is not int
            or pr.get("number") <= 0
            or pr.get("merged") is not False or pr.get("state") != "open"
            or pr.get("head_sha") != public_admission["candidate"].get("public_head")
            or pr.get("base_sha") != public_admission["candidate"].get("public_base")):
        raise ValueError(label)
    reviews = repair.get("result_reviews")
    if not isinstance(reviews, dict) or set(reviews) != set(SOURCE_ROLES):
        raise ValueError(label)
    result_payload_sha = _digest(_canonical(result))
    for key, role in SOURCE_ROLES.items():
        _check_review(root, reviews[key], role=role, payload_sha256=result_payload_sha)
        review_path = _path(root, _safe_relative(reviews[key]["path"], label))
        frontmatter = _frontmatter(_read_regular(review_path, cap=MAX_REVIEW_BYTES, label=label))
        if frontmatter.get("source_head") != source_admission.get("source_head"):
            raise ValueError(label)
    return {"source_admission": source_admission,
        "public_tree": public_admission["candidate"]["public_tree"],
        "public_base": public_admission["candidate"]["public_base"]}


def _validate_diagnostic_resumption_binding(*, stage: str, source_head: str,
        source_pins: dict[str, str], prior_source: dict[str, Any],
        repair: dict[str, Any], candidate: dict[str, Any] | None = None) -> None:
    """Allow ordinary continuation only on the exact reviewed diagnostic source/tree."""
    label = "fresh-batch-diagnostic-resumption-binding-invalid"
    if (stage not in ("source-preparation", "public-effects")
            or prior_source.get("status") != "source-preparation"
            or source_head != prior_source.get("source_head")
            or source_pins != prior_source.get("source_pins")
            or repair.get("diagnostic_profile") != NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
            or repair.get("diagnostic_public_tree") is None
            or repair.get("diagnostic_public_base") is None):
        raise ValueError(label)
    if candidate is not None and (candidate.get("public_tree") != repair.get("diagnostic_public_tree")
            or candidate.get("public_base") != repair.get("diagnostic_public_base")):
        raise ValueError(label)


def _require_diagnostic_successor_disposition(repair: dict[str, Any], disposition: str) -> None:
    if (repair.get("diagnostic_profile") == NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
            and disposition != "reviewed-diagnostic-resumption"):
        raise ValueError("fresh-batch-diagnostic-resumption-required")


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
    diagnostic = predecessor["disposition"] == "bounded-diagnostic-followup"
    reviewed_resumption = predecessor["disposition"] == "reviewed-diagnostic-resumption"
    if (predecessor.get("all_ci_terminal") is not True
            or predecessor.get("safety_status") != ("diagnostic-only" if diagnostic else "clear")
            or predecessor.get("unknown_high_findings") is not False):
        raise ValueError("fresh-batch-predecessor-stop-condition")
    cleanup_status = predecessor.get("cleanup_status")
    cleanup_reference = predecessor.get("cleanup_evidence")
    cleanup_value = None
    if diagnostic and (attempt_index <= 1
            or cleanup_status != "unknown-hosted-test-outcome"
            or cleanup_reference is not None):
        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
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
    elif cleanup_status == "unknown-hosted-test-outcome" and diagnostic:
        pass
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
    journal_value = None
    diagnostic_profile = None
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
        if key == "journal":
            journal_value = value
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
            diagnostic_case = value.get("owning_case")
            event = (value.get("event") if diagnostic_case in
                     (NATIVE_HOST_RUNTIME_CASE, NATIVE_RESULT_HANDOFF_CASE,
                      NATIVE_INPUT_MASK_ALIGNMENT_CASE, NATIVE_DIAGNOSTIC_RESUMPTION_CASE)
                     else "pull_request" if isinstance(value.get("pull_request"), dict)
                     else value.get("event"))
            expected_jobs = PREVIEW_REQUIRED_LANES | PREVIEW_CONDITIONAL_SKIPS
            if event == "push":
                expected_jobs.remove("attestation")
                expected_jobs.add("attestation")
            by_name = {row.get("name"): row for row in jobs
                       if isinstance(row, dict) and isinstance(row.get("name"), str)} \
                if isinstance(jobs, list) else {}
            if ((diagnostic or reviewed_resumption) and diagnostic_case in
                    (NATIVE_HOST_RUNTIME_CASE, NATIVE_RESULT_HANDOFF_CASE,
                     NATIVE_INPUT_MASK_ALIGNMENT_CASE, NATIVE_DIAGNOSTIC_RESUMPTION_CASE)):
                roster_valid = (event == "workflow_dispatch"
                    and isinstance(jobs, list) and len(by_name) == 16
                    and set(by_name) == NATIVE_HOST_RUNTIME_JOBS)
            else:
                roster_valid = (event in ("pull_request", "push")
                and len(by_name) == len(jobs) if isinstance(jobs, list) else False)
            if not no_ci and not ((diagnostic or reviewed_resumption) and diagnostic_case in
                    (NATIVE_HOST_RUNTIME_CASE, NATIVE_RESULT_HANDOFF_CASE,
                     NATIVE_INPUT_MASK_ALIGNMENT_CASE, NATIVE_DIAGNOSTIC_RESUMPTION_CASE)):
                roster_valid = (roster_valid and set(by_name) == expected_jobs
                    and all(by_name[name].get("conclusion") in
                        ("success", "failure", "cancelled") for name in PREVIEW_REQUIRED_LANES)
                    and all(by_name[name].get("conclusion") in ("skipped", "cancelled")
                        for name in PREVIEW_CONDITIONAL_SKIPS - ({"attestation"} if event == "push" else set()))
                    and (event != "push" or by_name["attestation"].get("conclusion")
                         in ("success", "cancelled")))
            if diagnostic or reviewed_resumption:
                diagnostic_case = value.get("owning_case")
                pull_request = value.get("pull_request")
                if diagnostic_case == DIAGNOSTIC_CASE:
                    diagnostic_profile = ("phase5-cleanup" if value.get("failed_lane") == "production"
                                          else "phase5-process")
                    failed_lane = "production" if diagnostic_profile == "phase5-cleanup" else "sanitizer"
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("failed_lane") != failed_lane
                            or value.get("native_lane") != "passed"
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("safety", "required-ci"))
                            or any(by_name[name].get("conclusion") != "success"
                                for name in PREVIEW_REQUIRED_LANES - {"safety", "required-ci"})
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in PREVIEW_CONDITIONAL_SKIPS)):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                    if diagnostic_profile == "phase5-cleanup" and (
                            value.get("sanitizer_lane") != "passed"
                            or value.get("merge_attempted") is not False
                            or value.get("diagnostic_subcase") != "stdout-cap"
                            or value.get("failure_exception") != "ValueError"
                            or value.get("failure_status") != "failed"
                            or value.get("failure_cleanup") != "unconfirmed"
                            or value.get("failure_cleanup_error") != "PermissionError"
                            or value.get("failure_return") != "missing"
                            or value.get("failure_result") != "cleanup-unconfirmed"):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == RSS_DIAGNOSTIC_CASE:
                    diagnostic_profile = "rss-smoke"
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("failed_lane") != "product-smoke"
                            or value.get("bound_violation_reason") != "phase7-rss-observation-unavailable"
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("local_monitor_cleanup") != "confirmed"
                            or value.get("original_failure_cause") != "unknown"
                            or value.get("merge_attempted") is not False
                            or value.get("safety_job_failed") is not False
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("product-smoke", "required-ci"))
                            or any(by_name[name].get("conclusion") != "success"
                                for name in ("gameplay", "package", "performance", "phase7-fast"))
                            or any(by_name[name].get("conclusion") not in ("success", "cancelled")
                                for name in ("safety", "desktop"))
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in PREVIEW_CONDITIONAL_SKIPS)):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == FIRST_PARTY_CLEANUP_CONTROL_CASE:
                    diagnostic_profile = "first-party-cleanup-control"
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("failed_lane") != "sanitizer"
                            or value.get("native_lane") != "passed"
                            or value.get("sanitizer_lane") != "failed"
                            or value.get("production_lane") != "not-run"
                            or value.get("safety_job_failed") is not True
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("merge_attempted") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("safety", "phase7-fast", "required-ci"))
                            or by_name["product-smoke"].get("conclusion") != "cancelled"
                            or any(by_name[name].get("conclusion") != "success"
                                for name in ("desktop", "gameplay", "package", "performance"))
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in PREVIEW_CONDITIONAL_SKIPS)
                            or value.get("failure_exception") != "RuntimeError"
                            or value.get("failure_cleanup") != "unconfirmed"
                            or value.get("cleanup_reason") != "cleanup-permission-denied"
                            or value.get("status_observation") != "group-status-unavailable"
                            or value.get("cleanup_queries") != 3
                            or value.get("observer_failure_stage") != "unknown"
                            or value.get("cleanup_signal_phase") != "unknown"):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == NATIVE_HOST_RUNTIME_CASE:
                    diagnostic_profile = NATIVE_HOST_RUNTIME_PROFILE
                    if (not roster_valid or not jobs_terminal or event != "workflow_dispatch"
                            or value.get("failed_lane") != "v02-runtime"
                            or value.get("diagnostic_profile") != NATIVE_HOST_RUNTIME_PROFILE
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("outer_runtime_cleanup") != "unknown"
                            or value.get("desktop_child_return") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("local_monitor_cleanup") != "confirmed"
                            or value.get("inner_row_cleanup") != "confirmed"
                            or value.get("inner_row_bound") != "none"
                            or type(value.get("batch_return")) is not int
                            or value.get("batch_return") != 1
                            or value.get("safety_job_failed") is not False
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not True
                            or value.get("merge_attempted") is not True
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not True
                            or pull_request.get("state") != "closed"
                            or any(by_name[name].get("conclusion") != expected
                                for name, expected in NATIVE_HOST_RUNTIME_OUTCOMES.items())):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == NATIVE_CASE_PREPARATION:
                    diagnostic_profile = "native-case-preparation"
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("safety_job_failed") is not False
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "success" for name in PREVIEW_REQUIRED_LANES)
                            or any(by_name[name].get("conclusion") != "skipped" for name in PREVIEW_CONDITIONAL_SKIPS)):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == NATIVE_RESULT_HANDOFF_CASE:
                    diagnostic_profile = NATIVE_RESULT_HANDOFF_PROFILE
                    if (not roster_valid or not jobs_terminal or event != "workflow_dispatch"
                            or value.get("diagnostic_profile") != NATIVE_RESULT_HANDOFF_PROFILE
                            or value.get("run_status") != "completed"
                            or value.get("run_conclusion") != "failure"
                            or value.get("workflow_run_id") != NATIVE_RESULT_HANDOFF_RUN_ID
                            or value.get("run_attempt") != 1
                            or value.get("head_sha") != NATIVE_RESULT_HANDOFF_SOURCE_SHA
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("merge_attempted") is not False
                            or value.get("safety_job_failed") is not False
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("diagnostic_outer_cleanup") != "confirmed"
                            or value.get("diagnostic_outer_return") != "zero"
                            or value.get("diagnostic_outer_bound_violation") is not False
                            or value.get("diagnostic_outer_rejection") is not None
                            or value.get("diagnostic_workload_outcome") != "unavailable"
                            or value.get("private_collector_rejection_cause") != "unknown"
                            or value.get("private_collector_bytes") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or not isinstance(pull_request, dict)
                            or pull_request.get("number") != 42
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("v02-runtime",))
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in NATIVE_HOST_RUNTIME_JOBS - {"v02-runtime"})):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == NATIVE_INPUT_MASK_ALIGNMENT_CASE:
                    diagnostic_profile = NATIVE_INPUT_MASK_ALIGNMENT_PROFILE
                    if (not roster_valid or not jobs_terminal or event != "workflow_dispatch"
                            or value.get("diagnostic_profile") != NATIVE_INPUT_MASK_ALIGNMENT_PROFILE
                            or value.get("run_status") != "completed"
                            or value.get("run_conclusion") != "failure"
                            or value.get("workflow_run_id") != NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID
                            or value.get("run_attempt") != 1
                            or value.get("head_sha") != NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("merge_attempted") is not False
                            or value.get("diagnostic_only") is not True
                            or value.get("safety_job_failed") is not False
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("diagnostic_outer_cleanup") != "confirmed"
                            or value.get("diagnostic_outer_return") != "zero"
                            or value.get("diagnostic_outer_bound_violation") is not False
                            or value.get("diagnostic_outer_rejection") is not None
                            or value.get("diagnostic_workload_outcome") != "unavailable"
                            or value.get("private_collector_rejection_cause") != "unknown"
                            or value.get("private_collector_bytes") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or not isinstance(pull_request, dict)
                            or pull_request.get("number") != 43
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("v02-runtime",))
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in NATIVE_HOST_RUNTIME_JOBS - {"v02-runtime"})):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == NATIVE_DIAGNOSTIC_RESUMPTION_CASE:
                    diagnostic_profile = NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
                    if (not reviewed_resumption or not roster_valid or not jobs_terminal
                            or event != "workflow_dispatch"
                            or value.get("diagnostic_profile") != NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
                            or value.get("run_status") != "completed"
                            or value.get("run_conclusion") != "success"
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("merge_attempted") is not False
                            or value.get("diagnostic_workload_outcome") != "pass"
                            or value.get("hosted_cleanup_outcome") != "confirmed"
                            or value.get("original_failure_cause") != "unknown"
                            or any(by_name[name].get("conclusion") != "success"
                                for name in ("v02-runtime",))
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in NATIVE_HOST_RUNTIME_JOBS - {"v02-runtime"})):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == WORKFLOW_TIMEOUT_CONTRACT_CASE:
                    diagnostic_profile = WORKFLOW_TIMEOUT_CONTRACT_PROFILE
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("failed_lane") != "phase7-fast"
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or value.get("local_monitor_safety_issue") is not False
                            or value.get("safety_job_failed") is not False
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("merge_attempted") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "failure"
                                for name in ("phase7-fast", "required-ci"))
                            or any(by_name[name].get("conclusion") != "success"
                                for name in PREVIEW_REQUIRED_LANES - {"phase7-fast", "required-ci"})
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in PREVIEW_CONDITIONAL_SKIPS)):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                elif diagnostic_case == PUBLICATION_RSS_OBSERVATION_CASE:
                    diagnostic_profile = PUBLICATION_RSS_OBSERVATION_PROFILE
                    if (not roster_valid or not jobs_terminal or event != "pull_request"
                            or value.get("failed_lane") != "publication"
                            or value.get("hosted_cleanup_outcome") != "unknown"
                            or value.get("original_failure_cause") != "unknown"
                            or value.get("local_monitor_safety_issue") is not True
                            or value.get("safety_job_failed") is not False
                            or value.get("qualification_accepted") is not False
                            or value.get("full_qualification_dispatched") is not False
                            or value.get("merge_attempted") is not False
                            or not isinstance(pull_request, dict)
                            or pull_request.get("merged") is not False
                            or pull_request.get("state") != "open"
                            or any(by_name[name].get("conclusion") != "success"
                                for name in PREVIEW_REQUIRED_LANES)
                            or any(by_name[name].get("conclusion") != "skipped"
                                for name in PREVIEW_CONDITIONAL_SKIPS)):
                        raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
                else:
                    raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
            if (not (no_ci or jobs_terminal)
                    or (not no_ci and not roster_valid)
                    or (not diagnostic and value.get("safety_job_failed") is True)
                    or (not diagnostic and any(row.get("name") == "safety" and row.get("conclusion") == "failure"
                           for row in jobs if isinstance(row, dict)))
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
                    value.get("safety_job_failed") is not
                        (diagnostic_profile in ("phase5-process", "phase5-cleanup",
                                                "first-party-cleanup-control"))
                    or value.get("qualification_accepted") is not False):
                raise ValueError("fresh-batch-predecessor-terminal-classification-missing")
            if (predecessor.get("cleanup_status") == "current-target-inactive"
                    and value.get("local_monitor_safety_issue") is not True):
                raise ValueError("fresh-batch-predecessor-terminal-observation-invalid")
        if key == "repair_evidence":
            common_invalid = value.get("live_retry_authorized") is not False
            if reviewed_resumption:
                if (common_invalid
                        or value.get("diagnostic_case") != NATIVE_DIAGNOSTIC_RESUMPTION_CASE
                        or value.get("diagnostic_profile") != NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE
                        or value.get("diagnostic_only") is not True
                        or value.get("diagnostic_workload_outcome") != "pass"
                        or value.get("hosted_cleanup_outcome") != "confirmed"
                        or value.get("cleanup_disposition") != "confirmed"
                        or value.get("qualification_accepted") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("merge_attempted") is not False
                        or value.get("unknown_high_findings") is not False
                        or value.get("safety_or_cleanup_issue") is not False
                        or value.get("diagnostic_public_tree") != terminal_value.get("diagnostic_public_tree")
                        or value.get("original_failure_cause") != "unknown"):
                    raise ValueError("fresh-batch-accepted-native-diagnostic-invalid")
            if diagnostic:
                common_diagnostic_invalid = (common_invalid
                    or value.get("diagnostic_only") is not True
                    or value.get("hosted_cleanup_outcome") != "unknown"
                    or value.get("qualification_accepted") is not False
                    or value.get("unknown_high_findings") is not False)
                if diagnostic_profile == "phase5-process":
                    profile_invalid = (value.get("diagnostic_case") != DIAGNOSTIC_CASE
                        or value.get("diagnostic_profile") is not None
                        or value.get("safety_job_failed") is not True
                        or value.get("had_safety_job_failure") is not True)
                elif diagnostic_profile == "phase5-cleanup":
                    profile_invalid = (value.get("diagnostic_case") != DIAGNOSTIC_CASE
                        or value.get("diagnostic_profile") != "phase5-cleanup"
                        or value.get("diagnostic_subcase") != "stdout-cap"
                        or value.get("safety_job_failed") is not True
                        or value.get("had_safety_job_failure") is not True
                        or value.get("failure_exception") != "ValueError"
                        or value.get("failure_status") != "failed"
                        or value.get("failure_cleanup") != "unconfirmed"
                        or value.get("failure_cleanup_error") != "PermissionError"
                        or value.get("failure_return") != "missing"
                        or value.get("failure_result") != "cleanup-unconfirmed")
                elif diagnostic_profile == "rss-smoke":
                    profile_invalid = (value.get("diagnostic_case") != RSS_DIAGNOSTIC_CASE
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("bound_violation_reason") != "phase7-rss-observation-unavailable"
                        or value.get("original_failure_cause") != "unknown"
                        or value.get("local_monitor_cleanup") != "confirmed")
                elif diagnostic_profile == "first-party-cleanup-control":
                    profile_invalid = (value.get("diagnostic_case") != FIRST_PARTY_CLEANUP_CONTROL_CASE
                        or value.get("diagnostic_profile") != "first-party-cleanup-control"
                        or value.get("control") != FIRST_PARTY_CLEANUP_CONTROL_METADATA
                        or value.get("safety_job_failed") is not True
                        or value.get("had_safety_job_failure") is not True
                        or value.get("hosted_cleanup_outcome") != "unknown"
                        or value.get("qualification_accepted") is not False
                        or value.get("unknown_high_findings") is not False)
                elif diagnostic_profile == NATIVE_HOST_RUNTIME_PROFILE:
                    profile_invalid = (value.get("diagnostic_case") != NATIVE_HOST_RUNTIME_CASE
                        or value.get("diagnostic_profile") != NATIVE_HOST_RUNTIME_PROFILE
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("full_qualification_dispatched") is not True
                        or value.get("outer_runtime_cleanup") != "unknown"
                        or value.get("inner_row_cleanup") != "confirmed"
                        or value.get("inner_row_bound") != "none"
                        or type(value.get("batch_return")) is not int
                        or value.get("batch_return") != 1
                        or value.get("desktop_child_return") != "unknown"
                        or value.get("original_failure_cause") != "unknown")
                elif diagnostic_profile == "native-case-preparation":
                    profile_invalid = (value.get("diagnostic_case") != NATIVE_CASE_PREPARATION
                        or value.get("safety_job_failed") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("original_failure_cause") != "unknown")
                elif diagnostic_profile == NATIVE_RESULT_HANDOFF_PROFILE:
                    profile_invalid = (value.get("diagnostic_case") != NATIVE_RESULT_HANDOFF_CASE
                        or value.get("diagnostic_profile") != NATIVE_RESULT_HANDOFF_PROFILE
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("merge_attempted") is not False
                        or value.get("diagnostic_only") is not True
                        or value.get("diagnostic_outer_cleanup") != "confirmed"
                        or value.get("diagnostic_workload_outcome") != "unavailable"
                        or value.get("private_collector_rejection_cause") != "unknown"
                        or value.get("private_collector_bytes") != "unknown"
                        or value.get("original_failure_cause") != "unknown")
                elif diagnostic_profile == NATIVE_INPUT_MASK_ALIGNMENT_PROFILE:
                    profile_invalid = (value.get("diagnostic_case") != NATIVE_INPUT_MASK_ALIGNMENT_CASE
                        or value.get("diagnostic_profile") != NATIVE_INPUT_MASK_ALIGNMENT_PROFILE
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("merge_attempted") is not False
                        or value.get("diagnostic_only") is not True
                        or value.get("diagnostic_outer_cleanup") != "confirmed"
                        or value.get("diagnostic_workload_outcome") != "unavailable"
                        or value.get("hosted_cleanup_outcome") != "unknown"
                        or value.get("private_collector_rejection_cause") != "unknown"
                        or value.get("private_collector_bytes") != "unknown"
                        or value.get("original_failure_cause") != "unknown")
                elif diagnostic_profile == WORKFLOW_TIMEOUT_CONTRACT_PROFILE:
                    profile_invalid = (value.get("diagnostic_case") != WORKFLOW_TIMEOUT_CONTRACT_CASE
                        or value.get("diagnostic_profile") != WORKFLOW_TIMEOUT_CONTRACT_PROFILE
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("merge_attempted") is not False
                        or value.get("original_failure_cause") != "unknown")
                elif diagnostic_profile == PUBLICATION_RSS_OBSERVATION_PROFILE:
                    profile_invalid = (value.get("diagnostic_case") != PUBLICATION_RSS_OBSERVATION_CASE
                        or value.get("diagnostic_profile") != PUBLICATION_RSS_OBSERVATION_PROFILE
                        or value.get("infrastructure_retry_reason") != "observation-reconciliation"
                        or value.get("safety_job_failed") is not False
                        or value.get("had_safety_job_failure") is not False
                        or value.get("full_qualification_dispatched") is not False
                        or value.get("merge_attempted") is not False
                        or value.get("local_monitor_safety_issue") is not True
                        or value.get("local_monitor_cleanup") != "confirmed"
                        or value.get("original_failure_cause") != "unknown")
                else:
                    profile_invalid = True
                if common_diagnostic_invalid or profile_invalid:
                    raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
            elif predecessor.get("cleanup_status") == "current-target-inactive":
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
    if diagnostic_profile == "rss-smoke":
        if not isinstance(terminal_value, dict) or not isinstance(repair_value, dict) \
                or not isinstance(journal_value, dict):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        _validate_rss_diagnostic_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value)
    if diagnostic_profile == PUBLICATION_RSS_OBSERVATION_PROFILE:
        if not all(isinstance(value, dict) for value in
                   (terminal_value, repair_value, journal_value, failure_value)):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        _validate_publication_rss_observation_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value,
            failure=failure_value)
    if diagnostic_profile == "phase5-cleanup":
        if not isinstance(terminal_value, dict) or not isinstance(repair_value, dict):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        _validate_phase5_cleanup_diagnostic_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value)
    if diagnostic_profile == "first-party-cleanup-control":
        if not isinstance(terminal_value, dict) or not isinstance(repair_value, dict) \
                or not isinstance(journal_value, dict):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        _validate_first_party_cleanup_control_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value)
    if diagnostic_profile == WORKFLOW_TIMEOUT_CONTRACT_PROFILE:
        if not isinstance(terminal_value, dict) or not isinstance(repair_value, dict):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        _validate_workflow_timeout_contract_artifact(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value)
    if diagnostic_profile == NATIVE_HOST_RUNTIME_PROFILE:
        if not all(isinstance(value, dict) for value in
                   (terminal_value, repair_value, journal_value)):
            raise ValueError("fresh-batch-predecessor-diagnostic-classification-invalid")
        delivery_value, _ = _read_reference(root, terminal_value.get("source_delivery"),
            label="fresh-batch-native-host-runtime-evidence-invalid")
        _validate_native_host_runtime_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value,
            source_delivery=delivery_value, failure=failure_value)
    if diagnostic_profile == "native-case-preparation":
        if not all(isinstance(value, dict) for value in (repair_value, journal_value, failure_value)):
            raise ValueError("native-diagnostic-assessed-preview-invalid")
        _validate_assessed_preview(root, expected_root, repair_value.get("diagnostic_assessment"),
            repair_value.get("assessment_reviews"), journal_value, failure_value)
    if diagnostic_profile == NATIVE_RESULT_HANDOFF_PROFILE:
        if not all(isinstance(value, dict) for value in
                   (terminal_value, repair_value, journal_value, failure_value)):
            raise ValueError("native-diagnostic-result-handoff-invalid")
        _validate_native_result_handoff_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value,
            failure=failure_value)
    if diagnostic_profile == NATIVE_INPUT_MASK_ALIGNMENT_PROFILE:
        if not all(isinstance(value, dict) for value in
                   (terminal_value, repair_value, journal_value, failure_value)):
            raise ValueError("native-diagnostic-input-mask-alignment-invalid")
        _validate_native_input_mask_alignment_artifacts(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value,
            failure=failure_value)
    if diagnostic_profile == NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE:
        if not all(isinstance(value, dict) for value in
                   (terminal_value, repair_value, journal_value, failure_value)):
            raise ValueError("fresh-batch-accepted-native-diagnostic-invalid")
        _validate_accepted_native_diagnostic(root, expected_root=expected_root,
            terminal=terminal_value, repair=repair_value, journal=journal_value,
            failure=failure_value)
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
                   expected_source_paths: set[str],
                   diagnostic_readiness_path: Path | None = None,
                   diagnostic_readiness_sha256: str | None = None) -> dict[str, Any]:
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
    diagnostic_effects = stage == "native-diagnostic"
    if stage not in ("source-preparation", "public-effects", "native-diagnostic"):
        raise ValueError("fresh-batch-stage-invalid")
    if diagnostic_effects != (diagnostic_readiness_path is not None and diagnostic_readiness_sha256 is not None):
        raise ValueError("native-diagnostic-readiness-required")
    if not diagnostic_effects and (diagnostic_readiness_path is not None or diagnostic_readiness_sha256 is not None):
        raise ValueError("native-diagnostic-readiness-route-invalid")
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
    if stage in ("public-effects", "native-diagnostic"):
        protected_inputs += (preflight_resolved,)
    if diagnostic_effects:
        protected_inputs += (diagnostic_readiness_path,)
        if output_resolved != batch_root / "native-diagnostic/result.json":
            raise ValueError("native-diagnostic-output-layout-invalid")
    if (_paths_overlap(expected_output_resolved, publication_resolved)
            or any(_paths_overlap(expected_output_resolved, protected) for protected in protected_inputs)
            or any(_paths_overlap(publication_resolved, protected) for protected in protected_inputs)):
        raise ValueError("fresh-batch-output-aliases-input")
    if expected_output_resolved.exists():
        raise ValueError("fresh-batch-output-already-exists")
    failure_path = batch_root / FAILURE_FILENAME
    if diagnostic_effects and (not failure_path.is_file() or failure_path.is_symlink()):
        raise ValueError("native-diagnostic-assessment-stop-required")
    if not diagnostic_effects and (failure_path.exists() or failure_path.is_symlink()):
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
    if stage in ("public-effects", "native-diagnostic"):
        expected_admission_keys.add("candidate")
    if (set(admission) != expected_admission_keys
            or admission.get("schema") != SCHEMA
            or admission.get("status") != ("public-effects" if diagnostic_effects else stage)
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
    diagnostic_disposition_transition = (
        predecessor["disposition"] == "bounded-diagnostic-followup"
        and admission["disposition"] == "reviewed-diagnostic-resumption")
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
    _require_diagnostic_successor_disposition(predecessor_evidence, admission["disposition"])
    validated_native_resumption = False
    if admission["disposition"] == "reviewed-diagnostic-resumption":
        if attempt_index <= 1:
            raise ValueError("fresh-batch-diagnostic-resumption-stage-invalid")
        prior_source_ref = predecessor.get("source_admission")
        if not isinstance(prior_source_ref, dict):
            raise ValueError("fresh-batch-diagnostic-resumption-source-invalid")
        prior_source, _ = _read_reference(root, prior_source_ref,
            label="fresh-batch-diagnostic-resumption-source-invalid")
        _validate_diagnostic_resumption_binding(stage=stage, source_head=source_head,
            source_pins=pins, prior_source=prior_source, repair=predecessor_evidence)
        validated_native_resumption = (
            predecessor_evidence.get("diagnostic_profile") == NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE)
        if diagnostic_disposition_transition:
            if not validated_native_resumption:
                raise ValueError("fresh-batch-diagnostic-disposition-mismatch")
    elif ((admission["disposition"] == "bounded-diagnostic-followup"
            or predecessor["disposition"] == "bounded-diagnostic-followup")
            and admission["disposition"] != predecessor["disposition"]):
        raise ValueError("fresh-batch-diagnostic-disposition-mismatch")
    if admission["disposition"] in ("routine-source-repair", "bounded-diagnostic-followup"):
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
            if admission["disposition"] == "bounded-diagnostic-followup":
                diagnostic_case = predecessor_evidence.get("diagnostic_case")
                if (diagnostic_case == DIAGNOSTIC_CASE
                        and predecessor_evidence.get("diagnostic_profile") == "phase5-cleanup"):
                    diagnostic_paths = PHASE5_CLEANUP_DIAGNOSTIC_SOURCE_PATHS
                elif diagnostic_case == DIAGNOSTIC_CASE:
                    diagnostic_paths = {"tests/evidence/phase5_baseline_contract.py",
                        "scripts/evidence/phase4_report.py", "tests/evidence/phase4_report_contract.py"}
                elif diagnostic_case == RSS_DIAGNOSTIC_CASE:
                    diagnostic_paths = RSS_DIAGNOSTIC_SOURCE_PATHS
                elif diagnostic_case == FIRST_PARTY_CLEANUP_CONTROL_CASE:
                    diagnostic_paths = FIRST_PARTY_CLEANUP_CONTROL_SOURCE_PATHS
                elif diagnostic_case == NATIVE_HOST_RUNTIME_CASE:
                    diagnostic_paths = NATIVE_HOST_RUNTIME_SOURCE_PATHS
                elif diagnostic_case == NATIVE_CASE_PREPARATION:
                    diagnostic_paths = NATIVE_CASE_PREPARATION_PATHS
                elif diagnostic_case == WORKFLOW_TIMEOUT_CONTRACT_CASE:
                    diagnostic_paths = WORKFLOW_TIMEOUT_CONTRACT_SOURCE_PATHS
                elif diagnostic_case == PUBLICATION_RSS_OBSERVATION_CASE:
                    diagnostic_paths = PUBLICATION_RSS_OBSERVATION_SOURCE_PATHS
                elif diagnostic_case == NATIVE_RESULT_HANDOFF_CASE:
                    diagnostic_paths = NATIVE_RESULT_HANDOFF_SOURCE_PATHS
                elif diagnostic_case == NATIVE_INPUT_MASK_ALIGNMENT_CASE:
                    diagnostic_paths = NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_PATHS
                else:
                    raise ValueError("fresh-batch-diagnostic-classification-invalid")
                if (not diagnostic_paths.issubset(pins)
                        or any(pins[name] == prior_pins.get(name) for name in diagnostic_paths)):
                    raise ValueError("fresh-batch-diagnostic-source-change-unproven")
                if (diagnostic_case in (NATIVE_HOST_RUNTIME_CASE, NATIVE_CASE_PREPARATION,
                                        WORKFLOW_TIMEOUT_CONTRACT_CASE,
                                        PUBLICATION_RSS_OBSERVATION_CASE,
                                        NATIVE_RESULT_HANDOFF_CASE,
                                        NATIVE_INPUT_MASK_ALIGNMENT_CASE)
                        and {name for name, digest in pins.items()
                             if prior_pins.get(name) != digest} != diagnostic_paths):
                    raise ValueError("fresh-batch-diagnostic-source-change-unproven")
    elif (not validated_native_resumption
            and predecessor_evidence.get("infrastructure_retry_reason") not in
                ("runner-transient", "observation-reconciliation")):
        raise ValueError("fresh-batch-infrastructure-retry-justification-required")

    if stage in ("public-effects", "native-diagnostic"):
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
        if admission["disposition"] == "reviewed-diagnostic-resumption":
            _validate_diagnostic_resumption_binding(stage=stage, source_head=source_head,
                source_pins=pins, prior_source=prior_source, repair=predecessor_evidence,
                candidate=candidate)
    native_ready = None
    if diagnostic_effects:
        native_ready = _validate_native_readiness(root, batch_root, admission, admission_sha256,
            diagnostic_readiness_path, diagnostic_readiness_sha256)
        if (runtime_cutoff - current).total_seconds() < 2700:
            raise ValueError("native-diagnostic-job-window-unavailable")
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
            "source_payload_sha256": source_payload_sha, "successor_claim": claim_path,
            "native_diagnostic_readiness": native_ready}


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
