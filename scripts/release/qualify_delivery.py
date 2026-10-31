#!/usr/bin/env python3
"""Observe protected hosted delivery and verify the exact public release bytes."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import secrets
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from scripts.ci import public_hygiene
from scripts.ci import repository_preflight
from scripts.release import promote

REQUIRED_JOBS = {"required-ci", "safety", "gameplay", "desktop", "package", "performance",
                 "attestation"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
V02_REQUIREMENTS = ("EVID-03", "COMP-02", "PERF-03", "REL-04", "DOC-02")
V02_PACKET_SCHEMA = "genewhip.v02-publisher-packet.v1"
V02_PREPUBLICATION_SCOPE = "publisher-readiness"


class DeliveryError(RuntimeError):
    pass


def validate_preflight(packet: Any, repository: str) -> list[str]:
    if not isinstance(packet, dict) or packet.get("schema") != "genewhip.publication-readiness-packet.v1":
        return ["preflight-schema-invalid"]
    if packet.get("repository") != repository:
        return ["preflight-destination-mismatch"]
    if packet.get("destination") != {"owner_repository": repository, "visibility": "public"}:
        return ["preflight-public-destination-unrecorded"]
    if packet.get("history_disposition") != "sanitized-snapshots-preserve-local-history":
        return ["preflight-history-disposition-unrecorded"]
    privacy = packet.get("privacy_scan")
    copy_scan = privacy.get("publication_copy") if isinstance(privacy, dict) else None
    if not isinstance(copy_scan, dict) or copy_scan.get("status") != "pass" \
            or copy_scan.get("findings") != []:
        return ["publication-privacy-findings"]
    observations = packet.get("repository_observations")
    if not isinstance(observations, dict) or observations.get("ready") is not True:
        return ["preflight-repository-policy-unobserved"]
    return []


def validate_status_checks(checks: Any) -> list[str]:
    if not isinstance(checks, list):
        return ["required-ci-missing"]
    required = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        name = check.get("name") or check.get("context")
        conclusion = check.get("conclusion") or check.get("state")
        if name == "required-ci":
            status = str(check.get("status", "")).upper()
            if status and status != "COMPLETED" and not conclusion:
                return ["required-ci-pending"]
            required.append(str(conclusion).upper())
    if not required:
        return ["required-ci-missing"]
    if any(value not in {"SUCCESS", "SUCCESSFUL"} for value in required):
        return ["required-ci-not-success"]
    return []


def validate_pull_request(pr: Any, expected_head: str, expected_base: str,
                          check_status: bool = True) -> list[str]:
    if not isinstance(pr, dict) or pr.get("state") != "OPEN":
        return ["pull-request-not-open"]
    if pr.get("isDraft") is True or pr.get("baseRefName") != "main":
        return ["pull-request-base-or-draft-invalid"]
    if pr.get("headRefOid") != expected_head:
        return ["pull-request-head-moved"]
    if pr.get("baseRefOid") != expected_base:
        return ["pull-request-base-moved"]
    return validate_status_checks(pr.get("statusCheckRollup")) if check_status else []


def validate_main_run(run: Any, expected_sha: str) -> list[str]:
    if not isinstance(run, dict) or run.get("event") != "push":
        return ["main-run-event-invalid"]
    if run.get("headSha") != expected_sha:
        return ["main-run-source-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["main-run-not-success"]
    jobs = run.get("jobs")
    if not isinstance(jobs, list):
        return ["main-run-jobs-unavailable"]
    observed = {job.get("name"): job.get("conclusion") for job in jobs if isinstance(job, dict)}
    if not REQUIRED_JOBS <= observed.keys():
        return ["main-run-qualification-job-missing"]
    if any(observed[name] != "success" for name in REQUIRED_JOBS):
        return ["main-run-qualification-job-not-success"]
    return []


def validate_v02_qualification_run(run: Any, expected_sha: str) -> list[str]:
    """Require the exact successful qualification close and its trusted source run."""
    if not isinstance(run, dict) or run.get("event") != "push":
        return ["v02-qualification-event-invalid"]
    if run.get("headSha") != expected_sha:
        return ["v02-qualification-source-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["v02-qualification-run-not-success"]
    jobs = run.get("jobs")
    if not isinstance(jobs, list):
        return ["v02-qualification-jobs-unavailable"]
    observed: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        if isinstance(job, dict) and isinstance(job.get("name"), str):
            observed.setdefault(job["name"], []).append(job)
    required = {"required-ci", "attestation", "v02-release-qualification"}
    if not required <= observed.keys() or any(len(observed[name]) != 1 for name in required):
        return ["v02-qualification-job-missing-or-ambiguous"]
    if any(observed[name][0].get("status") != "completed"
           or observed[name][0].get("conclusion") != "success" for name in required):
        return ["v02-qualification-job-not-success"]
    return []


def validate_v02_publisher_packet(packet: Any, repository: str | None = None) -> list[str]:
    """Validate untrusted packet shape; this alone never authenticates a publisher."""
    if not isinstance(packet, dict) or packet.get("schema") != V02_PACKET_SCHEMA:
        return ["v02-publisher-packet-schema-invalid"]
    repo = packet.get("repository")
    if not isinstance(repo, str) or not promote.REPO_RE.fullmatch(repo) or ".." in repo.split("/"):
        return ["v02-publisher-packet-repository-invalid"]
    if repository is not None and repository != repo:
        return ["v02-publisher-packet-repository-mismatch"]
    if packet.get("release_tag") != "v0.2.0" or not SHA_RE.fullmatch(str(packet.get("source_sha", ""))):
        return ["v02-publisher-packet-release-identity-invalid"]
    preflight = packet.get("preflight")
    if validate_preflight(preflight, repo):
        return ["v02-publisher-packet-preflight-invalid"]
    qualification = packet.get("qualification")
    publisher = packet.get("publisher")
    if not isinstance(qualification, dict) or not isinstance(publisher, dict):
        return ["v02-publisher-packet-run-identity-invalid"]
    if (not str(qualification.get("run_id", "")).isdigit()
            or type(qualification.get("run_attempt")) is not int or qualification["run_attempt"] < 1
            or qualification.get("source_sha") != packet["source_sha"]
            or qualification.get("workflow_path") != ".github/workflows/ci.yml"
            or qualification.get("ref") != "refs/heads/main" or qualification.get("event") != "push"):
        return ["v02-publisher-packet-qualification-identity-invalid"]
    if (not str(publisher.get("run_id", "")).isdigit()
            or type(publisher.get("run_attempt")) is not int or publisher["run_attempt"] < 1
            or not SHA_RE.fullmatch(str(publisher.get("source_sha", "")))
            or publisher.get("workflow_path") != ".github/workflows/release.yml"
            or publisher.get("ref") != "refs/heads/main"
            or publisher.get("event") != "workflow_dispatch"):
        return ["v02-publisher-packet-publisher-identity-invalid"]
    if not isinstance(packet.get("publisher_correlation_id"), str) or not packet["publisher_correlation_id"]:
        return ["v02-publisher-packet-correlation-id-invalid"]
    if not HEX_RE.fullmatch(str(packet.get("inventory_sha256", ""))):
        return ["v02-publisher-packet-inventory-digest-invalid"]
    if ("requirement_outcomes" in packet or "final_qualified" in packet
            or "final_outcomes" in packet):
        return ["v02-publisher-packet-final-claims-forbidden"]
    digests = packet.get("asset_digests")
    if not isinstance(digests, dict):
        return ["v02-publisher-packet-asset-digests-invalid"]
    expected_names = {
        name for prefix in ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64",
                            "genewhip-0.2.0-playable-preview-macos-arm64")
        for name in (f"{prefix}-{packet['source_sha'][:12]}.tar.gz",
                     f"{prefix}-{packet['source_sha'][:12]}.tar.gz.sha256",
                     f"{prefix}-{packet['source_sha'][:12]}.tar.gz.qualification.json")
    } | {"inventory.json", "SHA256SUMS"}
    if set(digests) != expected_names or any(not HEX_RE.fullmatch(str(value)) for value in digests.values()):
        return ["v02-publisher-packet-asset-roster-invalid"]
    if digests.get("inventory.json") != packet["inventory_sha256"]:
        return ["v02-publisher-packet-inventory-digest-mismatch"]
    claims = packet.get("prepublication_outcomes")
    if (packet.get("prepublication_scope") != V02_PREPUBLICATION_SCOPE
            or not isinstance(claims, dict) or set(claims) != set(V02_REQUIREMENTS)
            or any(claims.get(name) != "pass" for name in V02_REQUIREMENTS)):
        return ["v02-publisher-packet-prepublication-readiness-incomplete"]
    return []


def validate_v02_authenticated_packet(packet: Any, repository: str,
                                      qualification_run: Any, qualification_identity: Any,
                                      publisher_run: Any, publisher_identity: Any) -> list[str]:
    """Bind packet claims to independently fetched GitHub run/attempt/workflow facts."""
    problems = validate_v02_publisher_packet(packet, repository)
    if problems:
        return problems
    qualification = packet["qualification"]
    publisher = packet["publisher"]
    problems = validate_v02_qualification_run(qualification_run, packet["source_sha"])
    if problems:
        return problems
    if (str(qualification_run.get("databaseId")) != str(qualification["run_id"])
            or qualification_run.get("attempt") != qualification["run_attempt"]):
        return ["v02-qualification-run-attempt-mismatch"]
    problems = validate_workflow_identity(qualification_identity, qualification["workflow_path"],
                                          packet["source_sha"], "push")
    if problems:
        return problems
    if str(qualification_identity.get("id")) != str(qualification["run_id"]) \
            or qualification_identity.get("run_attempt") != qualification["run_attempt"]:
        return ["v02-qualification-workflow-attempt-mismatch"]
    problems = validate_publisher_run(
        publisher_run, publisher["source_sha"], qualification["run_id"],
        qualification["run_attempt"], packet["publisher_correlation_id"],
        qualified_source_sha=packet["source_sha"])
    if problems:
        return problems
    if (str(publisher_run.get("databaseId")) != str(publisher["run_id"])
            or publisher_run.get("attempt") != publisher["run_attempt"]):
        return ["v02-publisher-run-attempt-mismatch"]
    problems = validate_workflow_identity(publisher_identity, publisher["workflow_path"],
                                          publisher["source_sha"], "workflow_dispatch")
    if problems:
        return problems
    if (str(publisher_identity.get("id")) != str(publisher["run_id"])
            or publisher_identity.get("run_attempt") != publisher["run_attempt"]):
        return ["v02-publisher-workflow-attempt-mismatch"]
    return validate_publisher_branch_identity(publisher_identity, publisher["source_sha"])


def make_v02_adoption_receipt(packet: dict[str, Any], release_info: dict[str, Any],
                              docs_receipt: dict[str, Any]) -> dict[str, Any]:
    """Create a directional receipt outside the immutable release subjects."""
    expected_commands = {"play", "build", "embed", "offline_source_core_build", "errors"}
    packages = docs_receipt.get("packages")
    expected_archives = {
        "sdk": f"genewhip-0.2.0-sdk-diagnostic-darwin-arm64-{packet.get('source_sha', '')[:12]}.tar.gz",
        "desktop": f"genewhip-0.2.0-playable-preview-macos-arm64-{packet.get('source_sha', '')[:12]}.tar.gz",
    }
    if (docs_receipt.get("outcome") != "pass" or docs_receipt.get("mode") != "public-downloaded"
            or docs_receipt.get("local_source_identity") != packet.get("source_sha")
            or not isinstance(docs_receipt.get("commands"), dict)
            or set(docs_receipt["commands"]) != expected_commands
            or any(value != "pass" for value in docs_receipt["commands"].values())
            or not isinstance(packages, dict) or set(packages) != {"sdk", "desktop"}
            or any(item.get("source_revision") != packet.get("source_sha")
                   or item.get("source_state") != "clean" for item in packages.values())
            or any(packages[role].get("archive") != archive
                   or packages[role].get("archive_sha256") != packet.get("asset_digests", {}).get(archive)
                   for role, archive in expected_archives.items())
            or release_info.get("tag") != packet.get("release_tag")):
        raise DeliveryError("downloaded-adoption-not-qualified")
    processes = docs_receipt.get("processes")
    if (not isinstance(processes, list) or not processes
            or any(not isinstance(item, dict) or item.get("process_group_cleanup") != "confirmed"
                   for item in processes)):
        raise DeliveryError("downloaded-adoption-cleanup-unconfirmed")
    assets = release_info.get("assets")
    if not isinstance(assets, list):
        raise DeliveryError("downloaded-adoption-assets-missing")
    digests = {row.get("name"): row.get("sha256") for row in assets if isinstance(row, dict)}
    if digests != packet.get("asset_digests"):
        raise DeliveryError("downloaded-adoption-subject-digest-mismatch")
    return {"schema": "genewhip-v02-downloaded-adoption-v1", "version": "0.2.0",
            "outcome": "pass", "final_qualified": True,
            "repository": packet["repository"], "tag": packet["release_tag"],
            "source_sha": packet["source_sha"], "inventory_sha256": packet["inventory_sha256"],
            "qualification": packet["qualification"], "publisher": packet["publisher"],
            "publisher_correlation_id": packet["publisher_correlation_id"],
            "asset_digests": digests,
            "requirement_outcomes": {name: "pass" for name in V02_REQUIREMENTS},
            "adoption": {"outcome": "pass", "docs_receipt_sha256": hashlib.sha256(
                json.dumps(docs_receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}}


def validate_workflow_identity(run: Any, expected_path: str, expected_sha: str,
                               expected_event: str) -> list[str]:
    if not isinstance(run, dict) or run.get("path") != expected_path:
        return ["workflow-path-mismatch"]
    if run.get("head_sha") != expected_sha or run.get("event") != expected_event:
        return ["workflow-source-or-event-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["workflow-run-not-success"]
    return []


def publisher_display_title(source_sha: str, qualification_run_id: str,
                            qualification_attempt: int, correlation_id: str) -> str:
    return (f"Preview release for {source_sha} (qualification {qualification_run_id} "
            f"attempt {qualification_attempt}; dispatch {correlation_id})")


def validate_publisher_run(run: Any, expected_sha: str, qualification_run_id: str,
                           qualification_attempt: int, correlation_id: str,
                           *, qualified_source_sha: str | None = None) -> list[str]:
    if not isinstance(run, dict) or run.get("event") != "workflow_dispatch":
        return ["publisher-run-event-invalid"]
    if run.get("headSha") != expected_sha:
        return ["publisher-run-source-mismatch"]
    expected_title = publisher_display_title(qualified_source_sha or expected_sha,
                                             str(qualification_run_id),
                                             qualification_attempt, correlation_id)
    if run.get("displayTitle") != expected_title:
        return ["publisher-run-dispatch-identity-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["publisher-run-not-success"]
    if not any(isinstance(job, dict) and job.get("name") == "promote"
               and job.get("conclusion") == "success" for job in run.get("jobs", [])):
        return ["publisher-job-not-success"]
    return []


def validate_publisher_branch_identity(run: Any, expected_sha: str) -> list[str]:
    if not isinstance(run, dict) or run.get("head_sha") != expected_sha:
        return ["publisher-workflow-source-mismatch"]
    if run.get("head_branch") != "main":
        return ["publisher-workflow-not-main-branch"]
    return []


def validate_release(release: Any, repository: str, tag: str,
                     directory: pathlib.Path, expected_sha: str,
                     version: str = "0.1.0") -> dict[str, Any]:
    if not isinstance(release, dict) or release.get("tag_name") != tag \
            or release.get("draft") is not False or release.get("prerelease") is not True:
        raise DeliveryError("release-visibility-or-tag-invalid")
    if release.get("html_url") != f"https://github.com/{repository}/releases/tag/{tag}":
        raise DeliveryError("release-url-mismatch")
    inventory_path = directory / "inventory.json"
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise DeliveryError("release-inventory-missing-or-invalid") from None
    if inventory.get("source_revision") != expected_sha:
        raise DeliveryError("release-source-mismatch")
    expected_schema = (promote.V02_INVENTORY_SCHEMA if version == "0.2.0"
                       else "genewhip.release-inventory.v1")
    if inventory.get("version") != version or inventory.get("schema") != expected_schema:
        raise DeliveryError("release-inventory-version-mismatch")
    digests, problems = promote.validate_release_inventory(directory, inventory)
    if problems:
        raise DeliveryError(problems[0])
    problems = promote.validate_qualified_inventory(directory, inventory, expected_sha)
    if problems:
        raise DeliveryError(problems[0])
    remote_assets = release.get("assets")
    if not isinstance(remote_assets, list):
        raise DeliveryError("release-assets-unavailable")
    remote = {row.get("name"): row for row in remote_assets if isinstance(row, dict)}
    if set(remote) != set(digests):
        raise DeliveryError("release-asset-roster-mismatch")
    for name, digest in digests.items():
        row = remote[name]
        server_digest = row.get("digest")
        expected_size = (inventory_path.stat().st_size if name == "inventory.json" else
                         (directory / "SHA256SUMS").stat().st_size if name == "SHA256SUMS" else
                         inventory.get("assets", {}).get(name, {}).get("size"))
        if row.get("state") != "uploaded" or row.get("size") != expected_size:
            raise DeliveryError("release-asset-size-or-state-mismatch")
        expected_url = f"https://github.com/{repository}/releases/download/{tag}/{name}"
        if row.get("browser_download_url") != expected_url:
            raise DeliveryError("release-asset-url-mismatch")
        if server_digest != "sha256:" + digest:
            raise DeliveryError("release-asset-server-digest-mismatch")
    archive_findings = []
    for name in inventory["assets"]:
        if name.endswith(".tar.gz"):
            archive_findings.extend(public_hygiene.scan_archive(directory / name))
    if archive_findings:
        raise DeliveryError("release-archive-privacy-findings")
    urls = {name: f"https://github.com/{repository}/releases/download/{tag}/{name}"
            for name in sorted(digests)}
    return {"tag": tag, "version": version, "source_sha": expected_sha,
            "release_url": release.get("html_url"),
            "assets": [{"name": name, "sha256": digests[name], "url": urls[name]}
                       for name in sorted(digests)], "inventory": inventory}


def self_test() -> dict[str, Any]:
    sha = "a" * 40
    pr = {"state": "OPEN", "isDraft": False, "baseRefName": "main", "baseRefOid": "b" * 40,
          "headRefOid": sha, "statusCheckRollup": [{"name": "required-ci", "conclusion": "SUCCESS"}],
          "reviewDecision": None}
    jobs = [{"name": name, "conclusion": "success"} for name in REQUIRED_JOBS]
    run = {"event": "push", "headSha": sha, "status": "completed", "conclusion": "success",
           "jobs": jobs}
    ok = not validate_pull_request(pr, sha, "b" * 40) and not validate_main_run(run, sha)
    return {"schema": "genewhip.delivery-self-test.v1", "kind": "synthetic_contract_only",
            "pass": ok, "hosted_evidence": {"outcome": "not_run", "qualifies_rel_03": False},
            "mutations_performed": 0}


def _safe_path(value: pathlib.Path) -> pathlib.Path:
    path = value if value.is_absolute() else ROOT / value
    path = path.resolve()
    allowed = ((ROOT / "build" / "phase4").resolve(), (ROOT / "build" / "v02").resolve())
    if not any(root == path or root in path.parents for root in allowed):
        raise DeliveryError("output-path-outside-build")
    return path


def _gh(args: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(["gh", *args], cwd=ROOT, text=True, capture_output=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DeliveryError("github-cli-unavailable-or-timeout") from None
    if result.returncode:
        raise DeliveryError("github-command-failed-" + args[0])
    return result.stdout


def _gh_api_json(endpoint: str, timeout: int = 60) -> Any:
    """Preserve read-only API status classes needed for effective-policy checks."""
    try:
        result = subprocess.run(["gh", "api", endpoint], cwd=ROOT, text=True,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise repository_preflight.ServiceError("transport_error") from None
    if result.returncode:
        match = re.search(r"\(HTTP ([0-9]{3})\)", result.stderr)
        status = int(match.group(1)) if match else None
        if status == 404:
            raise repository_preflight.ServiceError("not_found", status)
        if status in (401, 403):
            raise repository_preflight.ServiceError("permission_denied", status)
        raise repository_preflight.ServiceError("transport_error")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise repository_preflight.ServiceError("transport_error") from None


def _gh_json(args: list[str], timeout: int = 60) -> Any:
    try:
        return json.loads(_gh(args, timeout))
    except json.JSONDecodeError:
        raise DeliveryError("github-response-invalid") from None


def authenticate_v02_publisher_packet(packet: Any, repository: str | None = None) -> dict[str, Any]:
    """Reopen every publisher/qualification identity through the live GitHub API."""
    problems = validate_v02_publisher_packet(packet, repository)
    if problems:
        raise DeliveryError(problems[0])
    repository = packet["repository"]
    qualification, publisher = packet["qualification"], packet["publisher"]
    qid, qattempt = str(qualification["run_id"]), qualification["run_attempt"]
    pid, pattempt = str(publisher["run_id"]), publisher["run_attempt"]
    qualification_run = _gh_json(["run", "view", qid, "--repo", repository,
                                  "--attempt", str(qattempt), "--json",
                                  "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId"])
    qualification_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{qid}/attempts/{qattempt}"])
    publisher_run = _gh_json(["run", "view", pid, "--repo", repository,
                              "--attempt", str(pattempt), "--json",
                              "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId,displayTitle"])
    publisher_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{pid}/attempts/{pattempt}"])
    problems = validate_v02_authenticated_packet(packet, repository, qualification_run,
                                                  qualification_identity, publisher_run,
                                                  publisher_identity)
    if problems:
        raise DeliveryError(problems[0])
    preflight = packet["preflight"]
    identity = preflight.get("expected_identity", {})
    head, base = identity.get("head"), identity.get("base")
    if not SHA_RE.fullmatch(str(head or "")) or not SHA_RE.fullmatch(str(base or "")):
        raise DeliveryError("v02-publisher-packet-preflight-identity-invalid")
    _inspect_live_repository(repository, head, base)
    release = _gh_json(["api", f"repos/{repository}/releases/tags/{packet['release_tag']}"])
    ref = _gh_json(["api", f"repos/{repository}/git/ref/tags/{packet['release_tag']}"])
    tag_object = ref.get("object") if isinstance(ref, dict) else None
    if not isinstance(tag_object, dict) or not isinstance(tag_object.get("sha"), str):
        raise DeliveryError("release-tag-reference-invalid")
    tag_sha = tag_object["sha"]
    if tag_object.get("type") == "tag":
        annotated = _gh_json(["api", f"repos/{repository}/git/tags/{tag_sha}"])
        target = annotated.get("object") if isinstance(annotated, dict) else None
        if not isinstance(target, dict) or target.get("type") != "commit":
            raise DeliveryError("release-tag-target-invalid")
        tag_sha = target.get("sha")
    if tag_sha != packet["source_sha"]:
        raise DeliveryError("release-tag-source-mismatch")
    return {"qualification_run": qualification_run, "qualification_identity": qualification_identity,
            "publisher_run": publisher_run, "publisher_identity": publisher_identity,
            "release": release, "tag_sha": tag_sha}


def verify_v02_subject_attestations(directory: pathlib.Path, packet: dict[str, Any]) -> None:
    """Verify archive and inventory provenance before parsing or executing package members."""
    directory = pathlib.Path(directory)
    for name, expected_digest in packet["asset_digests"].items():
        path = directory / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise DeliveryError("release-asset-missing-or-invalid") from None
        if path.is_symlink() or not path.is_file() or info.st_size > promote.MAX_RELEASE_ASSET_BYTES:
            raise DeliveryError("release-asset-missing-or-invalid")
        digest = hashlib.sha256()
        with path.open("rb") as asset:
            for chunk in iter(lambda: asset.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_digest:
            raise DeliveryError("release-asset-digest-mismatch")
    if hashlib.sha256((directory / "inventory.json").read_bytes()).hexdigest() != packet["inventory_sha256"]:
        raise DeliveryError("release-inventory-digest-mismatch")
    qualification = packet["qualification"]
    subject_names = [name for name in packet["asset_digests"] if name.endswith(".tar.gz")]
    subject_names.append("inventory.json")
    for name in subject_names:
        try:
            promote.verify_attestation(directory / name, packet["repository"], packet["source_sha"],
                                       str(qualification["run_id"]), qualification["run_attempt"])
        except promote.PromotionError as error:
            raise DeliveryError(str(error)) from None


def _read_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise DeliveryError("evidence-file-missing-or-invalid") from None


def _write_json(path: pathlib.Path, value: Any) -> None:
    path = _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _check_preflight(path: pathlib.Path, repository: str) -> dict[str, Any]:
    packet = _read_json(path)
    problems = validate_preflight(packet, repository)
    if problems:
        raise DeliveryError(problems[0])
    return packet


def _inspect_live_repository(repository: str, expected_head: str, expected_base: str) -> dict[str, Any]:
    def get_json(path: str) -> Any:
        return _gh_api_json(path)
    observed = repository_preflight.inspect_repository(
        repository, repository_preflight.GitHubClient(get_json), expected_head, expected_base)
    if observed.get("blockers"):
        raise DeliveryError("live-repository-policy-" + observed["blockers"][0])
    return observed


def prepare_merge(args: argparse.Namespace) -> dict[str, Any]:
    """Wait for the aggregate and return current identities before native auto-merge."""
    repository = args.repository
    packet = _check_preflight(args.preflight, repository)
    if not SHA_RE.fullmatch(args.expected_head or "") or not SHA_RE.fullmatch(args.expected_base or ""):
        raise DeliveryError("expected-pr-identity-invalid")
    fields = "state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,statusCheckRollup"
    pr = _gh_json(["pr", "view", str(args.pull_request), "--repo", repository, "--json", fields])
    problems = validate_pull_request(pr, args.expected_head, args.expected_base, check_status=False)
    if problems:
        raise DeliveryError(problems[0])
    _inspect_live_repository(repository, args.expected_head, args.expected_base)
    def aggregate_check():
        current = _gh_json(["pr", "view", str(args.pull_request), "--repo", repository,
                            "--json", fields])
        problems = validate_pull_request(current, args.expected_head, args.expected_base,
                                         check_status=False)
        if problems:
            raise DeliveryError(problems[0])
        checks = current.get("statusCheckRollup")
        if not isinstance(checks, list) or not any(
                isinstance(check, dict) and (check.get("name") or check.get("context")) == "required-ci"
                for check in checks):
            return None
        problems = validate_status_checks(checks)
        if problems == ["required-ci-pending"]:
            return None
        if problems:
            raise DeliveryError(problems[0])
        return current

    _wait_for(aggregate_check, args.timeout_seconds)
    pr = _gh_json(["pr", "view", str(args.pull_request), "--repo", repository,
                   "--json", fields + ",autoMergeRequest"])
    problems = validate_pull_request(pr, args.expected_head, args.expected_base)
    if problems:
        raise DeliveryError(problems[0])
    _inspect_live_repository(repository, args.expected_head, args.expected_base)
    if pr.get("baseRefOid") != packet["expected_identity"]["base"]:
        raise DeliveryError("preflight-base-changed")
    return {"schema": "genewhip.delivery-readiness.v1", "repository": repository,
            "pull_request": args.pull_request, "head_sha": args.expected_head,
            "base_sha": args.expected_base, "required_check": "required-ci",
            "native_auto_merge_enabled": bool(pr.get("autoMergeRequest")),
            "status": "ready-for-native-auto-merge", "mutations_performed": 0}


def _wait_for(predicate, seconds: int, interval: int = 15):
    end = time.monotonic() + seconds
    while True:
        value = predicate()
        if value is not None:
            return value
        if time.monotonic() >= end:
            raise DeliveryError("hosted-run-timeout")
        time.sleep(min(interval, max(1, int(end - time.monotonic()))))


def run_delivery(args: argparse.Namespace) -> dict[str, Any]:
    repository = args.repository
    readiness = prepare_merge(args)
    pr_fields = "state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,mergeCommit,mergeStateStatus,statusCheckRollup,autoMergeRequest"
    pr = _gh_json(["pr", "view", str(args.pull_request), "--repo", repository, "--json", pr_fields])
    problems = validate_pull_request(pr, args.expected_head, args.expected_base, check_status=False)
    if problems:
        raise DeliveryError(problems[0])
    # The caller enables GitHub native auto-merge through its authorized connector
    # after these checks pass. This process only observes the protected transition.
    if not pr.get("autoMergeRequest"):
        raise DeliveryError("native-auto-merge-not-enabled")

    def merged_pr():
        current = _gh_json(["pr", "view", str(args.pull_request), "--repo", repository,
                            "--json", pr_fields])
        if current.get("headRefOid") != args.expected_head or current.get("baseRefName") != "main" \
                or current.get("isDraft") is True:
            raise DeliveryError("pull-request-identity-changed-after-auto-merge")
        if current.get("state") == "MERGED":
            return current
        if current.get("state") != "OPEN":
            raise DeliveryError("pull-request-closed-without-merge")
        return None

    pr = _wait_for(merged_pr, args.timeout_seconds)
    merge = pr.get("mergeCommit") if isinstance(pr.get("mergeCommit"), dict) else {}
    source_sha = merge.get("oid")
    if not isinstance(source_sha, str) or len(source_sha) != 40:
        raise DeliveryError("merged-source-sha-unavailable")
    main_ref = _gh_json(["api", f"repos/{repository}/git/ref/heads/main"])
    if main_ref.get("object", {}).get("sha") != source_sha:
        raise DeliveryError("main-head-moved-after-merge")

    def main_run():
        rows = _gh_json(["run", "list", "--repo", repository, "--workflow", "ci.yml", "--branch",
                         "main", "--commit", source_sha, "--event", "push", "--limit", "10",
                         "--json", "databaseId,attempt,event,headSha,status,conclusion,workflowName,createdAt"])
        matches = [row for row in rows if isinstance(row, dict) and row.get("headSha") == source_sha
                   and row.get("event") == "push"]
        if not matches:
            return None
        row = matches[0]
        if row.get("status") != "completed":
            return None
        return _gh_json(["run", "view", str(row["databaseId"]), "--repo", repository,
                         "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId"])

    run = _wait_for(main_run, args.timeout_seconds)
    problems = (validate_v02_qualification_run(run, source_sha) if args.require_v02_qualification
                else validate_main_run(run, source_sha))
    if problems:
        raise DeliveryError(problems[0])
    run_id, attempt = str(run.get("databaseId")), int(run.get("attempt", 0))
    if not run_id or attempt < 1:
        raise DeliveryError("main-run-identity-invalid")
    main_ref = _gh_json(["api", f"repos/{repository}/git/ref/heads/main"])
    if main_ref.get("object", {}).get("sha") != source_sha:
        raise DeliveryError("main-head-moved-before-publication")
    publisher_sha = main_ref["object"]["sha"]
    main_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}"])
    problems = validate_workflow_identity(main_identity, ".github/workflows/ci.yml", source_sha, "push")
    if problems:
        raise DeliveryError(problems[0])

    dispatch_time = dt.datetime.now(dt.timezone.utc)
    correlation_id = secrets.token_hex(16)
    _gh(["workflow", "run", "release.yml", "--repo", repository, "--ref", "main",
         "-f", f"source_sha={source_sha}", "-f", f"run_id={run_id}",
         "-f", f"run_attempt={attempt}", "-f", f"correlation_id={correlation_id}",
         "-f", f"release_version={args.version}"])

    def publisher_run():
        rows = _gh_json(["run", "list", "--repo", repository, "--workflow", "release.yml", "--branch",
                         "main", "--event", "workflow_dispatch", "--limit", "10",
                         "--json", "databaseId,attempt,event,headSha,status,conclusion,workflowName,createdAt,displayTitle"])
        expected_title = publisher_display_title(source_sha, run_id, attempt, correlation_id)
        for row in rows:
            if not isinstance(row, dict) or row.get("headSha") != publisher_sha \
                    or row.get("event") != "workflow_dispatch" \
                    or row.get("displayTitle") != expected_title:
                continue
            created = dt.datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00"))
            if created < dispatch_time:
                continue
            if row.get("status") != "completed":
                return None
            return _gh_json(["run", "view", str(row["databaseId"]), "--repo", repository,
                             "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId,displayTitle"])
        return None

    publisher = _wait_for(publisher_run, args.timeout_seconds)
    problems = validate_publisher_run(publisher, publisher_sha, run_id, attempt,
                                      correlation_id, qualified_source_sha=source_sha)
    if problems:
        raise DeliveryError(problems[0])
    publisher_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{publisher.get('databaseId')}/attempts/{publisher.get('attempt')}"])
    problems = validate_workflow_identity(publisher_identity, ".github/workflows/release.yml",
                                          publisher_sha, "workflow_dispatch")
    if problems:
        raise DeliveryError(problems[0])
    problems = validate_publisher_branch_identity(publisher_identity, publisher_sha)
    if problems:
        raise DeliveryError(problems[0])
    evidence = {"schema": "genewhip.hosted-delivery.v1", "repository": repository,
                "pull_request": args.pull_request, "pull_request_head_sha": args.expected_head,
                "pull_request_base_sha": args.expected_base, "merged_source_sha": source_sha,
                "merge_commit_sha": source_sha, "qualification_run_id": run_id,
                "qualification_run_attempt": attempt, "qualification_workflow": run.get("workflowName"),
                "publisher_correlation_id": correlation_id,
                "publisher_run_id": str(publisher.get("databaseId")),
                "publisher_run_attempt": publisher.get("attempt"),
                "publisher_source_sha": publisher_sha,
                "publisher_workflow": publisher.get("workflowName"),
                "hosted_evidence": {"outcome": "success", "qualifies_rel_03": False},
                "release": None, "merge_readiness": readiness}
    _write_json(args.evidence_out, evidence)
    return evidence


def verify_release(args: argparse.Namespace) -> dict[str, Any]:
    if args.download_only:
        return verify_v02_download(args)
    repository = args.repository
    _check_preflight(args.preflight, repository)
    evidence = _read_json(args.evidence)
    source_sha = args.source_sha or evidence.get("merged_source_sha")
    if evidence.get("repository") != repository or evidence.get("merged_source_sha") != source_sha \
            or evidence.get("hosted_evidence", {}).get("outcome") != "success":
        raise DeliveryError("hosted-delivery-evidence-mismatch")
    qualification_id = evidence.get("qualification_run_id")
    qualification_attempt = evidence.get("qualification_run_attempt")
    publisher_id = evidence.get("publisher_run_id")
    publisher_attempt = evidence.get("publisher_run_attempt")
    publisher_sha = evidence.get("publisher_source_sha")
    correlation_id = evidence.get("publisher_correlation_id")
    if not all((qualification_id, qualification_attempt, publisher_id, publisher_attempt,
                publisher_sha, correlation_id)):
        raise DeliveryError("hosted-run-identities-missing")
    qualification = _gh_json(["run", "view", str(qualification_id), "--repo", repository,
                              "--attempt", str(qualification_attempt),
                              "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId"])
    problems = validate_main_run(qualification, source_sha)
    if problems:
        raise DeliveryError(problems[0])
    problems = validate_workflow_identity(
        _gh_json(["api", f"repos/{repository}/actions/runs/{qualification_id}/attempts/{qualification_attempt}"]),
        ".github/workflows/ci.yml", source_sha, "push")
    if problems:
        raise DeliveryError(problems[0])
    publisher = _gh_json(["run", "view", str(publisher_id), "--repo", repository,
                          "--attempt", str(publisher_attempt),
                          "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId,displayTitle"])
    problems = validate_publisher_run(publisher, publisher_sha, qualification_id,
                                      int(qualification_attempt), correlation_id,
                                      qualified_source_sha=source_sha)
    if problems:
        raise DeliveryError(problems[0])
    problems = validate_workflow_identity(
        _gh_json(["api", f"repos/{repository}/actions/runs/{publisher_id}/attempts/{publisher_attempt}"]),
        ".github/workflows/release.yml", publisher_sha, "workflow_dispatch")
    if problems:
        raise DeliveryError(problems[0])
    publisher_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{publisher_id}/attempts/{publisher_attempt}"])
    problems = validate_publisher_branch_identity(publisher_identity, publisher_sha)
    if problems:
        raise DeliveryError(problems[0])
    directory = _safe_path(args.download_dir)
    if directory.exists():
        if directory.is_symlink() or any(directory.iterdir()):
            raise DeliveryError("download-directory-not-empty")
    else:
        directory.mkdir(parents=True)
    release = _gh_json(["api", f"repos/{repository}/releases/tags/{args.release_tag}"])
    tag_ref = _gh_json(["api", f"repos/{repository}/git/ref/tags/{args.release_tag}"])
    if tag_ref.get("object", {}).get("sha") != source_sha:
        raise DeliveryError("release-tag-source-mismatch")
    _gh(["release", "download", args.release_tag, "--repo", repository, "--dir", str(directory)])
    release_info = validate_release(release, repository, args.release_tag, directory, source_sha,
                                    args.version)
    # Execute only after the archive inventory, SHA256SUMS, receipts, notices, and privacy scan pass.
    result = subprocess.run([sys.executable, str(ROOT / "tests/package/docs_commands.py"),
                             "--local-artifacts", str(directory),
                             "--release-url", release_info["release_url"]], cwd=ROOT, text=True,
                            capture_output=True, timeout=1800, check=False)
    if result.returncode:
        raise DeliveryError("downloaded-package-adoption-smoke-failed")
    evidence["release"] = release_info
    evidence["downloaded_package_adoption"] = "pass"
    evidence["hosted_evidence"] = {"outcome": "success", "qualifies_rel_03": True}
    evidence["requirements"] = {"REL-03": "pass", "REL-02": "pass", "DOC-01": "pass"}
    _write_json(args.evidence, evidence)
    return evidence


def resolve_v02_download_context(args: argparse.Namespace) -> dict[str, Any]:
    """Resolve optional repository/preflight from a valid packet before CLI guard bypass."""
    if args.version != "0.2.0" or args.release_tag != "v0.2.0":
        raise DeliveryError("download-only-requires-v0.2.0")
    packet = _read_json(args.evidence)
    problems = validate_v02_publisher_packet(packet, args.repository)
    if problems:
        raise DeliveryError(problems[0])
    if args.source_sha and args.source_sha != packet["source_sha"]:
        raise DeliveryError("v02-publisher-packet-source-mismatch")
    if args.preflight:
        supplied = _read_json(args.preflight)
        if supplied != packet["preflight"]:
            raise DeliveryError("v02-publisher-packet-preflight-mismatch")
    if pathlib.Path(args.evidence_out).resolve() == pathlib.Path(args.evidence).resolve():
        raise DeliveryError("download-adoption-output-would-overwrite-publisher-packet")
    facts = authenticate_v02_publisher_packet(packet, packet["repository"])
    args.repository = packet["repository"]
    args.packet = packet
    args.authenticated_facts = facts
    return packet


def make_v02_adoption_failure(packet: dict[str, Any], reason: str, *, published: bool) -> dict[str, Any]:
    """Record authenticated-path failure without converting readiness into final claims."""
    return {"schema": "genewhip-v02-downloaded-adoption-v1", "version": "0.2.0",
            "outcome": "failed", "final_qualified": False,
            "status": "published-but-failed" if published else "not-qualified",
            "blockers": [reason], "repository": packet["repository"],
            "tag": packet["release_tag"], "source_sha": packet["source_sha"],
            "prepublication_scope": V02_PREPUBLICATION_SCOPE,
            "prepublication_outcomes": packet["prepublication_outcomes"],
            "requirement_outcomes": {name: "not-qualified" for name in V02_REQUIREMENTS}}


def verify_v02_download(args: argparse.Namespace) -> dict[str, Any]:
    packet = args.packet
    facts = getattr(args, "authenticated_facts", None)
    authenticated = facts is not None
    directory = None
    published = False
    try:
        if facts is None:
            facts = authenticate_v02_publisher_packet(packet, args.repository)
            authenticated = True
        published = isinstance(facts.get("release"), dict) and facts["release"].get("draft") is False
        directory = _safe_path(args.download_dir)
        evidence_out = _safe_path(args.evidence_out)
        if evidence_out == directory or directory in evidence_out.parents:
            raise DeliveryError("download-adoption-output-inside-immutable-subjects")
        if directory.exists():
            if directory.is_symlink() or any(directory.iterdir()):
                raise DeliveryError("download-directory-not-empty")
        else:
            directory.mkdir(parents=True)
        _gh(["release", "download", packet["release_tag"], "--repo", packet["repository"],
             "--dir", str(directory)])
        # Hash and verify signed provenance before archive extraction or bundled execution.
        verify_v02_subject_attestations(directory, packet)
        release_info = validate_release(facts["release"], packet["repository"],
                                        packet["release_tag"], directory, packet["source_sha"], "0.2.0")
        if (hashlib.sha256((directory / "inventory.json").read_bytes()).hexdigest()
                != packet["inventory_sha256"]):
            raise DeliveryError("release-inventory-digest-mismatch")
        observed = {row["name"]: row["sha256"] for row in release_info["assets"]}
        if observed != packet["asset_digests"]:
            raise DeliveryError("release-asset-digest-mismatch")
        docs_receipt_path = pathlib.Path(args.evidence_out).with_name(
            pathlib.Path(args.evidence_out).stem + "-docs.json")
        docs_path = _safe_path(docs_receipt_path)
        if directory == docs_path or directory in docs_path.parents:
            raise DeliveryError("downloaded-adoption-receipt-inside-immutable-subjects")
        result = subprocess.run(
            [sys.executable, str(ROOT / "tests/package/docs_commands.py"),
             "--public-download", "--publisher-packet", str(pathlib.Path(args.evidence)),
             "--local-artifacts", str(directory), "--version", "0.2.0", "--offline",
             "--out", str(docs_path)], cwd=ROOT, text=True, capture_output=True,
            timeout=14400, check=False)
        if result.returncode:
            raise DeliveryError("downloaded-package-adoption-smoke-failed")
        try:
            docs_receipt = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            raise DeliveryError("downloaded-package-adoption-receipt-invalid") from None
        adoption = make_v02_adoption_receipt(packet, release_info, docs_receipt)
        adoption["docs_receipt"] = str(docs_path.relative_to(ROOT))
        _write_json(args.evidence_out, adoption)
        return adoption
    except (DeliveryError, OSError, ValueError, TypeError, KeyError,
            subprocess.SubprocessError, promote.PromotionError) as error:
        reason = str(error) if isinstance(error, DeliveryError) else type(error).__name__
        if authenticated and validate_v02_publisher_packet(packet, args.repository) == []:
            _write_json(args.evidence_out,
                        make_v02_adoption_failure(packet, reason, published=published))
        raise DeliveryError(reason) from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--prepare-merge", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--contracts-only", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument("--require-v02-qualification", action="store_true")
    parser.add_argument("--version", choices=("0.1.0", "0.2.0"), default="0.1.0")
    parser.add_argument("--repository")
    parser.add_argument("--preflight", type=pathlib.Path)
    parser.add_argument("--pull-request", type=int)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-base")
    parser.add_argument("--timeout-seconds", type=int, default=21600)
    parser.add_argument("--evidence-out", type=pathlib.Path,
                        default=pathlib.Path("build/phase4/delivery-evidence.json"))
    parser.add_argument("--evidence", type=pathlib.Path,
                        default=pathlib.Path("build/phase4/delivery-evidence.json"))
    parser.add_argument("--source-sha")
    parser.add_argument("--release-tag")
    parser.add_argument("--download-dir", type=pathlib.Path,
                        default=pathlib.Path("build/phase4/downloaded-release"))
    args = parser.parse_args()
    try:
        if not (args.self_test or args.prepare_merge or args.run or args.verify or args.contracts_only):
            parser.error("select --self-test, --prepare-merge, --run, --verify, or --contracts-only")
        if args.release_tag is None:
            args.release_tag = "v" + args.version
        if args.contracts_only:
            result = self_test()
            print(json.dumps(result, sort_keys=True))
            return 0 if result["pass"] else 1
        if args.self_test:
            result = self_test()
            print(json.dumps(result, sort_keys=True))
            return 0 if result["pass"] else 1
        if args.download_only:
            if not args.verify:
                parser.error("--download-only requires --verify")
            try:
                resolve_v02_download_context(args)
            except (DeliveryError, OSError, ValueError, TypeError, KeyError) as error:
                reason = str(error) if isinstance(error, DeliveryError) else type(error).__name__
                print("BLOCKED: " + reason, file=sys.stderr)
                return 1
            result = verify_release(args)
            print(json.dumps(result, sort_keys=True))
            return 0
        if not args.repository or not args.preflight:
            parser.error("--prepare-merge/--run/--verify require --repository and --preflight")
        if args.require_v02_qualification and args.version != "0.2.0":
            parser.error("--require-v02-qualification requires --version 0.2.0")
        if args.version == "0.2.0" and args.run and not args.require_v02_qualification:
            parser.error("v0.2 --run requires --require-v02-qualification")
        if args.timeout_seconds < 1 or args.timeout_seconds > 86400:
            parser.error("--timeout-seconds must be from 1 through 86400")
        if args.prepare_merge or args.run:
            if args.pull_request is None or args.expected_head is None or args.expected_base is None:
                parser.error("--prepare-merge/--run require --pull-request and both expected identities")
        result = (prepare_merge(args) if args.prepare_merge else
                  run_delivery(args) if args.run else verify_release(args))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (DeliveryError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("BLOCKED: " + (str(error) if isinstance(error, DeliveryError) else type(error).__name__),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
