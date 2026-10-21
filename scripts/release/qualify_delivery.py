#!/usr/bin/env python3
"""Observe protected hosted delivery and verify the exact public release bytes."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
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


def validate_workflow_identity(run: Any, expected_path: str, expected_sha: str,
                               expected_event: str) -> list[str]:
    if not isinstance(run, dict) or run.get("path") != expected_path:
        return ["workflow-path-mismatch"]
    if run.get("head_sha") != expected_sha or run.get("event") != expected_event:
        return ["workflow-source-or-event-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["workflow-run-not-success"]
    return []


def validate_publisher_run(run: Any, expected_sha: str) -> list[str]:
    if not isinstance(run, dict) or run.get("event") != "workflow_dispatch":
        return ["publisher-run-event-invalid"]
    if run.get("headSha") != expected_sha:
        return ["publisher-run-source-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return ["publisher-run-not-success"]
    if not any(isinstance(job, dict) and job.get("name") == "promote"
               and job.get("conclusion") == "success" for job in run.get("jobs", [])):
        return ["publisher-job-not-success"]
    return []


def validate_release(release: Any, repository: str, tag: str,
                     directory: pathlib.Path, expected_sha: str) -> dict[str, Any]:
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
    return {"tag": tag, "source_sha": expected_sha, "release_url": release.get("html_url"),
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
    allowed = (ROOT / "build" / "phase4").resolve()
    if allowed not in path.parents:
        raise DeliveryError("output-path-outside-phase4-build")
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
    problems = validate_main_run(run, source_sha)
    if problems:
        raise DeliveryError(problems[0])
    run_id, attempt = str(run.get("databaseId")), int(run.get("attempt", 0))
    if not run_id or attempt < 1:
        raise DeliveryError("main-run-identity-invalid")
    main_ref = _gh_json(["api", f"repos/{repository}/git/ref/heads/main"])
    if main_ref.get("object", {}).get("sha") != source_sha:
        raise DeliveryError("main-head-moved-before-publication")
    main_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}"])
    problems = validate_workflow_identity(main_identity, ".github/workflows/ci.yml", source_sha, "push")
    if problems:
        raise DeliveryError(problems[0])

    dispatch_time = dt.datetime.now(dt.timezone.utc)
    _gh(["workflow", "run", "release.yml", "--repo", repository, "--ref", "main",
         "-f", f"source_sha={source_sha}", "-f", f"run_id={run_id}", "-f", f"run_attempt={attempt}"])

    def publisher_run():
        rows = _gh_json(["run", "list", "--repo", repository, "--workflow", "release.yml", "--branch",
                         "main", "--event", "workflow_dispatch", "--limit", "10",
                         "--json", "databaseId,attempt,event,headSha,status,conclusion,workflowName,createdAt"])
        for row in rows:
            if not isinstance(row, dict) or row.get("headSha") != source_sha \
                    or row.get("event") != "workflow_dispatch":
                continue
            created = dt.datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00"))
            if created < dispatch_time:
                continue
            if row.get("status") != "completed":
                return None
            return _gh_json(["run", "view", str(row["databaseId"]), "--repo", repository,
                             "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId"])
        return None

    publisher = _wait_for(publisher_run, args.timeout_seconds)
    problems = validate_publisher_run(publisher, source_sha)
    if problems:
        raise DeliveryError(problems[0])
    publisher_identity = _gh_json(["api", f"repos/{repository}/actions/runs/{publisher.get('databaseId')}/attempts/{publisher.get('attempt')}"])
    problems = validate_workflow_identity(publisher_identity, ".github/workflows/release.yml",
                                          source_sha, "workflow_dispatch")
    if problems:
        raise DeliveryError(problems[0])
    evidence = {"schema": "genewhip.hosted-delivery.v1", "repository": repository,
                "pull_request": args.pull_request, "pull_request_head_sha": args.expected_head,
                "pull_request_base_sha": args.expected_base, "merged_source_sha": source_sha,
                "merge_commit_sha": source_sha, "qualification_run_id": run_id,
                "qualification_run_attempt": attempt, "qualification_workflow": run.get("workflowName"),
                "publisher_run_id": str(publisher.get("databaseId")),
                "publisher_run_attempt": publisher.get("attempt"),
                "publisher_workflow": publisher.get("workflowName"),
                "hosted_evidence": {"outcome": "success", "qualifies_rel_03": False},
                "release": None, "merge_readiness": readiness}
    _write_json(args.evidence_out, evidence)
    return evidence


def verify_release(args: argparse.Namespace) -> dict[str, Any]:
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
    if not all((qualification_id, qualification_attempt, publisher_id, publisher_attempt)):
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
                          "--json", "attempt,event,headSha,status,conclusion,jobs,workflowName,databaseId"])
    problems = validate_publisher_run(publisher, source_sha)
    if problems:
        raise DeliveryError(problems[0])
    problems = validate_workflow_identity(
        _gh_json(["api", f"repos/{repository}/actions/runs/{publisher_id}/attempts/{publisher_attempt}"]),
        ".github/workflows/release.yml", source_sha, "workflow_dispatch")
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
    release_info = validate_release(release, repository, args.release_tag, directory, source_sha)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--prepare-merge", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--verify", action="store_true")
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
    parser.add_argument("--release-tag", default="v0.1.0")
    parser.add_argument("--download-dir", type=pathlib.Path,
                        default=pathlib.Path("build/phase4/downloaded-release"))
    args = parser.parse_args()
    try:
        if args.self_test:
            result = self_test()
            print(json.dumps(result, sort_keys=True))
            return 0 if result["pass"] else 1
        if not args.repository or not args.preflight:
            parser.error("--prepare-merge/--run/--verify require --repository and --preflight")
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
