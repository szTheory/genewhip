#!/usr/bin/env python3
"""Read-only GitHub repository policy preflight; never configures or dispatches CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

import public_hygiene


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REQUIRED_CHECK = "required-ci"


@dataclass
class ServiceError(Exception):
    kind: str
    status: int | None = None


def _http_get(path: str, token: str | None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "genewhip-repository-preflight",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API_ROOT + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise ServiceError("permission_denied", error.code) from None
        if error.code == 404:
            raise ServiceError("not_found", 404) from None
        if error.code in (410, 422):
            raise ServiceError("unsupported_service", error.code) from None
        raise ServiceError("transport_error", error.code) from None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise ServiceError("transport_error") from None


class GitHubClient:
    def __init__(self, get_json: Callable[[str], Any]):
        self.get_json = get_json

    def get(self, path: str) -> Any:
        try:
            return self.get_json(path)
        except ServiceError:
            raise
        except PermissionError:
            raise ServiceError("permission_denied") from None
        except NotImplementedError:
            raise ServiceError("unsupported_service") from None
        except Exception:
            # Do not surface exception text: it can contain URLs, headers, or credentials.
            raise ServiceError("transport_error") from None


def _service_result(client: GitHubClient, path: str) -> tuple[Any | None, str]:
    try:
        return client.get(path), "observed"
    except ServiceError as error:
        return None, error.kind


def _valid_sha(value: str | None) -> bool:
    return bool(value and SHA_RE.fullmatch(value))


def inspect_repository(
    repository: str,
    client: GitHubClient,
    expected_head: str | None = None,
    expected_base: str | None = None,
) -> dict[str, Any]:
    """Collect read-only policy observations for a caller-selected OWNER/REPO."""
    if not REPO_RE.fullmatch(repository) or ".." in repository or repository.startswith("."):
        raise ValueError("repository must be an explicit OWNER/REPO identifier")
    owner, name = repository.split("/", 1)
    encoded = f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
    root = f"/repos/{encoded}"
    repo, repo_status = _service_result(client, root)
    blockers: list[str] = []

    if repo_status != "observed" or not isinstance(repo, dict):
        blockers.append(f"repository_{repo_status}")
        repo = {}

    default_branch = repo.get("default_branch")
    default_ref: Any = None
    default_ref_status = "unknown"
    if isinstance(default_branch, str) and default_branch:
        ref = urllib.parse.quote(f"heads/{default_branch}", safe="/")
        default_ref, default_ref_status = _service_result(client, root + f"/git/ref/{ref}")
    if default_ref_status != "observed":
        blockers.append(f"default_branch_ref_{default_ref_status}")
    actions, actions_status = _service_result(client, root + "/actions/permissions")
    workflow, workflow_status = _service_result(client, root + "/actions/permissions/workflow")
    if actions_status != "observed":
        blockers.append(f"actions_policy_{actions_status}")
    if workflow_status != "observed":
        blockers.append(f"workflow_permissions_{workflow_status}")

    protection: Any = None
    protection_status = "unknown"
    if isinstance(default_branch, str) and default_branch:
        branch_path = urllib.parse.quote(default_branch, safe="")
        protection, protection_status = _service_result(
            client, root + f"/branches/{branch_path}/protection"
        )
    if protection_status == "not_found":
        protection = None
    elif protection_status not in ("observed", "permission_denied"):
        blockers.append(f"branch_protection_{protection_status}")

    effective_rules: Any = []
    effective_rules_status = "unknown"
    if isinstance(default_branch, str) and default_branch:
        branch_path = urllib.parse.quote(default_branch, safe="")
        effective_rules, effective_rules_status = _service_result(
            client, root + f"/rules/branches/{branch_path}"
        )
    if effective_rules_status != "observed":
        blockers.append(f"effective_branch_rules_{effective_rules_status}")
        effective_rules = []
    if not isinstance(effective_rules, list):
        blockers.append("effective_branch_rules_malformed")
        effective_rules = []

    checks: list[str] = []
    if isinstance(protection, dict):
        required = protection.get("required_status_checks")
        if isinstance(required, dict):
            checks = required.get("contexts") or [
                check.get("context") for check in required.get("checks", [])
                if isinstance(check, dict)
            ]
    effective_rule_types: set[str] = set()
    effective_rule_sources: set[tuple[str, str]] = set()
    review_required_from_rules = False
    pull_request_required_from_rules = False
    for rule in effective_rules:
        if not isinstance(rule, dict):
            continue
        rule_type = rule.get("type")
        if not isinstance(rule_type, str):
            continue
        effective_rule_types.add(rule_type)
        source_type = rule.get("ruleset_source_type")
        source_id = rule.get("ruleset_id")
        if isinstance(source_type, str) and source_id is not None:
            effective_rule_sources.add((source_type, str(source_id)))
        parameters = rule.get("parameters")
        if not isinstance(parameters, dict):
            continue
        if rule_type == "required_status_checks":
            for check in parameters.get("required_status_checks", []):
                if isinstance(check, dict) and isinstance(check.get("context"), str):
                    checks.append(check["context"])
        elif rule_type == "pull_request":
            pull_request_required_from_rules = True
            approvals = parameters.get("required_approving_review_count")
            review_required_from_rules = (
                isinstance(approvals, int) and not isinstance(approvals, bool) and approvals > 0
            ) or review_required_from_rules
    required_checks = sorted({str(item) for item in checks if item})
    protection_present = isinstance(protection, dict) or bool(effective_rules)
    if protection_status == "permission_denied" and not (
            REQUIRED_CHECK in required_checks and pull_request_required_from_rules):
        blockers.append("branch_protection_permission_denied_without_equivalent_effective_rules")
    if not protection_present and protection_status == "not_found":
        blockers.append("default_branch_protection_missing")
    if REQUIRED_CHECK not in required_checks:
        blockers.append("required_aggregate_missing")

    review_settings = protection.get("required_pull_request_reviews") if isinstance(protection, dict) else None
    pull_request_required = isinstance(review_settings, dict) or pull_request_required_from_rules
    approval_count = (review_settings.get("required_approving_review_count")
                      if isinstance(review_settings, dict) else None)
    review_required = (isinstance(approval_count, int) and not isinstance(approval_count, bool)
                       and approval_count > 0) or review_required_from_rules
    if not pull_request_required:
        blockers.append("required_pull_request_policy_missing")

    if not isinstance(actions, dict):
        actions = {}
    if not isinstance(workflow, dict):
        workflow = {}
    actions_enabled = actions.get("enabled") is True if actions_status == "observed" else None
    if actions_enabled is not True:
        blockers.append("actions_disabled_or_unknown")

    expected_identity = {
        "head": expected_head if _valid_sha(expected_head) else None,
        "base": expected_base if _valid_sha(expected_base) else None,
    }
    ref_object = default_ref.get("object") if isinstance(default_ref, dict) else None
    observed_base = ref_object.get("sha") if isinstance(ref_object, dict) else None
    if not _valid_sha(observed_base):
        blockers.append("default_branch_sha_missing_or_invalid")
    if expected_identity["head"] is None:
        blockers.append("expected_head_missing_or_invalid")
    if expected_identity["base"] is None:
        blockers.append("expected_base_missing_or_invalid")
    elif _valid_sha(observed_base) and expected_identity["base"] != observed_base:
        blockers.append("expected_base_does_not_match_default_branch")

    permissions = repo.get("permissions") if isinstance(repo.get("permissions"), dict) else {}
    write_permission = permissions.get("push") is True or permissions.get("admin") is True
    if permissions.get("push") is None and permissions.get("admin") is None:
        permission_status = "unknown"
        blockers.append("write_permission_unknown")
    else:
        permission_status = "write" if write_permission else "read_only"

    visibility = repo.get("visibility") or ("public" if repo.get("private") is False else None)
    if visibility != "public":
        blockers.append("repository_visibility_not_public")
    if repo.get("allow_auto_merge") is not True:
        blockers.append("auto_merge_disabled_or_unknown")
    macos_capability = {
        "status": "unverified",
        "runner_label": "macos-15",
        "evidence": "Repository REST settings cannot establish hosted-runner availability or a successful native execution.",
    }
    # Hosted capability is verified by the actual trusted workflow in Task 2.
    # Repository readiness is distinct from hosted qualification and does not
    # imply REL-03; keep the unknown explicit in the observations below.

    result = {
        "schema": "genewhip.repository-preflight.v1",
        "mode": "inspect",
        "repository": repository,
        "service": "github.com",
        "observations": {
            "visibility": visibility,
            "default_branch": default_branch,
            "actions_enabled": actions_enabled if repo_status == "observed" else None,
            "actions_policy": {
                "status": actions_status,
                "enabled": actions.get("enabled"),
                "allowed_actions": actions.get("allowed_actions"),
            },
            "workflow_permissions": {
                "status": workflow_status,
                "default_workflow_permissions": workflow.get("default_workflow_permissions"),
                "can_approve_pull_request_reviews": workflow.get("can_approve_pull_request_reviews"),
            },
            "native_macos_capability": macos_capability,
            "auto_merge_enabled": repo.get("allow_auto_merge"),
            "branch_protection": {
                "status": protection_status,
                "classic_policy_read": protection_status,
                "required_status_checks": required_checks,
                "required_reviews": review_required,
                "pull_request_required": pull_request_required,
            },
            "rulesets": {
                "status": effective_rules_status,
                "count": len(effective_rule_sources),
                "applicable_active_count": len(effective_rule_sources),
                "applicable_active_names": [],
                "effective_rule_types": sorted(effective_rule_types),
                "effective_sources": [
                    {"type": source_type, "id": source_id}
                    for source_type, source_id in sorted(effective_rule_sources)
                ],
            },
            "expected_identity": {
                **expected_identity,
                "observed_default_branch_sha": observed_base if _valid_sha(observed_base) else None,
            },
            "permitted_merge_methods": [
                method for field, method in (
                    ("allow_merge_commit", "merge"),
                    ("allow_squash_merge", "squash"),
                    ("allow_rebase_merge", "rebase"),
                ) if repo.get(field) is True
            ],
            "caller_write_permission": permission_status,
        },
        "hosted_evidence": {"outcome": "not_run", "qualifies_rel_03": False},
        "blockers": sorted(set(blockers)),
        "ready_for_hosted_qualification": not blockers,
        "mutations_performed": 0,
    }
    return result


def build_authorized_packet(repository: str, destination: str, visibility: str,
                            history_disposition: str, expected_head: str,
                            expected_base: str, repository_observations: dict[str, Any],
                            publication_copy: pathlib.Path) -> dict[str, Any]:
    """Bind actual repository policy to a clean, sanitized publication snapshot."""
    if destination != repository or visibility != "public" or \
            history_disposition != "sanitized-snapshots-preserve-local-history":
        raise ValueError("authorized destination or history disposition mismatch")
    root = publication_copy.resolve()
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    tracked = [name for name in tracked if name]
    current_findings = public_hygiene.inspect(root, tracked)
    history = public_hygiene.scan_git_history(root)
    privacy = {
        "status": "pass" if not current_findings and not history["findings"] else "findings",
        "tracked_file_count": len(tracked),
        "current_findings": [{"path": path, "reason": reason} for path, reason in current_findings],
        "history_commits_scanned": history["commits_scanned"],
        "history_blobs_scanned": history["unique_blobs_scanned"],
        "findings": history["findings"],
        "commit_identity": history["commit_identity"],
    }
    ready = not repository_observations.get("blockers") and \
        repository_observations.get("observations", {}).get("visibility") == "public" and \
        repository_observations.get("observations", {}).get("auto_merge_enabled") is True and \
        repository_observations.get("observations", {}).get("caller_write_permission") == "write"
    return {
        "schema": "genewhip.publication-readiness-packet.v1",
        "repository": repository,
        "destination": {"owner_repository": destination, "visibility": visibility},
        "history_disposition": history_disposition,
        "privacy_scan": {"publication_copy": privacy},
        "repository_observations": {"ready": ready,
                                    "blockers": repository_observations.get("blockers", []),
                                    "observations": repository_observations.get("observations", {})},
        "expected_identity": {"head": expected_head, "base": expected_base},
        "hosted_evidence": {"outcome": "not_run", "qualifies_rel_03": False},
        "mutations_performed": 0,
    }


def build_publication_packet(
    source: dict[str, Any], account: dict[str, Any], privacy: dict[str, Any],
    inventory: dict[str, Any], historical_key: dict[str, Any],
) -> dict[str, Any]:
    """Build a sanitized, local-only packet; never infer a destination or approval."""
    branch = source.get("branch") if isinstance(source.get("branch"), str) else None
    head = source.get("head") if _valid_sha(source.get("head")) else None
    phase3_base = source.get("phase3_base") if _valid_sha(source.get("phase3_base")) else None
    destination = {"owner_repository": None, "visibility": None}
    blockers = ["destination_and_visibility_required", "history_disposition_required",
                "repository_settings_unobserved"]
    findings = privacy.get("history_findings", [])
    if not isinstance(findings, list):
        findings = []
    if privacy.get("working_tree_hygiene") != "pass" or findings:
        blockers.append("privacy_findings_require_review")
    if inventory.get("archive_content_findings"):
        blockers.append("archive_privacy_findings_require_review")
    account_result = {
        "account_connected": account.get("account_connected") is True,
        "account_identity": "redacted",
        "profile_observed": account.get("profile_observed") is True,
        "repository_discovery": account.get("repository_search", "not_observed"),
        "repository_identity_observed": False,
        "gh_cli_available": account.get("gh_cli_available"),
        "ci_monitor_available": account.get("ci_monitor_available"),
    }
    integration = (
        "Establish the "
        "agreed default branch at the Phase 3 base, then open a pull request from the "
        "Phase 4 branch. Require active effective rules on the default branch for the current "
        "required-ci aggregate and pull-request policy; directly observed classic protection is also "
        "acceptable. Use native auto-merge only after a fresh head/base policy "
        "inspection. If the destination already has a different history, stop and review "
        "the integration plan. Do not push directly to or rewrite the protected branch."
    )
    setting_delta = {
        "observed": "not_observable_without_destination",
        "desired": {
            "default_branch_policy": (
                "active effective rules targeting main require required-ci and pull requests; "
                "approval count follows the accepted repository policy; an equivalent classic protection policy is acceptable "
                "only when directly observed"
            ),
            "required_status_check": REQUIRED_CHECK,
            "required_pull_request": "required before merge; no new approval count imposed",
            "auto_merge": "enabled after policy is observed",
            "bypass": "no bypass of required checks or reviews",
            "workflow_permissions": "minimum permissions needed by each job",
            "release_policy_read": (
                "publisher reads effective main rules with standard GITHUB_TOKEN metadata access; "
                "no Administration permission or extra credential is required for this path"
            ),
        },
    }
    key_record = {
        "commit": str(historical_key.get("commit", ""))[:40],
        "path": historical_key.get("path") if isinstance(historical_key.get("path"), str) else None,
        "classification": historical_key.get("classification", "unknown"),
        "removed_in": str(historical_key.get("removed_in", ""))[:40],
        "history_rewrite_recommended": False,
        "owner_disposition": None,
    }
    return {
        "schema": "genewhip.publication-readiness-packet.v1",
        "source": {
            "branch": branch,
            "head": head,
            "phase3_base": phase3_base,
            "commits_since_phase3_base": source.get("commits_since_phase3_base"),
            "reachable_commit_count": source.get("commit_count"),
            "first_parent_commit_count": source.get("first_parent_commit_count"),
            "merge_commit_count": source.get("merge_commit_count"),
            "recent_first_parent_commits": source.get("recent_first_parent_commits", []),
            "configured_remote_count": source.get("remote_count"),
            "dirty_paths": source.get("dirty_paths", []),
            "proposed_integration_strategy": integration,
        },
        "destination": destination,
        "history_disposition": None,
        "privacy_scan": {
            "tracked_file_count": privacy.get("tracked_file_count", 0),
            "working_tree_hygiene": privacy.get("working_tree_hygiene", "unknown"),
            "working_tree_findings": privacy.get("working_tree_findings", []),
            "history_commits_scanned": privacy.get("history_commits_scanned", 0),
            "history_blobs_scanned": privacy.get("history_blobs_scanned", 0),
            "history_finding_counts": privacy.get("history_finding_counts", {}),
            "history_findings": findings,
            "history_binary_versions": privacy.get("history_binary_versions", []),
            "commit_identity": privacy.get("commit_identity", {}),
            "matched_bytes_included": False,
        },
        "archive_log_inventory": inventory,
        "excluded_local_log_finding_count": len(inventory.get("log_content_findings", [])),
        "historical_sdl_key": key_record,
        "account_observations": account_result,
        "settings_delta": setting_delta,
        "hosted_repository_observations": "not yet inspected",
        "blockers": sorted(set(blockers)),
        "mutations_performed": 0,
    }


def _git_text(root: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _relative_name(root: pathlib.Path, path: pathlib.Path) -> str:
    name = path.relative_to(root).as_posix()
    if (name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", name)):
        return "path-redacted"
    return name


def _file_record(root: pathlib.Path, path: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"path": _relative_name(root, path), "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def _artifact_inventory(root: pathlib.Path) -> dict[str, Any]:
    archive_files = sorted((root / "artifacts").glob("*.tar.gz"))
    release_dir = root / "build" / "phase4" / "release-assets-contract-final2"
    release_inventory: dict[str, Any] = {"status": "missing", "source_revision": None,
                                         "assets_match_inventory": False}
    inventory_path = release_dir / "inventory.json"
    if inventory_path.is_file():
        try:
            doc = json.loads(inventory_path.read_text(encoding="utf-8"))
            assets = doc.get("assets") if isinstance(doc, dict) else None
            matches = isinstance(assets, dict) and bool(assets)
            if matches:
                for name, row in assets.items():
                    candidate = release_dir / name
                    if not candidate.is_file() or not isinstance(row, dict):
                        matches = False
                        break
                    actual = _file_record(root, candidate)
                    if actual["sha256"] != row.get("sha256") or actual["size_bytes"] != row.get("size"):
                        matches = False
                        break
            release_inventory = {
                "status": "observed",
                "path": _relative_name(root, inventory_path),
                "sha256": _file_record(root, inventory_path)["sha256"],
                "source_revision": doc.get("source_revision"),
                "asset_count": len(assets) if isinstance(assets, dict) else 0,
                "assets_match_inventory": matches,
            }
        except (OSError, json.JSONDecodeError, TypeError):
            release_inventory["status"] = "invalid"
    archives = [_file_record(root, path) for path in archive_files]
    for path in sorted(release_dir.glob("*.tar.gz")) if release_dir.is_dir() else []:
        if path not in archive_files:
            archives.append(_file_record(root, path))
    log_candidates = set((root / "build" / "phase4").rglob("*.log"))
    logs = [_file_record(root, path) for path in sorted(log_candidates) if path.is_file()]
    archive_findings = []
    archive_paths = [root / row["path"] for row in archives]
    for archive in archive_paths:
        for finding in public_hygiene.scan_archive(archive):
            archive_findings.append({
                "archive": _relative_name(root, archive),
                "member": finding["member"], "reasons": finding["reasons"],
            })
    log_findings = [
        {"path": row["path"], "reasons": public_hygiene.scan_file(root / row["path"])}
        for row in logs
    ]
    log_findings = [row for row in log_findings if row["reasons"]]
    return {
        "archive_count": len(archives),
        "archives": archives,
        "archive_content_findings": archive_findings,
        "log_count": len(logs),
        "logs": logs,
        "log_content_findings": log_findings,
        "staged_release_inventory": release_inventory,
    }


def prepare_publication_packet(
    root: pathlib.Path, phase3_base: str, account_connected: bool,
    repository_search: str, profile_observed: bool = False,
) -> dict[str, Any]:
    root = pathlib.Path(root).resolve()
    head = _git_text(root, "rev-parse", "HEAD")
    branch = _git_text(root, "symbolic-ref", "--quiet", "--short", "HEAD")
    commits = _git_text(root, "rev-list", "--count", "HEAD")
    first_parent_commits = _git_text(root, "rev-list", "--first-parent", "--count", "HEAD")
    merge_commits = _git_text(root, "rev-list", "--min-parents=2", "--count", "HEAD")
    recent_chain = _git_text(root, "log", "--first-parent", "-n", "12", "--format=%H").splitlines()
    base_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", phase3_base, "HEAD"], cwd=root,
        check=False, capture_output=True).returncode == 0 if _valid_sha(phase3_base) else False
    since_base = (_git_text(root, "rev-list", "--count", f"{phase3_base}..HEAD")
                  if base_is_ancestor else None)
    tracked = _git_text(root, "ls-files", "-z").split("\0")
    tracked = [name for name in tracked if name]
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", "HEAD", "-z"], cwd=root, text=True).split("\0")
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root, text=True).split("\0")
    dirty_paths = sorted({name for name in changed + untracked if name})
    current_findings = public_hygiene.inspect(root, tracked)
    history = public_hygiene.scan_git_history(root)
    privacy = {
        "tracked_file_count": len(tracked),
        "working_tree_hygiene": "pass" if not current_findings else "findings",
        "working_tree_findings": [
            {"path": item[0], "reason": item[1]} for item in current_findings
        ],
        "history_commits_scanned": history["commits_scanned"],
        "history_blobs_scanned": history["unique_blobs_scanned"],
        "history_finding_counts": history["finding_counts"],
        "history_findings": history["findings"],
        "history_binary_versions": history["historical_binary_versions"],
        "commit_identity": history["commit_identity"],
    }
    remote_count = len(_git_text(root, "remote").splitlines()) if _git_text(root, "remote") else 0
    return build_publication_packet(
        {
            "branch": branch, "head": head, "phase3_base": phase3_base,
            "commits_since_phase3_base": int(since_base) if since_base is not None else None,
            "commit_count": int(commits), "remote_count": remote_count,
            "first_parent_commit_count": int(first_parent_commits),
            "merge_commit_count": int(merge_commits),
            "recent_first_parent_commits": recent_chain,
            "dirty_paths": dirty_paths,
        },
        {
            "account_connected": account_connected,
            "profile_observed": profile_observed,
            "repository_search": repository_search,
            "gh_cli_available": shutil.which("gh") is not None,
            "ci_monitor_available": (root / "scripts" / "ci_monitor.cjs").is_file(),
        },
        privacy,
        _artifact_inventory(root),
        {
            "commit": "8b404280828d78f20508dddfcfdf0c1a5f5978ff",
            "path": "packaging/dependencies/sdl3-release-keys.asc",
            "classification": "upstream_pgp_public_key",
            "removed_in": "950dc8339aeaf0b9cdd75e51f16f98447ee43776",
        },
    )


def _fixtures() -> dict[str, Any]:
    return {
        "/repos/acme/genewhip": {
            "default_branch": "main", "disabled": False, "private": False,
            "visibility": "public", "allow_auto_merge": True,
            "allow_merge_commit": False, "allow_squash_merge": True,
            "allow_rebase_merge": True,
            "permissions": {"push": True, "admin": False},
        },
        "/repos/acme/genewhip/git/ref/heads/main": {
            "ref": "refs/heads/main", "object": {"sha": "b" * 40},
        },
        "/repos/acme/genewhip/actions/permissions": {"enabled": True, "allowed_actions": "selected"},
        "/repos/acme/genewhip/actions/permissions/workflow": {
            "default_workflow_permissions": "read", "can_approve_pull_request_reviews": False,
        },
        "/repos/acme/genewhip/branches/main/protection": {
            "required_status_checks": {"contexts": [REQUIRED_CHECK]},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
        },
        "/repos/acme/genewhip/rules/branches/main": [],
    }


def self_test() -> dict[str, Any]:
    """Exercise recorded synthetic API shapes; this never counts as service evidence."""
    fixture = _fixtures()

    def get_json(path: str) -> Any:
        if path not in fixture:
            raise ServiceError("not_found", 404)
        return fixture[path]

    result = inspect_repository(
        "acme/genewhip", GitHubClient(get_json), "a" * 40, "b" * 40
    )
    typed_errors: dict[str, str] = {}
    for name, error in (
        ("permission_denied", ServiceError("permission_denied", 403)),
        ("unsupported_service", ServiceError("unsupported_service", 422)),
        ("transport_error", ServiceError("transport_error")),
    ):
        def failed(path: str, error: ServiceError = error) -> Any:
            if path == "/repos/acme/genewhip":
                raise error
            return fixture[path]
        observed = inspect_repository(
            "acme/genewhip", GitHubClient(failed), "a" * 40, "b" * 40
        )
        typed_errors[name] = next(
            (blocker for blocker in observed["blockers"] if blocker.startswith("repository_")),
            "not_classified",
        )

    def missing_protection(path: str) -> Any:
        if path.endswith("/protection"):
            raise ServiceError("not_found", 404)
        return fixture[path]

    observed = inspect_repository(
        "acme/genewhip", GitHubClient(missing_protection), "a" * 40, "b" * 40
    )
    typed_errors["missing_protection"] = (
        "default_branch_protection_missing"
        if "default_branch_protection_missing" in observed["blockers"] else "not_classified"
    )

    policy_shape_parsed = (
        result["observations"]["branch_protection"]["required_status_checks"] == [REQUIRED_CHECK]
        and result["observations"]["branch_protection"]["required_reviews"] is True
        and result["observations"]["branch_protection"]["pull_request_required"] is True
        and result["observations"]["rulesets"]["status"] == "observed"
        and result["observations"]["actions_enabled"] is True
        and result["observations"]["expected_identity"]["observed_default_branch_sha"] == "b" * 40
    )
    ok = (
        policy_shape_parsed
        and result["hosted_evidence"]["outcome"] == "not_run"
        and result["hosted_evidence"]["qualifies_rel_03"] is False
        and result["mutations_performed"] == 0
        and typed_errors == {
            "permission_denied": "repository_permission_denied",
            "unsupported_service": "repository_unsupported_service",
            "transport_error": "repository_transport_error",
            "missing_protection": "default_branch_protection_missing",
        }
    )
    return {
        "schema": "genewhip.repository-preflight.v1",
        "mode": "self-test",
        "kind": "synthetic_contract_only",
        "hosted_evidence": {"outcome": "not_run", "qualifies_rel_03": False},
        "mutations_performed": 0,
        "typed_errors": typed_errors,
        "synthetic_policy_shape_parsed": policy_shape_parsed,
        "pass": ok,
        "blockers": [] if ok else ["self_test_contract_failed"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true", help="validate synthetic response contracts only")
    mode.add_argument("--inspect", action="store_true", help="inspect one explicitly named repository using GET requests only")
    mode.add_argument("--inspect-authorized", action="store_true",
                      help="inspect the authorized repository and bind sanitized-copy evidence")
    mode.add_argument("--prepare-packet", action="store_true", help="write a sanitized local readiness packet without a destination")
    parser.add_argument("--repository", help="explicit GitHub OWNER/REPO; required with --inspect")
    parser.add_argument("--expected-head", help="expected 40-character lowercase source/head SHA")
    parser.add_argument("--expected-base", help="expected 40-character lowercase base SHA")
    parser.add_argument("--phase3-base", help="full Phase 3 source commit used for the proposed integration strategy")
    parser.add_argument("--account-connected", action="store_true", help="record that an authorized account context was observed; identity is omitted")
    parser.add_argument("--profile-observed", action="store_true", help="record that read-only account profile lookup succeeded; identity is omitted")
    parser.add_argument("--repository-search", choices=("not_observed", "timeout", "found", "no_match"),
                        default="not_observed", help="sanitized result of a read-only repository discovery attempt")
    parser.add_argument("--out", help="repository-relative JSON packet destination; only valid with --prepare-packet")
    parser.add_argument("--publication-copy", type=pathlib.Path,
                        help="clean publication snapshot repository; only valid with --inspect-authorized")
    parser.add_argument("--destination", help="explicit authorized OWNER/REPO")
    parser.add_argument("--visibility", choices=("public", "private"))
    parser.add_argument("--history-disposition",
                        choices=("sanitized-snapshots-preserve-local-history",))
    args = parser.parse_args(argv)

    if args.self_test:
        if (args.repository or args.expected_head or args.expected_base or args.phase3_base
                or args.account_connected or args.profile_observed
                or args.repository_search != "not_observed" or args.out):
            parser.error("--self-test cannot be combined with repository or packet arguments")
        result = self_test()
    elif args.inspect:
        if (args.out or args.phase3_base or args.account_connected or args.profile_observed
                or args.publication_copy or args.destination or args.visibility or args.history_disposition
                or args.repository_search != "not_observed"):
            parser.error("--inspect cannot be combined with local packet arguments")
        if not args.repository:
            parser.error("--inspect requires --repository OWNER/REPO; destination is never inferred")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        client = GitHubClient(lambda path: _http_get(path, token))
        try:
            result = inspect_repository(args.repository, client, args.expected_head, args.expected_base)
        except ValueError as error:
            parser.error(str(error))
    elif args.inspect_authorized:
        if (args.phase3_base or args.account_connected or args.profile_observed
                or args.repository_search != "not_observed"):
            parser.error("--inspect-authorized cannot be combined with local packet arguments")
        if not all((args.repository, args.expected_head, args.expected_base, args.out,
                    args.publication_copy, args.destination, args.visibility,
                    args.history_disposition)):
            parser.error("--inspect-authorized requires repository, identities, destination, visibility, history disposition, publication copy and --out")
        if not _valid_sha(args.expected_head) or not _valid_sha(args.expected_base):
            parser.error("--inspect-authorized requires full lowercase 40-character identities")
        if args.repository != args.destination or args.visibility != "public":
            parser.error("authorized destination must match repository and public visibility")
        def gh_get(path: str) -> Any:
            try:
                completed = subprocess.run(["gh", "api", path], text=True,
                                           capture_output=True, timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise ServiceError("transport_error") from None
            if completed.returncode:
                # GitHub CLI diagnostics may contain private URLs or credential context.
                if "404" in completed.stderr:
                    raise ServiceError("not_found", 404)
                if "403" in completed.stderr or "401" in completed.stderr:
                    raise ServiceError("permission_denied", 403)
                raise ServiceError("transport_error")
            try:
                return json.loads(completed.stdout)
            except json.JSONDecodeError:
                raise ServiceError("transport_error") from None
        inspected = inspect_repository(args.repository, GitHubClient(gh_get),
                                       args.expected_head, args.expected_base)
        packet = build_authorized_packet(args.repository, args.destination, args.visibility,
                                         args.history_disposition, args.expected_head,
                                         args.expected_base, inspected, args.publication_copy)
        if packet["privacy_scan"]["publication_copy"]["status"] != "pass":
            packet["repository_observations"]["ready"] = False
        output = pathlib.Path(args.out)
        if output.is_absolute() or ".." in output.parts:
            parser.error("--out must stay inside the repository and may not contain '..'")
        resolved = (pathlib.Path.cwd() / output).resolve()
        if pathlib.Path.cwd().resolve() not in resolved.parents:
            parser.error("--out must stay inside the repository")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(json.dumps(packet, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"packet_created": True, "path": output.as_posix(),
                          "ready": packet["repository_observations"]["ready"],
                          "privacy_status": packet["privacy_scan"]["publication_copy"]["status"],
                          "blockers": packet["repository_observations"]["blockers"],
                          "mutations_performed": 0}, sort_keys=True))
        return 0 if packet["repository_observations"]["ready"] else 1
    else:
        if (args.repository or args.expected_head or args.expected_base or args.publication_copy
                or args.destination or args.visibility or args.history_disposition):
            parser.error("--prepare-packet cannot include repository inspection arguments")
        if not _valid_sha(args.phase3_base):
            parser.error("--prepare-packet requires --phase3-base with a full 40-character commit SHA")
        try:
            result = prepare_publication_packet(
                pathlib.Path.cwd(), args.phase3_base, args.account_connected,
                args.repository_search, args.profile_observed)
        except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as error:
            parser.error(f"local packet preparation failed: {type(error).__name__}")
        if args.out:
            output = pathlib.Path(args.out)
            if output.is_absolute() or ".." in output.parts:
                parser.error("--out must stay inside the repository and may not contain '..'")
            resolved = (pathlib.Path.cwd() / output).resolve()
            if pathlib.Path.cwd().resolve() not in resolved.parents:
                parser.error("--out must stay inside the repository")
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"packet_created": True, "path": output.as_posix(),
                              "blockers": result["blockers"], "mutations_performed": 0},
                             sort_keys=True))
            return 0
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if (result.get("pass") is True if args.self_test else not result["blockers"]) else 1


if __name__ == "__main__":
    sys.exit(main())
