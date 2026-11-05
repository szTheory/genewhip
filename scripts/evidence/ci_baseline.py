#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect and validate a bounded, read-only GitHub Actions baseline."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "genewhip-ci-baseline.v1"
API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
JOB_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
MAX_API_RESPONSE = 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_RUNS = 100
MAX_ATTEMPTS = 3
MAX_JOBS = 100
MAX_STEPS = 100
MAX_REQUEST_SECONDS = 30
MAX_COLLECTION_SECONDS = 180
MAX_RUN_PAGES = 20
NORMAL_EVENTS = ("pull_request", "merge_group", "push")
EVENTS = NORMAL_EVENTS + ("schedule", "workflow_dispatch", "other")
JOB_STATUSES = ("queued", "in_progress", "completed", "unknown")
CONCLUSIONS = ("success", "failure", "cancelled", "skipped", "neutral",
               "timed_out", "action_required", "stale", "unknown")
STEP_CATEGORIES = ("checkout", "setup", "dependency_preparation", "build",
                   "test", "other", "unknown")
RUNNER_LABELS = {
    "ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-24.04-arm",
    "macos-latest", "macos-13", "macos-14", "macos-15", "macos-26",
    "macos-26-arm64", "windows-latest", "windows-2022", "windows-2025",
    "linux", "macos", "windows", "x64", "arm64", "self-hosted",
}


class CollectionError(Exception):
    """Safe, stable code for an API, input, or bounded-resource failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


_API_OPENER = urllib.request.build_opener(_NoRedirect())


def _open_api(request, timeout):
    return _API_OPENER.open(request, timeout=timeout)


class GitHubApi:
    def __init__(self, token: str | None, opener=None):
        self.opener = opener or _open_api
        self.token = token
        self.deadline = time.monotonic() + MAX_COLLECTION_SECONDS
        self.request_count = 0

    def get_json(self, path: str) -> dict:
        if not path.startswith("/repos/") or ".." in path.split("/"):
            raise CollectionError("api-path-invalid")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionError("collection-timeout")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "genewhip-ci-baseline/1",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(API_BASE + path, headers=headers, method="GET")
        self.request_count += 1
        try:
            with self.opener(request, timeout=min(MAX_REQUEST_SECONDS, remaining)) as response:
                status = response.getcode()
                payload = response.read(MAX_API_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise CollectionError(f"api-http-{code}") from None
        except urllib.error.URLError:
            raise CollectionError("api-network-error") from None
        except TimeoutError:
            raise CollectionError("api-request-timeout") from None
        except OSError:
            raise CollectionError("api-transport-error") from None
        if status != 200:
            raise CollectionError(f"api-http-{status}")
        if len(payload) > MAX_API_RESPONSE:
            raise CollectionError("api-response-too-large")
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                                parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CollectionError("api-json-invalid") from None
        if not isinstance(value, dict):
            raise CollectionError("api-response-not-object")
        return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("non-finite-json-number")


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _valid_repo(value: str) -> bool:
    if not isinstance(value, str) or not REPO_NAME.fullmatch(value):
        return False
    return all(part not in (".", "..") for part in value.split("/"))


def _valid_workflow_path(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith(".github/workflows/"):
        return False
    if ".." in value.split("/") or "\\" in value or "?" in value or "#" in value:
        return False
    return value.endswith((".yml", ".yaml")) and len(value) <= 240


def _valid_sha(value) -> bool:
    return isinstance(value, str) and bool(SHA40.fullmatch(value))


def _safe_event(value) -> str:
    return value if isinstance(value, str) and value in EVENTS[:-1] else "other"


def _safe_status(value) -> str:
    return value if isinstance(value, str) and value in JOB_STATUSES else "unknown"


def _safe_conclusion(value) -> str:
    return value if isinstance(value, str) and value in CONCLUSIONS else "unknown"


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def _duration(start, end):
    start_value = _timestamp(start)
    end_value = _timestamp(end)
    if start_value is None or end_value is None or end_value < start_value:
        return None
    return round(end_value - start_value, 3)


def _time_fields(start, end):
    return {"started_at": start if _timestamp(start) is not None else None,
            "completed_at": end if _timestamp(end) is not None else None,
            "elapsed_seconds": _duration(start, end)}


def _strip_comment(line: str) -> str:
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def _yaml_scalar(value):
    value = value.strip()
    if not value:
        return None
    if value[0] in ("'", '"'):
        if len(value) < 2 or value[-1] != value[0]:
            return False
        inner = value[1:-1]
        if any(character in inner for character in "{}[]&*!|>"):
            return False
        return inner
    if re.fullmatch(r"[A-Za-z0-9_. /:+-]{1,160}", value):
        return value
    return False


def _parse_needs_inline(value):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        values = [part.strip() for part in inner.split(",")]
        if any(not JOB_ID.fullmatch(part) for part in values):
            return None
        return values
    scalar = _yaml_scalar(value)
    if scalar is False or scalar is None or not JOB_ID.fullmatch(scalar):
        return None
    return [scalar]


def parse_workflow_graph(text: str) -> dict:
    """Parse only the simple job/name/needs subset used for a source graph."""
    errors = []
    jobs = {}
    lines = text.splitlines()
    jobs_line = None
    for index, raw in enumerate(lines):
        if "\t" in raw:
            errors.append("workflow-tabs-unsupported")
            continue
        line = _strip_comment(raw)
        if line == "jobs:":
            if jobs_line is not None:
                errors.append("workflow-duplicate-jobs-key")
            else:
                jobs_line = index
            break
    if jobs_line is None:
        return {"status": "incomplete", "jobs": {}, "errors": ["workflow-jobs-missing"]}

    current = None
    pending_needs = False
    needs_block_has_item = False
    in_jobs = True
    for raw in lines[jobs_line + 1:]:
        if "\t" in raw:
            errors.append("workflow-tabs-unsupported")
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line[indent:]
        if indent == 0:
            in_jobs = False
            break
        if not in_jobs:
            continue
        if indent == 2 and stripped.endswith(":"):
            if pending_needs and not needs_block_has_item:
                errors.append("unsupported-needs-syntax")
            pending_needs = False
            needs_block_has_item = False
            identifier = stripped[:-1]
            if not JOB_ID.fullmatch(identifier) or identifier in jobs:
                errors.append("workflow-job-id-invalid")
                current = None
                continue
            jobs[identifier] = {"id": identifier, "name": identifier,
                                "needs": [], "matrix": False}
            current = identifier
            continue
        if current is None:
            if indent >= 4:
                errors.append("workflow-job-syntax-unsupported")
            continue
        if indent == 4:
            if pending_needs and not needs_block_has_item:
                errors.append("unsupported-needs-syntax")
            pending_needs = False
            needs_block_has_item = False
            match = re.fullmatch(r"([A-Za-z0-9_-]+):(?:\s*(.*))?", stripped)
            if not match:
                errors.append("workflow-job-property-unsupported")
                continue
            key, value = match.group(1), (match.group(2) or "").strip()
            if key == "needs":
                if not value:
                    pending_needs = True
                else:
                    parsed = _parse_needs_inline(value)
                    if parsed is None:
                        errors.append("unsupported-needs-syntax")
                    else:
                        jobs[current]["needs"] = parsed
            elif key == "name":
                scalar = _yaml_scalar(value)
                if scalar is False or scalar is None:
                    errors.append("workflow-job-name-unsupported")
                else:
                    jobs[current]["name"] = scalar
            elif key == "strategy":
                # Matrix jobs are represented as unresolved until every expansion
                # can be tied to a concrete API job without guessing.
                jobs[current]["matrix"] = bool(value)
            elif key in {"if", "runs-on", "timeout-minutes", "continue-on-error",
                         "env", "permissions", "steps", "outputs", "defaults",
                         "concurrency", "container", "services"}:
                pass
            continue
        if pending_needs and indent == 6:
            item = re.fullmatch(r"-\s*([A-Za-z0-9_-]+)", stripped)
            if item is None:
                errors.append("unsupported-needs-syntax")
            else:
                jobs[current]["needs"].append(item.group(1))
                needs_block_has_item = True
            continue
        if indent >= 6 and re.match(r"matrix\s*:", stripped):
            jobs[current]["matrix"] = True

    if pending_needs and not needs_block_has_item:
        errors.append("unsupported-needs-syntax")
    if len(jobs) > 200:
        errors.append("workflow-job-count-exceeded")
    for identifier, job_value in jobs.items():
        if job_value["matrix"]:
            errors.append("matrix-graph-unresolved")
        if len(job_value["needs"]) != len(set(job_value["needs"])):
            errors.append("workflow-needs-duplicate")
        for dependency in job_value["needs"]:
            if dependency not in jobs:
                errors.append("workflow-needs-unknown")

    temporary, permanent = set(), set()
    def visit(identifier):
        if identifier in permanent:
            return
        if identifier in temporary:
            errors.append("dependency-cycle")
            return
        temporary.add(identifier)
        for dependency in jobs.get(identifier, {}).get("needs", []):
            if dependency in jobs:
                visit(dependency)
        temporary.remove(identifier)
        permanent.add(identifier)
    for identifier in sorted(jobs):
        visit(identifier)
    unique_errors = sorted(set(errors))
    return {"status": "complete" if not unique_errors else "incomplete",
            "jobs": jobs, "errors": unique_errors}


def _graph_digest(graph: dict) -> str:
    value = {"jobs": graph.get("jobs", {}), "errors": graph.get("errors", [])}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _git_blob_sha(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _safe_ref(value, event):
    if not isinstance(value, str):
        return "unknown"
    if event == "pull_request" and re.fullmatch(r"refs/pull/[0-9]{1,12}/merge", value):
        return value
    if event in ("push", "schedule", "workflow_dispatch") and value == "refs/heads/main":
        return value
    if event == "merge_group":
        return "merge_group"
    return "other"


def _workflow_path_from_api(value):
    if not isinstance(value, str):
        return None
    path = value.split("@", 1)[0]
    return path if _valid_workflow_path(path) else None


def _normalize_runner(labels, visibility):
    safe = []
    if isinstance(labels, list):
        for label in labels:
            if not isinstance(label, str) or len(label) > 80:
                continue
            lowered = label.lower()
            if lowered in RUNNER_LABELS:
                safe.append(lowered)
            elif re.fullmatch(r"(?:ubuntu|macos|windows)-[0-9]{2}(?:\.[0-9]{1,2})?(?:-arm64)?", lowered):
                safe.append(lowered)
    safe = sorted(set(safe))
    if "self-hosted" in safe:
        runner_type = "self-hosted"
    elif any(label in {"ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04",
                       "ubuntu-24.04-arm", "macos-latest", "macos-13",
                       "macos-14", "macos-15", "macos-26", "macos-26-arm64",
                       "windows-latest", "windows-2022", "windows-2025"} or
             re.fullmatch(r"(?:ubuntu|macos|windows)-[0-9]{2}(?:\.[0-9]{1,2})?(?:-arm64)?", label)
             for label in safe):
        runner_type = "github-hosted-standard"
    else:
        runner_type = "unknown"
    if any(label.startswith(("ubuntu-", "linux")) for label in safe):
        os_name = "linux"
    elif any(label.startswith(("macos-", "macos")) for label in safe):
        os_name = "macos"
    elif any(label.startswith(("windows-", "windows")) for label in safe):
        os_name = "windows"
    else:
        os_name = "unknown"
    if not safe:
        runner_type = "unknown"
    return {"labels": safe, "type": runner_type, "os": os_name}


def _classify_step(name):
    if not isinstance(name, str) or not name:
        return "unknown", {"actual_module": False, "address_sanitizer": False,
                            "undefined_sanitizer": False}
    lower = name.lower()
    if "checkout" in lower:
        category = "checkout"
    elif "dependenc" in lower or lower.startswith(("install ", "prepare ")):
        category = "dependency_preparation"
    elif "set up" in lower or "setup" in lower or "configure" in lower:
        category = "setup"
    elif "build" in lower or "compile" in lower:
        category = "build"
    elif "test" in lower or "ctest" in lower or "contract" in lower or "smoke" in lower:
        category = "test"
    else:
        category = "other"
    evidence = {
        "actual_module": "actual module" in lower or "actual-module" in lower,
        "address_sanitizer": "address sanitizer" in lower or "address-sanitizer" in lower or "asan" in lower,
        "undefined_sanitizer": "undefined sanitizer" in lower or "undefined-sanitizer" in lower or "ubsan" in lower,
        "linux_x86_64_runner": "linux x86_64" in lower or "linux-x86_64" in lower,
    }
    return category, evidence


def _safe_step(raw):
    number = raw.get("number")
    if not isinstance(number, int) or number < 0 or number > 10000:
        number = None
    category, evidence = _classify_step(raw.get("name"))
    fields = _time_fields(raw.get("started_at"), raw.get("completed_at"))
    return {"number": number, "category": category,
            "status": _safe_status(raw.get("status")),
            "conclusion": _safe_conclusion(raw.get("conclusion")),
            **fields, "evidence": evidence}


def _job_name_index(graph):
    index = {}
    for identifier, item in graph.get("jobs", {}).items():
        for name in {identifier, item.get("name", identifier)}:
            if isinstance(name, str):
                index[name.casefold()] = identifier
    return index


def _normalize_job(raw, graph, visibility):
    job_id = raw.get("id")
    if not isinstance(job_id, int) or job_id <= 0:
        job_id = None
    api_name = raw.get("name")
    job_index = _job_name_index(graph)
    identifier = job_index.get(api_name.casefold()) if isinstance(api_name, str) else None
    unresolved = identifier is None
    graph_job = graph.get("jobs", {}).get(identifier, {}) if identifier else {}
    status = _safe_status(raw.get("status"))
    conclusion = _safe_conclusion(raw.get("conclusion"))
    fields = _time_fields(raw.get("started_at"), raw.get("completed_at"))
    steps_raw = raw.get("steps", [])
    steps = [_safe_step(step) for step in steps_raw[:MAX_STEPS]
             if isinstance(step, dict)] if isinstance(steps_raw, list) else []
    runner = _normalize_runner(raw.get("labels"), visibility)
    return {
        "job_id": job_id,
        "name": identifier or "unknown",
        "needs": list(graph_job.get("needs", [])),
        "needs_status": "unresolved" if unresolved else "resolved",
        "status": status,
        "conclusion": conclusion,
        **fields,
        "runner": runner,
        "steps": steps,
        "job_queue": {"status": "unknown", "seconds": None,
                      "reason": "api-does-not-expose-job-queue"},
    }


def _critical_path(graph, jobs):
    graph_jobs = graph.get("jobs", {})
    by_name = {item.get("name"): item for item in jobs if item.get("name") != "unknown"}
    errors = []
    expected = set(graph_jobs)
    observed = set(by_name)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    if graph.get("status") != "complete":
        errors.extend(graph.get("errors", []))
    if missing:
        errors.append("jobs-missing")
    if extra:
        errors.append("jobs-unexpected")
    if any(item.get("needs_status") != "resolved" for item in jobs):
        errors.append("job-name-unresolved")

    indegree = {name: len(graph_jobs[name].get("needs", [])) for name in graph_jobs}
    children = {name: [] for name in graph_jobs}
    for name, value in graph_jobs.items():
        for dependency in value.get("needs", []):
            if dependency in children:
                children[dependency].append(name)
    ready = sorted(name for name, count in indegree.items() if count == 0)
    order = []
    while ready:
        name = ready.pop(0)
        order.append(name)
        for child in sorted(children[name]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if len(order) != len(graph_jobs):
        errors.append("dependency-cycle")
        return {"status": "incomplete", "graph_sha256": _graph_digest(graph),
                "path": [], "observed_weighted_seconds": 0,
                "wall_span_seconds": None, "unavailable_gaps_seconds": None,
                "unknown_job_ids": sorted(expected), "errors": sorted(set(errors))}

    best = {}
    for name in order:
        job_value = by_name.get(name)
        if job_value is None:
            duration = 0.0
            errors.append("jobs-missing")
        elif job_value.get("conclusion") == "skipped":
            duration = 0.0
        else:
            if job_value.get("status") != "completed":
                errors.append("job-not-terminal")
            duration = job_value.get("elapsed_seconds")
            if duration is None:
                duration = 0.0
                errors.append("job-timestamp-unavailable")
        dependencies = graph_jobs[name].get("needs", [])
        parents = [best[parent] for parent in dependencies if parent in best]
        prefix = max(parents, key=lambda item: (item[0], tuple(item[1]))) if parents else (0.0, [])
        best[name] = (prefix[0] + duration, prefix[1] + [name])
    if best:
        _, path = max(best.values(), key=lambda item: (item[0], tuple(item[1])))
    else:
        path = []
    weighted = round(sum((0.0 if by_name.get(name) is None or
                          by_name[name].get("conclusion") == "skipped" else
                          (by_name[name].get("elapsed_seconds") or 0.0)) for name in path), 3)
    path_jobs = [by_name[name] for name in path if name in by_name]
    times = [(_timestamp(item.get("started_at")), _timestamp(item.get("completed_at")))
             for item in path_jobs]
    known = [(start, end) for start, end in times if start is not None and end is not None]
    wall_span = round(max(end for _, end in known) - min(start for start, _ in known), 3) if known else None
    gaps = round(wall_span - weighted, 3) if wall_span is not None and wall_span >= weighted else None
    if wall_span is not None and gaps is None:
        errors.append("critical-path-time-overlap")
    unknown_jobs = sorted(name for name in expected
        if name not in by_name or (by_name[name].get("conclusion") != "skipped" and
                                   by_name[name].get("elapsed_seconds") is None))
    status = "complete" if not errors and not unknown_jobs else "incomplete"
    return {"status": status, "graph_sha256": _graph_digest(graph), "path": path,
            "observed_weighted_seconds": weighted, "wall_span_seconds": wall_span,
            "unavailable_gaps_seconds": gaps, "unknown_job_ids": unknown_jobs,
            "errors": sorted(set(errors))}


def _runner_seconds_by_os(jobs):
    totals = {}
    for item in jobs:
        elapsed = item.get("elapsed_seconds")
        if elapsed is None:
            continue
        os_name = item.get("runner", {}).get("os", "unknown")
        totals[os_name] = round(totals.get(os_name, 0.0) + elapsed, 3)
    return {key: totals[key] for key in sorted(totals)}


def _billing(visibility, jobs):
    if visibility == "public" and jobs and all(
        item.get("conclusion") == "skipped" or
        item.get("runner", {}).get("type") == "github-hosted-standard" for item in jobs
    ):
        return {"status": "not_applicable", "reason": "public-standard-github-hosted"}
    return {"status": "unknown", "reason": "authoritative-billing-data-unavailable"}


def _safe_collection_error(errors, code, run_id=None, attempt_number=None):
    if run_id is not None and attempt_number is not None:
        code = f"{code}:{run_id}:{attempt_number}"
    elif run_id is not None:
        code = f"{code}:{run_id}"
    if code not in errors:
        errors.append(code)


def _content_version(api, repo, workflow_path, source_sha):
    encoded_path = urllib.parse.quote(workflow_path, safe="/")
    query = urllib.parse.urlencode({"ref": source_sha})
    body = api.get_json(f"/repos/{repo}/contents/{encoded_path}?{query}")
    if body.get("encoding") != "base64" or not isinstance(body.get("content"), str):
        raise CollectionError("workflow-content-encoding-invalid")
    if not isinstance(body.get("size"), int) or body["size"] > MAX_WORKFLOW_BYTES:
        raise CollectionError("workflow-source-too-large")
    try:
        raw = base64.b64decode("".join(body["content"].split()), validate=True)
    except (binascii.Error, ValueError):
        raise CollectionError("workflow-content-base64-invalid") from None
    if len(raw) != body["size"] or len(raw) > MAX_WORKFLOW_BYTES:
        raise CollectionError("workflow-content-size-mismatch")
    blob_sha = body.get("sha")
    if not _valid_sha(blob_sha) or _git_blob_sha(raw) != blob_sha:
        raise CollectionError("workflow-blob-identity-mismatch")
    try:
        graph = parse_workflow_graph(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise CollectionError("workflow-source-not-utf8") from None
    return {
        "workflow_source_sha": source_sha,
        "workflow_blob_sha": blob_sha,
        "workflow_sha256": hashlib.sha256(raw).hexdigest(),
        "graph_sha256": _graph_digest(graph),
        "graph": graph,
    }


def _fetch_runs(api, repo, workflow_path, source_sha, max_runs, errors):
    filename = urllib.parse.quote(Path(workflow_path).name, safe="")
    selected = []
    total_count = None
    page = 1
    while page <= MAX_RUN_PAGES and len(selected) < max_runs:
        query_values = {"per_page": 100, "page": page}
        if source_sha:
            query_values["head_sha"] = source_sha
        query = urllib.parse.urlencode(query_values)
        try:
            body = api.get_json(f"/repos/{repo}/actions/workflows/{filename}/runs?{query}")
        except CollectionError as exc:
            _safe_collection_error(errors, exc.code)
            break
        page_total = body.get("total_count")
        items = body.get("workflow_runs")
        if not isinstance(page_total, int) or page_total < 0 or not isinstance(items, list):
            _safe_collection_error(errors, "workflow-runs-schema-invalid")
            break
        if total_count is None:
            total_count = page_total
        elif total_count != page_total:
            _safe_collection_error(errors, "workflow-runs-total-changed")
        for item in items:
            if isinstance(item, dict):
                selected.append(item)
                if len(selected) >= max_runs:
                    break
        if len(selected) >= max_runs or len(selected) >= total_count:
            break
        if not items:
            _safe_collection_error(errors, "workflow-runs-pagination-incomplete")
            break
        page += 1
    if page > MAX_RUN_PAGES and len(selected) < max_runs and total_count is not None and len(selected) < total_count:
        _safe_collection_error(errors, "workflow-runs-page-limit-exceeded")
    return selected


def _fetch_jobs(api, repo, run_id, attempt_number, errors, unknowns):
    all_jobs = []
    total_count = None
    page = 1
    while page <= 2:
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        try:
            body = api.get_json(
                f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs?{query}")
        except CollectionError as exc:
            _safe_collection_error(errors, exc.code, run_id, attempt_number)
            break
        count = body.get("total_count")
        items = body.get("jobs")
        if not isinstance(count, int) or count < 0 or not isinstance(items, list):
            _safe_collection_error(errors, "jobs-schema-invalid", run_id, attempt_number)
            break
        if total_count is None:
            total_count = count
        elif total_count != count:
            _safe_collection_error(errors, "jobs-total-changed", run_id, attempt_number)
        if total_count > MAX_JOBS:
            _safe_collection_error(errors, "jobs-truncated", run_id, attempt_number)
            _safe_collection_error(unknowns, "jobs-truncated", run_id, attempt_number)
            all_jobs.extend(item for item in items[:MAX_JOBS] if isinstance(item, dict))
            break
        all_jobs.extend(item for item in items if isinstance(item, dict))
        if len(all_jobs) >= total_count:
            break
        if not items:
            _safe_collection_error(errors, "jobs-pagination-incomplete", run_id, attempt_number)
            break
        page += 1
    if total_count is not None and total_count <= MAX_JOBS and len(all_jobs) != total_count:
        _safe_collection_error(errors, "jobs-pagination-incomplete", run_id, attempt_number)
    return all_jobs


def _attempt_record(api, repo, run_summary, attempt_number, workflow_path,
                    visibility, versions, requested_source, errors, unknowns):
    run_id = run_summary.get("id")
    if not isinstance(run_id, int) or run_id <= 0:
        _safe_collection_error(errors, "run-id-invalid")
        return None
    attempt_errors = []
    try:
        detail = api.get_json(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt_number}")
    except CollectionError as exc:
        _safe_collection_error(errors, exc.code, run_id, attempt_number)
        detail = {}
        attempt_errors.append(exc.code)

    event = _safe_event(detail.get("event"))
    source = detail.get("head_sha")
    status = _safe_status(detail.get("status"))
    conclusion = _safe_conclusion(detail.get("conclusion"))
    ref = _safe_ref(detail.get("head_branch") or detail.get("ref"), event)
    created_at = detail.get("created_at")
    started_at = detail.get("run_started_at")
    completed_at = detail.get("completed_at")
    workflow_api_path = detail.get("path")
    observed_path = _workflow_path_from_api(workflow_api_path)

    if detail.get("id") != run_id or detail.get("run_attempt") != attempt_number:
        attempt_errors.append("run-attempt-identity-mismatch")
    if not _valid_sha(source):
        attempt_errors.append("run-source-sha-invalid")
    elif requested_source and source != requested_source:
        attempt_errors.append("run-source-mismatch")
    if observed_path != workflow_path:
        attempt_errors.append("run-workflow-path-mismatch")
    if status != "completed":
        attempt_errors.append("run-not-completed")

    version = None
    if not attempt_errors and source not in versions:
        try:
            versions[source] = _content_version(api, repo, workflow_path, source)
        except CollectionError as exc:
            attempt_errors.append(exc.code)
    if source in versions:
        version = versions[source]
        if version["graph"].get("status") != "complete":
            attempt_errors.append("workflow-graph-invalid")

    raw_jobs = []
    if status == "completed" and version is not None and not attempt_errors:
        raw_jobs = _fetch_jobs(api, repo, run_id, attempt_number, errors, unknowns)
    jobs = [_normalize_job(item, version["graph"], visibility) for item in raw_jobs]
    if any(not isinstance(item.get("steps", []), list) or len(item.get("steps", [])) > MAX_STEPS
           for item in raw_jobs):
        attempt_errors.append("steps-truncated")
    if any(isinstance(item.get("steps"), list) and len(item["steps"]) > MAX_STEPS
           for item in raw_jobs):
        attempt_errors.append("steps-truncated")

    if version is not None:
        graph = version["graph"]
        critical = _critical_path(graph, jobs)
        for code in critical["errors"]:
            attempt_errors.append(code)
    else:
        critical = {"status": "incomplete", "graph_sha256": None, "path": [],
                    "observed_weighted_seconds": 0, "wall_span_seconds": None,
                    "unavailable_gaps_seconds": None, "unknown_job_ids": [],
                    "errors": ["workflow-graph-unavailable"]}

    queue_seconds = _duration(created_at, started_at)
    if queue_seconds is None:
        unknowns.append("workflow-queue-unavailable")
    wall_seconds = _duration(started_at, completed_at)
    if completed_at is None or wall_seconds is None:
        unknowns.append("workflow-terminal-time-unavailable")
    run = {
        "run_id": run_id,
        "run_attempt": attempt_number,
        "event": event,
        "ref": ref,
        "head_sha": source if _valid_sha(source) else None,
        "workflow_source_sha": source if _valid_sha(source) else None,
        "status": status,
        "conclusion": conclusion,
        "created_at": created_at if _timestamp(created_at) is not None else None,
        "run_started_at": started_at if _timestamp(started_at) is not None else None,
        "completed_at": completed_at if _timestamp(completed_at) is not None else None,
        "queue_seconds": queue_seconds,
        "wall_seconds": wall_seconds,
        "workflow_blob_sha": version.get("workflow_blob_sha") if version else None,
        "workflow_sha256": version.get("workflow_sha256") if version else None,
        "graph_sha256": version.get("graph_sha256") if version else None,
        "jobs": jobs,
        "critical_path": critical,
        "runner_seconds_by_os": _runner_seconds_by_os(jobs),
        "billing": _billing(visibility, jobs),
        "errors": sorted(set(attempt_errors)),
    }
    for code in attempt_errors:
        _safe_collection_error(errors, code, run_id, attempt_number)
    return run


def collect_report(*, repo, workflow_path, source_sha=None, max_runs=3,
                   max_attempts=3, token=None, opener=None):
    errors = []
    unknowns = []
    versions = {}
    if not _valid_repo(repo):
        raise CollectionError("repository-invalid")
    if not _valid_workflow_path(workflow_path):
        raise CollectionError("workflow-path-invalid")
    if source_sha is not None and not _valid_sha(source_sha):
        raise CollectionError("source-sha-invalid")
    if not isinstance(max_runs, int) or not 1 <= max_runs <= MAX_RUNS:
        raise CollectionError("max-runs-out-of-range")
    if not isinstance(max_attempts, int) or not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise CollectionError("max-attempts-out-of-range")
    if token is not None and (not isinstance(token, str) or len(token) > 4096 or
                              any(ord(char) < 33 or ord(char) > 126 for char in token)):
        raise CollectionError("token-invalid")
    api = GitHubApi(token, opener)

    visibility = "unknown"
    try:
        repository = api.get_json(f"/repos/{repo}")
        if repository.get("private") is False and repository.get("visibility", "public") == "public":
            visibility = "public"
        elif repository.get("private") is True or repository.get("visibility") in ("private", "internal"):
            visibility = "private"
        else:
            _safe_collection_error(errors, "repository-visibility-unknown")
    except CollectionError as exc:
        _safe_collection_error(errors, exc.code)

    run_summaries = _fetch_runs(api, repo, workflow_path, source_sha, max_runs, errors)
    if not run_summaries:
        _safe_collection_error(errors, "workflow-runs-not-found-for-source" if source_sha else "workflow-runs-not-found")

    runs = []
    for summary in run_summaries:
        if source_sha and summary.get("head_sha") != source_sha:
            _safe_collection_error(errors, "run-source-mismatch", summary.get("id"))
            continue
        latest_attempt = summary.get("run_attempt", 1)
        if not isinstance(latest_attempt, int) or latest_attempt < 1:
            _safe_collection_error(errors, "run-attempt-count-invalid", summary.get("id"))
            continue
        if latest_attempt > max_attempts:
            _safe_collection_error(errors, "attempts-truncated", summary.get("id"))
            _safe_collection_error(unknowns, "attempts-truncated", summary.get("id"))
        attempt_limit = min(latest_attempt, max_attempts)
        for number in range(1, attempt_limit + 1):
            record = _attempt_record(api, repo, summary, number, workflow_path,
                                     visibility, versions, source_sha, errors, unknowns)
            if record is not None:
                runs.append(record)

    version_values = list(versions.values())
    graph_versions = []
    for item in sorted(version_values, key=lambda value: value["workflow_source_sha"]):
        graph_versions.append({"workflow_source_sha": item["workflow_source_sha"],
            "workflow_blob_sha": item["workflow_blob_sha"],
            "workflow_sha256": item["workflow_sha256"],
            "graph_sha256": item["graph_sha256"], "status": item["graph"]["status"],
            "jobs": item["graph"]["jobs"], "errors": item["graph"]["errors"]})
    unique_blob = {item["workflow_blob_sha"] for item in graph_versions}
    unique_sha256 = {item["workflow_sha256"] for item in graph_versions}
    unique_source = {item["workflow_source_sha"] for item in runs if item.get("workflow_source_sha")}
    report_source = source_sha if source_sha else (next(iter(unique_source)) if len(unique_source) == 1 else None)
    cohorts = {event: {"run_ids": [], "attempts": 0} for event in EVENTS}
    for item in runs:
        cohort = cohorts.setdefault(item["event"], {"run_ids": [], "attempts": 0})
        cohort["attempts"] += 1
        if item["run_id"] not in cohort["run_ids"]:
            cohort["run_ids"].append(item["run_id"])
    report = {
        "schema_version": SCHEMA,
        "repository": repo,
        "visibility": visibility,
        "source_sha": report_source,
        "requested_source_sha": source_sha,
        "collection_time": _now_utc(),
        "workflow_path": workflow_path,
        "workflow_blob_sha": next(iter(unique_blob)) if len(unique_blob) == 1 else None,
        "workflow_sha256": next(iter(unique_sha256)) if len(unique_sha256) == 1 else None,
        "graph": {"status": "complete" if all(item["status"] == "complete" for item in graph_versions) else "incomplete",
                  "versions": graph_versions},
        "cohorts": cohorts,
        "runs": runs,
        "unknowns": sorted(set(unknowns)),
        "observations": [f"bounded-run-window:{max_runs}",
                         f"bounded-attempt-window:{max_attempts}"],
        "errors": sorted(set(errors)),
        "collection_status": "incomplete" if errors else "complete",
        "limits": {"max_runs": max_runs, "max_attempts_per_run": max_attempts,
                   "max_jobs_per_attempt": MAX_JOBS, "max_steps_per_job": MAX_STEPS,
                   "max_response_bytes": MAX_API_RESPONSE,
                   "max_report_bytes": MAX_REPORT_BYTES,
                   "max_request_seconds": MAX_REQUEST_SECONDS,
                   "max_collection_seconds": MAX_COLLECTION_SECONDS,
                   "api_requests": api.request_count},
    }
    validation = validate_report(report)
    if validation["errors"]:
        report["errors"] = sorted(set(report["errors"] + validation["errors"]))
        report["collection_status"] = "incomplete"
    return report


def _sensitive_value(value):
    if not isinstance(value, str):
        return False
    patterns = (r"(?i)(?:/Users/|/home/|/private/var/|[A-Z]:\\)",
                r"(?i)\bBearer\s+\S+", r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
                r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
    return any(re.search(pattern, value) for pattern in patterns)


def _privacy_errors(value):
    errors = []
    blocked_keys = {"authorization", "token", "password", "actor", "runner_name",
                    "runner_group_name", "raw_payload", "log", "private_path"}
    def visit(item, key=None):
        if key in blocked_keys:
            errors.append("private-data-field")
        if isinstance(item, dict):
            for child_key, child_value in item.items():
                visit(child_value, child_key if isinstance(child_key, str) else None)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif _sensitive_value(item):
            errors.append("private-data-value")
    visit(value)
    return sorted(set(errors))


def _valid_job_seconds(job_value):
    if job_value.get("conclusion") == "skipped":
        return job_value.get("elapsed_seconds") is None
    elapsed = _duration(job_value.get("started_at"), job_value.get("completed_at"))
    return elapsed is not None and job_value.get("elapsed_seconds") == elapsed


def _same_number(actual, expected):
    if actual is None or expected is None:
        return actual is None and expected is None
    return isinstance(actual, (int, float)) and not isinstance(actual, bool) and round(actual, 3) == round(expected, 3)


def _only_fields(value, allowed):
    return isinstance(value, dict) and set(value).issubset(allowed)


def _validate_libretro_qualification(runs):
    latest_attempt = {}
    for run in runs:
        run_id = run.get("run_id")
        if isinstance(run_id, int):
            latest_attempt[run_id] = max(latest_attempt.get(run_id, 0), run.get("run_attempt", 0))
    for run in runs:
        if run.get("event") not in NORMAL_EVENTS or run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        if run.get("run_attempt") != latest_attempt.get(run.get("run_id")):
            continue
        if not any(job.get("name") == "required-aggregate" and
                   job.get("status") == "completed" and job.get("conclusion") == "success" and
                   "libretro" in job.get("needs", [])
                   for job in run.get("jobs", [])):
            continue
        for job_value in run.get("jobs", []):
            if job_value.get("name") != "libretro" or job_value.get("status") != "completed" or job_value.get("conclusion") != "success":
                continue
            if job_value.get("runner", {}).get("os") != "linux":
                continue
            evidence = {"actual_module": False, "address_sanitizer": False,
                        "undefined_sanitizer": False, "linux_x86_64_runner": False}
            for step in job_value.get("steps", []):
                if step.get("conclusion") == "success":
                    for name in evidence:
                        evidence[name] = evidence[name] or step.get("evidence", {}).get(name) is True
            if all(evidence.values()):
                return True
    return False


def _validate_report(report, *, require_source=None, require_libretro=False):
    errors = []
    def reject(code):
        if code not in errors:
            errors.append(code)
    if not isinstance(report, dict):
        return {"status": "incomplete", "errors": ["report-not-object"]}
    try:
        report_size = len(json.dumps(report, ensure_ascii=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        return {"status": "incomplete", "errors": ["report-json-invalid"]}
    if report_size > MAX_REPORT_BYTES:
        reject("report-too-large")
    if report.get("schema_version") != SCHEMA:
        reject("schema-version-unsupported")
    if not _only_fields(report, {
        "schema_version", "repository", "visibility", "source_sha", "requested_source_sha",
        "collection_time", "workflow_path", "workflow_blob_sha", "workflow_sha256", "graph",
        "cohorts", "runs", "unknowns", "observations", "errors", "collection_status", "limits",
    }):
        reject("report-field-unrecognized")
    if not _valid_repo(report.get("repository")):
        reject("repository-invalid")
    if report.get("visibility") not in ("public", "private", "unknown"):
        reject("visibility-invalid")
    if not _valid_workflow_path(report.get("workflow_path")):
        reject("workflow-path-invalid")
    if not isinstance(report.get("runs"), list) or not report["runs"]:
        reject("runs-missing")
        runs = []
    else:
        runs = report["runs"]
    if not isinstance(report.get("errors"), list):
        reject("errors-invalid")
    elif report["errors"]:
        reject("collection-errors-present")
    if report.get("collection_status") != "complete":
        reject("collection-incomplete")
    requested = report.get("requested_source_sha")
    if requested is not None and not _valid_sha(requested):
        reject("requested-source-invalid")

    graph = report.get("graph")
    graph_versions = graph.get("versions", []) if isinstance(graph, dict) else []
    by_graph_sha = {}
    if not _only_fields(graph, {"status", "versions"}):
        reject("workflow-graph-field-unrecognized")
    if not isinstance(graph_versions, list) or not graph_versions:
        reject("workflow-graph-missing")
        graph_versions = []
    for version in graph_versions:
        if not isinstance(version, dict):
            reject("workflow-graph-invalid")
            continue
        if not _only_fields(version, {"workflow_source_sha", "workflow_blob_sha", "workflow_sha256",
                                      "graph_sha256", "status", "jobs", "errors"}):
            reject("workflow-version-field-unrecognized")
        graph_jobs = version.get("jobs", {})
        graph_errors = version.get("errors", [])
        if not isinstance(graph_jobs, dict) or not isinstance(graph_errors, list):
            reject("workflow-graph-invalid")
            graph_jobs = {}
            graph_errors = ["graph-schema-invalid"]
        for graph_job in graph_jobs.values():
            if not _only_fields(graph_job, {"id", "name", "needs", "matrix"}):
                reject("workflow-job-field-unrecognized")
        if not _valid_sha(version.get("workflow_source_sha")) or not _valid_sha(version.get("workflow_blob_sha")):
            reject("workflow-identity-invalid")
        if not isinstance(version.get("workflow_sha256"), str) or not SHA256.fullmatch(version.get("workflow_sha256", "")) or not isinstance(version.get("graph_sha256"), str) or not SHA256.fullmatch(version.get("graph_sha256", "")):
            reject("workflow-digest-invalid")
        version_graph = {"jobs": graph_jobs, "errors": graph_errors}
        if version.get("graph_sha256") != _graph_digest(version_graph):
            reject("workflow-graph-digest-mismatch")
        if version.get("status") != "complete" or graph_errors:
            reject("workflow-graph-incomplete")
        graph_sha = version.get("graph_sha256")
        if isinstance(graph_sha, str) and graph_sha in by_graph_sha and by_graph_sha[graph_sha] != version:
            reject("workflow-graph-identity-conflict")
        if isinstance(graph_sha, str):
            by_graph_sha[graph_sha] = version

    graph_status = "complete" if graph_versions and all(
        isinstance(item, dict) and item.get("status") == "complete" for item in graph_versions
    ) else "incomplete"
    if not isinstance(graph, dict) or graph.get("status") != graph_status:
        reject("workflow-graph-status-mismatch")
    unique_blob = {item.get("workflow_blob_sha") for item in graph_versions if isinstance(item, dict)}
    unique_sha256 = {item.get("workflow_sha256") for item in graph_versions if isinstance(item, dict)}
    expected_blob = next(iter(unique_blob)) if len(unique_blob) == 1 else None
    expected_sha256 = next(iter(unique_sha256)) if len(unique_sha256) == 1 else None
    if report.get("workflow_blob_sha") != expected_blob:
        reject("workflow-blob-summary-mismatch")
    if report.get("workflow_sha256") != expected_sha256:
        reject("workflow-content-summary-mismatch")

    grouped_attempts = {}
    run_sources = set()
    expected_cohorts = {event: {"run_ids": [], "attempts": 0} for event in EVENTS}
    for run in runs:
        if not isinstance(run, dict):
            reject("run-invalid")
            continue
        if not _only_fields(run, {
            "run_id", "run_attempt", "event", "ref", "head_sha", "workflow_source_sha",
            "status", "conclusion", "created_at", "run_started_at", "completed_at",
            "queue_seconds", "wall_seconds", "workflow_blob_sha", "workflow_sha256",
            "graph_sha256", "jobs", "critical_path", "runner_seconds_by_os", "billing", "errors",
        }):
            reject("run-field-unrecognized")
        run_id = run.get("run_id")
        number = run.get("run_attempt")
        if not isinstance(run_id, int) or run_id <= 0 or not isinstance(number, int) or not 1 <= number <= MAX_ATTEMPTS:
            reject("run-attempt-invalid")
        else:
            grouped_attempts.setdefault(run_id, []).append(number)
        event = run.get("event")
        if event not in EVENTS:
            reject("event-invalid")
            event = "other"
        cohort = expected_cohorts[event]
        cohort["attempts"] += 1
        if run_id not in cohort["run_ids"]:
            cohort["run_ids"].append(run_id)
        if run.get("status") != "completed":
            reject("run-not-completed")
        if run.get("conclusion") not in CONCLUSIONS or run.get("conclusion") == "unknown":
            reject("run-conclusion-invalid")
        source = run.get("workflow_source_sha")
        if not _valid_sha(source) or run.get("head_sha") != source:
            reject("run-source-invalid")
        else:
            run_sources.add(source)
        if require_source is not None and source != require_source:
            reject("required-source-mismatch")
        if requested is not None and source != requested:
            reject("run-source-mismatch")
        graph_sha = run.get("graph_sha256")
        version = by_graph_sha.get(graph_sha)
        if version is None:
            reject("run-workflow-graph-unbound")
            version_graph = {"jobs": {}, "errors": ["unbound"]}
        else:
            version_graph = {"jobs": version.get("jobs", {}),
                             "errors": version.get("errors", [])}
            if run.get("workflow_source_sha") != version.get("workflow_source_sha"):
                reject("run-workflow-source-mismatch")
        if version is None or run.get("workflow_blob_sha") != version.get("workflow_blob_sha"):
            reject("run-workflow-blob-unbound")
        if version is None or run.get("workflow_sha256") != version.get("workflow_sha256"):
            reject("run-workflow-content-unbound")
        if run.get("ref") == "unknown" or run.get("ref") == "other":
            # Unknown/other references are retained as such; their original value
            # is intentionally not copied into a public report.
            pass
        if not _same_number(run.get("queue_seconds"), _duration(run.get("created_at"), run.get("run_started_at"))):
            reject("workflow-queue-mismatch")
        if not _same_number(run.get("wall_seconds"), _duration(run.get("run_started_at"), run.get("completed_at"))):
            reject("workflow-wall-mismatch")
        if not isinstance(run.get("jobs"), list) or len(run.get("jobs", [])) > MAX_JOBS:
            reject("jobs-invalid")
            job_list = []
        else:
            job_list = run["jobs"]
        observed_names = []
        for job_value in job_list:
            if not isinstance(job_value, dict):
                reject("job-invalid")
                continue
            if not _only_fields(job_value, {"job_id", "name", "needs", "needs_status", "status",
                                            "conclusion", "started_at", "completed_at", "elapsed_seconds",
                                            "runner", "steps", "job_queue"}):
                reject("job-field-unrecognized")
            name = job_value.get("name")
            observed_names.append(name)
            if name not in version_graph.get("jobs", {}):
                reject("job-name-unresolved")
            elif job_value.get("needs") != version_graph["jobs"][name].get("needs", []):
                reject("job-needs-mismatch")
            if job_value.get("needs_status") != "resolved":
                reject("job-needs-unresolved")
            if job_value.get("status") not in JOB_STATUSES:
                reject("job-status-invalid")
            if job_value.get("conclusion") not in CONCLUSIONS:
                reject("job-conclusion-invalid")
            if not _valid_job_seconds(job_value):
                reject("job-timestamp-unavailable")
            queue = job_value.get("job_queue")
            if not _only_fields(queue, {"status", "seconds", "reason"}):
                reject("job-queue-field-unrecognized")
            if not isinstance(queue, dict) or queue.get("status") != "unknown" or queue.get("seconds") is not None or queue.get("reason") != "api-does-not-expose-job-queue":
                reject("job-queue-not-authoritative")
            runner = job_value.get("runner")
            if not _only_fields(runner, {"labels", "type", "os"}):
                reject("runner-field-unrecognized")
            if not isinstance(runner, dict) or runner.get("os") not in ("linux", "macos", "windows", "unknown") or runner.get("type") not in ("github-hosted-standard", "self-hosted", "unknown"):
                reject("runner-invalid")
            if not isinstance(job_value.get("steps"), list) or len(job_value.get("steps", [])) > MAX_STEPS:
                reject("steps-invalid")
            else:
                for step in job_value["steps"]:
                    if not isinstance(step, dict) or step.get("category") not in STEP_CATEGORIES:
                        reject("step-invalid")
                    elif not _only_fields(step, {"number", "category", "status", "conclusion",
                                                "started_at", "completed_at", "elapsed_seconds", "evidence"}):
                        reject("step-field-unrecognized")
                    elif not _only_fields(step.get("evidence"), {"actual_module", "address_sanitizer",
                                                                  "undefined_sanitizer", "linux_x86_64_runner"}):
                        reject("step-evidence-field-unrecognized")
        if len(observed_names) != len(set(observed_names)):
            reject("job-duplicate")
        if set(observed_names) != set(version_graph.get("jobs", {})):
            reject("jobs-missing-or-unexpected")
        if run.get("critical_path") != _critical_path(version_graph, job_list):
            reject("critical-path-mismatch")
        if not _only_fields(run.get("critical_path"), {"status", "graph_sha256", "path",
                "observed_weighted_seconds", "wall_span_seconds", "unavailable_gaps_seconds",
                "unknown_job_ids", "errors"}):
            reject("critical-path-field-unrecognized")
        if run.get("runner_seconds_by_os") != _runner_seconds_by_os(job_list):
            reject("runner-seconds-mismatch")
        expected_billing = _billing(report.get("visibility"), job_list)
        if run.get("billing") != expected_billing:
            if isinstance(run.get("billing"), dict) and run["billing"].get("status") not in ("unknown", "not_applicable"):
                reject("billing-unsupported")
            else:
                reject("billing-applicability-mismatch")
        if not _only_fields(run.get("billing"), {"status", "reason"}):
            reject("billing-field-unrecognized")
    if not _only_fields(report.get("limits"), {"max_runs", "max_attempts_per_run",
            "max_jobs_per_attempt", "max_steps_per_job", "max_response_bytes", "max_report_bytes",
            "max_request_seconds", "max_collection_seconds", "api_requests"}):
        reject("limits-field-unrecognized")
    cohorts = report.get("cohorts")
    if isinstance(cohorts, dict):
        for value in cohorts.values():
            if not _only_fields(value, {"run_ids", "attempts"}):
                reject("cohort-field-unrecognized")
    expected_source = requested if requested is not None else (
        next(iter(run_sources)) if len(run_sources) == 1 else None)
    if report.get("source_sha") != expected_source:
        reject("report-source-mismatch")
    limits = report.get("limits")
    if isinstance(limits, dict):
        fixed_limits = {
            "max_jobs_per_attempt": MAX_JOBS,
            "max_steps_per_job": MAX_STEPS,
            "max_response_bytes": MAX_API_RESPONSE,
            "max_report_bytes": MAX_REPORT_BYTES,
            "max_request_seconds": MAX_REQUEST_SECONDS,
            "max_collection_seconds": MAX_COLLECTION_SECONDS,
        }
        if any(limits.get(key) != value for key, value in fixed_limits.items()):
            reject("limits-mismatch")
        for key, maximum in (("max_runs", MAX_RUNS), ("max_attempts_per_run", MAX_ATTEMPTS)):
            value = limits.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                reject("limits-invalid")
        request_count = limits.get("api_requests")
        if not isinstance(request_count, int) or isinstance(request_count, bool) or request_count < 0:
            reject("limits-invalid")
    for run_id, attempts in grouped_attempts.items():
        ordered = sorted(attempts)
        if ordered != list(range(1, max(ordered) + 1)):
            reject("attempt-history-incomplete")
    if report.get("cohorts") != expected_cohorts:
        reject("cohort-event-mismatch")
    if require_source is not None:
        if not _valid_sha(require_source):
            reject("required-source-invalid")
        elif report.get("source_sha") != require_source:
            reject("required-source-mismatch")
    if require_libretro and not _validate_libretro_qualification(runs):
        reject("libretro-qualification-missing")
    errors.extend(_privacy_errors(report))
    errors = sorted(set(errors))
    return {"status": "complete" if not errors else "incomplete", "errors": errors}


def validate_report(report, *, require_source=None, require_libretro=False):
    try:
        return _validate_report(report, require_source=require_source,
                                require_libretro=require_libretro)
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError):
        return {"status": "incomplete", "errors": ["report-schema-invalid"]}


def _read_report(path: str):
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise CollectionError("report-read-failed") from None
    if len(data) > MAX_REPORT_BYTES:
        raise CollectionError("report-too-large")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise CollectionError("report-json-invalid") from None
    return value


def _write_report(path: str, report: dict):
    data = (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise CollectionError("report-too-large")
    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(destination)
    except OSError:
        raise CollectionError("report-write-failed") from None


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect", help="read bounded completed workflow run data")
    collect.add_argument("--repo", required=True)
    collect.add_argument("--workflow", default=".github/workflows/ci.yml")
    collect.add_argument("--source-sha")
    collect.add_argument("--max-runs", type=int, default=3)
    collect.add_argument("--max-attempts", type=int, default=3)
    collect.add_argument("--output", required=True)
    validate = subparsers.add_parser("validate", help="validate a collected report without network access")
    validate.add_argument("--input", required=True)
    validate.add_argument("--require-source")
    validate.add_argument("--require-libretro", action="store_true")
    return parser


def main(argv=None, *, environ=None, opener=None):
    try:
        args = _parser().parse_args(argv)
        if args.command == "collect":
            env = os.environ if environ is None else environ
            token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
            report = collect_report(repo=args.repo, workflow_path=args.workflow,
                source_sha=args.source_sha, max_runs=args.max_runs,
                max_attempts=args.max_attempts, token=token, opener=opener)
            _write_report(args.output, report)
            result = validate_report(report)
            if result["status"] != "complete":
                print("INCOMPLETE: " + ", ".join(result["errors"]), file=sys.stderr)
                return 1
            print(f"PASS: collected {len(report['runs'])} attempt(s) for {report['repository']}")
            return 0
        report = _read_report(args.input)
        result = validate_report(report, require_source=args.require_source,
                                  require_libretro=args.require_libretro)
        if result["status"] != "complete":
            for error in result["errors"]:
                print("REJECT: " + error, file=sys.stderr)
            return 1
        print("PASS: CI baseline report is structurally valid")
        return 0
    except CollectionError as exc:
        print("REJECT: " + exc.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("REJECT: input-invalid:" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
