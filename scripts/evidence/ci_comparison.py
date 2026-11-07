#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and validate a conservative, source-bound Phase 9 CI comparison."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evidence import ci_baseline  # noqa: E402
from scripts.release import qualify_delivery  # noqa: E402


SCHEMA = "genewhip-ci-comparison.v1"
REPO = "szTheory/genewhip"
MAX_JSON_BYTES = 5 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class ComparisonError(Exception):
    """Stable, non-sensitive input or evidence rejection."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite-json-number")


def _read_json(path: str | Path) -> tuple[dict, bytes]:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise ComparisonError("input-read-failed") from None
    if len(raw) > MAX_JSON_BYTES:
        raise ComparisonError("input-size-limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ComparisonError("input-json-invalid") from None
    if not isinstance(value, dict):
        raise ComparisonError("input-object-required")
    return value, raw


def _write_json(path: str | Path, value: dict) -> None:
    try:
        raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError):
        raise ComparisonError("output-json-invalid") from None
    if len(raw) > MAX_JSON_BYTES:
        raise ComparisonError("output-size-limit")
    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_bytes(raw)
        temporary.replace(destination)
    except OSError:
        raise ComparisonError("output-write-failed") from None


def _finite_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def stable_order(rows: list[dict]) -> list[dict]:
    """Use numeric run and attempt ordering so ties never depend on API order."""
    return sorted(rows, key=lambda row: (int(row["run_id"]), int(row["run_attempt"])))


def latest_attempts(rows: list[dict]) -> list[dict]:
    """Keep only each run's latest attempt; a failure cannot fall back to success."""
    latest = {}
    for row in rows:
        run_id = row.get("run_id")
        attempt = row.get("run_attempt")
        if type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt < 1:
            continue
        current = latest.get(run_id)
        if current is None or attempt > current["run_attempt"]:
            latest[run_id] = row
    return stable_order(list(latest.values()))


def successful_observations(rows: list[dict]) -> list[dict]:
    return [row for row in latest_attempts(rows)
            if row.get("status") == "completed" and row.get("conclusion") == "success"]


def compare_pair(before: dict, after: dict) -> dict:
    """Compare two rows only when event, graph, runner and check roster match."""
    reasons = []
    fields = (("event", "event-mismatch"),
              ("workflow_sha256", "workflow-content-mismatch"),
              ("graph_sha256", "workflow-graph-mismatch"),
              ("runner_os", "runner-os-mismatch"),
              ("required_jobs", "required-check-roster-mismatch"))
    for field, reason in fields:
        if before.get(field) != after.get(field):
            reasons.append(reason)
    for row in (before, after):
        if row.get("status") != "completed" or row.get("conclusion") != "success":
            reasons.append("latest-attempt-not-successful")
            break

    result = {
        "before_run_id": before.get("run_id"),
        "before_run_attempt": before.get("run_attempt"),
        "after_run_id": after.get("run_id"),
        "after_run_attempt": after.get("run_attempt"),
        "status": "incomparable" if reasons else "comparable",
        "reasons": sorted(set(reasons)),
        "critical_path_delta_seconds": None,
        "runner_seconds_delta_by_os": {},
    }
    if reasons:
        return result

    before_critical = before.get("critical_path_seconds")
    after_critical = after.get("critical_path_seconds")
    if _finite_number(before_critical) and _finite_number(after_critical):
        result["critical_path_delta_seconds"] = round(after_critical - before_critical, 3)

    before_runners = before.get("runner_seconds_by_os")
    after_runners = after.get("runner_seconds_by_os")
    if isinstance(before_runners, dict) and isinstance(after_runners, dict):
        for label in sorted(set(before_runners) & set(after_runners)):
            if _finite_number(before_runners[label]) and _finite_number(after_runners[label]):
                result["runner_seconds_delta_by_os"][label] = round(
                    after_runners[label] - before_runners[label], 3)
    return result


def compare_summaries(before: list[dict], after: list[dict]) -> dict:
    before_latest = successful_observations(before)
    after_latest = successful_observations(after)
    result = {"status": "insufficient", "before_count": len(before_latest),
              "after_count": len(after_latest), "pairs": [],
              "critical_path_delta_seconds": None,
              "runner_seconds_delta_by_os": {},
              "reason": "at-least-two-successful-observations-per-side-required"}
    if len(before_latest) < 2 or len(after_latest) < 2:
        return result

    pairs = [compare_pair(old, new) for old in before_latest for new in after_latest]
    result["pairs"] = pairs
    incompatible = [pair for pair in pairs if pair["status"] != "comparable"]
    if incompatible:
        result["status"] = "incomparable"
        result["reason"] = "event-workflow-graph-runner-or-required-roster-differs"
        return result

    critical = [pair["critical_path_delta_seconds"] for pair in pairs
                if pair["critical_path_delta_seconds"] is not None]
    if critical:
        result["critical_path_delta_seconds"] = round(sum(critical) / len(critical), 3)
    labels = sorted(set.intersection(*(set(pair["runner_seconds_delta_by_os"])
                                      for pair in pairs))) if pairs else []
    result["runner_seconds_delta_by_os"] = {
        label: round(sum(pair["runner_seconds_delta_by_os"][label] for pair in pairs)
                     / len(pairs), 3)
        for label in labels
    }
    result["status"] = "comparable"
    result["reason"] = "same-event-workflow-graph-runner-and-required-roster"
    return result


def _observation(report: dict, run: dict) -> dict:
    jobs = run.get("jobs", [])
    successful_jobs = [job for job in jobs if isinstance(job, dict)
                       and job.get("conclusion") != "skipped"]
    runner_os = sorted({job.get("runner", {}).get("os", "unknown")
                        for job in successful_jobs})
    required_jobs = sorted({job.get("name") for job in successful_jobs
                            if isinstance(job.get("name"), str)})
    critical = run.get("critical_path")
    critical_seconds = (critical.get("observed_weighted_seconds")
                        if isinstance(critical, dict)
                        and critical.get("status") == "complete" else None)
    critical_path = (critical.get("path", []) if isinstance(critical, dict)
                     and critical.get("status") == "complete" else [])
    runner_seconds = run.get("runner_seconds_by_os")
    if not isinstance(runner_seconds, dict):
        runner_seconds = {}
    dependency_preparation = []
    for job in jobs:
        if not isinstance(job, dict) or job.get("conclusion") == "skipped":
            continue
        seconds = sum(step.get("elapsed_seconds", 0) for step in job.get("steps", [])
                      if isinstance(step, dict)
                      and step.get("category") == "dependency_preparation"
                      and _finite_number(step.get("elapsed_seconds")))
        if seconds:
            dependency_preparation.append({
                "job": job.get("name"),
                "runner_os": job.get("runner", {}).get("os", "unknown"),
                "seconds": round(seconds, 3),
            })
    return {
        "run_id": run.get("run_id"),
        "run_attempt": run.get("run_attempt"),
        "event": run.get("event"),
        "source_sha": run.get("workflow_source_sha"),
        "head_sha": run.get("head_sha"),
        "base_sha": run.get("base_sha"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "workflow_sha256": run.get("workflow_sha256"),
        "graph_sha256": run.get("graph_sha256"),
        "runner_os": runner_os,
        "required_jobs": required_jobs,
        "critical_path_jobs": critical_path,
        "critical_path_seconds": critical_seconds if _finite_number(critical_seconds) else None,
        "runner_seconds_by_os": {
            key: value for key, value in sorted(runner_seconds.items())
            if isinstance(key, str) and _finite_number(value)
        },
        "dependency_preparation_by_job": sorted(
            dependency_preparation, key=lambda row: row["job"] or ""),
        "workflow_wall_seconds": (run.get("wall_seconds")
                                  if _finite_number(run.get("wall_seconds")) else None),
        "workflow_queue_seconds": (run.get("queue_seconds")
                                   if _finite_number(run.get("queue_seconds")) else None),
        "unknowns": sorted(set(report.get("unknowns", [])) |
                            {"job-queue-unavailable"}),
    }


def _report_entry(path: str | Path, *, require_libretro=True) -> tuple[dict, list[dict]]:
    report, raw = _read_json(path)
    general = ci_baseline.validate_report(report)
    required = ci_baseline.validate_report(report, require_libretro=require_libretro)
    errors = sorted(set(general.get("errors", []) + required.get("errors", [])))
    raw_runs = report.get("runs", [])
    observations = ([_observation(report, row) for row in raw_runs if isinstance(row, dict)]
                    if not errors else [])
    attempts = []
    for row in raw_runs:
        if not isinstance(row, dict):
            continue
        attempts.append({key: row.get(key) for key in (
            "run_id", "run_attempt", "event", "workflow_source_sha", "head_sha",
            "base_sha", "status", "conclusion", "errors")})
    attempts.sort(key=lambda row: (row.get("run_id") or 0, row.get("run_attempt") or 0))
    return ({"report_sha256": hashlib.sha256(raw).hexdigest(),
             "report_name": Path(path).name,
             "collection_status": report.get("collection_status"),
             "validation_status": "complete" if not errors else "incomplete",
             "errors": errors,
             "source_sha": report.get("source_sha"),
             "workflow_path": report.get("workflow_path"),
             "observation_count": len(observations),
             "events": sorted({row.get("event") for row in attempts
                               if isinstance(row.get("event"), str)}),
             "run_ids": sorted({row.get("run_id") for row in attempts
                                if type(row.get("run_id")) is int}),
             "attempts": attempts}, observations)


def phase8_baseline_summary() -> dict:
    path = ROOT / "evidence/phase8-ci-baseline.json"
    report, _ = _read_json(path)
    result = ci_baseline.validate_report(report, require_libretro=True)
    if result["status"] != "complete" or len(report.get("runs", [])) != 1:
        raise ComparisonError("phase8-baseline-invalid")
    run = report["runs"][0]
    return {
        "run_id": run["run_id"],
        "run_attempt": run["run_attempt"],
        "source_sha": run["workflow_source_sha"],
        "critical_path_seconds": run["critical_path"]["observed_weighted_seconds"],
        "workflow_wall_seconds": run["wall_seconds"],
        "workflow_queue_seconds": run["queue_seconds"],
        "job_queue": "unknown",
        "public_standard_runner_billing": run["billing"]["status"],
    }


def _first_release(path: str | Path) -> dict:
    evidence, _ = _read_json(path)
    errors = qualify_delivery.validate_v03_delivery_record(evidence)
    if errors:
        raise ComparisonError("first-release-evidence-invalid")
    return {
        "release_tag": evidence["release_tag"],
        "source_sha": evidence["source_sha"],
        "qualification_run_id": evidence["qualification"]["run_id"],
        "qualification_run_attempt": evidence["qualification"]["run_attempt"],
        "publisher_run_id": evidence["publisher"]["run_id"],
        "publisher_run_attempt": evidence["publisher"]["run_attempt"],
        "adoption_run_id": evidence["adoption"]["adoption_run_id"],
        "adoption_run_attempt": int(evidence["adoption"]["adoption_run_attempt"]),
    }


def _candidate_assessment(observations: list[dict], analysis: dict) -> dict:
    prep = []
    for observation in observations:
        for job in observation.get("dependency_preparation_by_job", []):
            prep.append({"run_id": observation.get("run_id"),
                         "run_attempt": observation.get("run_attempt"),
                         "job": job["job"], "runner_os": job["runner_os"],
                         "dependency_preparation_seconds": job["seconds"]})
    prep.sort(key=lambda row: (row["run_id"], row["run_attempt"], row["job"]))
    return {
        "decision": "no-change",
        "candidate": "Share pinned evidence preparation between isolated safety and desktop jobs",
        "measured_dependency_preparation": prep,
        "observed_critical_paths": [
            {"run_id": row.get("run_id"), "run_attempt": row.get("run_attempt"),
             "jobs": row.get("critical_path_jobs", [])}
            for row in observations
        ],
        "critical_path_comparison_status": analysis["status"],
        "reason": (
            "No comparable before/after optimization evidence exists. The observed preparation "
            "runs on separate macOS jobs in parallel; sharing its outputs would add a producer/" 
            "consumer artifact boundary that is not currently present or identity-validated. "
            "Do not alter the required graph without proof of net critical-path or runner savings."
        ),
        "workflow_changed": False,
        "measured_saving_claimed": False,
    }


def build_comparison(*, before_reports: list[tuple[dict, list[dict]]],
                     after_reports: list[tuple[dict, list[dict]]],
                     rejected_reports: list[dict], first_release: dict) -> dict:
    before_observations = [row for _, rows in before_reports for row in rows]
    after_observations = [row for _, rows in after_reports for row in rows]
    analysis = compare_summaries(before_observations, after_observations)
    if not after_reports:
        analysis["status"] = "insufficient"
        analysis["reason"] = "no-ci-workflow-change-no-after-run-applicable"
    accepted_before = [entry for entry, _ in before_reports]
    accepted_after = [entry for entry, _ in after_reports]
    return {
        "schema_version": SCHEMA,
        "repository": REPO,
        "first_release": first_release,
        "before": {"status": "insufficient" if analysis["status"] != "comparable" else "comparable",
                   "reports": accepted_before, "observations": before_observations},
        "after": {"status": "not_applicable" if not after_reports else analysis["status"],
                  "reports": accepted_after, "observations": after_observations},
        "rejected_reports": rejected_reports,
        "analysis": analysis,
        "phase8_baseline": phase8_baseline_summary(),
        "candidate_assessment": _candidate_assessment(
            [row for _, rows in before_reports for row in rows], analysis),
        "decision": "no-change",
        "phase9_ci_after": "not_applicable",
        "later_release": "not_applicable",
    }


def validate_comparison(value: object, *, first_release: dict | None = None) -> list[str]:
    errors = []
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA:
        return ["comparison-schema-invalid"]
    if value.get("repository") != REPO:
        errors.append("comparison-repository-invalid")
    expected_first = {key: None for key in (
        "release_tag", "source_sha", "qualification_run_id", "qualification_run_attempt",
        "publisher_run_id", "publisher_run_attempt", "adoption_run_id", "adoption_run_attempt")}
    record_first = value.get("first_release")
    if not isinstance(record_first, dict) or set(record_first) != set(expected_first):
        errors.append("comparison-first-release-invalid")
    else:
        if (record_first["release_tag"] != "v0.3.0"
                or not SHA40_RE.fullmatch(str(record_first["source_sha"]))
                or any(not re.fullmatch(r"[1-9][0-9]*", str(record_first[key]))
                       for key in ("qualification_run_id", "publisher_run_id", "adoption_run_id"))
                or any(type(record_first[key]) is not int or record_first[key] < 1
                       for key in ("qualification_run_attempt", "publisher_run_attempt",
                                   "adoption_run_attempt"))):
            errors.append("comparison-first-release-invalid")
        if first_release is not None and record_first != first_release:
            errors.append("comparison-first-release-mismatch")

    for label in ("before", "after"):
        section = value.get(label)
        if not isinstance(section, dict) or not isinstance(section.get("reports"), list) \
                or not isinstance(section.get("observations"), list):
            errors.append(f"comparison-{label}-invalid")
            continue
        if section.get("status") not in ("insufficient", "comparable", "not_applicable"):
            errors.append(f"comparison-{label}-status-invalid")
        for entry in section["reports"]:
            if (not isinstance(entry, dict)
                    or not SHA256_RE.fullmatch(str(entry.get("report_sha256", "")))
                    or entry.get("validation_status") != "complete"
                    or entry.get("collection_status") != "complete"
                    or not SHA40_RE.fullmatch(str(entry.get("source_sha", "")))
                    or not isinstance(entry.get("attempts"), list)):
                errors.append(f"comparison-{label}-report-invalid")
        for row in section["observations"]:
            if (not isinstance(row, dict) or type(row.get("run_id")) is not int
                    or row["run_id"] <= 0 or type(row.get("run_attempt")) is not int
                    or row["run_attempt"] < 1 or row.get("status") != "completed"
                    or row.get("conclusion") != "success"
                    or not SHA40_RE.fullmatch(str(row.get("source_sha", "")))
                    or not SHA256_RE.fullmatch(str(row.get("workflow_sha256", "")))
                    or not SHA256_RE.fullmatch(str(row.get("graph_sha256", "")))
                    or not isinstance(row.get("runner_os"), list)
                    or not isinstance(row.get("required_jobs"), list)):
                errors.append(f"comparison-{label}-observation-invalid")

    analysis = value.get("analysis")
    if not isinstance(analysis, dict) or analysis.get("status") not in (
            "insufficient", "comparable", "incomparable"):
        errors.append("comparison-analysis-invalid")
    else:
        if analysis.get("status") == "comparable":
            pairs = analysis.get("pairs")
            if not isinstance(pairs, list) or not pairs or any(
                    not isinstance(pair, dict) or pair.get("status") != "comparable"
                    for pair in pairs):
                errors.append("comparison-pairs-invalid")
        if analysis.get("status") != "comparable" and (
                analysis.get("critical_path_delta_seconds") is not None
                or analysis.get("runner_seconds_delta_by_os") != {}):
            errors.append("comparison-unknown-metric-fabricated")

    phase8 = value.get("phase8_baseline")
    if (not isinstance(phase8, dict) or phase8.get("run_id") != 42118267359
            or phase8.get("run_attempt") != 1
            or phase8.get("critical_path_seconds") != 901.0
            or phase8.get("workflow_wall_seconds") is not None
            or phase8.get("job_queue") != "unknown"
            or phase8.get("public_standard_runner_billing") != "not_applicable"):
        errors.append("comparison-phase8-baseline-drift")

    candidate = value.get("candidate_assessment")
    if (not isinstance(candidate, dict) or candidate.get("decision") != "no-change"
            or candidate.get("workflow_changed") is not False
            or candidate.get("measured_saving_claimed") is not False
            or not isinstance(candidate.get("reason"), str) or not candidate["reason"]
            or not isinstance(candidate.get("measured_dependency_preparation"), list)):
        errors.append("comparison-candidate-assessment-invalid")
    for entry in value.get("rejected_reports", []):
        if (not isinstance(entry, dict)
                or not SHA256_RE.fullmatch(str(entry.get("report_sha256", "")))
                or entry.get("validation_status") != "incomplete"
                or not isinstance(entry.get("errors"), list)
                or not isinstance(entry.get("attempts"), list)):
            errors.append("comparison-rejected-report-invalid")
    if not isinstance(value.get("rejected_reports"), list):
        errors.append("comparison-rejected-reports-invalid")
    if (value.get("decision") != "no-change"
            or value.get("phase9_ci_after") != "not_applicable"
            or value.get("later_release") != "not_applicable"):
        errors.append("comparison-no-change-closure-invalid")
    return sorted(set(errors))


def _load_reports(paths: list[str], *, accepted: bool) -> tuple[list, list]:
    good, rejected = [], []
    for path in paths:
        entry, rows = _report_entry(path)
        if entry["validation_status"] == "complete":
            good.append((entry, rows))
        else:
            rejected.append(entry)
    return good, rejected


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build an offline comparison from collected reports")
    build.add_argument("--before", action="append", required=True, help="source-bound baseline report; repeat up to three times")
    build.add_argument("--after", action="append", default=[], help="source-bound after report; repeat up to three times")
    build.add_argument("--rejected-report", action="append", default=[], help="retain identity/digest for an incomplete collector report")
    build.add_argument("--output", required=True)
    build.add_argument("--require-first-release", required=True)
    validate = commands.add_parser("validate", help="validate an existing comparison offline")
    validate.add_argument("--input", required=True)
    validate.add_argument("--require-first-release", required=True)
    args = parser.parse_args(argv)

    try:
        first_release = _first_release(args.require_first_release)
        if args.command == "build":
            if len(args.before) > 3 or len(args.after) > 3 or len(args.rejected_report) > 3:
                raise ComparisonError("observation-limit-exceeded")
            before, rejected_before = _load_reports(args.before, accepted=True)
            after, rejected_after = _load_reports(args.after, accepted=True)
            rejected_extra = []
            for path in args.rejected_report:
                entry, _ = _report_entry(path)
                rejected_extra.append(entry)
            record = build_comparison(before_reports=before, after_reports=after,
                rejected_reports=rejected_before + rejected_after + rejected_extra,
                first_release=first_release)
            problems = validate_comparison(record, first_release=first_release)
            if problems:
                raise ComparisonError(problems[0])
            _write_json(args.output, record)
            print("PASS: CI comparison records source-bound observations and explicit no-change")
            return 0

        record, _ = _read_json(args.input)
        problems = validate_comparison(record, first_release=first_release)
        if problems:
            for problem in problems:
                print("REJECT: " + problem, file=sys.stderr)
            return 1
        print("PASS: CI comparison and first-release linkage are valid")
        return 0
    except ComparisonError as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
