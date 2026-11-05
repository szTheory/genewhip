#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic contract for the bounded, read-only CI baseline collector."""
import base64
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/evidence/ci_baseline.py"
SOURCE = "1" * 40
OTHER_SOURCE = "2" * 40
WORKFLOW = b"""name: Contract CI\njobs:\n  left:\n  right:\n  join:\n    needs: [left, right]\n"""
WORKFLOW_BLOB_SHA = hashlib.sha1(
    b"blob " + str(len(WORKFLOW)).encode("ascii") + b"\0" + WORKFLOW).hexdigest()


def load_module(test):
    if not SCRIPT.is_file():
        test.fail("ci-baseline-collector-missing")
    spec = importlib.util.spec_from_file_location("gw_ci_baseline", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(body, headers=None):
    class FakeResponse:
        status = 200

        def __init__(self):
            self.headers = headers or {}
            self.payload = json.dumps(body, separators=(",", ":")).encode()

        def read(self, limit=-1):
            return self.payload if limit < 0 else self.payload[:limit]

        def getcode(self):
            return self.status

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    return FakeResponse()


def job(job_id, name, start, end, *, conclusion="success", labels=("ubuntu-24.04",),
        steps=None, status="completed"):
    return {
        "id": job_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": start,
        "completed_at": end,
        "labels": list(labels),
        "runner_id": 9,
        "runner_name": "private-host-name",
        "runner_group_name": "private-runner-group",
        "steps": steps if steps is not None else [{
            "number": 1,
            "name": "Run tests",
            "status": "completed",
            "conclusion": conclusion,
            "started_at": start,
            "completed_at": end,
        }],
    }


def attempt(run_attempt, *, conclusion="success", source=SOURCE, status="completed", run_id=123):
    return {
        "id": run_id,
        "run_attempt": run_attempt,
        "event": "pull_request",
        "status": status,
        "conclusion": conclusion,
        "head_sha": source,
        "path": ".github/workflows/ci.yml@refs/pull/7/merge",
        "ref": "refs/pull/7/merge",
        "created_at": "2026-11-05T10:00:00Z",
        "run_started_at": "2026-11-05T10:01:00Z",
        "completed_at": "2026-11-05T10:06:00Z",
    }


def run_summary(run_id=123, attempt_count=2, *, event="pull_request", source=SOURCE):
    return {"id": run_id, "run_attempt": attempt_count, "event": event,
            "status": "completed", "conclusion": "success", "head_sha": source,
            "path": ".github/workflows/ci.yml@refs/pull/7/merge",
            "ref": "refs/pull/7/merge" if event == "pull_request" else "refs/heads/main"}


def jobs_for_attempt(number):
    conclusion = "failure" if number == 1 else "success"
    return {
        "total_count": 3,
        "jobs": [
            job(100 + number, "left", "2026-11-05T10:01:10Z", "2026-11-05T10:02:50Z",
                conclusion=conclusion),
            job(200 + number, "right", "2026-11-05T10:01:20Z", "2026-11-05T10:04:40Z"),
            job(300 + number, "join", "2026-11-05T10:04:50Z", "2026-11-05T10:05:40Z"),
        ],
    }


class FakeApi:
    def __init__(self, *, run_pages=None, attempts=None, jobs=None, repository=None,
                 workflow=WORKFLOW):
        self.run_pages = run_pages or {1: [run_summary()]}
        self.attempts = attempts or {1: attempt(1, conclusion="failure"),
                                     2: attempt(2, conclusion="success")}
        self.jobs = jobs or {1: jobs_for_attempt(1), 2: jobs_for_attempt(2)}
        self.repository = repository or {"private": False, "visibility": "public"}
        self.workflow = workflow
        self.workflow_blob_sha = hashlib.sha1(
            b"blob " + str(len(workflow)).encode("ascii") + b"\0" + workflow).hexdigest()
        self.requests = []

    def __call__(self, request, timeout=30):
        url = request.full_url
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        authorization = next((value for name, value in request.header_items()
                              if name.lower() == "authorization"), None)
        self.requests.append({"url": url, "timeout": timeout,
                              "authorization": authorization,
                              "method": request.get_method()})
        path = parsed.path
        if path == "/repos/example/project":
            body = self.repository
        elif path == "/repos/example/project/actions/workflows/ci.yml/runs":
            page = int(query.get("page", ["1"])[0])
            body = {"total_count": sum(len(items) for items in self.run_pages.values()),
                    "workflow_runs": self.run_pages.get(page, [])}
        elif "/actions/runs/" in path and "/attempts/" in path:
            run_id = int(path.split("/actions/runs/", 1)[1].split("/", 1)[0])
            attempt_part = path.split("/attempts/", 1)[1].split("/", 1)[0]
            number = int(attempt_part) if attempt_part.isdigit() else int(query.get("attempt_number", ["1"])[0])
            if path.endswith("/jobs"):
                page = int(query.get("page", ["1"])[0])
                body = self.jobs.get((run_id, number), self.jobs.get(number,
                    {"total_count": 0, "jobs": []})) if page == 1 else {"total_count": 0, "jobs": []}
            else:
                summary = next((item for page_items in self.run_pages.values()
                                for item in page_items if item.get("id") == run_id), {})
                body = dict(self.attempts.get((run_id, number), self.attempts[number]), id=run_id,
                            event=summary.get("event", "pull_request"),
                            path=summary.get("path", ".github/workflows/ci.yml@refs/pull/7/merge"),
                            ref=summary.get("ref", "refs/pull/7/merge"))
        elif path == "/repos/example/project/contents/.github/workflows/ci.yml":
            body = {"sha": self.workflow_blob_sha, "size": len(self.workflow),
                    "encoding": "base64",
                    "content": base64.b64encode(self.workflow).decode("ascii")}
        else:
            raise AssertionError(f"unexpected API request: {url}")
        return response(body)


class BaselineCollectorContract(unittest.TestCase):
    def collect(self, module, directory, api, *, source=SOURCE, extra=(), env=None):
        output = Path(directory) / "baseline.json"
        argv = ["collect", "--repo", "example/project", "--workflow",
                ".github/workflows/ci.yml", "--source-sha", source,
                "--max-runs", "3", "--max-attempts", "3", "--output", str(output), *extra]
        code = module.main(argv, environ=env or {}, opener=api)
        return code, output

    def test_collect_binds_each_terminal_attempt_to_exact_source_jobs_and_workflow_bytes(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory() as directory:
            api = FakeApi()
            code, output = self.collect(module, directory, api,
                env={"GH_TOKEN": "secret-test-token"})
            report = json.loads(output.read_text())
            report_size = output.stat().st_size

        self.assertEqual(code, 0, "completed-attempt-collection-succeeds")
        self.assertEqual(report["schema_version"], "genewhip-ci-baseline.v1")
        self.assertEqual(report["repository"], "example/project")
        self.assertEqual(report["visibility"], "public")
        self.assertEqual(report["source_sha"], SOURCE)
        self.assertEqual(report["workflow_path"], ".github/workflows/ci.yml")
        self.assertEqual(report["workflow_blob_sha"], WORKFLOW_BLOB_SHA)
        self.assertEqual(report["workflow_sha256"], hashlib.sha256(WORKFLOW).hexdigest())
        self.assertEqual([row["run_attempt"] for row in report["runs"]], [1, 2])
        self.assertEqual([row["conclusion"] for row in report["runs"]], ["failure", "success"])
        self.assertTrue(all(row["workflow_source_sha"] == SOURCE for row in report["runs"]))
        latest = report["runs"][-1]
        self.assertEqual(latest["critical_path"]["path"], ["right", "join"])
        self.assertEqual(latest["critical_path"]["observed_weighted_seconds"], 250)
        self.assertEqual(latest["critical_path"]["wall_span_seconds"], 260)
        self.assertEqual(latest["critical_path"]["unavailable_gaps_seconds"], 10)
        self.assertEqual(latest["queue_seconds"], 60)
        self.assertEqual(latest["wall_seconds"], 300)
        self.assertEqual(latest["runner_seconds_by_os"], {"linux": 350})
        self.assertEqual(latest["billing"], {
            "status": "not_applicable", "reason": "public-standard-github-hosted"})
        self.assertTrue(all(row["job_queue"]["status"] == "unknown" for row in latest["jobs"]))
        serialized = json.dumps(report)
        for private in ("private-host-name", "private-runner-group", "secret-test-token"):
            self.assertNotIn(private, serialized, f"private-api-field-not-retained:{private}")
        self.assertTrue(any("/attempts/1/jobs" in item["url"] for item in api.requests),
                        "attempt-one-specific-jobs-endpoint-used")
        self.assertTrue(all(item["timeout"] <= 30 for item in api.requests),
                        "per-request-timeout-bounded")
        self.assertTrue(all(item["method"] == "GET" for item in api.requests),
                        "collection-api-is-read-only")
        run_request = next(item for item in api.requests if item["url"].endswith("/runs?per_page=100&page=1&head_sha=" + SOURCE))
        self.assertEqual(parse_qs(urlsplit(run_request["url"]).query)["head_sha"], [SOURCE])
        self.assertTrue(all(item["authorization"] == "Bearer secret-test-token"
                            for item in api.requests), "explicit-token-used-without-reporting")
        self.assertLess(report_size, 1024 * 1024, "report-size-under-one-MiB")

    def test_run_pagination_stops_at_requested_limit_and_events_remain_separate(self):
        module = load_module(self)
        page_one = [
            run_summary(123, 1),
            {**run_summary(124, 1, event="merge_group"),
             "path": ".github/workflows/ci.yml@refs/heads/main"},
        ]
        page_two = [{**run_summary(125, 1, event="push"),
             "path": ".github/workflows/ci.yml@refs/heads/main"}]
        api = FakeApi(run_pages={1: page_one, 2: page_two},
            attempts={1: attempt(1)}, jobs={1: jobs_for_attempt(2)})
        api.attempts = {1: attempt(1)}
        api.jobs = {1: jobs_for_attempt(2)}
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())

        self.assertEqual(code, 0)
        self.assertEqual(len({row["run_id"] for row in report["runs"]}), 3)
        self.assertEqual(report["cohorts"]["pull_request"]["attempts"], 1)
        self.assertEqual(report["cohorts"]["merge_group"]["attempts"], 1)
        self.assertEqual(report["cohorts"]["push"]["attempts"], 1)
        run_pages = [parse_qs(urlsplit(item["url"]).query).get("page", ["1"])[0]
                     for item in api.requests if urlsplit(item["url"]).path.endswith("/runs")]
        self.assertEqual(run_pages, ["1", "2"], "run-pages-read-only-and-bounded")

    def test_schedule_and_dispatch_remain_separate_from_normal_event_cohorts(self):
        module = load_module(self)
        events = ("pull_request", "merge_group", "push", "schedule", "workflow_dispatch")
        runs = []
        for index, event in enumerate(events):
            item = run_summary(500 + index, 1, event=event)
            if event != "pull_request":
                item["path"] = ".github/workflows/ci.yml@refs/heads/main"
            runs.append(item)
        api = FakeApi(run_pages={1: runs}, attempts={1: attempt(1)},
                      jobs={1: jobs_for_attempt(1)})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api,
                                        extra=("--max-runs", "5"))
            report = json.loads(output.read_text())
        self.assertEqual(code, 0)
        for event in events:
            self.assertEqual(report["cohorts"][event]["attempts"], 1, event)
        self.assertEqual(report["cohorts"]["other"]["attempts"], 0)

    def test_terminal_metrics_keep_failed_and_cancelled_runner_time_and_skip_missing_intervals(self):
        module = load_module(self)
        rows = jobs_for_attempt(1)["jobs"]
        rows[0]["conclusion"] = "failure"
        rows[1]["conclusion"] = "cancelled"
        rows[1]["labels"] = ["macos-26", "arm64"]
        rows[2].update(conclusion="skipped", started_at=None, completed_at=None,
                       labels=[])
        api = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                      attempts={1: attempt(1, conclusion="failure")},
                      jobs={1: {"total_count": 3, "jobs": rows}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())
        self.assertEqual(code, 0)
        run = report["runs"][0]
        self.assertEqual(run["runner_seconds_by_os"], {"linux": 100, "macos": 200})
        self.assertEqual(run["critical_path"]["path"], ["right", "join"])
        self.assertEqual(run["billing"]["status"], "not_applicable")

    def test_unknown_terminal_time_is_not_replaced_by_updated_at(self):
        module = load_module(self)
        completed = attempt(1)
        completed.pop("completed_at")
        completed["updated_at"] = "2026-11-05T10:20:00Z"
        api = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                      attempts={1: completed}, jobs={1: jobs_for_attempt(1)})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())
        self.assertEqual(code, 0)
        self.assertIsNone(report["runs"][0]["completed_at"])
        self.assertIsNone(report["runs"][0]["wall_seconds"])
        self.assertIn("workflow-terminal-time-unavailable", report["unknowns"])

    def test_private_or_self_hosted_runner_billing_remains_unknown(self):
        module = load_module(self)
        rows = jobs_for_attempt(1)["jobs"]
        for item in rows:
            item["labels"] = ["self-hosted", "linux"]
        api = FakeApi(repository={"private": True, "visibility": "private"},
                      run_pages={1: [run_summary(attempt_count=1)]},
                      attempts={1: attempt(1)}, jobs={1: {"total_count": 3, "jobs": rows}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(report["visibility"], "private")
        self.assertEqual(report["runs"][0]["billing"]["status"], "unknown")

    def test_exact_source_filter_never_substitutes_another_revision(self):
        module = load_module(self)
        api = FakeApi(run_pages={1: [run_summary(source=OTHER_SOURCE)]},
                      attempts={1: attempt(1, source=OTHER_SOURCE)},
                      jobs={1: jobs_for_attempt(1)})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api, source=SOURCE)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertEqual(report["runs"], [])
        self.assertIn("run-source-mismatch:123", report["errors"])
        self.assertFalse(any("/contents/" in item["url"] for item in api.requests),
                         "other-revision-workflow-not-fetched")

    def test_source_attempt_and_completion_mismatches_make_collection_incomplete(self):
        module = load_module(self)
        bad_cases = (
            ("wrong-source", FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                attempts={1: attempt(1, source=OTHER_SOURCE)}, jobs={1: jobs_for_attempt(1)})),
            ("wrong-attempt", FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                attempts={1: attempt(2)}, jobs={1: jobs_for_attempt(1)})),
            ("running-attempt", FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                attempts={1: attempt(1, status="in_progress")}, jobs={1: jobs_for_attempt(1)})),
        )
        for label, api in bad_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                code, output = self.collect(module, directory, api)
                report = json.loads(output.read_text())
                self.assertNotEqual(code, 0, f"{label}-cannot-earn-complete-baseline")
                self.assertEqual(module.validate_report(report)["status"], "incomplete")

    def test_job_truncation_missing_timestamps_and_cycles_are_not_complete(self):
        module = load_module(self)
        oversized_jobs = {1: {"total_count": 101, "jobs": jobs_for_attempt(2)["jobs"]}}
        api = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
                      attempts={1: attempt(1)}, jobs=oversized_jobs)
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertIn("jobs-truncated", " ".join(report["unknowns"]))

        graph = module.parse_workflow_graph("jobs:\n  a:\n    needs: b\n  b:\n    needs: a\n")
        self.assertIn("dependency-cycle", graph["errors"])

        matrix = module.parse_workflow_graph(
            "jobs:\n  build:\n    strategy:\n      matrix:\n        os: [ubuntu, macos]\n")
        self.assertIn("matrix-graph-unresolved", matrix["errors"])

        missing_time_rows = jobs_for_attempt(1)["jobs"]
        missing_time_rows[0].update(started_at=None, completed_at=None)
        missing_time = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
            attempts={1: attempt(1)}, jobs={1: {"total_count": 3, "jobs": missing_time_rows}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, missing_time)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertTrue(any("job-timestamp-unavailable" in value for value in report["errors"]))

        missing_job = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
            attempts={1: attempt(1)}, jobs={1: {"total_count": 2,
                "jobs": jobs_for_attempt(1)["jobs"][:2]}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, missing_job)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertTrue(any("jobs-missing" in value for value in report["errors"]))

        incomplete_pagination = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
            attempts={1: attempt(1)}, jobs={1: {"total_count": 4,
                "jobs": jobs_for_attempt(1)["jobs"]}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, incomplete_pagination)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertTrue(any("jobs-pagination-incomplete" in value
                            for value in report["errors"]))

        too_many_steps = jobs_for_attempt(1)["jobs"]
        too_many_steps[0]["steps"] = [job_step for job_step in too_many_steps[0]["steps"]] * 101
        step_overflow = FakeApi(run_pages={1: [run_summary(attempt_count=1)]},
            attempts={1: attempt(1)}, jobs={1: {"total_count": 3, "jobs": too_many_steps}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, step_overflow)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertTrue(any("steps-truncated" in value for value in report["errors"]))

    def test_attempt_limit_reports_truncation_and_preserves_the_collected_attempts(self):
        module = load_module(self)
        api = FakeApi(run_pages={1: [run_summary(attempt_count=4)]},
            attempts={1: attempt(1, conclusion="failure"),
                      2: attempt(2), 3: attempt(3)},
            jobs={1: jobs_for_attempt(1), 2: jobs_for_attempt(2),
                  3: jobs_for_attempt(2)})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())
        self.assertNotEqual(code, 0)
        self.assertEqual([run["run_attempt"] for run in report["runs"]], [1, 2, 3])
        self.assertTrue(any(value.startswith("attempts-truncated") for value in report["unknowns"]))

    def test_report_and_api_response_limits_fail_closed_without_raw_payloads(self):
        module = load_module(self)

        class TooLargeResponse:
            def getcode(self): return 200
            def read(self, limit=-1): return b"x" * limit
            def __enter__(self): return self
            def __exit__(self, *_args): return False

        with self.assertRaises(module.CollectionError) as caught:
            module.GitHubApi(None, lambda *_args, **_kwargs: TooLargeResponse()).get_json(
                "/repos/example/project")
        self.assertEqual(caught.exception.code, "api-response-too-large")

        with self.assertRaises(module.CollectionError) as caught:
            module.GitHubApi(None, lambda *_args, **_kwargs: response({"value": float("nan")})).get_json(
                "/repos/example/project")
        self.assertEqual(caught.exception.code, "api-json-invalid")

        oversized = {"schema_version": "genewhip-ci-baseline.v1",
                     "unbounded": "x" * module.MAX_REPORT_BYTES}
        self.assertIn("report-too-large", module.validate_report(oversized)["errors"])
        malformed = {"runs": [{"event": [], "graph_sha256": []}],
                     "graph": {"versions": [{"graph_sha256": []}]}}
        self.assertEqual(module.validate_report(malformed), {
            "status": "incomplete", "errors": ["report-schema-invalid"]})

    def test_validate_cli_is_offline_and_source_bound(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory() as directory:
            _, output = self.collect(module, directory, FakeApi())
            with mock.patch.object(module, "_open_api", side_effect=AssertionError("network-not-allowed")):
                code = module.main(["validate", "--input", str(output),
                                    "--require-source", SOURCE])
        self.assertEqual(code, 0)

    def test_workflow_needs_parser_accepts_limited_forms_and_rejects_unsupported_syntax(self):
        module = load_module(self)
        parsed = module.parse_workflow_graph(
            "jobs:\n  base:\n  scalar:\n    needs: base\n"
            "  list:\n    needs:\n      - base\n      - scalar\n")
        self.assertEqual(parsed["status"], "complete")
        self.assertEqual(parsed["jobs"]["scalar"]["needs"], ["base"])
        self.assertEqual(parsed["jobs"]["list"]["needs"], ["base", "scalar"])
        unsupported = module.parse_workflow_graph("jobs:\n  test:\n    needs: ${{ fromJSON('[]') }}\n")
        self.assertIn("unsupported-needs-syntax", unsupported["errors"])

    def test_actual_workflow_dependency_graph_parses_with_expected_required_check(self):
        module = load_module(self)
        parsed = module.parse_workflow_graph((ROOT / ".github/workflows/ci.yml").read_text())
        self.assertEqual(parsed["status"], "complete", parsed["errors"])
        self.assertIn("libretro", parsed["jobs"])
        self.assertEqual(parsed["jobs"]["required-aggregate"]["needs"], [
            "safety", "gameplay", "desktop", "package", "performance",
            "product-smoke", "phase7-fast", "v02-release-qualification", "attestation",
            "libretro",
        ])

    def test_validator_rejects_unknown_queue_fabricated_cost_unsafe_fields_and_bad_cohorts(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory() as directory:
            api = FakeApi()
            _, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())

        good = module.validate_report(report)
        self.assertEqual(good["status"], "complete")
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["jobs"][0]["job_queue"] = {
            "status": "measured", "seconds": 12, "reason": None}
        self.assertIn("job-queue-not-authoritative", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["billing"] = {"status": "actual", "reason": "estimate"}
        self.assertIn("billing-unsupported", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["private_path"] = "private-rom-path-placeholder"
        self.assertIn("private-data-field", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["environment_dump"] = "not-retained"
        self.assertIn("run-field-unrecognized", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["event"] = "schedule"
        self.assertIn("cohort-event-mismatch", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["runs"][-1]["workflow_blob_sha"] = "a" * 40
        self.assertIn("run-workflow-blob-unbound", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["workflow_sha256"] = "a" * 64
        self.assertIn("workflow-content-summary-mismatch",
                      module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["source_sha"] = OTHER_SOURCE
        self.assertIn("report-source-mismatch", module.validate_report(mutated)["errors"])
        mutated = json.loads(json.dumps(report))
        mutated["limits"]["max_response_bytes"] = 0
        self.assertIn("limits-mismatch", module.validate_report(mutated)["errors"])

    def test_require_libretro_requires_successful_linux_module_and_sanitizer_execution(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory() as directory:
            api = FakeApi()
            _, output = self.collect(module, directory, api)
            report = json.loads(output.read_text())

        self.assertIn("libretro-qualification-missing",
                      module.validate_report(report, require_source=SOURCE,
                                             require_libretro=True)["errors"])
        qualifying_workflow = WORKFLOW.replace(
            b"  join:\n    needs: [left, right]\n",
            b"  join:\n    needs: [left, right]\n  libretro:\n"
            b"  required-aggregate:\n    needs: [libretro]\n")
        qualifying_jobs = jobs_for_attempt(2)["jobs"] + [job(
            400, "libretro", "2026-11-05T10:01:00Z", "2026-11-05T10:03:00Z",
            labels=("ubuntu-24.04",), steps=[
                {"number": 0, "name": "Confirm Linux x86_64 runner", "status": "completed",
                 "conclusion": "success", "started_at": "2026-11-05T10:01:00Z",
                 "completed_at": "2026-11-05T10:01:10Z"},
                {"number": 1, "name": "Load actual module", "status": "completed",
                 "conclusion": "success", "started_at": "2026-11-05T10:01:00Z",
                 "completed_at": "2026-11-05T10:01:30Z"},
                {"number": 2, "name": "Run Address Sanitizer", "status": "completed",
                 "conclusion": "success", "started_at": "2026-11-05T10:01:30Z",
                 "completed_at": "2026-11-05T10:02:00Z"},
                {"number": 3, "name": "Run Undefined Sanitizer", "status": "completed",
                 "conclusion": "success", "started_at": "2026-11-05T10:02:00Z",
                 "completed_at": "2026-11-05T10:02:30Z"},
            ]),
            job(500, "required-aggregate", "2026-11-05T10:05:40Z", "2026-11-05T10:05:50Z")]
        qualifying_api = FakeApi(workflow=qualifying_workflow,
            run_pages={1: [run_summary(attempt_count=1)]},
            attempts={1: attempt(1)},
            jobs={1: {"total_count": 5, "jobs": qualifying_jobs}})
        with tempfile.TemporaryDirectory() as directory:
            code, output = self.collect(module, directory, qualifying_api)
            qualifying = json.loads(output.read_text())
            require_code = module.main(["validate", "--input", str(output),
                "--require-source", SOURCE, "--require-libretro"])
        self.assertEqual(code, 0)
        self.assertEqual(require_code, 0)
        self.assertEqual(module.validate_report(qualifying, require_source=SOURCE,
                                                require_libretro=True)["errors"], [])
        later_failure = json.loads(json.dumps(qualifying))
        failed_attempt = json.loads(json.dumps(later_failure["runs"][-1]))
        failed_attempt["run_attempt"] = 2
        failed_attempt["conclusion"] = "failure"
        later_failure["runs"].append(failed_attempt)
        self.assertIn("libretro-qualification-missing", module.validate_report(
            later_failure, require_source=SOURCE, require_libretro=True)["errors"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
