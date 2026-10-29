#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise benchmark report rejection paths and a bounded public-path run."""
import copy
import importlib.util
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gw_core_benchmark", ROOT / "tools/evidence/core_benchmark.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def valid_report():
    modes = []
    process_id = 1000
    output = {"video": [(i + 120, (i + 120) * 100, 256, 224, "a" * 64) for i in range(600)],
              "pcm_frames": 480619, "pcm_sha256": "b" * 64,
              "ram_sha256": "c" * 64, "machine_sha256": "d" * 64}
    for diagnostics, observer in ((False, "sampled"), (False, "aggregate"),
                                  (True, "sampled"), (True, "aggregate")):
        runs = []
        for _ in range(5):
            process_id += 1
            runs.append({"process_id": process_id, "process_instance": f"pid-{process_id}",
                "elapsed_ns": 6000000, "fields": 600, "ticks": 537624000,
                "actual_tick_start": 0, "actual_tick_end": 537624000, "stop_reason": 5,
                "fields_per_second": 100000, "core_owned_current_bytes": 1000000,
                "core_owned_peak_bytes": 1100000, "process_ru_maxrss_bytes": 200000000,
                "diagnostic_records": 256 if diagnostics else 0, "diagnostic_dropped": 100 if diagnostics else 0,
                "output_identity": copy.deepcopy(output),
                "field_ns": [10000] * 600 if observer == "sampled" else [],
                "field_latency_ns": ({"samples": 600, "median": 10000, "p95": 10000,
                                      "observed_maximum": 10000} if observer == "sampled" else None)})
        latency = {"samples": 3000, "median": 10000, "p95": 10000,
                   "p99": 10000, "observed_maximum": 10000} if observer == "sampled" else None
        modes.append({"diagnostics_enabled": diagnostics, "observer": observer, "runs": runs,
                      "aggregate_elapsed_ns_median": 6000000, "latency_ns": latency})
    return {"schema": benchmark.REPORT_SCHEMA, "version": 1, "outcome": "pass", "qualification": True,
        "profile": "sustained-qualified-workload", "source_revision": benchmark.git("rev-parse", "HEAD"),
        "source_state": "clean implementation and fixture sources; planning-only local edits excluded",
        "source_identity_sha256": benchmark.source_identity(),
        "build_identity": {"cmake": {"CMAKE_BUILD_TYPE": "Release"},
                           "build_configuration_sha256": "build-identity"},
        "benchmark_binary_sha256": "e" * 64,
        "workload": benchmark.workload_identity(),
        "qualification_evidence": {"fixture_id": benchmark.workload_identity()["fixture_id"],
            "source_sha256": benchmark.workload_identity()["source_sha256"],
            "rom_sha256": benchmark.workload_identity()["rom_sha256"],
            "scenario_sha256": benchmark.workload_identity()["scenario_sha256"],
            "oracle_sha256": benchmark.workload_identity()["oracle_sha256"],
            "build_configuration_sha256": "build-identity", "clients": ["headless", "desktop"],
            "client_sha256": ["f" * 64, "a" * 64], "denominator": 6, "fields": 840,
            "sustained_fields": 720, "sustained_outcome": "pass"},
        "protocol": {**benchmark.PROTOCOL, "processes_per_mode": 5, "fresh_process_per_run": True,
                     "reset_policy": "one fresh process and machine for each measured run; guest starts at power-on reset",
                     "drain_api": "gw_get_video_field plus one gw_audio_read with capacity 4096 frames per field",
                     "timed_window": "600 public gw_run_until field stops, video pixel copies, and bounded PCM drains; no formatting, hashes, or filesystem I/O",
                     "p99_minimum_comparable_field_samples": 1000},
        "resource_exposure": {"max_fresh_processes": 20, "max_parallel_processes": 1,
                              "wall_timeout_seconds_per_process": 240,
                              "preallocated_video_capture_bytes": 600 * 320 * 224 * 4,
                              "preallocated_pcm_capture_bytes": 600 * 4096 * 2 * 2,
                              "os_address_space_limit_enforced": False},
        "memory_units": {"core_owned": "bytes", "process_ru_maxrss": "bytes"},
        "rss_scope": "fresh-process macOS whole-process high-water; includes harness",
        "modes": modes,
        "sampled_vs_aggregate_pairs": [{"run": i} for i in range(10)],
        "diagnostics_pairs": [{"run": i, "output_equivalent": True} for i in range(10)],
        "runs": [], "counts": {"fresh_processes": 20, "measured_fields_per_process": 600,
                                 "comparable_field_timing_samples": 6000, "outputs_equivalent": True}}


def valid_v02_report():
    workloads = {}
    pid = 100
    for title, fields, warmup in (("control", 600, 120), ("recursion94", 3631, 0),
                                  ("tank-battle", 4196, 0)):
        identity = {"video_sha256": "a" * 64, "pcm_sha256": "b" * 64,
                    "ram_sha256": "c" * 64, "machine_sha256": "d" * 64,
                    "cpu_sha256": "e" * 64, "controller_sha256": "f" * 64}
        reference = {"untimed": True, "elapsed_ns": 0, "fields_completed": fields,
                     "warmup_fields": warmup, "ticks_completed": 100,
                     "output_identity": identity, "process_id": pid, "process_instance": f"p{pid}",
                     "process_ru_maxrss_bytes": 1000000000,
                     "rss_unit_source": "Darwin getrusage(2) ru_maxrss bytes",
                     "resource_receipt": {"process_group_cleanup": "confirmed", "bound_violation": False}}
        pid += 1
        rows = []
        for diagnostics, observer in ((False, "sampled"), (False, "aggregate"),
                                      (True, "sampled"), (True, "aggregate")):
            for repetition in range(1, 6):
                rows.append({"workload": title, "diagnostics_enabled": diagnostics,
                    "observer": observer, "repetition": repetition, "fields_completed": fields,
                    "warmup_fields": warmup, "elapsed_ns": 50000, "ticks_completed": 100,
                    "last_stop_reason": 5 if title == "control" else None,
                    "route_status": 0 if title != "control" else None,
                    "terminal_tick": 100 if title != "control" else None,
                    "untimed": False, "output_identity": identity,
                    "untimed_output_identity": identity,
                    "field_ns": [100] * fields if observer == "sampled" else [],
                    "process_ru_maxrss_bytes": 1000000000, "process_id": pid,
                    "rss_unit_source": "Darwin getrusage(2) ru_maxrss bytes",
                    "process_instance": f"p{pid}",
                    "resource_receipt": {"process_group_cleanup": "confirmed", "bound_violation": False}})
                pid += 1
        input_identity = {"fixture_id": title, "rom_sha256": "1" * 64,
            "scenario_sha256": "2" * 64, "oracle_sha256": "3" * 64}
        workloads[title] = {"input_identity": input_identity, "completed_fields": fields,
            "warmup_fields": warmup, "timed_runs": rows, "untimed_reference": reference}
    return {"schema": benchmark.V02_REPORT_SCHEMA, "version": 2, "outcome": "pass",
        "qualification": True, "serial_children": True, "source_identity_sha256": "0" * 64,
        "workloads": workloads, "counts": {"timed_children": 60, "untimed_references": 3,
            "process_starts": 63, "timed_samples_per_workload": 20}}


class BenchmarkContract(unittest.TestCase):
    def test_shared_runtime_partition_clamps_queue_and_retry_elapsed_time(self):
        scope = {"qualification_batch": {"runtime_wall_seconds": 64800}}
        start = "2026-10-29T00:00:00Z"
        self.assertEqual(benchmark.qualification_runtime_remaining(scope, start,
            "2026-10-29T02:00:00Z"), 57600)
        with self.assertRaisesRegex(ValueError, "runtime-partition-deadline"):
            benchmark.qualification_runtime_remaining(scope, start, "2026-10-29T18:00:01Z")
        with self.assertRaisesRegex(ValueError, "clock-invalid"):
            benchmark.qualification_runtime_remaining(scope, start, "2026-10-28T23:59:59Z")

    def test_production_control_launch_clamps_timeout_and_limit_at_shared_cutoff(self):
        import json
        import subprocess
        import time

        original = (benchmark._ACTIVE_QUALIFICATION_START,
            benchmark._ACTIVE_RUNTIME_LIMIT_SECONDS, benchmark._ACTIVE_BATCH_START,
            benchmark._ACTIVE_BATCH_LIMIT_SECONDS, benchmark._ACTIVE_JOURNAL)
        captured = []

        class RouteBoundary:
            @staticmethod
            def _run_client(_binary, _command, receipts, **kwargs):
                captured.append((kwargs["timeout"], kwargs["limits"]["wall_seconds"]))
                receipts.append({"pid": 100, "process_group_cleanup": "confirmed",
                                 "bound_violation": False})
                return subprocess.CompletedProcess([], 0, "{}", "")

        with tempfile.TemporaryDirectory(prefix="gw-bench-clock-") as directory:
            root = Path(directory)
            benchmark._ACTIVE_RUNTIME_LIMIT_SECONDS = 64800
            benchmark._ACTIVE_QUALIFICATION_START = time.time() - (64800 - 0.35)
            benchmark._ACTIVE_BATCH_LIMIT_SECONDS = 43200
            benchmark._ACTIVE_BATCH_START = time.monotonic() - (43200 - 0.35)
            limits = {"wall_seconds": 600, "cleanup_grace_seconds": 30,
                "max_rss_bytes": 4 * 1024**3, "max_stdout_stderr_bytes": 16 * 1024**2,
                "max_json_bytes": 32 * 1024**2, "max_binary_file_bytes": 2 * 1024**3,
                "max_capture_bytes": 2 * 1024**3, "max_scratch_bytes": 16 * 1024**3,
                "max_retained_bytes": 4 * 1024**3, "max_fields": 7200,
                "max_calls": 100_000_000}
            try:
                with mock.patch.object(benchmark, "load_v02_launcher", return_value=SimpleNamespace(
                        available_memory_bytes=lambda: 16 * 1024**3,
                        require_memory_reserve=lambda *_: None)), \
                     mock.patch.object(benchmark, "load_route_contract", return_value=RouteBoundary), \
                     mock.patch.object(benchmark, "validate_control_reference", return_value=True), \
                     mock.patch.object(benchmark, "output_identity", return_value={"video": [1]}):
                    benchmark.run_control_reference(root, {}, limits)
                self.assertEqual(len(captured), 1)
                self.assertGreater(captured[0][0], 0)
                self.assertLess(captured[0][0], 0.35)
                self.assertEqual(captured[0][0], captured[0][1])
            finally:
                (benchmark._ACTIVE_QUALIFICATION_START,
                 benchmark._ACTIVE_RUNTIME_LIMIT_SECONDS, benchmark._ACTIVE_BATCH_START,
                 benchmark._ACTIVE_BATCH_LIMIT_SECONDS, benchmark._ACTIVE_JOURNAL) = original

    def test_legacy_control_runs_receive_explicit_repetition_indices(self):
        modes = [{"diagnostics_enabled": diagnostics, "observer": observer,
                  "runs": [{"elapsed_ns": i} for i in range(5)]}
                 for diagnostics, observer in ((False, "sampled"), (False, "aggregate"),
                                               (True, "sampled"), (True, "aggregate"))]
        rows = benchmark.normalize_control_rows({"modes": modes})
        self.assertEqual(len(rows), 20)
        self.assertEqual({(r["diagnostics_enabled"], r["observer"], r["repetition"])
                          for r in rows},
                         {(d, o, n) for d, o in ((False, "sampled"), (False, "aggregate"),
                                                 (True, "sampled"), (True, "aggregate"))
                          for n in range(1, 6)})

    def test_v02_measurement_roster_covers_three_workloads_four_modes_and_references(self):
        self.assertTrue(hasattr(benchmark, "measurement_roster"),
                        "production benchmark is missing its exact v02 measurement roster")
        roster = benchmark.measurement_roster()
        self.assertEqual(len(roster["timed"]), 60)
        self.assertEqual(len(roster["untimed"]), 3)
        self.assertEqual({row["workload"] for row in roster["timed"]},
                         {"control", "recursion94", "tank-battle"})
        self.assertTrue(all(row["repetition"] in range(1, 6) for row in roster["timed"]))
        self.assertEqual({(row["diagnostics_enabled"], row["observer"]) for row in roster["timed"]},
                         {(False, "sampled"), (False, "aggregate"),
                          (True, "sampled"), (True, "aggregate")})

    def test_v02_descriptive_stats_preserve_exposure_and_do_not_claim_run_p99(self):
        self.assertTrue(hasattr(benchmark, "summarize_performance_samples"),
                        "production benchmark is missing descriptive sample summaries")
        summarize = benchmark.summarize_performance_samples
        result = summarize([10, 20, 30, 40, 50], sample_kind="whole_run", host_id="host-a",
                           workload_id="tank-battle")
        self.assertEqual(result, {"samples": 5, "median": 30, "p95": 50,
                                  "observed_maximum": 50, "p99": None,
                                  "p99_reason": "requires 1000 comparable field samples",
                                  "sample_kind": "whole_run", "host_id": "host-a",
                                  "workload_id": "tank-battle"})
        with self.assertRaisesRegex(ValueError, "one host and workload"):
            summarize([10, 20], sample_kind="field", host_id=["host-a", "host-b"],
                      workload_id="tank-battle")

    def test_v02_report_requires_exact_63_processes_and_complete_mode_roster(self):
        self.assertEqual(benchmark.validate_v02_report(valid_v02_report()), [])
        report = valid_v02_report()
        report["workloads"]["tank-battle"]["timed_runs"].pop()
        self.assertIn("sample-count", benchmark.validate_v02_report(report))

    def test_v02_report_rejects_identity_forgery_after_outer_digest_recomputation(self):
        report = valid_v02_report()
        report["workloads"]["recursion94"]["timed_runs"][0]["output_identity"] = copy.deepcopy(
            report["workloads"]["recursion94"]["timed_runs"][0]["output_identity"])
        report["workloads"]["recursion94"]["timed_runs"][0]["output_identity"]["pcm_sha256"] = "9" * 64
        self.assertIn("output-divergence", benchmark.validate_v02_report(report))

    def test_public_summary_keeps_diagnostics_distributions_separate(self):
        summary = benchmark.render_performance_summary(valid_v02_report())
        control = next(row for row in summary["workloads"] if row["workload"] == "control")
        self.assertNotIn("field_latency_ns", control)
        self.assertEqual(control["field_latency_by_diagnostics"]["False"]["samples"], 3000)
        self.assertEqual(control["field_latency_by_diagnostics"]["True"]["samples"], 3000)
        self.assertIsNone(control["whole_run_exposure"]["p99"])

    def test_control_reference_requires_exact_untimed_window_and_rss_provenance(self):
        row = {"untimed": True, "elapsed_ns": 0, "fields_completed": 600,
            "warmup_fields": 120, "rss_unit_source": "Darwin getrusage(2) ru_maxrss bytes",
            "process_ru_maxrss_bytes": 1000, "video_fields": [{"sequence": 1}],
            "machine_sha256": "a" * 64, "pcm_sha256": "b" * 64,
            "resource_receipt": {"process_group_cleanup": "confirmed", "bound_violation": False}}
        self.assertTrue(benchmark.validate_control_reference(row, {"max_rss_bytes": 4000}))
        bad = dict(row, rss_unit_source=None)
        with self.assertRaisesRegex(ValueError, "control-reference-rss-provenance"):
            benchmark.validate_control_reference(bad, {"max_rss_bytes": 4000})

    def test_attempt_journal_retains_prior_rows_and_failed_child_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = benchmark.MeasurementJournal(Path(directory) / "attempt.json", 2)
            first = journal.launch("recursion94", "sampled", False, 1, ["binary"],
                                   fields=3631, warmup=0)
            receipt = {"pid": 123, "process_group_cleanup": "confirmed", "bound_violation": False}
            journal.finish(first, exit_code=0, receipt=receipt,
                            row={"process_id": 123, "elapsed_ns": 10, "fields_completed": 3631},
                            stdout="first child result")
            journal.finish(first, exit_code=0, receipt=receipt,
                            row={"process_id": 123, "elapsed_ns": 10, "fields_completed": 3631})
            journal.set_partial_report({"accepted_rows": 1})
            second = journal.launch("tank-battle", "aggregate", True, 1, ["binary"],
                                    fields=4196, warmup=0)
            failed_receipt = {"pid": 124, "process_group_cleanup": "confirmed", "bound_violation": True}
            journal.finish(second, exit_code=124, receipt=failed_receipt)
            journal.fail("bounded child rejected")
            saved = __import__("json").loads((Path(directory) / "attempt.json").read_text())
            self.assertEqual(saved["status"], "non-qualifying")
            self.assertEqual(saved["partial_report"], {"accepted_rows": 1})
            self.assertEqual([row["status"] for row in saved["children"]], ["completed", "failed"])
            self.assertEqual(saved["children"][1]["resource_receipt"], failed_receipt)
            self.assertTrue(saved["children"][0]["stdout_sha256"])

    def test_unusable_benchmark_binary_retains_launch_failure_without_inventing_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "v02").mkdir()
            journal = benchmark.MeasurementJournal(root / "diagnostic.json", "diagnostic")
            fake_limits = SimpleNamespace(available_memory_bytes=lambda: 16 * 1024**3,
                require_memory_reserve=lambda available, required: None)
            benchmark._ACTIVE_JOURNAL = journal
            try:
                with mock.patch.object(benchmark, "load_v02_launcher", return_value=fake_limits):
                    with self.assertRaisesRegex(ValueError, "launch-failed"):
                        benchmark.run_control_reference(root, {}, {
                            "wall_seconds": 600, "cleanup_grace_seconds": 30,
                            "max_rss_bytes": 4 * 1024**3, "max_stdout_stderr_bytes": 16 * 1024**2,
                            "max_json_bytes": 32 * 1024**2, "max_binary_file_bytes": 2 * 1024**3,
                            "max_capture_bytes": 2 * 1024**3, "max_scratch_bytes": 16 * 1024**3,
                            "max_retained_bytes": 4 * 1024**3, "max_fields": 7200,
                            "max_calls": 100_000_000})
            finally:
                benchmark._ACTIVE_JOURNAL = None
            saved = __import__("json").loads((root / "diagnostic.json").read_text())
            child = saved["children"][0]
            self.assertEqual(saved["observed_exposure"]["child_launch_attempts"], 1)
            self.assertEqual(saved["observed_exposure"]["child_process_starts"], 0)
            self.assertEqual(child["status"], "launch-failed")
            self.assertIsNone(child["resource_receipt"]["pid"])
            self.assertTrue(child["resource_receipt"]["launch_error"])
            self.assertEqual(child["executable"], "gw_core_benchmark")
            self.assertIn("gw_core_benchmark", child["argv"])

    def test_actual_route_benchmark_uses_shared_typed_capture(self):
        header = (ROOT / "tools/session/route_controller.h").read_text()
        child = (ROOT / "tools/evidence/core_benchmark.c").read_text()
        self.assertIn("gw_route_controller_run_capture", header)
        self.assertIn("--route-plan", child)
        self.assertIn("--route-capture-limit", child)
        self.assertIn("--untimed", child)

    def test_legacy_control_benchmark_supports_untimed_full_window_reference(self):
        child = (ROOT / "tools/evidence/core_benchmark.c").read_text()
        self.assertIn('argc == 7 && strcmp(argv[6], "--untimed")', child)
        self.assertIn(r'\"untimed\":%s,\"timed_samples\":%s', child)

    def test_v02_capture_size_is_checked_before_allocation(self):
        pixels, pcm, total = benchmark.checked_capture_size(4196, 4096, 256)
        self.assertEqual(pixels, 4196 * 320 * 224 * 4)
        self.assertEqual(pcm, 4196 * 4096 * 2 * 2)
        self.assertEqual(total, pixels + pcm + 4196 * 256 + 4096 * 40 + 64 * 24 + 4096)
        with self.assertRaisesRegex(ValueError, "capture-size"):
            benchmark.checked_capture_size(sys.maxsize, 4096, 64)
        with self.assertRaisesRegex(ValueError, "capture-size"):
            benchmark.checked_capture_size(7200, 4096, 64)

    def test_full_route_workload_specs_retain_actual_field_counts(self):
        scope = {"workload": {"max_fields": 7200}}
        self.assertEqual(benchmark.workload_spec("recursion94", scope)["completed_fields"], 3631)
        self.assertEqual(benchmark.workload_spec("tank-battle", scope)["completed_fields"], 4196)
        with self.assertRaisesRegex(ValueError, "field cap"):
            benchmark.workload_spec("tank-battle", {"workload": {"max_fields": 3600}})

    def test_all_workload_roster_binds_each_real_route_and_denominator(self):
        try:
            specs = benchmark.workload_spec("all", {"workload": {"max_fields": 7200}})
        except ValueError:
            specs = []
        self.assertEqual([row["workload"] for row in specs],
                         ["control", "recursion94", "tank-battle"])
        self.assertEqual([row["completed_fields"] for row in specs], [600, 3631, 4196])
        good = {"fields_completed": 3631, "warmup_fields": 0, "elapsed_ns": 10,
                "last_stop_reason": 5, "ticks_completed": 1, "actual_tick_start": 0,
                "actual_tick_end": 1, "completed_steps": 3600,
                "untimed": True, "output_identity": {key: "a" * 64 for key in
                    ("ram_sha256", "cpu_sha256", "controller_sha256", "video_sha256", "pcm_sha256")}}
        self.assertTrue(benchmark.validate_workload_run(good, specs[1]))
        bad = dict(good, completed_steps=3599)
        with self.assertRaisesRegex(ValueError, "step-denominator"):
            benchmark.validate_workload_run(bad, specs[1])

    def test_route_terminal_tick_and_output_mutants_fail_at_their_contracts(self):
        spec = benchmark.workload_spec("recursion94", {"workload": {"max_fields": 7200}})
        identity = {key: "a" * 64 for key in
                    ("ram_sha256", "cpu_sha256", "controller_sha256", "video_sha256", "pcm_sha256")}
        good = {"fields_completed": 3631, "completed_steps": 3600, "warmup_fields": 0,
                "route_status": 0, "untimed": True, "elapsed_ns": 0, "ticks_completed": 12,
                "actual_tick_start": 0, "actual_tick_end": 12, "terminal_tick": 12,
                "output_identity": identity}
        self.assertTrue(benchmark.validate_workload_run(good, spec))
        bad = dict(good, actual_tick_end=0)
        with self.assertRaisesRegex(ValueError, "invalid-workload-ticks"):
            benchmark.validate_workload_run(bad, spec)
        timed = dict(good, untimed=False, elapsed_ns=10, untimed_output_identity=dict(identity))
        self.assertTrue(benchmark.validate_workload_run(timed, spec))
        timed["output_identity"] = dict(identity, pcm_sha256="b" * 64)
        with self.assertRaisesRegex(ValueError, "output-divergence"):
            benchmark.validate_workload_run(timed, spec)

    def test_valid_complete_report_passes_production_validator(self):
        self.assertEqual(benchmark.validate_report(valid_report(), qualification=True), [])

    def test_quick_report_cannot_claim_full_qualification(self):
        report = {"schema": benchmark.REPORT_SCHEMA, "version": 1, "outcome": "pass",
                  "qualification": False, "profile": "quick-contract"}
        self.assertEqual(benchmark.validate_report(report, qualification=True), ["workload-qualification"])

    def test_quick_protocol_accepts_default_native_and_hooks_off_builds(self):
        self.assertIsNone(benchmark.validate_protocol_build(
            {"CMAKE_BUILD_TYPE": "", "GENEWHIP_TEST_HOOKS": "ON"}, quick=True))
        self.assertIsNone(benchmark.validate_protocol_build(
            {"CMAKE_BUILD_TYPE": "Debug", "GENEWHIP_TEST_HOOKS": "OFF"}, quick=True))

    def test_full_protocol_still_rejects_default_or_nonrelease_builds(self):
        for cmake in ({"CMAKE_BUILD_TYPE": "", "GENEWHIP_TEST_HOOKS": "ON"},
                      {"CMAKE_BUILD_TYPE": "Debug", "GENEWHIP_TEST_HOOKS": "ON"},
                      {"CMAKE_BUILD_TYPE": "Release", "GENEWHIP_TEST_HOOKS": "OFF"}):
            with self.subTest(cmake=cmake), self.assertRaisesRegex(
                    ValueError, "full benchmark requires identified Release build with private hooks enabled"):
                benchmark.validate_protocol_build(cmake, quick=False)

    def test_build_identity_selects_actual_single_config_generator_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            (build / "Makefile").write_text("# make rules\n")
            (build / "build.ninja").write_text("# ninja rules\n")
            self.assertEqual(benchmark.build_rules_file(build, "Unix Makefiles"), build / "Makefile")
            self.assertEqual(benchmark.build_rules_file(build, "Ninja"), build / "build.ninja")

    def test_build_identity_rejects_missing_or_unsupported_generator_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            with self.assertRaisesRegex(ValueError, "unsupported benchmark build generator"):
                benchmark.build_rules_file(build, "Xcode")
            with self.assertRaisesRegex(ValueError, "build rules for Ninja are missing"):
                benchmark.build_rules_file(build, "Ninja")

    def assert_reason(self, expected, mutate):
        report = valid_report()
        mutate(report)
        self.assertEqual(benchmark.validate_report(report, qualification=True), [expected])

    def test_units_are_checked_by_production_validator(self):
        self.assert_reason("memory-units", lambda r: r["memory_units"].update(process_ru_maxrss="KiB"))

    def test_fresh_process_identity_cannot_be_reused(self):
        self.assert_reason("process-reused", lambda r: r["modes"][1]["runs"][0].update(
            process_id=r["modes"][0]["runs"][0]["process_id"]))

    def test_incomplete_field_denominator_is_rejected(self):
        self.assert_reason("incomplete-samples", lambda r: r["modes"][0]["runs"][0].update(fields=599))

    def test_missing_sustained_qualification_is_rejected(self):
        self.assert_reason("workload-qualification", lambda r: r["qualification_evidence"].update(sustained_fields=24))

    def test_stale_fixture_identity_is_rejected(self):
        def mutate(report):
            report["workload"].update(rom_sha256="0" * 64)
            report["qualification_evidence"].update(rom_sha256="0" * 64)
        self.assert_reason("stale-identity", mutate)

    def test_divergent_machine_video_or_audio_output_is_rejected(self):
        self.assert_reason("output-divergence", lambda r: r["modes"][3]["runs"][4]["output_identity"].update(
            pcm_sha256="f" * 64))

    def test_unearned_percentile_is_rejected(self):
        self.assert_reason("percentile-exposure", lambda r: r["modes"][0]["latency_ns"].update(samples=999))

    def test_stale_revision_join_is_rejected(self):
        report = valid_report()
        expected = {"source_revision": "current", "build_configuration_sha256": "build-identity",
                    "benchmark_binary_sha256": "e" * 64, "source_identity_sha256": benchmark.source_identity()}
        self.assertIn("stale-identity", benchmark.validate_report(report, qualification=True, expected=expected))

    def test_timing_summary_units_are_recomputed_from_samples(self):
        self.assert_reason("timing-units", lambda r: r["modes"][0]["latency_ns"].update(median=1))


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BenchmarkContract)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful(): return 1
    args = sys.argv[1:]
    if len(args) not in (2, 3) or args[0] != "--build" or (len(args) == 3 and args[2] not in ("--v02-contracts", "--v02-child-contracts")):
        print("usage: benchmark_contract.py --build BUILD [--v02-contracts|--v02-child-contracts]", file=sys.stderr)
        return 2
    build = Path(args[1]).resolve()
    if len(args) == 3 and args[2] in ("--v02-contracts", "--v02-child-contracts"):
        import subprocess
        child = subprocess.run([str(build / "gw_core_benchmark"), "--v02-child-contracts"],
                               cwd=ROOT, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=30, check=False)
        if child.returncode or "PASS (6 capture-size and layout assertions)" not in child.stdout:
            print("v02 benchmark child contract failed: " + child.stderr.strip(), file=sys.stderr)
            return 1
        if args[2] == "--v02-child-contracts":
            try:
                from tempfile import TemporaryDirectory
                import json
                def load_module(name, path):
                    spec = importlib.util.spec_from_file_location(name, path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return module
                v02_run = load_module("gw_v02_run", ROOT / "scripts/evidence/v02_run.py")
                routes_module = load_module("gw_phase6_routes", ROOT / "scripts/evidence/phase6_routes.py")
                mapping = json.loads((ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json").read_text())
                routes = routes_module.compile_routes(mapping, "public-core")["routes"]
                scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
                limits = scope["per_child_limits"]
                required_memory = benchmark.checked_capture_size(4196)[2] + 512 * 1024 * 1024
                def check_memory_reserve():
                    v02_run.require_memory_reserve(v02_run.available_memory_bytes(), required_memory)
                invocations = 0
                with TemporaryDirectory(prefix="gw-bench-v02-", dir=ROOT / "build/v02") as temp_name:
                    temp = Path(temp_name)
                    route_spec = importlib.util.spec_from_file_location(
                        "gw_phase6_route_contract", ROOT / "tests/session/phase6_route_contract.py")
                    route_contract = importlib.util.module_from_spec(route_spec)
                    route_spec.loader.exec_module(route_contract)
                    for workload, title, field_count, call_limit in (
                            ("recursion94", "recursion94", 3631, 100_000_000),
                            ("tank-battle", "tank-battle", 4196, 10_000_000)):
                        route = next(row for row in routes if row["fixture"] == title and row["case"]["id"] == "full-route")
                        compiled, _ = routes_module.lower_route(route, call_limit, mapping if title == "recursion94" else None,
                                                                client="public-core")
                        plan_path = temp / f"{workload}.gwrc"
                        plan_path.write_bytes(compiled)
                        rom = ROOT / routes_module.SOURCES[title][3]
                        spec = benchmark.workload_spec(workload, scope)
                        identities = []
                        for diagnostics in (1, 0):
                            command = [str(build / "gw_core_benchmark"), str(rom), "aggregate", str(diagnostics), "0",
                                       str(field_count), "--route-plan", str(plan_path),
                                       "--route-capture-limit", str(limits["max_capture_bytes"]), "--untimed"]
                            report = temp / f"{workload}-{diagnostics}.json"
                            process_runs = []
                            check_memory_reserve()
                            result_run = route_contract._run_client(build / "gw_core_benchmark", command, process_runs,
                                report=report, timeout=limits["wall_seconds"], cwd=temp,
                                limits=limits, scratch_roots=(temp,))
                            if (result_run.returncode or len(process_runs) != 1 or
                                    process_runs[0].get("process_group_cleanup") != "confirmed" or
                                    process_runs[0].get("bound_violation") is not False):
                                raise ValueError(f"{workload} bounded child did not complete cleanly: "
                                    f"return={result_run.returncode} process={process_runs} stderr={result_run.stderr[-500:]}")
                            row = json.loads(result_run.stdout)
                            if (row.get("completed_fields") != spec["completed_fields"] or row.get("untimed") is not True or
                                    row.get("diagnostics_enabled") is not bool(diagnostics) or row.get("terminal_tick", 0) <= 0 or
                                    row.get("process_ru_maxrss_bytes", 0) <= 0 or
                                    row.get("rss_unit_source") != "Darwin getrusage(2) ru_maxrss bytes"):
                                raise ValueError(f"{workload} route contract rejected its actual child result")
                            benchmark.validate_workload_run(row, spec)
                            hooks_on = benchmark.build_identity(build)["cmake"].get("GENEWHIP_TEST_HOOKS") == "ON"
                            if hooks_on and (not isinstance(row.get("core_owned_current_bytes"), int) or
                                    row["core_owned_peak_bytes"] < row["core_owned_current_bytes"]):
                                raise ValueError("route child omitted private core allocation accounting")
                            identities.append(row["output_identity"])
                            invocations += 1
                        if identities[0] != identities[1]:
                            raise ValueError(f"{workload} diagnostics changed complete untimed route output")
                        command = [str(build / "gw_core_benchmark"), str(rom), "sampled", "0", "0",
                                   str(field_count), "--route-plan", str(plan_path),
                                   "--route-capture-limit", str(limits["max_capture_bytes"])]
                        process_runs = []
                        check_memory_reserve()
                        result_run = route_contract._run_client(build / "gw_core_benchmark", command, process_runs,
                            report=temp / f"{workload}-sampled.json", timeout=limits["wall_seconds"], cwd=temp,
                            limits=limits, scratch_roots=(temp,))
                        if (result_run.returncode or len(process_runs) != 1 or
                                process_runs[0].get("process_group_cleanup") != "confirmed" or
                                process_runs[0].get("bound_violation") is not False):
                            raise ValueError(f"{workload} sampled child did not complete cleanly")
                        sampled = json.loads(result_run.stdout)
                        if (sampled.get("elapsed_ns", 0) <= 0 or sampled.get("timed_samples") is not True or
                                len(sampled.get("field_ns", [])) != field_count or
                                any(type(value) is not int or value <= 0 for value in sampled["field_ns"]) or
                                sampled.get("output_identity") != identities[1]):
                            raise ValueError(f"{workload} sampled timing or untimed-equivalence contract failed")
                        invocations += 1
                print(f"benchmark_contract: PASS ({result.testsRun} assertions; {invocations} bounded actual-title diag-off/on route children; capture and RSS contracts)")
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                print("v02 actual-title child contract failed: " + str(exc), file=sys.stderr)
                return 1
            return 0
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gw-bench-quick-") as tmp:
        output = Path(tmp) / "quick.json"
        import subprocess
        command = [sys.executable, str(ROOT / "tools/evidence/core_benchmark.py"),
                   "--build", str(build), "--out", str(output), "--quick"]
        run = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=180, check=False)
        if run.returncode:
            print("benchmark quick contract failed: " + run.stderr.strip(), file=sys.stderr)
            return 1
        report = __import__("json").loads(output.read_text())
        if report.get("qualification") is not False or report.get("protocol", {}).get("measured_fields") != 4 or \
                len(report.get("runs", [])) != 4:
            print("quick contract was relabeled as a full performance result", file=sys.stderr)
            return 1
        identities = {__import__("json").dumps(benchmark.output_identity(row), sort_keys=True)
                      for row in report["runs"]}
        if len(identities) != 1 or any(row.get("fields_completed") != 4 or
                row.get("last_stop_reason") != 5 for row in report["runs"]):
            print("quick public-path output diverged or stopped early", file=sys.stderr)
            return 1
        hooks_on = benchmark.build_identity(build)["cmake"].get("GENEWHIP_TEST_HOOKS") == "ON"
        for row in report["runs"]:
            if hooks_on and (not isinstance(row.get("core_owned_current_bytes"), int) or
                             row["core_owned_current_bytes"] <= 0):
                print("quick hook-enabled build omitted private accounting", file=sys.stderr)
                return 1
            if not hooks_on and any(row.get(key) is not None for key in
                    ("core_owned_current_bytes", "core_owned_peak_bytes", "allocation_calls_total")):
                print("hooks-off quick mode fabricated private accounting", file=sys.stderr)
                return 1
    print(f"benchmark_contract: PASS ({result.testsRun} report assertions, four bounded public-path modes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
