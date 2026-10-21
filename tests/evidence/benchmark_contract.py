#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise benchmark report rejection paths and a bounded public-path run."""
import copy
import importlib.util
import sys
import tempfile
import unittest
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


class BenchmarkContract(unittest.TestCase):
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
    if len(args) != 2 or args[0] != "--build":
        print("usage: benchmark_contract.py --build BUILD", file=sys.stderr)
        return 2
    build = Path(args[1]).resolve()
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
