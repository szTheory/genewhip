#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure contract tests for explicit package performance subject identity."""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("contract-module-unavailable:" + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PackagePerformanceIdentityContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-package-identity-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.sdk = load_module("gw_package_identity_sdk", ROOT / "scripts/package_sdk.py")
        self.benchmark = self.sdk._load_benchmark_module()
        fixtures = load_module("gw_package_identity_fixtures",
            ROOT / "tests/evidence/v02_qualification_contract.py")
        self.revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        self.identity = {"source_sha": self.revision, "head_sha": self.revision,
            "base_sha": "088114d099803205214fbe343809270dccc86eaa",
            "run_id": "41735435251", "run_attempt": "1"}

        scope_relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        scope_path = self.root / scope_relative
        scope_path.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / scope_relative, scope_path)
        scope_bytes = scope_path.read_bytes()
        self.scope_sha = hashlib.sha256(scope_bytes).hexdigest()
        self.scope = json.loads(scope_bytes)
        scope_module_path = self.root / "scripts/evidence/v02_scope.py"
        scope_module_path.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/evidence/v02_scope.py", scope_module_path)

        source_identity = self.benchmark.source_identity()
        reports = fixtures.synthetic_qualified_reports(self.benchmark, self.identity,
            source_identity, self.scope["scope_id"], self.scope_sha)
        report_root = self.root / "build/v02/collected"
        self.raw_digests = {}
        for workload, report in reports.items():
            path = report_root / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            self.raw_digests[workload] = hashlib.sha256(path.read_bytes()).hexdigest()
        public = self.root / "build/v02/public"
        public.mkdir(parents=True)
        self.performance_path = public / "performance.json"
        projection = self.benchmark.build_public_performance_projection(reports, self.raw_digests,
            identity=self.identity, source_identity_sha256=source_identity,
            scope_id=self.scope["scope_id"], scope_sha256=self.scope_sha)
        self._write_projection(projection)

        self._patchers = [
            patch.object(self.sdk, "ROOT", self.root),
            patch.object(self.sdk, "_load_benchmark_module", return_value=self.benchmark),
            patch.dict(os.environ, {
                "GENEWHIP_QUALIFICATION_SCOPE_PATH": scope_relative.as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": self.scope_sha,
            }),
        ]
        for patcher in self._patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write_projection(self, projection):
        self.performance_path.write_text(
            json.dumps(projection, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _github_identity(self, identity):
        return {
            "GITHUB_SHA": identity["head_sha"],
            "GITHUB_BASE_SHA": identity["base_sha"],
            "GITHUB_RUN_ID": identity["run_id"],
            "GITHUB_RUN_ATTEMPT": identity["run_attempt"],
        }

    def test_explicit_hosted_subject_accepts_original_projection_despite_ambient_mismatch(self):
        ambient = {"source_sha": self.revision, "head_sha": "f" * 40,
            "base_sha": "e" * 40, "run_id": "12345", "run_attempt": "8"}
        with patch.dict(os.environ, self._github_identity(ambient)):
            digest = self.sdk._validate_performance_evidence(self.performance_path,
                self.revision, expected_identity=self.identity)
        self.assertEqual(digest, hashlib.sha256(self.performance_path.read_bytes()).hexdigest())

    def test_default_subject_still_uses_ambient_ci_identity_and_rejects_mismatch(self):
        with patch.dict(os.environ, self._github_identity(self.identity)):
            digest = self.sdk._validate_performance_evidence(self.performance_path, self.revision)
        self.assertEqual(digest, hashlib.sha256(self.performance_path.read_bytes()).hexdigest())

        ambient = {"source_sha": self.revision, "head_sha": "f" * 40,
            "base_sha": "e" * 40, "run_id": "12345", "run_attempt": "8"}
        with patch.dict(os.environ, self._github_identity(ambient)):
            with self.assertRaisesRegex(ValueError, "public-performance-policy-rejected:.*public-performance-envelope"):
                self.sdk._validate_performance_evidence(self.performance_path, self.revision)

    def test_explicit_identity_requires_exact_complete_fields_and_matching_source(self):
        invalid = (
            ({**self.identity, "run_id": "local"}, "package-performance-identity-invalid"),
            ({**self.identity, "run_attempt": "0"}, "package-performance-identity-invalid"),
            ({**self.identity, "head_sha": "short"}, "package-performance-identity-invalid"),
            ({**self.identity, "extra": "field"}, "package-performance-identity-invalid"),
            ({key: value for key, value in self.identity.items() if key != "base_sha"},
             "package-performance-identity-invalid"),
            ({**self.identity, "source_sha": "a" * 40},
             "package-performance-identity-source-mismatch"),
        )
        for expected, reason in invalid:
            with self.subTest(reason=reason, expected=expected):
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    self.sdk._validate_performance_evidence(self.performance_path,
                        self.revision, expected_identity=expected)

    def test_valid_but_wrong_run_and_base_subjects_reject(self):
        for field, value in (("head_sha", "f" * 40), ("base_sha", "e" * 40),
                ("run_id", "999999999"), ("run_attempt", "2")):
            expected = {**self.identity, field: value}
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError,
                        "public-performance-policy-rejected:.*public-performance-envelope"):
                    self.sdk._validate_performance_evidence(self.performance_path,
                        self.revision, expected_identity=expected)

    def test_recomputed_report_hashes_do_not_rebind_run_or_scope_identity(self):
        original = json.loads(self.performance_path.read_text(encoding="utf-8"))
        changed = json.loads(json.dumps(original))
        changed["identity"]["run_id"] = "999999999"
        for entry in changed["workloads"].values():
            entry["report"]["run_id"] = "999999999"
            entry["public_report_sha256"] = self.benchmark._canonical_json_sha256(entry["report"])
        # The report digests have been recomputed, but the separately supplied
        # subject and source report files remain the original hosted attempt.
        self._write_projection(changed)
        with self.assertRaisesRegex(ValueError, "public-performance-policy-rejected:"):
            self.sdk._validate_performance_evidence(self.performance_path,
                self.revision, expected_identity=self.identity)

        changed = json.loads(json.dumps(original))
        changed["scope_sha256"] = "f" * 64
        for entry in changed["workloads"].values():
            entry["report"]["scope_sha256"] = "f" * 64
            entry["public_report_sha256"] = self.benchmark._canonical_json_sha256(entry["report"])
        self._write_projection(changed)
        with self.assertRaisesRegex(ValueError, "public-performance-policy-rejected:"):
            self.sdk._validate_performance_evidence(self.performance_path,
                self.revision, expected_identity=self.identity)


if __name__ == "__main__":
    unittest.main(verbosity=2)
