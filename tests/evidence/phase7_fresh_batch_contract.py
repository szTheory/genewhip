#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure authorization/admission and coordinator-boundary contracts for fresh Plan 10."""
from __future__ import annotations

import ctypes
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import ExitStack


ROOT = Path(__file__).resolve().parents[2]
DENIALS: list[str] = []
NATIVE_EVENTS: list[str] = []
FIXTURE_ENV_PREFIXES = ("GENEWHIP_QUALIFICATION_", "GENEWHIP_FRESH_BATCH_", "GENEWHIP_RECOVERY_")


def fixture_environment_snapshot() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if key.startswith(FIXTURE_ENV_PREFIXES)}


INITIAL_FIXTURE_ENV = fixture_environment_snapshot()


def synthetic_preview_jobs():
    outcomes = {"phase7-fast": "failure", "required-ci": "failure",
        "safety": "cancelled", "package": "cancelled", "performance": "success",
        "product-smoke": "cancelled", "desktop": "cancelled", "gameplay": "cancelled",
        "attestation": "cancelled"}
    for name in ("v02-runtime", "extended", "v02-benchmark-control",
            "v02-benchmark-recursion94", "v02-benchmark-tank-battle",
            "v02-package", "v02-release-qualification"):
        outcomes[name] = "skipped"
    return [{"name": name, "status": "completed", "conclusion": conclusion}
        for name, conclusion in sorted(outcomes.items())]


def deny_process(event: str, args: tuple[object, ...]) -> None:
    if (event == "subprocess.Popen" or event in ("os.system", "os.fork", "os.forkpty", "pty.spawn")
            or event in ("os.kill", "os.killpg", "signal.raise_signal")
            or event.startswith(("os.exec", "os.spawn", "os.posix_spawn"))):
        DENIALS.append(event)
        raise PermissionError("fresh-batch-process-denied")


def deny_native(event: str, args: tuple[object, ...]) -> None:
    if event in ("ctypes.dlopen", "ctypes.dlsym"):
        NATIVE_EVENTS.append(event)
        raise PermissionError("fresh-batch-native-denied")


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fresh-batch-test-import-failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Independent audit hooks are installed before importing either production module.
sys.addaudithook(deny_process)
sys.addaudithook(deny_native)
def denial_self_test(label: str) -> None:
    before_process = len(DENIALS)
    before_native = len(NATIVE_EVENTS)
    probes = (("subprocess.Popen", lambda: subprocess.Popen(["/__fresh_batch_denial_probe__"])),
              ("os.kill", lambda: os.kill(os.getpid(), 0)),
              ("os.killpg", lambda: os.killpg(987654321, 0)))
    for expected, probe in probes:
        try:
            probe()
        except PermissionError as error:
            if str(error) != "fresh-batch-process-denied" or DENIALS[-1] != expected:
                raise AssertionError(f"fresh-batch-{label}-process-self-test-failed") from error
        else:
            raise AssertionError(f"fresh-batch-{label}-process-self-test-not-reached")
    try:
        ctypes.CDLL("/__fresh_batch_native_denial_probe__")
    except PermissionError as error:
        if str(error) != "fresh-batch-native-denied" or NATIVE_EVENTS[-1:] != ["ctypes.dlopen"]:
            raise AssertionError(f"fresh-batch-{label}-native-self-test-failed") from error
    else:
        raise AssertionError(f"fresh-batch-{label}-native-self-test-not-reached")
    if DENIALS[before_process:] != [event for event, _ in probes]:
        raise AssertionError(f"fresh-batch-{label}-unexpected-process-denials")
    if NATIVE_EVENTS[before_native:] != ["ctypes.dlopen"]:
        raise AssertionError(f"fresh-batch-{label}-unexpected-native-denials")


denial_self_test("before-production-imports")
BATCH = load(ROOT / "scripts/release/v02_batch.py", "gw_fresh_batch_contract")


class FreshBatchContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_paths = {
            "scripts/release/v02_batch.py", "scripts/release/v02_qualification.py",
            "tests/evidence/phase7_fresh_batch_contract.py", "scripts/ci/required-gate.sh"}
        cls.source_bytes = {name: (ROOT / name).read_bytes() for name in cls.source_paths}

    def setUp(self):
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for key in fixture_environment_snapshot():
            os.environ.pop(key, None)
        self.temp = tempfile.TemporaryDirectory(prefix="gw-fresh-batch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.started = "2026-10-31T12:43:19+00:00"
        self._constant_patches = []

        def trust(name, value):
            patcher = mock.patch.object(BATCH, name, value)
            patcher.start()
            self._constant_patches.append(patcher)
            self.addCleanup(patcher.stop)

        self.batch_path = Path("build/v02/policy-test/authorization.json")
        self.policy_root = self.batch_path.parent
        self.scope_path = Path("evidence/v02-execution.json")
        self.old_campaign_path = Path("build/v02/campaign15/campaign.json")
        self.old_journal_path = Path("build/v02/campaign15/hosted-delivery-journal.json")
        self.previous_batch_root = Path("build/v02/previous-attempt")
        self.previous_failure_path = self.previous_batch_root / "failure.json"
        self.previous_journal_path = self.previous_batch_root / "hosted-delivery-journal.json"
        self.previous_terminal_path = self.previous_batch_root / "terminal-observation.json"
        self.previous_repair_path = self.previous_batch_root / "repair-evidence.json"
        for name, value in (("AUTH_PATH", self.batch_path), ("SCOPE_PATH", self.scope_path),
                            ("OLD_CAMPAIGN_PATH", self.old_campaign_path),
                            ("OLD_JOURNAL_PATH", self.old_journal_path),
                            ("POLICY_ROOT", self.policy_root)):
            trust(name, value)
        self.batch_root = self.root / BATCH.POLICY_ROOT / "attempt-0001"
        self.batch_root.mkdir(parents=True)
        os.environ["GENEWHIP_FRESH_BATCH_ROOT"] = self.batch_root.relative_to(self.root).as_posix()
        self.auth = self.root / BATCH.AUTH_PATH
        self.auth.parent.mkdir(parents=True, exist_ok=True)
        self.scope_bytes = json.dumps({"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200}}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.old_campaign_bytes = b'{"schema":"synthetic-old-campaign"}\n'
        self.old_journal_bytes = b'{"schema":"synthetic-old-journal"}\n'
        self.previous_failure_bytes = json.dumps({"schema": "genewhip.phase7-fresh-batch-failure.v1",
            "stage": "preview-ci", "reason": "required-ci-failed"}, sort_keys=True).encode() + b"\n"
        self.previous_journal_bytes = b'{"schema":"synthetic-previous-journal"}\n'
        self.previous_terminal_bytes = json.dumps({"all_jobs_terminal": True,
            "event": "pull_request", "jobs": synthetic_preview_jobs(),
            "safety_job_failed": False, "qualification_accepted": False,
            "full_qualification_dispatched": False},
            sort_keys=True).encode() + b"\n"
        self.previous_repair_bytes = json.dumps({"live_retry_authorized": False,
            "safety_or_cleanup_issue": False,
            "file_sha256": hashlib.sha256(self.source_bytes[
                "tests/evidence/phase7_fresh_batch_contract.py"]).hexdigest()},
            sort_keys=True).encode() + b"\n"
        trust("SCOPE_SHA256", hashlib.sha256(self.scope_bytes).hexdigest())
        trust("OLD_CAMPAIGN_SHA256", hashlib.sha256(self.old_campaign_bytes).hexdigest())
        trust("OLD_JOURNAL_SHA256", hashlib.sha256(self.old_journal_bytes).hexdigest())
        self.started_dt = datetime.datetime.fromisoformat(self.started)
        self.auth_value = {"schema": "genewhip.phase7-continuing-ci-authorization.v1",
            "source_head": "0baeedeab8aadbf09bb2c3a2726c2a05c45eea36",
            "source_fix_head": "f18a30842ad73bb29de18a0fdcdba86ded292f19",
            "previous_campaign_sha256": BATCH.OLD_CAMPAIGN_SHA256,
            "previous_failed_journal_sha256": BATCH.OLD_JOURNAL_SHA256,
            "scope_path": BATCH.SCOPE_PATH.as_posix(), "scope_sha256": BATCH.SCOPE_SHA256,
            "ci_before_full_qualification": True, "stop_on_failure": True,
            "historical_risk_accepted": False, "next_phase_authorized": False,
            "ordinary_ci_retries_approved": True, "resource_limits_unchanged": True,
            "reviewed_public_updates_approved": True, "safety_stop_required": True,
            "failure_stop_scope": "attempt", "repository": "szTheory/genewhip",
            "started_at": self.started,
            "runtime_cutoff": (self.started_dt + datetime.timedelta(hours=18)).isoformat(),
            "package_cutoff": (self.started_dt + datetime.timedelta(hours=22)).isoformat(),
            "global_cutoff": (self.started_dt + datetime.timedelta(hours=24)).isoformat(),
            "initial_predecessor": {"attempt_root": self.previous_batch_root.as_posix(),
                "failure": self._reference(self.previous_failure_path, self.previous_failure_bytes),
                "journal": self._reference(self.previous_journal_path, self.previous_journal_bytes),
                "terminal_observation": self._reference(self.previous_terminal_path, self.previous_terminal_bytes),
                "repair_evidence": self._reference(self.previous_repair_path, self.previous_repair_bytes)},
            "historical_records": []}
        self.auth_value["historical_records"] = []
        for index in range(6):
            historical_path = Path(f"build/v02/history-fixture-{index}.json")
            historical_bytes = json.dumps({"fixture": index}, sort_keys=True).encode() + b"\n"
            (self.root / historical_path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / historical_path).write_bytes(historical_bytes)
            self.auth_value["historical_records"].append(self._reference(historical_path, historical_bytes))
        auth_bytes = json.dumps(self.auth_value, sort_keys=True, indent=2).encode() + b"\n"
        trust("AUTH_SHA256", hashlib.sha256(auth_bytes).hexdigest())
        self.auth_bytes = auth_bytes
        self.auth.write_bytes(auth_bytes)
        for relative, data in ((BATCH.SCOPE_PATH, self.scope_bytes),
                               (BATCH.OLD_CAMPAIGN_PATH, self.old_campaign_bytes),
                               (BATCH.OLD_JOURNAL_PATH, self.old_journal_bytes),
                               (self.previous_failure_path, self.previous_failure_bytes),
                               (self.previous_journal_path, self.previous_journal_bytes),
                               (self.previous_terminal_path, self.previous_terminal_bytes),
                               (self.previous_repair_path, self.previous_repair_bytes)):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.source_head = "a" * 40
        self.predecessor = {"attempt_index": 0,
            "attempt_root": self.previous_batch_root.as_posix(),
            "failure": self._reference(self.previous_failure_path, self.previous_failure_bytes),
            "journal": self._reference(self.previous_journal_path, self.previous_journal_bytes),
            "terminal_observation": self._reference(self.previous_terminal_path, self.previous_terminal_bytes),
            "repair_evidence": self._reference(self.previous_repair_path, self.previous_repair_bytes),
            "cleanup_evidence": None, "source_admission": None,
            "disposition": "routine-source-repair",
            "all_ci_terminal": True, "safety_status": "clear",
            "cleanup_status": "not-applicable", "unknown_high_findings": False}
        self.pins = {}
        for name, data in self.source_bytes.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.pins[name] = hashlib.sha256(data).hexdigest()
        self.review_dir = self.root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
        self.review_dir.mkdir(parents=True)
        self.source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, attempt_root=self.batch_root.relative_to(self.root).as_posix(),
            attempt_index=1, predecessor=self.predecessor, disposition="routine-source-repair",
            source_pins=self.pins)
        self.source_payload_sha = hashlib.sha256(BATCH._canonical(self.source_payload)).hexdigest()
        self.source_reviews = self._reviews("source", self.source_payload_sha)
        self.source_admission = self._source_admission()
        self.source_admission_path = self.batch_root / "source-admission.json"
        self._write_admission(self.source_admission_path, self.source_admission)
        self.journal = self.batch_root / "hosted-delivery-journal.json"
        self.publication = self.batch_root / "candidate/publication-copy"
        self.preparation = self.batch_root / "candidate/preparation.json"
        self.output = self.batch_root / "candidate/result.json"
        self.expected_failure_paths: set[Path] = set()

    def tearDown(self):
        self.assertEqual(self.auth.read_bytes(), self.auth_bytes)
        self.assertEqual((self.root / BATCH.SCOPE_PATH).read_bytes(), self.scope_bytes)
        self.assertEqual((self.root / BATCH.OLD_CAMPAIGN_PATH).read_bytes(), self.old_campaign_bytes)
        self.assertEqual((self.root / BATCH.OLD_JOURNAL_PATH).read_bytes(), self.old_journal_bytes)
        for path in (self.batch_root / "failure.json",):
            self.assertEqual(path.exists(), path in self.expected_failure_paths)
        self.assertEqual((self.root / self.previous_failure_path).read_bytes(), self.previous_failure_bytes)
        self.assertEqual((self.root / self.previous_journal_path).read_bytes(), self.previous_journal_bytes)

    def _reviews(self, prefix: str, payload_sha: str):
        result = {}
        roles = {"code": "gsd-code-reviewer", "security": "gsd-security-auditor"}
        for key, role in roles.items():
            path = self.review_dir / f"{prefix}-{key}.md"
            raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                   f"payload_sha256: {payload_sha}\n---\nIndependent review fixture.\n").encode()
            path.write_bytes(raw)
            result[key] = {"path": path.relative_to(self.root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                "status": "accepted", "payload_sha256": payload_sha}
        return result

    def _reference(self, path: Path, raw: bytes) -> dict[str, str]:
        relative = path.relative_to(self.root) if path.is_absolute() else path
        return {"path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}

    def _configure_coordinator(self, coordinator):
        coordinator.ROOT = self.root
        coordinator.FRESH_BATCH_POLICY_ROOT = BATCH.POLICY_ROOT
        coordinator.LEGACY_BATCH_ROOTS = (Path("build/v02/batch-closed"),
            Path("build/v02/batch-closed-retry1"), BATCH.POLICY_ROOT)
        return coordinator

    def _source_admission(self, source_pins=None, *, attempt_index=1,
                          predecessor=None, disposition="routine-source-repair"):
        source_pins = source_pins or self.pins
        attempt_root = self.batch_root if attempt_index == 1 else (
            self.root / BATCH.POLICY_ROOT / f"attempt-{attempt_index:04d}")
        predecessor = self.predecessor if predecessor is None else predecessor
        source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, attempt_root=attempt_root.relative_to(self.root).as_posix(),
            attempt_index=attempt_index, predecessor=predecessor,
            disposition=disposition, source_pins=source_pins)
        payload_sha = hashlib.sha256(BATCH._canonical(source_payload)).hexdigest()
        return {"schema": BATCH.SCHEMA, "status": "source-preparation",
            "authorization_path": BATCH.AUTH_PATH.as_posix(),
            "authorization_sha256": BATCH.AUTH_SHA256,
            "scope_path": BATCH.SCOPE_PATH.as_posix(), "scope_sha256": BATCH.SCOPE_SHA256,
            "batch_root": attempt_root.relative_to(self.root).as_posix(),
            "attempt_index": attempt_index, "attempt_root": attempt_root.relative_to(self.root).as_posix(),
            "predecessor": predecessor, "disposition": disposition,
            "started_at": self.started,
            "source_head": self.source_head, "source_pins": source_pins,
            "source_payload_sha256": payload_sha,
            "source_reviews": self._reviews(f"source-refresh-{attempt_index}", payload_sha)}

    def _write_admission(self, path: Path, value: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _sandbox_batch_source(self) -> str:
        source = (ROOT / "scripts/release/v02_batch.py").read_text()
        replacements = {
            'AUTH_PATH = Path("build/v02/ci-continuation-20261031T124319Z/authorization.json")':
                f'AUTH_PATH = Path("{BATCH.AUTH_PATH.as_posix()}")',
            'AUTH_SHA256 = "51ea5e62bca6ad2cb153f060dfc97ff3c74b75eb2b36b55f7dccf48c5c780cbc"':
                f'AUTH_SHA256 = "{BATCH.AUTH_SHA256}"',
            'POLICY_ROOT = AUTH_PATH.parent':
                f'POLICY_ROOT = Path("{BATCH.POLICY_ROOT.as_posix()}")',
            'SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"':
                f'SCOPE_SHA256 = "{BATCH.SCOPE_SHA256}"',
            'OLD_CAMPAIGN_SHA256 = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"':
                f'OLD_CAMPAIGN_SHA256 = "{BATCH.OLD_CAMPAIGN_SHA256}"',
            'OLD_JOURNAL_SHA256 = "085a769ceefe2dbaae88b0fd911fb777213d37ff142c85b2ca9f9ac912a18826"':
                f'OLD_JOURNAL_SHA256 = "{BATCH.OLD_JOURNAL_SHA256}"'}
        for old, new in replacements.items():
            if old not in source:
                raise AssertionError("synthetic-batch-constant-not-found")
            source = source.replace(old, new, 1)
        return source

    def _validate(self, *, stage="source-preparation", now=None, admission_path=None,
                  admission_sha=None, journal=None, publication=None, preflight=None, output=None,
                  source_is_ancestor=lambda ancestor, descendant: True):
        admission_path = admission_path or self.source_admission_path
        admission_sha = admission_sha or hashlib.sha256(admission_path.read_bytes()).hexdigest()
        return BATCH.validate_batch(self.root, self.auth, BATCH.AUTH_SHA256,
            admission_path, admission_sha, stage=stage, source_head=self.source_head,
            now=now or datetime.datetime.fromisoformat("2026-10-31T12:50:00+00:00"),
            scope_path=self.root / BATCH.SCOPE_PATH,
            journal_path=journal or self.journal,
            publication_copy=publication or self.publication,
            preflight_path=preflight or self.preparation,
            output_path=output or self.preparation,
            source_is_ancestor=source_is_ancestor,
            expected_source_paths=self.source_paths)

    def test_source_preparation_admission_accepts_exact_authority_and_all_source_pins(self):
        result = self._validate()
        self.assertEqual(result["started_at"], self.started)
        self.assertEqual(os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"], self.started)
        self.assertEqual(result["batch_root"], self.batch_root.resolve())

    def _diagnostic_successor(self, diagnostic_case=BATCH.DIAGNOSTIC_CASE):
        if diagnostic_case == BATCH.DIAGNOSTIC_CASE:
            diagnostic_paths = {"tests/evidence/phase5_baseline_contract.py",
                "scripts/evidence/phase4_report.py", "tests/evidence/phase4_report_contract.py"}
        else:
            diagnostic_paths = set(BATCH.RSS_DIAGNOSTIC_SOURCE_PATHS)
        self.source_paths = set(self.source_paths) | diagnostic_paths
        for name in diagnostic_paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# prior diagnostic fixture\n")
            self.pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self._write_admission(self.source_admission_path, self._source_admission())
        self._validate()
        BATCH.write_failure_sentinel(self.root, attempt_root=self.batch_root,
            stage="preview-ci", reason="pull-request-required-ci-failed",
            observed_at="2026-10-31T12:55:00+00:00")
        self.expected_failure_paths.add(self.batch_root / "failure.json")
        self.journal.write_text('{"schema":"genewhip.v02-delivery-journal.v1"}\n')
        rss_profile = diagnostic_case == BATCH.RSS_DIAGNOSTIC_CASE
        failed_lanes = {"product-smoke", "required-ci"} if rss_profile else {"safety", "required-ci"}
        canceled_lanes = {"safety", "desktop"} if rss_profile else set()
        jobs = [{"name": name, "status": "completed", "conclusion":
            "failure" if name in failed_lanes else
            "cancelled" if name in canceled_lanes else
            "success" if name in BATCH.PREVIEW_REQUIRED_LANES else "skipped",
            **({"id": 124591302116} if rss_profile and name == "product-smoke" else {})}
            for name in sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS)]
        public_head, public_base = "c" * 40, "d" * 40
        if rss_profile:
            self.journal.write_text(json.dumps({"schema": "genewhip.v02-delivery-journal.v1",
                "repository": "szTheory/genewhip", "source_head": public_head,
                "public_base_sha": public_base, "started_at": self.started}, sort_keys=True) + "\n")
        terminal = {"all_jobs_terminal": True, "jobs": jobs,
            "event": "pull_request",
            "pull_request": {"state": "open", "merged": False,
                "number": 31 if rss_profile else None,
                "head_sha": public_head if rss_profile else "c" * 40,
                "base_sha": public_base if rss_profile else "d" * 40},
            "safety_job_failed": not rss_profile, "qualification_accepted": False,
            "full_qualification_dispatched": False, "local_monitor_safety_issue": False,
            "owning_case": diagnostic_case,
            "failed_lane": "product-smoke" if rss_profile else "sanitizer",
            "native_lane": "passed", "hosted_cleanup_outcome": "unknown"}
        if rss_profile:
            terminal.update({"local_monitor_cleanup": "confirmed",
                "bound_violation_reason": "phase7-rss-observation-unavailable",
                "original_failure_cause": "unknown", "merge_attempted": False})
        repair = {"live_retry_authorized": False, "diagnostic_only": True,
            "diagnostic_case": diagnostic_case, "safety_job_failed": not rss_profile,
            "had_safety_job_failure": not rss_profile, "hosted_cleanup_outcome": "unknown",
            "qualification_accepted": False, "unknown_high_findings": False}
        if rss_profile:
            receipt_path = self.batch_root / "coordinator-external-attempts/external-12345-67890.attempt.json"
            receipt = {"schema": "genewhip.v02-coordinator-child-attempt.v1", "returncode": -15,
                "argv": ["gh", "pr", "view", "31", "--repo", "szTheory/genewhip",
                    "--json", "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"],
                "process_group_cleanup": "confirmed", "processes": [{"pid": 58201,
                    "pgid": 58201, "bound_violation": True, "status": "failed",
                    "return_code": -15, "process_group_cleanup": "confirmed",
                    "bound_violation_reason": "phase7-rss-observation-unavailable"}]}
            self._write_admission(receipt_path, receipt)
            receipt_ref = self._reference(receipt_path, receipt_path.read_bytes())
            log_path = self.batch_root / "ci-failure/product-smoke-124591302116.log"
            log_bytes = ("RuntimeError: tank-battle/full-route: process failed\n"
                         "BOUND: phase7-rss-observation-unavailable\n").encode()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_bytes(log_bytes)
            repair.update({"local_monitor_receipt": receipt_ref,
                "hosted_log": self._reference(log_path, log_bytes),
                "bound_violation_reason": "phase7-rss-observation-unavailable",
                "original_failure_cause": "unknown",
                "local_monitor_cleanup": "confirmed"})
        terminal_path, repair_path = (self.batch_root / "terminal-observation.json",
                                      self.batch_root / "repair-evidence.json")
        self._write_admission(terminal_path, terminal)
        self._write_admission(repair_path, repair)
        predecessor = {"attempt_index": 1,
            "attempt_root": self.batch_root.relative_to(self.root).as_posix(),
            **{key: self._reference(path, path.read_bytes()) for key, path in (
                ("failure", self.batch_root / "failure.json"), ("journal", self.journal),
                ("terminal_observation", terminal_path), ("repair_evidence", repair_path),
                ("source_admission", self.source_admission_path))},
            "cleanup_evidence": None, "disposition": "bounded-diagnostic-followup",
            "all_ci_terminal": True, "safety_status": "diagnostic-only",
            "cleanup_status": "unknown-hosted-test-outcome", "unknown_high_findings": False}
        pins = dict(self.pins)
        for name in diagnostic_paths:
            path = self.root / name
            path.write_bytes(b"# fresh fixed-enum diagnostic fixture\n")
            pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        second = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        second.mkdir()
        return second, predecessor, pins

    def test_diagnostic_admission_preserves_unknown_and_cannot_become_normal_retry(self):
        second, predecessor, pins = self._diagnostic_successor()
        path = second / "source-admission.json"
        def validate(pred=predecessor, disposition="bounded-diagnostic-followup", selected=pins):
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition=disposition)
            digest = self._write_admission(path, admission)
            return self._validate(admission_path=path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")
        with self.assertRaisesRegex(ValueError, "diagnostic-disposition-mismatch"):
            validate(disposition="routine-source-repair")
        for changes in ({"cleanup_status": "not-applicable"}, {"safety_status": "clear"},
                        {"unknown_high_findings": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate(pred={**predecessor, **changes})
        with self.assertRaisesRegex(ValueError, "source-pin-stale"):
            validate(selected=self.pins)
        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        original_terminal = terminal_path.read_bytes()
        for changes in ({"owning_case": "other"}, {"local_monitor_safety_issue": True},
                        {"hosted_cleanup_outcome": "confirmed"}, {"native_lane": "failed"}):
            value = {**json.loads(original_terminal), **changes}
            self._write_admission(terminal_path, value)
            selected = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid"):
                validate(pred=selected)
        terminal_path.write_bytes(original_terminal)
        diagnostic_path = self.root / "tests/evidence/phase4_report_contract.py"
        fresh_bytes = diagnostic_path.read_bytes()
        diagnostic_path.write_bytes(b"# prior diagnostic fixture\n")
        partial = {**pins, "tests/evidence/phase4_report_contract.py": self.pins[
            "tests/evidence/phase4_report_contract.py"]}
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=partial)
        diagnostic_path.write_bytes(fresh_bytes)
        result = validate()
        self.assertEqual(result["admission"]["disposition"], "bounded-diagnostic-followup")
        self.assertEqual(result["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")

    def test_rss_smoke_diagnostic_requires_exact_roster_receipts_and_four_source_changes(self):
        second, predecessor, pins = self._diagnostic_successor(BATCH.RSS_DIAGNOSTIC_CASE)
        path = second / "source-admission.json"

        def validate(pred=predecessor, disposition="bounded-diagnostic-followup", selected=pins):
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition=disposition)
            digest = self._write_admission(path, admission)
            return self._validate(admission_path=path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        with self.assertRaisesRegex(ValueError, "diagnostic-disposition-mismatch"):
            validate(disposition="evidence-backed-infrastructure-retry")
        result = validate()
        self.assertEqual(result["admission"]["disposition"], "bounded-diagnostic-followup")
        self.assertEqual(result["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")

        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_bytes = terminal_path.read_bytes()
        terminal = json.loads(terminal_bytes)
        jobs = terminal["jobs"]
        mutations = []
        wrong_case = {**terminal, "owning_case": "smoke/other/title"}
        mutations.append(wrong_case)
        wrong_job = json.loads(terminal_bytes)
        next(row for row in wrong_job["jobs"] if row["name"] == "product-smoke")["conclusion"] = "success"
        mutations.append(wrong_job)
        missing_lane = json.loads(terminal_bytes)
        missing_lane["jobs"] = [row for row in missing_lane["jobs"] if row["name"] != "desktop"]
        mutations.append(missing_lane)
        active_lane = json.loads(terminal_bytes)
        next(row for row in active_lane["jobs"] if row["name"] == "desktop")["status"] = "in_progress"
        mutations.append(active_lane)
        extra_lane = json.loads(terminal_bytes)
        extra_lane["jobs"].append({"name": "unknown-lane", "status": "completed",
                                  "conclusion": "success"})
        mutations.append(extra_lane)
        unknown_cleanup = {**terminal, "local_monitor_cleanup": "unknown"}
        mutations.append(unknown_cleanup)
        wrong_head = json.loads(terminal_bytes)
        wrong_head["pull_request"]["head_sha"] = "e" * 40
        mutations.append(wrong_head)
        for value in mutations:
            self._write_admission(terminal_path, value)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(terminal=value), self.assertRaisesRegex(ValueError,
                    "diagnostic-(classification|evidence)-invalid"):
                validate(pred=pred)
        terminal_path.write_bytes(terminal_bytes)

        repair_path = self.root / predecessor["repair_evidence"]["path"]
        repair_bytes = repair_path.read_bytes()
        repair = json.loads(repair_bytes)
        for field, value in (("local_monitor_receipt", {"path": "missing.json",
                    "sha256": "0" * 64}),
                ("local_monitor_receipt", {**repair["local_monitor_receipt"],
                    "path": repair["local_monitor_receipt"]["path"].replace(
                        "coordinator-external-attempts/", "")}),
                ("bound_violation_reason", "other-bound-reason"),
                ("bound_violation_reason", None),
                ("original_failure_cause", "rss-root-cause-claimed"),
                ("original_failure_cause", None),
                ("local_monitor_cleanup", "unconfirmed"),
                ("local_monitor_cleanup", None),
                ("hosted_log", {"path": "wrong.log", "sha256": "0" * 64}),
                ("local_monitor_receipt", {**repair["local_monitor_receipt"], "sha256": "0" * 64}),
                ("hosted_log", {**repair["hosted_log"], "sha256": "0" * 64})):
            altered = {**repair, field: value}
            self._write_admission(repair_path, altered)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-(classification|evidence)-invalid"):
                validate(pred=pred)
        repair_path.write_bytes(repair_bytes)

        receipt_path = self.root / repair["local_monitor_receipt"]["path"]
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes)
        receipt["processes"][0]["process_group_cleanup"] = "unconfirmed"
        self._write_admission(receipt_path, receipt)
        altered_repair = {**repair, "local_monitor_receipt": self._reference(
            receipt_path, receipt_path.read_bytes())}
        self._write_admission(repair_path, altered_repair)
        altered_pred = {**predecessor, "repair_evidence": self._reference(
            repair_path, repair_path.read_bytes())}
        with self.assertRaisesRegex(ValueError, "diagnostic-evidence-invalid"):
            validate(pred=altered_pred)
        receipt_path.write_bytes(receipt_bytes)
        repair_path.write_bytes(repair_bytes)

        for mutation in (
                lambda value: value.update(argv=["gh", "pr", "view", "99", "--repo",
                    "szTheory/genewhip", "--json",
                    "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"]),
                lambda value: value["processes"][0].update(bound_violation=False),
                lambda value: value["processes"][0].update(pgid=58202)):
            value = json.loads(receipt_bytes)
            mutation(value)
            self._write_admission(receipt_path, value)
            altered_repair = {**repair, "local_monitor_receipt": self._reference(
                receipt_path, receipt_path.read_bytes())}
            self._write_admission(repair_path, altered_repair)
            altered_pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.assertRaisesRegex(ValueError, "diagnostic-evidence-invalid"):
                validate(pred=altered_pred)
        receipt_path.write_bytes(receipt_bytes)
        repair_path.write_bytes(repair_bytes)

        log_path = self.root / repair["hosted_log"]["path"]
        log_bytes = log_path.read_bytes()
        wrong_job_log = self.batch_root / "ci-failure/product-smoke-999.log"
        wrong_job_log.write_bytes(log_bytes)
        altered_repair = {**repair, "hosted_log": self._reference(wrong_job_log, log_bytes)}
        self._write_admission(repair_path, altered_repair)
        altered_pred = {**predecessor, "repair_evidence": self._reference(
            repair_path, repair_path.read_bytes())}
        with self.assertRaisesRegex(ValueError, "diagnostic-evidence-invalid"):
            validate(pred=altered_pred)
        log_path.write_text("tank-battle/full-route: process failed\nBOUND: other\n")
        altered_repair = {**repair, "hosted_log": self._reference(log_path, log_path.read_bytes())}
        self._write_admission(repair_path, altered_repair)
        altered_pred = {**predecessor, "repair_evidence": self._reference(
            repair_path, repair_path.read_bytes())}
        with self.assertRaisesRegex(ValueError, "diagnostic-evidence-invalid"):
            validate(pred=altered_pred)
        log_path.write_bytes(log_bytes)
        repair_path.write_bytes(repair_bytes)

        partial = dict(pins)
        changed_path = next(iter(BATCH.RSS_DIAGNOSTIC_SOURCE_PATHS))
        changed_source = self.root / changed_path
        fresh_source_bytes = changed_source.read_bytes()
        changed_source.write_bytes(b"# prior diagnostic fixture\n")
        partial[changed_path] = self.pins[changed_path]
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=partial)
        changed_source.write_bytes(fresh_source_bytes)

    def _diagnostic_publication(self, *, merged=False, resumed=False, latch_error=False,
                                failed=False):
        path = self.root / "scripts/release/v02_qualification.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", path)
        coordinator = self._configure_coordinator(load(path, "gw_diagnostic_publication"))
        head, base = "c" * 40, "d" * 40
        self.publication.mkdir(parents=True)
        packet = {"repository": "szTheory/genewhip", "public_identity": {
            "head_sha": head, "base_sha": base}}
        admission = {"admission": {"disposition": "bounded-diagnostic-followup"}}
        self.diagnostic_calls = []
        checks = [{"name": name, "status": "COMPLETED", "conclusion":
            "SUCCESS" if name in BATCH.PREVIEW_REQUIRED_LANES else "SKIPPED"}
            for name in sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS)]
        if failed:
            for row in checks:
                if row["name"] in {"safety", "required-ci"}:
                    row["conclusion"] = "FAILURE"
        def external(argv, **kwargs):
            self.diagnostic_calls.append(argv)
            if argv[:2] == ["git", "push"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:3] == ["gh", "pr", "list"]:
                value = [{"number": 19, "state": "MERGED" if merged else "OPEN",
                          "headRefOid": head, "baseRefName": "main"}]
            elif argv[:3] == ["gh", "pr", "view"]:
                value = {"number": 19, "state": "OPEN", "headRefOid": head,
                    "baseRefOid": base, "statusCheckRollup": checks,
                    "url": "https://github.com/szTheory/genewhip/pull/19"}
            else:
                raise AssertionError("diagnostic reached merge or dispatch boundary")
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")
        def latch(**kwargs):
            if latch_error:
                raise OSError("synthetic stop-record failure")
            self.expected_failure_paths.add(self.batch_root / "failure.json")
            return BATCH.write_failure_sentinel(self.root, attempt_root=self.batch_root,
                observed_at="2026-10-31T12:55:00+00:00", **kwargs)
        if resumed:
            self._write_admission(self.journal, {"schema": "genewhip.v02-delivery-journal.v1",
                "repository": packet["repository"], "source_head": head,
                "public_base_sha": base, "started_at": self.started,
                "public_source_sha": "e" * 40})
        with ExitStack() as stack:
            for name, value in {"_fresh_batch_guard": mock.Mock(return_value=admission),
                    "_require_campaign_for_journal": mock.Mock(),
                    "_valid_packet_for_delivery": mock.Mock(return_value=packet),
                    "_fresh_public_policy": mock.Mock(return_value={}),
                    "_require_hosted_budget": mock.Mock(return_value=3600),
                    "_external": mock.Mock(side_effect=external),
                    "_write_fresh_batch_failure": mock.Mock(side_effect=latch),
                    "_verified_merge_receipt": mock.Mock(side_effect=AssertionError("merge adopted")),
                    "_adopt_incomplete_merged_source": mock.Mock(side_effect=AssertionError("merge adopted"))}.items():
                stack.enter_context(mock.patch.object(coordinator, name, value))
            return coordinator.publish_sanitized_source(self.preparation, self.publication,
                self.journal, scope_path=self.root / BATCH.SCOPE_PATH,
                batch_authorization=self.auth, batch_authorization_sha256=BATCH.AUTH_SHA256,
                batch_admission=self.source_admission_path, batch_admission_sha256="a" * 64,
                batch_output_path=self.output)

    def test_green_diagnostic_ci_persists_stop_before_merge_and_reentry(self):
        result = self._diagnostic_publication()
        self.assertEqual(result["status"], "diagnostic-ci-complete")
        self.assertNotIn("public_source_sha", result)
        self.assertFalse(result["merge_attempted"])
        self.assertTrue(json.loads(self.journal.read_bytes())["assessment_required"])
        self.assertEqual(json.loads((self.batch_root / "failure.json").read_bytes())["reason"],
                         "diagnostic-ci-complete-assessment-required")
        with self.assertRaisesRegex(ValueError, "terminal-failure-present"):
            self._validate()

    def test_diagnostic_cli_writes_and_prints_an_assessment_result_not_a_merge(self):
        path = self.root / "scripts/release/v02_qualification.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", path)
        coordinator = self._configure_coordinator(load(path, "gw_diagnostic_cli"))
        result = {"status": "diagnostic-ci-complete", "assessment_required": True,
                  "diagnostic_only": True, "candidate_sha": "c" * 40,
                  "merge_attempted": False}
        stream = io.StringIO()
        with mock.patch.object(coordinator, "_fresh_batch_guard", return_value={
                "admission": {"disposition": "bounded-diagnostic-followup"}}), \
             mock.patch.object(coordinator, "publish_sanitized_source", return_value=result), \
             mock.patch.object(sys, "stdout", stream):
            status = coordinator.main(["--mode", "stage-public", "--scope",
                str(self.root / BATCH.SCOPE_PATH), "--journal", str(self.journal),
                "--publication-copy", str(self.publication), "--preflight", str(self.preparation),
                "--out", str(self.output), "--batch-authorization", str(self.auth),
                "--batch-authorization-sha256", BATCH.AUTH_SHA256,
                "--batch-admission", str(self.source_admission_path),
                "--batch-admission-sha256", "a" * 64])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(self.output.read_bytes())["status"], "diagnostic-ci-complete")
        self.assertTrue(stream.getvalue().startswith("public-source-diagnostic:"))
        self.assertNotIn("public-source-delivery: merged", stream.getvalue())

    def test_diagnostic_stop_write_failure_cannot_reach_merge(self):
        with self.assertRaisesRegex(OSError, "synthetic stop-record failure"):
            self._diagnostic_publication(latch_error=True)

    def test_red_diagnostic_ci_remains_failed_without_merge(self):
        with self.assertRaisesRegex(ValueError, "required-public-pull-request-check-failed"):
            self._diagnostic_publication(failed=True)
        self.assertEqual(json.loads((self.batch_root / "failure.json").read_bytes())["reason"],
                         "pull-request-required-ci-failed")

    def test_legacy_retry_apis_cannot_rewrite_diagnostic_attempts(self):
        path = self.root / "scripts/release/v02_qualification.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", path)
        coordinator = self._configure_coordinator(load(path, "gw_diagnostic_legacy_rejection"))
        with mock.patch.object(coordinator, "_require_campaign_for_journal",
                               side_effect=AssertionError("legacy recovery reached")):
            for name in ("retry_sanitized_source", "source_successor_sanitized_source",
                         "failed_hosted_successor_sanitized_source"):
                with self.subTest(api=name), self.assertRaisesRegex(ValueError,
                        "fresh-batch-authorization-required"):
                    getattr(coordinator, name)(self.preparation, self.publication, self.journal,
                        scope_path=self.root / BATCH.SCOPE_PATH, campaign_path=None,
                        campaign_sha256=None, recovery_selection="17", continuation_path=None,
                        continuation_purpose="current-native-return")

    def test_diagnostic_cannot_adopt_an_already_merged_pr(self):
        with self.assertRaisesRegex(ValueError, "diagnostic-public-source-already-merged"):
            self._diagnostic_publication(merged=True)

    def test_diagnostic_cannot_reopen_a_merged_journal(self):
        with self.assertRaisesRegex(ValueError, "diagnostic-public-source-already-merged"):
            self._diagnostic_publication(resumed=True)

    def test_direct_hosted_api_rejects_diagnostic_before_publish_or_dispatch(self):
        path = self.root / "scripts/release/v02_qualification.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", path)
        coordinator = self._configure_coordinator(load(path, "gw_diagnostic_hosted_rejection"))
        with mock.patch.object(coordinator, "_fresh_batch_guard", return_value={
                "admission": {"disposition": "bounded-diagnostic-followup"}}), \
             mock.patch.object(coordinator, "publish_sanitized_source",
                               side_effect=AssertionError("diagnostic publish reached")), \
             mock.patch.object(coordinator, "_dispatch_qualification_run",
                               side_effect=AssertionError("diagnostic dispatch reached")):
            with self.assertRaisesRegex(ValueError, "diagnostic-admission-prohibits-hosted"):
                coordinator.run_hosted_qualification(self.preparation, self.publication,
                    self.root / BATCH.SCOPE_PATH, self.output, self.journal,
                    batch_authorization=self.auth, batch_authorization_sha256=BATCH.AUTH_SHA256,
                    batch_admission=self.source_admission_path, batch_admission_sha256="a" * 64)

    def test_successor_attempt_requires_terminal_chain_and_claim_is_idempotent(self):
        first = self._validate()
        claim = Path(first["successor_claim"])
        claim_bytes = claim.read_bytes()
        self.assertEqual(self._validate()["successor_claim"], claim)
        identity = first["predecessor_identity_sha256"]
        with self.assertRaisesRegex(ValueError, "already-claimed"):
            BATCH._claim_successor(self.root, predecessor_sha256=identity,
                predecessor_record_sha256=first["predecessor_sha256"],
                attempt_root=self.batch_root.relative_to(self.root).as_posix(),
                source_payload_sha256="f" * 64)
        changed_metadata = dict(self.predecessor)
        changed_metadata["disposition"] = "evidence-backed-infrastructure-retry"
        with self.assertRaisesRegex(ValueError, "already-claimed"):
            BATCH._claim_successor(self.root,
                predecessor_sha256=BATCH._predecessor_identity_sha256(changed_metadata),
                predecessor_record_sha256=hashlib.sha256(
                    BATCH._canonical(changed_metadata)).hexdigest(),
                attempt_root=self.batch_root.relative_to(self.root).as_posix(),
                source_payload_sha256="e" * 64)

        failure_path = self.batch_root / "failure.json"
        self.expected_failure_paths.add(failure_path)
        BATCH.write_failure_sentinel(self.root, attempt_root=self.batch_root,
            stage="preview-ci", reason="required-ci-failed",
            observed_at="2026-10-31T12:55:00+00:00")
        journal_path = self.batch_root / "hosted-delivery-journal.json"
        journal_bytes = b'{"schema":"genewhip.v02-delivery-journal.v1","status":"failed"}\n'
        journal_path.write_bytes(journal_bytes)
        terminal_path = self.batch_root / "terminal-observation.json"
        terminal_bytes = json.dumps({"all_jobs_terminal": True,
            "event": "pull_request", "jobs": synthetic_preview_jobs(),
            "safety_job_failed": False, "qualification_accepted": False,
            "full_qualification_dispatched": False,
            "cleanup_disposition": "not-applicable"}, sort_keys=True).encode() + b"\n"
        terminal_path.write_bytes(terminal_bytes)
        repair_path = self.batch_root / "repair-evidence.json"
        repair_bytes = json.dumps({"live_retry_authorized": False,
            "safety_or_cleanup_issue": False, "cleanup_disposition": "not-applicable",
            "qualification_accepted": False,
            "infrastructure_retry_reason": "runner-transient"}, sort_keys=True).encode() + b"\n"
        repair_path.write_bytes(repair_bytes)
        source_ref = self._reference(self.source_admission_path,
                                     self.source_admission_path.read_bytes())
        predecessor = {"attempt_index": 1,
            "attempt_root": self.batch_root.relative_to(self.root).as_posix(),
            "failure": self._reference(failure_path, failure_path.read_bytes()),
            "journal": self._reference(journal_path, journal_bytes),
            "terminal_observation": self._reference(terminal_path, terminal_bytes),
            "repair_evidence": self._reference(repair_path, repair_bytes),
            "cleanup_evidence": None, "source_admission": source_ref,
            "disposition": "evidence-backed-infrastructure-retry", "all_ci_terminal": True,
            "safety_status": "clear", "cleanup_status": "not-applicable",
            "unknown_high_findings": False}
        second_root = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        second_root.mkdir()
        rejected = self._source_admission(attempt_index=2, predecessor=predecessor,
            disposition="routine-source-repair")
        second_path = second_root / "source-admission.json"
        rejected_sha = self._write_admission(second_path, rejected)
        with self.assertRaisesRegex(ValueError, "source-repair-change-unproven"):
            BATCH.validate_batch(self.root, self.auth, BATCH.AUTH_SHA256,
                second_path, rejected_sha, stage="source-preparation", source_head=self.source_head,
                now=datetime.datetime.fromisoformat("2026-10-31T12:50:00+00:00"),
                scope_path=self.root / BATCH.SCOPE_PATH,
                journal_path=second_root / "hosted-delivery-journal.json",
                publication_copy=second_root / "candidate/publication-copy",
                preflight_path=second_root / "candidate/preparation.json",
                output_path=second_root / "candidate/result.json",
                source_is_ancestor=lambda ancestor, descendant: True,
                expected_source_paths=self.source_paths)
        second_claim = self.root / BATCH.POLICY_ROOT / "successors" / (
            BATCH._predecessor_identity_sha256(predecessor) + ".json")
        self.assertFalse(second_claim.exists())
        second_admission = self._source_admission(attempt_index=2, predecessor=predecessor,
            disposition="evidence-backed-infrastructure-retry")
        second_sha = self._write_admission(second_path, second_admission)
        result = BATCH.validate_batch(self.root, self.auth, BATCH.AUTH_SHA256,
            second_path, second_sha, stage="source-preparation", source_head=self.source_head,
            now=datetime.datetime.fromisoformat("2026-10-31T12:50:00+00:00"),
            scope_path=self.root / BATCH.SCOPE_PATH, journal_path=second_root / "hosted-delivery-journal.json",
            publication_copy=second_root / "candidate/publication-copy",
            preflight_path=second_root / "candidate/preparation.json",
            output_path=second_root / "candidate/result.json",
            source_is_ancestor=lambda ancestor, descendant: True,
            expected_source_paths=self.source_paths)
        self.assertEqual(result["attempt_index"], 2)
        self.assertTrue(claim.exists())
        self.assertEqual(claim.read_bytes(), claim_bytes)
        self.assertEqual(json.loads(claim_bytes)["attempt_root"],
                         self.batch_root.relative_to(self.root).as_posix())

    def test_fixed_authority_rejects_stale_digest_old_journal_scope_and_future_or_expired_clock(self):
        with self.assertRaisesRegex(ValueError, "authorization-path-or-pin-invalid"):
            BATCH.validate_batch(self.root, self.auth, "0" * 64, self.source_admission_path,
                hashlib.sha256(self.source_admission_path.read_bytes()).hexdigest(),
                stage="source-preparation", source_head=self.source_head,
                now=datetime.datetime.fromisoformat("2026-10-31T12:50:00+00:00"),
                scope_path=self.root / BATCH.SCOPE_PATH, journal_path=self.journal,
                publication_copy=self.publication, preflight_path=self.preparation,
                output_path=self.preparation, source_is_ancestor=lambda a, b: True,
                expected_source_paths=self.source_paths)
        journal = self.root / BATCH.OLD_JOURNAL_PATH
        journal.write_bytes(journal.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "old-history-changed"):
            self._validate()
        journal.write_bytes(self.old_journal_bytes)
        scope = self.root / BATCH.SCOPE_PATH
        scope.write_bytes(scope.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "scope-stale"):
            self._validate()
        scope.write_bytes(self.scope_bytes)
        for when in ("2026-10-31T12:43:18+00:00", "2026-11-01T06:43:19+00:00"):
            with self.assertRaisesRegex(ValueError, "runtime-window-expired-or-future"):
                self._validate(now=datetime.datetime.fromisoformat(when))

    def test_retry_requires_exact_previous_failure_and_journal_bytes(self):
        previous_failure = self.root / self.previous_failure_path
        previous_journal = self.root / self.previous_journal_path
        previous_failure.write_bytes(self.previous_failure_bytes + b" ")
        with self.assertRaisesRegex(ValueError, "predecessor-artifact-invalid"):
            self._validate()
        previous_failure.write_bytes(self.previous_failure_bytes)
        previous_journal.write_bytes(self.previous_journal_bytes + b" ")
        with self.assertRaisesRegex(ValueError, "predecessor-artifact-invalid"):
            self._validate()
        previous_journal.write_bytes(self.previous_journal_bytes)

    def test_unknown_safety_cleanup_or_skipped_attempt_chain_is_rejected(self):
        for field, value, expected in (
                ("safety_status", "failed", "predecessor-stop-condition"),
                ("unknown_high_findings", True, "predecessor-stop-condition"),
                ("cleanup_status", "unconfirmed", "predecessor-stop-condition")):
            with self.subTest(field=field):
                admission = dict(self.source_admission)
                admission["predecessor"] = dict(self.predecessor)
                admission["predecessor"][field] = value
                admission["source_payload_sha256"] = "0" * 64
                digest = self._write_admission(self.source_admission_path, admission)
                with self.assertRaisesRegex(ValueError, expected):
                    self._validate(admission_sha=digest)
        incomplete_terminal = {"all_jobs_terminal": True, "event": "pull_request",
            "jobs": [row for row in synthetic_preview_jobs() if row["name"] != "safety"],
            "full_qualification_dispatched": False, "safety_job_failed": False,
            "qualification_accepted": False}
        terminal_bytes = json.dumps(incomplete_terminal, sort_keys=True).encode() + b"\n"
        (self.root / self.previous_terminal_path).write_bytes(terminal_bytes)
        bad_predecessor = dict(self.predecessor)
        bad_predecessor["terminal_observation"] = self._reference(
            self.previous_terminal_path, terminal_bytes)
        with self.assertRaisesRegex(ValueError, "fresh-batch-initial-predecessor-mismatch"):
            BATCH._validate_predecessor(self.root, self.auth_value, attempt_index=1,
                                        predecessor=bad_predecessor)
        skipped_root = self.root / BATCH.POLICY_ROOT / "attempt-0003"
        skipped_root.mkdir()
        skipped = self._source_admission(attempt_index=3)
        path = skipped_root / "source-admission.json"
        digest = self._write_admission(path, skipped)
        with self.assertRaisesRegex(ValueError, "predecessor-index-invalid"):
            BATCH.validate_batch(self.root, self.auth, BATCH.AUTH_SHA256, path, digest,
                stage="source-preparation", source_head=self.source_head,
                now=datetime.datetime.fromisoformat("2026-10-31T12:50:00+00:00"),
                scope_path=self.root / BATCH.SCOPE_PATH,
                journal_path=skipped_root / "hosted-delivery-journal.json",
                publication_copy=skipped_root / "candidate/publication-copy",
                preflight_path=skipped_root / "candidate/preparation.json",
                output_path=skipped_root / "candidate/result.json",
                source_is_ancestor=lambda ancestor, descendant: True,
                expected_source_paths=self.source_paths)

    def test_current_target_reconciliation_requires_exact_receipt_and_fresh_snapshot(self):
        self._validate()
        prior_root = self.batch_root
        def write_json(path, value):
            raw = json.dumps(value, sort_keys=True).encode() + b"\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            return self._reference(path, raw)

        failure = {"schema": "genewhip.phase7-fresh-batch-failure.v1",
            "stage": "publication", "reason": "monitor-failure",
            "observed_at": "2026-10-31T14:54:48.224287+00:00"}
        failure_path = prior_root / "failure.json"
        failure_ref = write_json(failure_path, failure)
        self.expected_failure_paths.add(failure_path)
        journal_ref = write_json(prior_root / "hosted-delivery-journal.json",
            {"schema": "genewhip.v02-delivery-journal.v1", "status": "failed"})
        terminal_ref = write_json(prior_root / "terminal-observation.json", {
            "all_jobs_terminal": True, "event": "pull_request",
            "jobs": synthetic_preview_jobs(), "safety_job_failed": False,
            "qualification_accepted": False, "full_qualification_dispatched": False,
            "local_monitor_safety_issue": True})
        repair_ref = write_json(prior_root / "repair-evidence.json", {
            "live_retry_authorized": False, "had_cleanup_issue": True,
            "unresolved_current_safety_or_cleanup_issue": False,
            "qualification_accepted": False})
        pid = pgid = 73895
        receipt_ref = write_json(prior_root / "coordinator-external-attempts/process-receipts/"
            "bfa7a6689d684fb9975243e8e30061a4.json", {"processes": [{
                "pid": pid, "pgid": pgid, "process_group_cleanup": "unconfirmed",
                "cleanup_reason": "cleanup-permission-denied",
                "cleanup_status_observation": "not-observed",
                "bound_violation_reason": "phase7-rss-observation-unavailable"}]})
        snapshot_path = prior_root / "monitor-failure/process-snapshot.json"
        snapshot = {"schema": "genewhip.original10-readonly-process-snapshot.v1",
            "complete": True, "returncode": 0, "reason": None, "matching_rows": [],
            "signals_to_target_processes": False, "target_numeric_ids": [pid],
            "row_count_observed": 1175, "validated_rows": 1175, "row_cap": 4096,
            "observed_bytes": 155845, "stdout_cap_bytes": 1048576,
            "finished_at_utc": "2026-10-31T14:58:10.818656+00:00"}
        cleanup = {"schema": "genewhip.phase7-current-target-reconciliation.v1",
            "confirmation_type": "post-failure-current-target-inactive",
            "original_cleanup": "unconfirmed", "pid": pid, "pgid": pgid,
            "process_receipt": receipt_ref}
        cleanup_path = prior_root / "cleanup-evidence.json"
        predecessor = {"attempt_index": 1,
            "attempt_root": prior_root.relative_to(self.root).as_posix(),
            "failure": failure_ref, "journal": journal_ref,
            "terminal_observation": terminal_ref, "repair_evidence": repair_ref,
            "cleanup_evidence": None,
            "source_admission": self._reference(self.source_admission_path,
                self.source_admission_path.read_bytes()),
            "disposition": "evidence-backed-infrastructure-retry", "all_ci_terminal": True,
            "safety_status": "clear", "cleanup_status": "current-target-inactive",
            "unknown_high_findings": False}

        def validate_case(*, snapshot_changes=None, cleanup_changes=None,
                          repair_changes=None, accepted=True,
                          expected_error="current-target-reconciliation-invalid"):
            snapshot_value = {**snapshot, **(snapshot_changes or {})}
            snapshot_ref = write_json(snapshot_path, snapshot_value)
            record = {**cleanup, "snapshot": snapshot_ref, **(cleanup_changes or {})}
            cleanup_ref = write_json(cleanup_path, record)
            candidate = {**predecessor, "cleanup_evidence": cleanup_ref}
            if repair_changes:
                repair_value = {"live_retry_authorized": False, "had_cleanup_issue": True,
                    "unresolved_current_safety_or_cleanup_issue": False,
                    "qualification_accepted": False, **repair_changes}
                candidate["repair_evidence"] = write_json(prior_root / "repair-evidence.json",
                                                            repair_value)
            if accepted:
                BATCH._validate_predecessor(self.root, self.auth_value, attempt_index=2,
                                            predecessor=candidate)
            else:
                with self.assertRaisesRegex(ValueError, expected_error):
                    BATCH._validate_predecessor(self.root, self.auth_value, attempt_index=2,
                                                predecessor=candidate)

        validate_case()
        validate_case(cleanup_changes={"pid": pid + 1}, accepted=False)
        validate_case(cleanup_changes={"pgid": pgid + 1}, accepted=False)
        validate_case(cleanup_changes={"original_cleanup": "confirmed"}, accepted=False)
        validate_case(snapshot_changes={"complete": False}, accepted=False)
        validate_case(snapshot_changes={"matching_rows": [{"pid": pid}]}, accepted=False)
        validate_case(snapshot_changes={"signals_to_target_processes": True}, accepted=False)
        validate_case(snapshot_changes={"finished_at_utc": "2026-10-31T14:00:00+00:00"}, accepted=False)
        validate_case(snapshot_changes={"row_count_observed": 4097}, accepted=False)
        validate_case(repair_changes={"unresolved_current_safety_or_cleanup_issue": True},
                      accepted=False, expected_error="predecessor-repair-evidence-invalid")

    def test_ordinary_route_rejects_both_closed_and_current_batch_roots(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = load(coordinator_path, "gw_fresh_batch_closed_root_contract")
        self._configure_coordinator(coordinator)
        coordinator.FRESH_BATCH_POLICY_ROOT = BATCH.POLICY_ROOT
        coordinator.LEGACY_BATCH_ROOTS = (Path("build/v02/batch-closed"),
            Path("build/v02/batch-closed-retry1"), BATCH.POLICY_ROOT)
        for batch_root in coordinator.LEGACY_BATCH_ROOTS:
            with self.subTest(batch_root=batch_root.as_posix()):
                with self.assertRaisesRegex(ValueError, "fresh-batch-authorization-required"):
                    coordinator._fresh_batch_guard(
                        batch_authorization=None, batch_authorization_sha256=None,
                        batch_admission=None, batch_admission_sha256=None,
                        stage="source-preparation", scope_path=self.root / "evidence/v02-execution.json",
                        journal_path=self.root / batch_root / "hosted-delivery-journal.json",
                        publication_copy=self.root / "elsewhere/publication-copy",
                        preflight_path=self.root / "elsewhere/preparation.json",
                        output_path=self.root / "elsewhere/result.json")

    def test_invalid_attempt_scratch_root_rejects_before_git_or_directory_creation(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = self._configure_coordinator(load(
            coordinator_path, "gw_fresh_batch_scratch_root_contract"))
        outside = self.root / "outside-attempt"
        outside.mkdir()
        old_root = self.root / "build/v02/batch-closed"
        old_root.mkdir(parents=True)
        symlink = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        symlink.symlink_to(outside, target_is_directory=True)
        for invalid in (old_root, symlink):
            with self.subTest(path=invalid.name), \
                 mock.patch.object(coordinator, "_external",
                                   side_effect=AssertionError("invalid path reached Git")):
                with self.assertRaisesRegex(ValueError, "attempt-namespace-invalid"):
                    coordinator._bounded_publication_paths(
                        self.root, fresh_attempt_root=invalid)
        self.assertFalse((old_root / "coordinator-external-attempts").exists())
        self.assertFalse((outside / "coordinator-external-attempts").exists())

    def test_clock_conflict_stale_source_pin_and_review_mismatch_reject(self):
        with mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": "2026-10-31T12:43:20+00:00"}):
            with self.assertRaisesRegex(ValueError, "environment-clock-conflict"):
                self._validate()
        changed = self.root / "scripts/release/v02_batch.py"
        changed.write_bytes(changed.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "source-pin-stale"):
            self._validate()
        changed.write_bytes(self.source_bytes["scripts/release/v02_batch.py"])
        review_ref = self.source_admission["source_reviews"]["code"]
        review_path = self.root / review_ref["path"]
        review_path.write_text(review_path.read_text().replace("status: accepted", "status: rejected"))
        review_ref["sha256"] = hashlib.sha256(review_path.read_bytes()).hexdigest()
        digest = self._write_admission(self.source_admission_path, self.source_admission)
        with self.assertRaisesRegex(ValueError, "review-stale-or-rejected"):
            self._validate(admission_sha=digest)

    def test_source_pin_roster_cannot_omit_a_tracked_dependency(self):
        self.source_admission["source_pins"].pop("scripts/ci/required-gate.sh")
        digest = self._write_admission(self.source_admission_path, self.source_admission)
        with self.assertRaisesRegex(ValueError, "source-pin-roster-stale"):
            self._validate(admission_sha=digest)

    def test_source_pin_cap_accepts_large_tracked_file_and_rejects_oversize_before_read(self):
        self.source_paths = set(self.source_paths)
        large_rel = "tests/evidence/large-source-fixture.bin"
        large_path = self.root / large_rel
        large_path.parent.mkdir(parents=True, exist_ok=True)
        large_bytes = b"x" * (9 * 1024 * 1024)
        large_path.write_bytes(large_bytes)
        self.source_paths.add(large_rel)
        pins = dict(self.pins)
        pins[large_rel] = hashlib.sha256(large_bytes).hexdigest()
        self._write_admission(self.source_admission_path, self._source_admission(pins))
        self.assertEqual(self._validate().get("started_at"), self.started)

        oversized_rel = "tests/evidence/oversized-source-fixture.bin"
        oversized = self.root / oversized_rel
        with oversized.open("wb") as stream:
            stream.truncate(BATCH.MAX_SOURCE_BYTES + 1)
        self.source_paths.add(oversized_rel)
        pins[oversized_rel] = "f" * 64
        digest = self._write_admission(self.source_admission_path, self._source_admission(pins))
        original_read_bytes = Path.read_bytes
        def reject_oversized_read(path):
            if path.resolve() == oversized.resolve():
                raise AssertionError("oversize-source-was-read-before-stat-rejection")
            return original_read_bytes(path)
        with mock.patch.object(Path, "read_bytes", reject_oversized_read):
            with self.assertRaisesRegex(ValueError, "source-pin-file-invalid"):
                self._validate(admission_sha=digest)

    def test_admission_alias_symlink_output_collision_and_terminal_failure_reject(self):
        with self.assertRaisesRegex(ValueError, "admission-path-invalid"):
            self._validate(admission_path=self.batch_root / "other.json", admission_sha="0" * 64)
        alias = self.batch_root / "source-admission-link.json"
        alias.symlink_to(self.source_admission_path)
        with self.assertRaisesRegex(ValueError, "admission-path-invalid"):
            self._validate(admission_path=alias, admission_sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "output-aliases-input"):
            self._validate(output=self.source_admission_path)
        alias_directory = self.batch_root / "candidate-alias"
        alias_directory.symlink_to(self.batch_root / "candidate", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "publication-path-invalid"):
            self._validate(publication=alias_directory / "publication-copy")
        with self.assertRaisesRegex(ValueError, "output-aliases-input"):
            self._validate(output=self.publication / "nested-output.json")
        with self.assertRaisesRegex(ValueError, "output-aliases-input"):
            self._validate(output=self.batch_root / "candidate")
        BATCH.write_failure_sentinel(self.root, attempt_root=self.batch_root,
            stage="preview-ci",
            reason="test-terminal-preview-failed", observed_at="2026-10-31T12:55:00+00:00")
        self.expected_failure_paths.add(self.batch_root / "failure.json")
        with self.assertRaisesRegex(ValueError, "terminal-failure-present"):
            self._validate()

    def test_intermediate_symlink_is_rejected_before_reading_a_review(self):
        target = self.root / "review-target"
        target.mkdir()
        review = self.root / self.source_admission["source_reviews"]["code"]["path"]
        raw = review.read_bytes()
        review.unlink()
        review.symlink_to(target / "review.md")
        self.source_admission["source_reviews"]["code"]["sha256"] = "0" * 64
        digest = self._write_admission(self.source_admission_path, self.source_admission)
        with self.assertRaisesRegex(ValueError, "review-file-invalid|path-symlink"):
            self._validate(admission_sha=digest)
        review.unlink()
        review.write_bytes(raw)

    def _public_admission(self, source_pins=None):
        self.publication.mkdir(parents=True)
        for relative in (source_pins or self.pins):
            source = self.root / relative
            target = self.publication / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        (self.publication / "LICENSE").write_text("Permission is hereby granted, free of charge, to any person obtaining a copy.\n")
        vectors = self.publication / "tests/vectors/manifest.json"
        vectors.parent.mkdir(parents=True, exist_ok=True)
        vectors.write_text('{"retained_files":[]}\n')
        destination_auth = self.root / "build/phase4/delivery-preflight.json"
        destination_auth.parent.mkdir(parents=True, exist_ok=True)
        destination_auth.write_text(json.dumps({"schema": "genewhip.publication-readiness-packet.v1",
            "history_disposition": "sanitized-snapshots-preserve-local-history",
            "repository": "szTheory/genewhip", "destination": {
                "owner_repository": "szTheory/genewhip", "visibility": "public"}}))
        policy_path = self.batch_root / "candidate/repository-policy.json"
        policy = {"schema": "genewhip.publication-readiness-packet.v1",
            "repository": "szTheory/genewhip", "destination": {"owner_repository": "szTheory/genewhip",
                "visibility": "public"}, "expected_identity": {"head": "c" * 40, "base": "d" * 40},
            "mutations_performed": 0,
            "repository_observations": {"ready": True, "blockers": [], "observations": {
                "visibility": "public", "default_branch": "main",
                "expected_identity": {"observed_default_branch_sha": "d" * 40},
                "branch_protection": {"required_status_checks": ["required-ci"],
                    "pull_request_required": True}, "auto_merge_enabled": True,
                "caller_write_permission": "write", "permitted_merge_methods": ["squash"]}},
            "privacy_scan": {"publication_copy": {"status": "pass"}}}
        policy_path.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n")
        manifest_sha = "b" * 64
        public_head, public_base, public_tree = "c" * 40, "d" * 40, "e" * 40
        prep = {"schema": "genewhip.v02-public-source-preflight.v1", "status": "prepared",
            "repository": "szTheory/genewhip", "mutations_performed": 0,
            "push_performed": False, "pull_request_opened": False,
            "workflow_dispatched": False,
            "source_identity": {"private_git_head": self.source_head,
                "source_manifest_sha256": manifest_sha},
            "source_manifest": [{"path": name} for name in sorted(source_pins or self.pins)],
            "publication_copy": self.publication.relative_to(self.root).as_posix(),
            "repository_preflight": policy_path.relative_to(self.root).as_posix(),
            "public_identity": {"head_sha": public_head, "base_sha": public_base,
                "tree_sha": public_tree}, "source_manifest_sha256": manifest_sha,
            "privacy": {"status": "pass"}, "blockers": []}
        self.preparation.parent.mkdir(parents=True, exist_ok=True)
        prep_bytes = json.dumps(prep, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.preparation.write_bytes(prep_bytes)
        candidate = {"preparation_path": self.preparation.relative_to(self.root).as_posix(),
            "preparation_sha256": hashlib.sha256(prep_bytes).hexdigest(),
            "publication_path": self.publication.relative_to(self.root).as_posix(),
            "repository_policy_path": policy_path.relative_to(self.root).as_posix(),
            "repository_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "public_head": public_head, "public_base": public_base,
            "public_tree": public_tree, "source_manifest_sha256": manifest_sha}
        source_admission = self._source_admission(source_pins)
        source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, attempt_root=self.batch_root.relative_to(self.root).as_posix(),
            attempt_index=1, predecessor=self.predecessor,
            disposition="routine-source-repair", source_pins=source_pins or self.pins)
        candidate_payload = BATCH.candidate_review_payload(source_payload, candidate)
        candidate_payload_sha = hashlib.sha256(BATCH._canonical(candidate_payload)).hexdigest()
        candidate["candidate_payload_sha256"] = candidate_payload_sha
        candidate["candidate_reviews"] = self._reviews("candidate", candidate_payload_sha)
        admission = {**source_admission, "status": "public-effects", "candidate": candidate}
        path = self.batch_root / "public-admission.json"
        digest = self._write_admission(path, admission)
        return path, digest, policy_path

    def test_public_admission_reopens_candidate_privacy_policy_and_two_fresh_reviews(self):
        path, digest, _ = self._public_admission()
        result = self._validate(stage="public-effects", admission_path=path, admission_sha=digest,
            output=self.output)
        self.assertEqual(result["started_at"], self.started)

    def test_positive_production_guard_packet_and_policy_validation_composition(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        hygiene_path = self.root / "scripts/ci/public_hygiene.py"
        hygiene_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/ci/public_hygiene.py", hygiene_path)
        batch_source = self._sandbox_batch_source()
        batch_path = self.root / "scripts/release/v02_batch.py"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        batch_bytes = batch_source.encode()
        batch_path.write_bytes(batch_bytes)
        source_pins = dict(self.pins)
        source_pins["scripts/release/v02_batch.py"] = hashlib.sha256(batch_bytes).hexdigest()
        path, digest, policy_path = self._public_admission(source_pins)
        coordinator = load(coordinator_path, "gw_fresh_batch_positive_composition")
        self._configure_coordinator(coordinator)
        preparation = json.loads(self.preparation.read_bytes())
        manifest_paths = sorted(row["path"] for row in preparation["source_manifest"])
        source_roster = sorted(source_pins)
        calls = []
        def fake_git(root, *args, check=True):
            if args == ("rev-parse", "HEAD"):
                return self.source_head if root.resolve() == self.root.resolve() else "c" * 40
            if args == ("rev-parse", "HEAD^{tree}"): return "e" * 40
            if args == ("rev-parse", "HEAD^"): return "d" * 40
            if args == ("symbolic-ref", "--short", "HEAD"): return "main"
            if args == ("show", "-s", "--format=%P", "c" * 40): return "d" * 40
            if args == ("for-each-ref", "--format=%(refname)"):
                return "refs/heads/main\nrefs/remotes/origin/main"
            if args == ("ls-files", "-z"): return "\0".join(manifest_paths)
            raise AssertionError("unexpected git validation query")
        def policy_value(head="c" * 40, base="d" * 40):
            return {"schema": "genewhip.publication-readiness-packet.v1",
                "repository": "szTheory/genewhip", "destination": {
                    "owner_repository": "szTheory/genewhip", "visibility": "public"},
                "expected_identity": {"head": head, "base": base}, "mutations_performed": 0,
                "repository_observations": {"ready": True, "blockers": [], "observations": {
                    "visibility": "public", "default_branch": "main",
                    "expected_identity": {"observed_default_branch_sha": base},
                    "branch_protection": {"required_status_checks": ["required-ci"],
                        "pull_request_required": True}, "auto_merge_enabled": True,
                    "caller_write_permission": "write", "permitted_merge_methods": ["squash"]}},
                "privacy_scan": {"publication_copy": {"status": "pass"}}}
        def fake_external(argv, **kwargs):
            calls.append(tuple(argv))
            if argv == ["git", "ls-files", "-z"]:
                return subprocess.CompletedProcess(argv, 0, "\0".join(source_roster) + "\0", "")
            if len(argv) == 5 and argv[:3] == ["git", "merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:3] == ["git", "remote", "get-url"]:
                return subprocess.CompletedProcess(argv, 0, "https://github.com/szTheory/genewhip.git\n", "")
            if argv[:4] == ["git", "fetch", "--no-tags", "origin"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:2] == ["git", "rev-parse"]:
                return subprocess.CompletedProcess(argv, 0, "d" * 40 + "\n", "")
            if "repository_preflight.py" in argv[1]:
                output_arg = argv[argv.index("--out") + 1]
                output = self.root / output_arg
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(policy_value(), sort_keys=True) + "\n")
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError("unexpected bounded process/API seam")
        policy_module = load(hygiene_path, "gw_fresh_batch_hygiene_positive")
        with mock.patch.object(coordinator, "_git", side_effect=fake_git), \
             mock.patch.object(coordinator, "_external", side_effect=fake_external), \
             mock.patch.object(policy_module.subprocess, "check_output",
                side_effect=["a" * 40 + "\n", "", ""]), \
             mock.patch.object(policy_module.subprocess, "run",
                return_value=subprocess.CompletedProcess(["git", "cat-file"], 0, "", "")):
            admitted = coordinator._fresh_batch_guard(batch_authorization=self.auth.resolve(),
                batch_authorization_sha256=BATCH.AUTH_SHA256, batch_admission=path.resolve(),
                batch_admission_sha256=digest, stage="public-effects",
                scope_path=(self.root / BATCH.SCOPE_PATH).resolve(), journal_path=self.journal.resolve(),
                publication_copy=self.publication.resolve(), preflight_path=self.preparation.resolve(),
                output_path=self.output.resolve())
            packet = coordinator._valid_packet_for_delivery(self.preparation.resolve(), self.publication.resolve())
            policy = coordinator._fresh_public_policy(packet, self.publication.resolve())
        self.assertEqual(admitted["started_at"], self.started)
        self.assertEqual(packet["status"], "prepared")
        self.assertTrue(policy["repository_observations"]["ready"])
        self.assertTrue(any(call[:2] == ("git", "ls-files") for call in calls))

        # Exercise the direct hosted API after a real successful admission. Only
        # remote/service and bounded process seams are controlled; the late
        # package failure runs through the real failure latch and next-entry guard.
        journal_value = {"started_at": self.started, "repository": "szTheory/genewhip"}
        source_receipt = {"public_source_sha": "c" * 40, "public_base_sha": "d" * 40}
        run = {"id": 101, "run_attempt": 1, "head_sha": "c" * 40}
        download = mock.Mock(side_effect=ValueError("synthetic-package-validation-failure"))
        def publish_stub(*args, **kwargs):
            self.journal.write_text(json.dumps(journal_value))
            return source_receipt
        with mock.patch.object(coordinator, "_git", side_effect=fake_git), \
             mock.patch.object(coordinator, "_external", side_effect=fake_external), \
             mock.patch.object(coordinator, "publish_sanitized_source", side_effect=publish_stub), \
             mock.patch.object(coordinator, "_gh_json",
                return_value={"object": {"sha": "c" * 40}}), \
             mock.patch.object(coordinator, "_wait_for_fresh_batch_push_ci",
                return_value={"id": 100}), \
             mock.patch.object(coordinator, "_dispatch_qualification_run", return_value="nonce"), \
             mock.patch.object(coordinator, "_wait_for_exact_qualification_run", return_value=run), \
             mock.patch.object(coordinator, "_wait_for_selected_run_completion", return_value=run), \
             mock.patch.object(coordinator, "_validate_hosted_run", return_value={
                "run_id": "101", "run_attempt": "1", "event": "workflow_dispatch",
                "created_at": "2026-10-31T12:50:00Z"}), \
             mock.patch.object(coordinator, "_require_hosted_budget", return_value=3600), \
             mock.patch.object(coordinator, "_download_run_artifact", download):
            with self.assertRaisesRegex(ValueError, "synthetic-package-validation-failure"):
                coordinator.run_hosted_qualification(self.preparation.resolve(),
                    self.publication.resolve(), (self.root / BATCH.SCOPE_PATH).resolve(),
                    self.output.resolve(), self.journal.resolve(),
                    batch_authorization=self.auth.resolve(),
                    batch_authorization_sha256=BATCH.AUTH_SHA256,
                    batch_admission=path.resolve(), batch_admission_sha256=digest)
        self.assertEqual(download.call_count, 1)
        failure = self.batch_root / "failure.json"
        self.expected_failure_paths.add(failure)
        self.assertEqual(json.loads(failure.read_bytes())["stage"], "package")
        with mock.patch.object(coordinator, "_git", side_effect=fake_git), \
             mock.patch.object(coordinator, "_external", side_effect=fake_external):
            with self.assertRaisesRegex(ValueError, "terminal-failure-present"):
                coordinator._fresh_batch_guard(batch_authorization=self.auth.resolve(),
                    batch_authorization_sha256=BATCH.AUTH_SHA256,
                    batch_admission=path.resolve(), batch_admission_sha256=digest,
                    stage="public-effects", scope_path=(self.root / BATCH.SCOPE_PATH).resolve(),
                    journal_path=self.journal.resolve(), publication_copy=self.publication.resolve(),
                    preflight_path=self.preparation.resolve(), output_path=self.output.resolve())

    def test_public_admission_rejects_missing_reviews_stale_candidate_or_policy_failure(self):
        path, digest, policy_path = self._public_admission()
        good_admission = json.loads(path.read_bytes())
        admission = json.loads(path.read_bytes())
        admission["candidate"]["candidate_reviews"].pop("security")
        digest = self._write_admission(path, admission)
        with self.assertRaisesRegex(ValueError, "candidate-reviews-missing"):
            self._validate(stage="public-effects", admission_path=path, admission_sha=digest,
                output=self.output)
        digest = self._write_admission(path, good_admission)
        policy = json.loads(policy_path.read_bytes())
        policy["repository_observations"]["ready"] = False
        policy_path.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaisesRegex(ValueError, "candidate-or-policy-stale"):
            self._validate(stage="public-effects", admission_path=path, admission_sha=digest,
                output=self.output)

    def test_fresh_partition_preserves_runtime_package_and_close_boundaries(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = load(coordinator_path, "gw_fresh_batch_budget_contract")
        scope = {"qualification_batch": {"wall_seconds": 86400, "runtime_wall_seconds": 64800,
            "package_wall_seconds": 14400, "close_wall_seconds": 7200}}
        self.assertGreater(coordinator._require_hosted_budget(self.started,
            "2026-11-01T06:43:18+00:00", scope, phase="runtime"), 0)
        with self.assertRaisesRegex(ValueError, "runtime-partition-deadline"):
            coordinator._require_hosted_budget(self.started,
                "2026-11-01T06:43:19+00:00", scope, phase="runtime")
        self.assertGreater(coordinator._require_hosted_budget(self.started,
            "2026-11-01T10:43:18+00:00", scope, phase="package"), 0)
        with self.assertRaisesRegex(ValueError, "package-partition-deadline"):
            coordinator._require_hosted_budget(self.started,
                "2026-11-01T10:43:19+00:00", scope, phase="package")

    def test_production_api_requires_fresh_batch_admission_before_packet_or_effects(self):
        # The caller enters the real publication API. Its only permitted fake is
        # the read-only Git ancestry boundary; an old source-preparation admission
        # cannot reach packet validation, repository policy, GitHub, or the journal.
        qualification_path = self.root / "scripts/release/v02_qualification.py"
        qualification_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", qualification_path)
        coordinator = load(qualification_path, "gw_fresh_batch_coordinator_test")
        self._configure_coordinator(coordinator)
        with mock.patch.object(coordinator, "_git", side_effect=AssertionError("incomplete admission reached git")), \
             mock.patch.object(coordinator, "_valid_packet_for_delivery",
                               side_effect=AssertionError("packet/effect boundary reached")):
            with self.assertRaisesRegex(ValueError, "authorization-and-admission-required"):
                coordinator.publish_sanitized_source(self.preparation, self.publication, self.journal,
                    batch_authorization=self.auth, batch_authorization_sha256=BATCH.AUTH_SHA256,
                    batch_output_path=self.output)
        self.assertFalse(self.journal.exists())

    def test_direct_hosted_api_rejects_output_inside_candidate_before_effects(self):
        source_pins = dict(self.pins)
        files = {
            "scripts/release/v02_qualification.py": ROOT / "scripts/release/v02_qualification.py",
            "tests/evidence/phase7_fresh_batch_contract.py": ROOT / "tests/evidence/phase7_fresh_batch_contract.py",
            "scripts/ci/required-gate.sh": ROOT / "scripts/ci/required-gate.sh"}
        for relative, original in files.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)

        batch_source = self._sandbox_batch_source()
        batch_path = self.root / "scripts/release/v02_batch.py"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        batch_bytes = batch_source.encode()
        batch_path.write_bytes(batch_bytes)
        source_pins["scripts/release/v02_batch.py"] = hashlib.sha256(batch_bytes).hexdigest()
        admission_path, admission_sha, _ = self._public_admission(source_pins)
        coordinator = load(self.root / "scripts/release/v02_qualification.py",
                           "gw_fresh_batch_hosted_api")
        self._configure_coordinator(coordinator)
        source_roster = sorted(source_pins)
        calls = []

        def fake_external(argv, **kwargs):
            calls.append(argv)
            if argv == ["git", "ls-files", "-z"]:
                return subprocess.CompletedProcess(argv, 0, "\0".join(source_roster) + "\0", "")
            if len(argv) == 5 and argv[:3] == ["git", "merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError("unexpected external effect reached")

        output = self.publication / "nested-result.json"
        before = {item.relative_to(self.publication): hashlib.sha256(item.read_bytes()).hexdigest()
                  for item in self.publication.rglob("*") if item.is_file()}
        with mock.patch.object(coordinator, "_git", return_value=self.source_head), \
             mock.patch.object(coordinator, "_external", side_effect=fake_external), \
             mock.patch.object(coordinator, "_require_campaign_for_journal",
                               side_effect=AssertionError("campaign/effect boundary reached")), \
             mock.patch.object(coordinator, "publish_sanitized_source",
                               side_effect=AssertionError("publication boundary reached")):
            with self.assertRaisesRegex(ValueError, "output-aliases-input"):
                coordinator.run_hosted_qualification(self.preparation, self.publication,
                    self.root / BATCH.SCOPE_PATH, output, self.journal,
                    batch_authorization=self.auth, batch_authorization_sha256=BATCH.AUTH_SHA256,
                    batch_admission=admission_path, batch_admission_sha256=admission_sha)
        self.assertEqual(calls, [["git", "ls-files", "-z"]])
        self.assertFalse(output.exists())
        self.assertFalse(self.journal.exists())
        after = {item.relative_to(self.publication): hashlib.sha256(item.read_bytes()).hexdigest()
                 for item in self.publication.rglob("*") if item.is_file()}
        self.assertEqual(after, before)

    def test_merged_main_push_preview_waits_for_exact_successful_full_roster(self):
        coordinator_path = ROOT / "scripts/release/v02_qualification.py"
        copy_path = self.root / "scripts/release/v02_qualification.py"
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(coordinator_path, copy_path)
        batch_copy = self.root / "scripts/release/v02_batch.py"
        batch_copy.parent.mkdir(parents=True, exist_ok=True)
        batch_copy.write_text(self._sandbox_batch_source())
        coordinator = load(copy_path, "gw_fresh_batch_push_gate")
        self._configure_coordinator(coordinator)
        source = "f" * 40
        base_run = {"id": 77, "run_attempt": 1, "path": ".github/workflows/ci.yml@refs/heads/main",
            "event": "push", "head_branch": "main", "head_sha": source,
            "status": "in_progress", "conclusion": None,
            "repository": {"full_name": "szTheory/genewhip"},
            "created_at": "2026-10-31T12:50:00Z"}
        complete = {**base_run, "status": "completed", "conclusion": "success"}
        lanes = {"safety", "gameplay", "desktop", "package", "performance",
                 "product-smoke", "phase7-fast", "required-ci", "attestation"}
        skipped = {"v02-runtime", "extended", "v02-benchmark-control",
                   "v02-benchmark-recursion94", "v02-benchmark-tank-battle",
                   "v02-package", "v02-release-qualification"}
        jobs = ([{"name": name, "status": "completed", "conclusion": "success"}
                 for name in sorted(lanes)]
                + [{"name": name, "status": "completed", "conclusion": "skipped"}
                   for name in sorted(skipped)])
        self.assertEqual(len(jobs), 16)
        with mock.patch.object(coordinator, "_workflow_runs", side_effect=[[base_run], [complete]]), \
             mock.patch.object(coordinator, "_external", return_value=subprocess.CompletedProcess(
                 [], 0, json.dumps({"total_count": len(jobs), "jobs": jobs}), "")), \
             mock.patch.object(coordinator, "_require_hosted_budget", return_value=3600), \
             mock.patch.object(coordinator.time, "sleep", return_value=None):
            result = coordinator._wait_for_fresh_batch_push_ci("szTheory/genewhip", source,
                self.started, {"qualification_batch": {"close_wall_seconds": 7200}})
        self.assertEqual(result["id"], 77)

    def test_push_roster_rejects_missing_or_skipped_attestation_and_pr_keeps_skip(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = load(coordinator_path, "gw_fresh_batch_event_roster_contract")
        required = {"safety", "gameplay", "desktop", "package", "performance",
                    "product-smoke", "phase7-fast", "required-ci"}
        conditional = {"v02-runtime", "extended", "v02-benchmark-control",
            "v02-benchmark-recursion94", "v02-benchmark-tank-battle", "v02-package",
            "v02-release-qualification"}
        push_jobs = ([{"name": name, "status": "COMPLETED", "conclusion": "SUCCESS"}
                      for name in sorted(required | {"attestation"})]
                     + [{"name": name, "status": "COMPLETED", "conclusion": "SKIPPED"}
                        for name in sorted(conditional)])
        self.assertEqual(len(push_jobs), 16)
        self.assertIn("attestation", coordinator._validate_preview_rollup(
            push_jobs, error="push-roster-invalid", event="push"))
        with self.assertRaisesRegex(ValueError, "push-roster-invalid"):
            coordinator._validate_preview_rollup(
                [row for row in push_jobs if row["name"] != "attestation"],
                error="push-roster-invalid", event="push")
        wrong_attestation = [dict(row) for row in push_jobs]
        next(row for row in wrong_attestation if row["name"] == "attestation")["conclusion"] = "SKIPPED"
        with self.assertRaisesRegex(ValueError, "push-roster-invalid"):
            coordinator._validate_preview_rollup(
                wrong_attestation, error="push-roster-invalid", event="push")
        pr_jobs = ([{"name": name, "status": "COMPLETED", "conclusion": "SUCCESS"}
                    for name in sorted(required)]
                   + [{"name": name, "status": "COMPLETED", "conclusion": "SKIPPED"}
                      for name in sorted(conditional | {"attestation"})])
        self.assertEqual(len(pr_jobs), 16)
        self.assertIn("attestation", coordinator._validate_preview_rollup(
            pr_jobs, error="pr-roster-invalid"))

    def test_merged_main_push_preview_rejects_omitted_lane(self):
        coordinator_path = ROOT / "scripts/release/v02_qualification.py"
        copy_path = self.root / "scripts/release/v02_qualification.py"
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(coordinator_path, copy_path)
        batch_copy = self.root / "scripts/release/v02_batch.py"
        batch_copy.parent.mkdir(parents=True, exist_ok=True)
        batch_copy.write_text(self._sandbox_batch_source())
        coordinator = load(copy_path, "gw_fresh_batch_push_gate_negative")
        self._configure_coordinator(coordinator)
        source = "f" * 40
        run = {"id": 78, "run_attempt": 1, "path": ".github/workflows/ci.yml@refs/heads/main",
            "event": "push", "head_branch": "main", "head_sha": source,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": "szTheory/genewhip"},
            "created_at": "2026-10-31T12:50:00Z"}
        jobs = [{"name": "required-ci", "status": "completed", "conclusion": "success"}]
        with mock.patch.object(coordinator, "_workflow_runs", return_value=[run]), \
             mock.patch.object(coordinator, "_external", return_value=subprocess.CompletedProcess(
                 [], 0, json.dumps({"total_count": len(jobs), "jobs": jobs}), "")), \
             mock.patch.object(coordinator, "_require_hosted_budget", return_value=3600):
            with self.assertRaisesRegex(ValueError, "preview-roster-failed"):
                coordinator._wait_for_fresh_batch_push_ci("szTheory/genewhip", source,
                    self.started, {"qualification_batch": {"close_wall_seconds": 7200}})
        self.expected_failure_paths.add(self.batch_root / "failure.json")
        self.assertTrue((self.batch_root / "failure.json").exists())
        # The sentinel above is isolated to this temporary coordinator root.

    def test_merged_main_push_preview_rejects_a_run_created_before_batch_start(self):
        coordinator_path = ROOT / "scripts/release/v02_qualification.py"
        copy_path = self.root / "scripts/release/v02_qualification.py"
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(coordinator_path, copy_path)
        batch_copy = self.root / "scripts/release/v02_batch.py"
        batch_copy.parent.mkdir(parents=True, exist_ok=True)
        batch_copy.write_text(self._sandbox_batch_source())
        coordinator = load(copy_path, "gw_fresh_batch_push_gate_stale")
        self._configure_coordinator(coordinator)
        run = {"id": 79, "run_attempt": 1, "path": ".github/workflows/ci.yml@refs/heads/main",
            "event": "push", "head_branch": "main", "head_sha": "f" * 40,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": "szTheory/genewhip"},
            "created_at": "2026-10-31T12:43:18Z"}
        with mock.patch.object(coordinator, "_workflow_runs", return_value=[run]), \
             mock.patch.object(coordinator, "_require_hosted_budget", return_value=3600), \
             mock.patch.object(coordinator.time, "monotonic", side_effect=[0.0, 301.0]):
            with self.assertRaisesRegex(ValueError, "push-ci-not-found"):
                coordinator._wait_for_fresh_batch_push_ci("szTheory/genewhip", "f" * 40,
                    self.started, {"qualification_batch": {"close_wall_seconds": 7200}})
        self.expected_failure_paths.add(self.batch_root / "failure.json")


def main():
    runner = unittest.main(verbosity=2, exit=False)
    if fixture_environment_snapshot() != INITIAL_FIXTURE_ENV:
        raise AssertionError("fresh-batch-fixture-environment-not-restored")
    denial_self_test("after-contracts")
    if (DENIALS != ["subprocess.Popen", "os.kill", "os.killpg"] * 2
            or NATIVE_EVENTS != ["ctypes.dlopen"] * 2):
        raise AssertionError("fresh-batch-independent-denial-ledger-invalid")
    print("fresh-batch audit: real process starts=0, signals=0, native calls=0; "
          "pre/post sticky denial self-tests passed")
    if not runner.result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
