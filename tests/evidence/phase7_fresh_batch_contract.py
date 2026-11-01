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
            "tests/evidence/phase7_fresh_batch_contract.py", ".github/workflows/ci.yml",
            "scripts/ci/required-gate.sh"}
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
                  diagnostic_readiness_path=None, diagnostic_readiness_sha=None,
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
            expected_source_paths=self.source_paths,
            diagnostic_readiness_path=diagnostic_readiness_path,
            diagnostic_readiness_sha256=diagnostic_readiness_sha)

    def test_source_preparation_admission_accepts_exact_authority_and_all_source_pins(self):
        result = self._validate()
        self.assertEqual(result["started_at"], self.started)
        self.assertEqual(os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"], self.started)
        self.assertEqual(result["batch_root"], self.batch_root.resolve())

    def _diagnostic_successor(self, diagnostic_case=BATCH.DIAGNOSTIC_CASE,
                              diagnostic_profile=None):
        if diagnostic_case == BATCH.DIAGNOSTIC_CASE:
            diagnostic_paths = (set(BATCH.PHASE5_CLEANUP_DIAGNOSTIC_SOURCE_PATHS)
                if diagnostic_profile == "phase5-cleanup" else
                {"tests/evidence/phase5_baseline_contract.py",
                 "scripts/evidence/phase4_report.py", "tests/evidence/phase4_report_contract.py"})
        elif diagnostic_case == BATCH.FIRST_PARTY_CLEANUP_CONTROL_CASE:
            diagnostic_paths = set(BATCH.FIRST_PARTY_CLEANUP_CONTROL_SOURCE_PATHS)
        elif diagnostic_case == BATCH.NATIVE_HOST_RUNTIME_CASE:
            diagnostic_paths = set(BATCH.NATIVE_HOST_RUNTIME_SOURCE_PATHS)
        elif diagnostic_case == BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE:
            diagnostic_paths = set(BATCH.WORKFLOW_TIMEOUT_CONTRACT_SOURCE_PATHS)
        elif diagnostic_case == BATCH.PUBLICATION_RSS_OBSERVATION_CASE:
            diagnostic_paths = set(BATCH.PUBLICATION_RSS_OBSERVATION_SOURCE_PATHS)
        else:
            diagnostic_paths = set(BATCH.RSS_DIAGNOSTIC_SOURCE_PATHS)
        self.source_paths = set(self.source_paths) | diagnostic_paths
        for name in diagnostic_paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name != "tests/evidence/phase7_fresh_batch_contract.py":
                path.write_bytes(b"# prior diagnostic fixture\n")
            self.pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self._write_admission(self.source_admission_path, self._source_admission())
        self._validate()
        publication_rss_profile = diagnostic_case == BATCH.PUBLICATION_RSS_OBSERVATION_CASE
        if publication_rss_profile:
            source_admission = self._source_admission(disposition="bounded-diagnostic-followup")
            self._write_admission(self.source_admission_path, source_admission)
            identity = BATCH._predecessor_identity_sha256(source_admission["predecessor"])
            claim_path = self.root / BATCH.POLICY_ROOT / "successors" / f"{identity}.json"
            claim_path.write_bytes(BATCH._canonical({
                "schema": "genewhip.phase7-successor-claim.v1",
                "predecessor_sha256": identity,
                "attempt_root": self.batch_root.relative_to(self.root).as_posix(),
                "predecessor_record_sha256": hashlib.sha256(BATCH._canonical(
                    source_admission["predecessor"])).hexdigest(),
                "source_payload_sha256": source_admission["source_payload_sha256"]}) + b"\n")
        BATCH.write_failure_sentinel(self.root, attempt_root=self.batch_root,
            stage="publication" if publication_rss_profile else "preview-ci",
            reason="fresh-batch-publication-failed" if publication_rss_profile else "pull-request-required-ci-failed",
            observed_at="2026-10-31T12:55:00+00:00")
        self.expected_failure_paths.add(self.batch_root / "failure.json")
        self.journal.write_text('{"schema":"genewhip.v02-delivery-journal.v1"}\n')
        rss_profile = diagnostic_case == BATCH.RSS_DIAGNOSTIC_CASE
        cleanup_profile = diagnostic_profile == "phase5-cleanup"
        first_party_profile = diagnostic_case == BATCH.FIRST_PARTY_CLEANUP_CONTROL_CASE
        workflow_timeout_profile = diagnostic_case == BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE
        publication_rss_profile = diagnostic_case == BATCH.PUBLICATION_RSS_OBSERVATION_CASE
        failed_lanes = ({"product-smoke", "required-ci"} if rss_profile else
                        {"phase7-fast", "required-ci"} if workflow_timeout_profile else
                        {"safety", "phase7-fast", "required-ci"} if first_party_profile else
                        {"safety", "required-ci"} if not publication_rss_profile else set())
        canceled_lanes = {"safety", "desktop"} if rss_profile else set()
        if first_party_profile:
            canceled_lanes = {"product-smoke"}
        jobs = [{"name": name, "status": "completed", "conclusion":
            "failure" if name in failed_lanes else
            "cancelled" if name in canceled_lanes else
            "success" if name in BATCH.PREVIEW_REQUIRED_LANES else "skipped",
            **({"id": 124591302116} if rss_profile and name == "product-smoke" else
               {"id": 124617412421} if cleanup_profile and name == "safety" else
               {"id": 124626360017} if first_party_profile and name == "safety" else
               {"id": 124626360087} if first_party_profile and name == "phase7-fast" else
               {"id": 124700000001} if workflow_timeout_profile and name == "phase7-fast" else {})}
            for name in sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS)]
        if publication_rss_profile:
            for index, row in enumerate(jobs):
                row["id"] = 900000000100 + index
                row["run_id"] = 900000000041
        public_head, public_base = "c" * 40, "d" * 40
        if rss_profile or first_party_profile or workflow_timeout_profile or publication_rss_profile:
            self.journal.write_text(json.dumps({"schema": "genewhip.v02-delivery-journal.v1",
                "repository": "szTheory/genewhip", "source_head": public_head,
                "public_base_sha": public_base, "started_at": self.started,
                **({"push_performed": True} if publication_rss_profile else {})}, sort_keys=True) + "\n")
        terminal = {"all_jobs_terminal": True, "jobs": jobs,
            "event": "pull_request",
            "pull_request": {"state": "open", "merged": False,
                "number": 31 if rss_profile else 35 if first_party_profile else 40 if workflow_timeout_profile else 41 if publication_rss_profile else None,
                "head_sha": public_head if rss_profile or first_party_profile or workflow_timeout_profile or publication_rss_profile else "c" * 40,
                "base_sha": public_base if rss_profile or first_party_profile or workflow_timeout_profile or publication_rss_profile else "d" * 40},
            "safety_job_failed": not (rss_profile or workflow_timeout_profile or publication_rss_profile), "qualification_accepted": False,
            "full_qualification_dispatched": False, "local_monitor_safety_issue": publication_rss_profile,
            "owning_case": diagnostic_case,
            "failed_lane": "product-smoke" if rss_profile else
                "phase7-fast" if workflow_timeout_profile else
                "publication" if publication_rss_profile else
                "production" if cleanup_profile else "sanitizer",
            "native_lane": "passed", "hosted_cleanup_outcome": "unknown"}
        if cleanup_profile:
            terminal.update({"sanitizer_lane": "passed", "merge_attempted": False,
                "diagnostic_subcase": "stdout-cap",
                "failure_exception": "ValueError", "failure_status": "failed",
                "failure_cleanup": "unconfirmed", "failure_cleanup_error": "PermissionError",
                "failure_return": "missing", "failure_result": "cleanup-unconfirmed"})
        if rss_profile:
            terminal.update({"local_monitor_cleanup": "confirmed",
                "bound_violation_reason": "phase7-rss-observation-unavailable",
                "original_failure_cause": "unknown", "merge_attempted": False})
        if first_party_profile:
            terminal.update({"sanitizer_lane": "failed", "production_lane": "not-run",
                "merge_attempted": False, "failure_exception": "RuntimeError",
                "failure_cleanup": "unconfirmed", "cleanup_reason": "cleanup-permission-denied",
                "status_observation": "group-status-unavailable", "cleanup_queries": 3,
                "observer_failure_stage": "unknown", "cleanup_signal_phase": "unknown",
                "fast_job_failure": {"cases": [
                    "ProcessAdmissionContract.test_baseline_fake_cancel_and_setup_failure_always_cleanup",
                    "ProcessAdmissionContract.test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler"],
                    "exception": "AssertionError", "classification": "old mocked argument expectations",
                    "real_child_in_failing_cases": False}})
        if workflow_timeout_profile:
            terminal.update({"merge_attempted": False,
                "original_failure_cause": "unknown",
                "fast_job_failure": {
                    "outer_case": "test_default_unittest_suites_do_not_reach_any_os_process_seam",
                    "inner_case": BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE,
                    "exception": "AssertionError",
                    "expected_literal": "timeout-minutes: 360",
                    "classification": "workflow-timeout-expression-updated",
                    "real_child_in_failing_cases": False}})
        repair = {"live_retry_authorized": False, "diagnostic_only": True,
            "diagnostic_case": diagnostic_case, "safety_job_failed": not (rss_profile or workflow_timeout_profile or publication_rss_profile),
            "had_safety_job_failure": not (rss_profile or workflow_timeout_profile or publication_rss_profile), "hosted_cleanup_outcome": "unknown",
            "qualification_accepted": False, "unknown_high_findings": False}
        if cleanup_profile:
            repair.update({"diagnostic_profile": "phase5-cleanup",
                "diagnostic_subcase": "stdout-cap", "failure_exception": "ValueError",
                "failure_status": "failed", "failure_cleanup": "unconfirmed",
                "failure_cleanup_error": "PermissionError", "failure_return": "missing",
                "failure_result": "cleanup-unconfirmed"})
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
        if cleanup_profile:
            log_path = self.batch_root / "ci-failure/safety-job-124617412421.log"
            log_bytes = ("2026-10-31T00:00:00Z CTest process subcase: "
                "BaselineRecordContract.test_real_process_output_cap_timeout_and_status "
                "[stdout-cap; failure; exception=ValueError; status=failed; cleanup=unconfirmed; "
                "cleanup_error=PermissionError; return=missing; result=cleanup-unconfirmed]\n").encode()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_bytes(log_bytes)
            repair["hosted_log"] = self._reference(log_path, log_bytes)
        if first_party_profile:
            repair.update({"diagnostic_profile": "first-party-cleanup-control",
                "control": dict(BATCH.FIRST_PARTY_CLEANUP_CONTROL_METADATA),
                "safety_job_failed": True, "had_safety_job_failure": True,
                "failure_exception": "RuntimeError", "failure_cleanup": "unconfirmed",
                "cleanup_reason": "cleanup-permission-denied",
                "status_observation": "group-status-unavailable", "cleanup_queries": 3,
                "observer_failure_stage": "unknown", "cleanup_signal_phase": "unknown"})
            safety_log = self.batch_root / "ci-failure/safety-job-124626360017.log"
            safety_text = ("2026-10-31T00:00:00Z 100% tests passed out of 146\n"
                "2026-10-31T00:01:00Z CTest subtest failure: "
                "NativeParserContract.test_phase7_launcher_keeps_shorter_caller_deadline "
                "[error; exception=RuntimeError; cleanup=unconfirmed; bound=other; "
                "cleanup_reason=cleanup-permission-denied; status_observation=group-status-unavailable; cleanup_queries=3]\n"
                "2026-10-31T00:02:00Z 99% tests passed, 1 tests failed out of 146\n").encode()
            safety_log.parent.mkdir(parents=True, exist_ok=True)
            safety_log.write_bytes(safety_text)
            fast_log = self.batch_root / "ci-failure/phase7-fast-124626360087.log"
            call_actual = ("Actual: _terminate_process_group(<Mock id='{id}'>, status_budget="
                "{'remaining': 16, 'attempted': 0, 'last_reason': 'cleanup-unclassified', "
                "'status_reason': 'not-observed'})\n")
            fast_text = (
                "FAIL: test_baseline_fake_cancel_and_setup_failure_always_cleanup "
                "(__main__.ProcessAdmissionContract.test_baseline_fake_cancel_and_setup_failure_always_cleanup)\n"
                "Expected: _terminate_process_group(<Mock id='1234'>)\n" +
                call_actual.replace("{id}", "1234") +
                "FAIL: test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler "
                "(__main__.ProcessAdmissionContract.test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler)\n"
                "Expected: _terminate_process_group(<Mock id='5678'>)\n" +
                call_actual.replace("{id}", "5678") +
                "Ran 25 tests in 2.945s\nFAILED (failures=2)\n").encode()
            fast_log.parent.mkdir(parents=True, exist_ok=True)
            fast_log.write_bytes(fast_text)
            repair["hosted_logs"] = {
                "safety": self._reference(safety_log, safety_text),
                "phase7-fast": self._reference(fast_log, fast_text)}
        if publication_rss_profile:
            terminal.update({"workflow_run_id": 900000000041,
                "event_basis": "github_fetch_commit_workflow_runs:pull-request-filter",
                "queried_source_sha": public_head,
                "workflow_run": {"id": 900000000041, "status": "completed",
                    "conclusion": "success", "workflow_id": 392236816},
                "original_failure_cause": "unknown", "merge_attempted": False})
            capture_dir = self.batch_root / "ci-failure"
            capture_dir.mkdir(parents=True, exist_ok=True)
            pr_capture = {"number": 41, "state": "open", "merged": False,
                "head_sha": public_head, "base_sha": public_base}
            run_capture = {"provider": "github_fetch_commit_workflow_runs",
                "repo_full_name": "szTheory/genewhip", "commit_sha": public_head,
                "workflow_runs": [{"id": 900000000041, "status": "completed",
                    "conclusion": "success", "workflow_id": 392236816}]}
            for key, filename, value in (
                    ("pr", "pull-request-41.json", pr_capture),
                    ("workflow_runs", f"commit-workflow-runs-{public_head[:12]}.json", run_capture),
                    ("jobs", "jobs-900000000041.json", {"jobs": jobs})):
                path = capture_dir / filename
                raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                self._write_admission(path, value)
                terminal.setdefault("connector_captures", {})[key] = self._reference(path, raw)
            receipt_path = self.batch_root / "coordinator-external-attempts/external-12345-67890.attempt.json"
            receipt = {"schema": "genewhip.v02-coordinator-child-attempt.v1",
                "argv": ["gh", "pr", "view", "41", "--repo", "szTheory/genewhip", "--json",
                    "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"],
                "returncode": -15, "process_group_cleanup": "confirmed",
                "stderr_tail": "\nBOUND: phase7-rss-observation-unavailable",
                "processes": [{"pid": 12345, "pgid": 12345, "status": "failed",
                    "return_code": -15, "process_group_cleanup": "confirmed",
                    "bound_violation": True, "bound_violation_reason": "phase7-rss-observation-unavailable",
                    "rss_bytes_peak": 48_349_184, "rss_bytes_observed": 0,
                    "rss_observation_reason": "task-info-unavailable", "rss_observation_errno": "esrch",
                    "rss_observation_result": "missing", "stdout_bytes": 0, "stderr_bytes": 42,
                    "wall_seconds": 0.822}]}
            self._write_admission(receipt_path, receipt)
            repair.update({"diagnostic_profile": BATCH.PUBLICATION_RSS_OBSERVATION_PROFILE,
                "infrastructure_retry_reason": "observation-reconciliation",
                "local_monitor_receipt": self._reference(receipt_path, receipt_path.read_bytes()),
                "local_monitor_safety_issue": True, "local_monitor_cleanup": "confirmed",
                "original_failure_cause": "unknown", "merge_attempted": False,
                "full_qualification_dispatched": False, "qualification_accepted": False,
                "safety_job_failed": False, "had_safety_job_failure": False})
            source_admission = json.loads(self.source_admission_path.read_bytes())
            source_payload = BATCH.source_review_payload(source_head=source_admission["source_head"],
                started_at=source_admission["started_at"], attempt_root=self.batch_root.relative_to(self.root).as_posix(),
                attempt_index=source_admission["attempt_index"], predecessor=source_admission["predecessor"],
                disposition=source_admission["disposition"], source_pins=source_admission["source_pins"])
            candidate = {"preparation_sha256": "a" * 64,
                "repository_policy_sha256": "b" * 64,
                "public_head": public_head, "public_base": public_base,
                "public_tree": "e" * 40, "source_manifest_sha256": "f" * 64}
            candidate_payload = BATCH.candidate_review_payload(source_payload, candidate)
            candidate["candidate_payload_sha256"] = hashlib.sha256(BATCH._canonical(candidate_payload)).hexdigest()
            candidate["candidate_reviews"] = self._source_head_reviews(
                "publication-rss-candidate", candidate["candidate_payload_sha256"])
            public_admission = {**source_admission, "status": "public-effects", "candidate": candidate}
            public_path = self.batch_root / "public-admission.json"
            self._write_admission(public_path, public_admission)
            terminal["public_admission"] = self._reference(public_path, public_path.read_bytes())
        if workflow_timeout_profile:
            repair.update({"diagnostic_profile": BATCH.WORKFLOW_TIMEOUT_CONTRACT_PROFILE,
                "original_failure_cause": "unknown", "merge_attempted": False,
                "full_qualification_dispatched": False})
            fast_log = self.batch_root / "ci-failure/phase7-fast-124700000001.log"
            fast_text = (
                "FAIL: test_default_unittest_suites_do_not_reach_any_os_process_seam "
                "(__main__.ProcessAdmissionContract.test_default_unittest_suites_do_not_reach_any_os_process_seam)\n"
                "  File \"tests/evidence/phase7_process_admission_contract.py\", line 1, in "
                "test_default_unittest_suites_do_not_reach_any_os_process_seam\n"
                "  nested failure: QualificationCoordinatorContract "
                "testMethod=test_workflow_wires_real_product_smoke_and_serial_full_jobs\n"
                "    self.assertIn(\"timeout-minutes: 360\", text)\n"
                "    AssertionError: \\'timeout-minutes: 360\\' not found in workflow text\n"
                "AssertionError: Lists differ: nested failure details\n"
                "  repeated failure details: QualificationCoordinatorContract "
                "testMethod=test_workflow_wires_real_product_smoke_and_serial_full_jobs\n"
                "    self.assertIn(\"timeout-minutes: 360\", text)\n"
                "    AssertionError: \\'timeout-minutes: 360\\' not found in workflow text\n"
                "Ran 27 tests in 0.001s\nFAILED (failures=1)\n").encode()
            fast_log.parent.mkdir(parents=True, exist_ok=True)
            fast_log.write_bytes(fast_text)
            repair["hosted_log"] = self._reference(fast_log, fast_text)
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

    def _native_host_runtime_successor(self):
        second, predecessor, pins = self._diagnostic_successor(
            BATCH.NATIVE_HOST_RUNTIME_CASE, BATCH.NATIVE_HOST_RUNTIME_PROFILE)
        attempt_root = self.batch_root
        public_base, public_head = "b" * 40, "c" * 40
        nonce, run_id = "2b535a0debbb4f6cb380d84e7683c474", 41244409258
        created = "2026-10-31T21:36:49Z"
        job_outcomes = dict(BATCH.NATIVE_HOST_RUNTIME_OUTCOMES)
        terminal_jobs = []
        snapshot_jobs = []
        for index, name in enumerate(sorted(job_outcomes)):
            job_id = 124660000000 + index
            outcome = job_outcomes[name]
            failed_steps = (["Run complete current-source product safety and chunk roster"]
                if name == "v02-runtime" else
                ["Reject incomplete or stale required lanes"] if name == "required-ci" else [])
            terminal_jobs.append({"id": job_id, "name": name, "status": "completed",
                "conclusion": outcome})
            snapshot_jobs.append({"id": job_id, "name": name, "status": "completed",
                "conclusion": outcome, "run_id": run_id, "logs_url": None,
                "steps": [{"name": step, "status": "completed", "conclusion": "failure"}
                    for step in failed_steps] or [{"name": "Complete job", "status": "completed",
                        "conclusion": "success"}]})
        run = {"id": run_id, "event": "workflow_dispatch", "status": "completed",
            "conclusion": "failure", "path": ".github/workflows/ci.yml",
            "head_sha": public_head, "created_at": created, "run_attempt": 1,
            "display_title": f"Plan10 qualification {nonce}",
            "name": f"Plan10 qualification {nonce}",
            "head_branch": "main",
            "html_url": f"https://github.com/szTheory/genewhip/actions/runs/{run_id}",
            "head_commit": {"id": public_head, "tree_id": "d" * 40},
            "repository": {"full_name": "szTheory/genewhip", "private": False,
                "owner": {"login": "szTheory"}},
            "head_repository": {"full_name": "szTheory/genewhip", "private": False}}
        journal_value = {"schema": "genewhip.v02-delivery-journal.v1",
            "repository": "szTheory/genewhip", "source_head": public_head,
            "public_base_sha": public_base, "public_source_sha": public_head,
            "candidate_sha": "a" * 40, "tree_sha": "d" * 40,
            "started_at": self.started, "qualification_started_at": self.started,
            "qualification_dispatch_requested": True, "qualification_dispatch_submitted": True,
            "qualification_dispatch_nonce": nonce, "selected_run_created_at": created,
            "pull_request": "38", "merge_parents": [public_base], "merge_strategy": "squash"}
        journal_path = attempt_root / "hosted-delivery-journal.json"
        self._write_admission(journal_path, journal_value)
        failure_path = attempt_root / "failure.json"
        self._write_admission(failure_path, {"schema": "genewhip.phase7-fresh-batch-failure.v1",
            "authorization_sha256": BATCH.AUTH_SHA256, "stage": "qualification",
            "reason": "fresh-batch-qualification-failed",
            "observed_at": "2026-10-31T21:57:06.732067+00:00"})
        predecessor["failure"] = self._reference(failure_path, failure_path.read_bytes())
        delivery = {"schema": "genewhip.v02-public-source-delivery.v1", "status": "merged",
            "public_source_sha": public_head, "public_base_sha": public_base,
            "candidate_sha": journal_value["candidate_sha"], "tree_sha": journal_value["tree_sha"],
            "pull_request": "38", "merge_parents": [public_base], "merge_strategy": "squash"}
        delivery_path = attempt_root / "source-delivery.json"
        self._write_admission(delivery_path, delivery)
        terminal_dir = attempt_root / f"terminal-record-{run_id}"
        terminal_dir.mkdir(parents=True, exist_ok=True)
        run_path, jobs_path = terminal_dir / "run.json", terminal_dir / "jobs.json"
        self._write_admission(run_path, run)
        self._write_admission(jobs_path, snapshot_jobs)
        safe_line = ("REJECT: qualification-child-failed:runtime:1:BLOCKED: "
            "phase7-host-batch-failed:backend=native;report=fail;"
            "case=recursion94/withhold-first-plate;row=fail;return=1;"
            "cleanup=confirmed;bound=none;cleanup_reason=missing;"
            "status_observation=missing;cleanup_queries=other")
        log_path = terminal_dir / "v02-runtime-job.log"
        log_path.write_text(safe_line + "\n")
        runtime_job = next(row for row in terminal_jobs if row["name"] == "v02-runtime")
        packet_jobs = []
        for row in terminal_jobs:
            failures = [step.get("name") for step in next(item for item in snapshot_jobs
                if item["name"] == row["name"]).get("steps", [])
                if step.get("conclusion") == "failure"]
            packet_jobs.append({**row, "failed_steps": failures})
        packet = {"schema": "genewhip.phase7-attempt-terminal-evidence.v1",
            "attempt_root": attempt_root.relative_to(self.root).as_posix(), "nonce": nonce,
            "coordinator_terminal": {"exit_code": 1,
                "failure_record_observed_at": "2026-10-31T21:57:06.732067+00:00",
                "failure_record_reason": "fresh-batch-qualification-failed",
                "failure_record_stage": "qualification"},
            "source_commit": public_head, "public_tree": journal_value["tree_sha"],
            "qualification_state": "failed/nonqualifying; no acceptance, inventory, or release claim",
            "workflow_run": {key: run[key] for key in ("id", "name", "event", "status",
                "conclusion", "created_at", "head_sha", "path", "run_attempt", "display_title", "html_url")},
            "jobs": packet_jobs,
            "job_totals": {"conclusions": {"failure": 2, "skipped": 7, "success": 7}, "total": 16},
            "pull_request": {"number": 38, "state": "closed", "merged": True,
                "head_sha": public_head, "base_sha": public_base,
                "merge_commit_sha": public_head},
            "runtime_failure": {"job_id": runtime_job["id"],
                "failed_step": "Run complete current-source product safety and chunk roster",
                "bounded_failure_line": safe_line,
                "cause_limit": "Retained hosted log has no underlying assertion/test traceback; do not infer cause.",
                "log": {"path": log_path.relative_to(self.root).as_posix(),
                    "sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
                    "bytes": log_path.stat().st_size}}}
        packet_path = terminal_dir / "terminal-packet.json"
        self._write_admission(packet_path, packet)
        terminal = {"schema": "genewhip.phase7-terminal-observation.v1", "attempt_index": 1,
            "attempt_root": attempt_root.relative_to(self.root).as_posix(), "all_jobs_terminal": True,
            "event": "workflow_dispatch", "workflow_run_id": run_id, "run_attempt": 1,
            "created_at": created, "run_status": "completed", "run_conclusion": "failure",
            "head_sha": public_head, "started_at": self.started,
            "qualification_dispatch_nonce": nonce, "qualification_run": run,
            "qualification_jobs": snapshot_jobs, "jobs": terminal_jobs,
            "qualification_run_snapshot": self._reference(run_path, run_path.read_bytes()),
            "qualification_jobs_snapshot": self._reference(jobs_path, jobs_path.read_bytes()),
            "terminal_packet": self._reference(packet_path, packet_path.read_bytes()),
            "hosted_log": self._reference(log_path, log_path.read_bytes()),
            "source_delivery": self._reference(delivery_path, delivery_path.read_bytes()),
            "hosted_delivery_journal": self._reference(journal_path, journal_path.read_bytes()),
            "diagnostic_profile": BATCH.NATIVE_HOST_RUNTIME_PROFILE,
            "owning_case": BATCH.NATIVE_HOST_RUNTIME_CASE, "failed_lane": "v02-runtime",
            "inner_row_cleanup": "confirmed", "inner_row_bound": "none", "batch_return": 1,
            "outer_runtime_cleanup": "unknown", "hosted_cleanup_outcome": "unknown",
            "desktop_child_return": "unknown", "original_failure_cause": "unknown",
            "local_monitor_safety_issue": False, "local_monitor_cleanup": "confirmed",
            "safety_job_failed": False, "qualification_accepted": False,
            "full_qualification_dispatched": True, "merge_attempted": True,
            "actual_pr_merged": True, "pull_request": {"number": 38, "state": "closed",
                "merged": True, "head_sha": public_head, "base_sha": public_base,
                "merge_commit_sha": public_head}}
        terminal_path = attempt_root / "terminal-observation.json"
        self._write_admission(terminal_path, terminal)
        repair_path = attempt_root / "repair-evidence.json"
        repair = {"live_retry_authorized": False, "diagnostic_only": True,
            "diagnostic_case": BATCH.NATIVE_HOST_RUNTIME_CASE,
            "diagnostic_profile": BATCH.NATIVE_HOST_RUNTIME_PROFILE,
            "safety_job_failed": False, "had_safety_job_failure": False,
            "hosted_cleanup_outcome": "unknown", "qualification_accepted": False,
            "unknown_high_findings": False, "full_qualification_dispatched": True,
            "outer_runtime_cleanup": "unknown", "inner_row_cleanup": "confirmed",
            "inner_row_bound": "none", "batch_return": 1,
            "desktop_child_return": "unknown", "original_failure_cause": "unknown"}
        self._write_admission(repair_path, repair)
        predecessor = {"attempt_index": 1, "attempt_root": attempt_root.relative_to(self.root).as_posix(),
            **{key: self._reference(path, path.read_bytes()) for key, path in (
                ("failure", attempt_root / "failure.json"), ("journal", journal_path),
                ("terminal_observation", terminal_path), ("repair_evidence", repair_path),
                ("source_admission", self.source_admission_path))},
            "cleanup_evidence": None, "disposition": "bounded-diagnostic-followup",
            "all_ci_terminal": True, "safety_status": "diagnostic-only",
            "cleanup_status": "unknown-hosted-test-outcome", "unknown_high_findings": False}
        for name in BATCH.NATIVE_HOST_RUNTIME_SOURCE_PATHS:
            source = self.root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"# fresh native host diagnostic fixture\n")
            pins[name] = hashlib.sha256(source.read_bytes()).hexdigest()
        second = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        return second, predecessor, pins

    def test_native_host_runtime_profile_binds_failed_full_run_without_resolving_outer_cleanup(self):
        second, predecessor, pins = self._native_host_runtime_successor()
        admission_path = second / "source-admission.json"

        def validate(pred=predecessor, selected=pins,
                     disposition="bounded-diagnostic-followup"):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition=disposition)
            digest = self._write_admission(admission_path, admission)
            return self._validate(admission_path=admission_path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        result = validate()
        self.assertEqual(result["admission"]["disposition"], "bounded-diagnostic-followup")
        self.assertEqual(result["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")
        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_raw = terminal_path.read_bytes()
        terminal = json.loads(terminal_raw)
        for field, value in (
                ("event", "pull_request"), ("failed_lane", "safety"),
                ("owning_case", "other-native-case"), ("outer_runtime_cleanup", "confirmed"),
                ("hosted_cleanup_outcome", "confirmed"), ("desktop_child_return", "zero"),
                ("original_failure_cause", "assertion-known"), ("safety_job_failed", True),
                ("qualification_accepted", True), ("full_qualification_dispatched", False),
                ("merge_attempted", False),
                ("batch_return", 0), ("batch_return", True),
                ("inner_row_bound", "violation")):
            changed = {**terminal, field: value}
            self._write_admission(terminal_path, changed)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid|native-host-runtime-evidence-invalid"):
                validate(pred=pred)
        terminal_path.write_bytes(terminal_raw)

        for mutate in (
                lambda value: value["jobs"].pop(),
                lambda value: value["jobs"][0].update(status="in_progress"),
                lambda value: value["jobs"][0].update(conclusion="cancelled"),
                lambda value: value["jobs"].append({"id": 999, "name": "unknown",
                    "status": "completed", "conclusion": "success"}),
                lambda value: value["jobs"][1].update(id=value["jobs"][0]["id"]),
                lambda value: value["qualification_jobs"].pop(),
                lambda value: value["qualification_run"].update(head_sha="f" * 40),
                lambda value: value["qualification_run"].update(event="push"),
                lambda value: value["qualification_run"].update(conclusion="success"),
                lambda value: value["pull_request"].update(merged=False),
                lambda value: value.update(qualification_dispatch_nonce="3" * 32),
                lambda value: value.update(source_delivery=dict(value["terminal_packet"])),
                lambda value: value.update(terminal_packet={"path": value["terminal_packet"]["path"],
                    "sha256": "0" * 64}),
                lambda value: value.update(qualification_jobs_snapshot=dict(value["terminal_packet"])),
                lambda value: value.update(hosted_log=dict(value["terminal_packet"])),
        ):
            changed = json.loads(terminal_raw)
            mutate(changed)
            self._write_admission(terminal_path, changed)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.assertRaises(ValueError):
                validate(pred=pred)
        terminal_path.write_bytes(terminal_raw)

        for key in ("outer_runtime_cleanup", "inner_row_cleanup", "batch_return",
                    "desktop_child_return", "original_failure_cause", "full_qualification_dispatched"):
            repair_path = self.root / predecessor["repair_evidence"]["path"]
            repair_raw = repair_path.read_bytes()
            repair = json.loads(repair_raw)
            repair[key] = {"outer_runtime_cleanup": "confirmed", "inner_row_cleanup": "unconfirmed",
                "batch_return": 0, "desktop_child_return": "zero", "original_failure_cause": "known",
                "full_qualification_dispatched": False}[key]
            self._write_admission(repair_path, repair)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(repair_key=key), self.assertRaises(ValueError):
                validate(pred=pred)
            repair_path.write_bytes(repair_raw)

        packet_path = self.root / terminal["terminal_packet"]["path"]
        packet_raw = packet_path.read_bytes()
        packet = json.loads(packet_raw)
        packet["job_totals"]["conclusions"]["failure"] = 1
        self._write_admission(packet_path, packet)
        changed = {**terminal, "terminal_packet": self._reference(packet_path, packet_path.read_bytes())}
        self._write_admission(terminal_path, changed)
        pred = {**predecessor, "terminal_observation": self._reference(
            terminal_path, terminal_path.read_bytes())}
        with self.assertRaisesRegex(ValueError, "native-host-runtime-evidence-invalid"):
            validate(pred=pred)
        packet_path.write_bytes(packet_raw)
        terminal_path.write_bytes(terminal_raw)

        log_path = self.root / terminal["hosted_log"]["path"]
        log_raw = log_path.read_bytes()
        for replacement in (b"case=recursion94/other-case", b"return=0", b"cleanup=unconfirmed"):
            bad_log = log_raw.replace(b"case=recursion94/withhold-first-plate", replacement) \
                if replacement.startswith(b"case=") else log_raw.replace(
                    b"return=1" if replacement == b"return=0" else b"cleanup=confirmed", replacement)
            log_path.write_bytes(bad_log)
            changed = {**terminal, "hosted_log": self._reference(log_path, bad_log)}
            self._write_admission(terminal_path, changed)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.assertRaisesRegex(ValueError, "native-host-runtime-evidence-invalid"):
                validate(pred=pred)
        log_path.write_bytes(log_raw)
        terminal_path.write_bytes(terminal_raw)

        source_path = "scripts/evidence/v02_run.py"
        source_file = self.root / source_path
        source_raw = source_file.read_bytes()
        partial = dict(pins)
        partial[source_path] = self.pins[source_path]
        source_file.write_bytes(b"# prior diagnostic fixture\n")
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=partial)
        source_file.write_bytes(source_raw)
    def test_diagnostic_admission_preserves_unknown_and_cannot_become_normal_retry(self):
        second, predecessor, pins = self._diagnostic_successor()
        path = second / "source-admission.json"
        def validate(pred=predecessor, disposition="bounded-diagnostic-followup", selected=pins):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
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

    def test_phase5_cleanup_diagnostic_requires_exact_safe_failure_and_six_source_changes(self):
        second, predecessor, pins = self._diagnostic_successor(
            BATCH.DIAGNOSTIC_CASE, "phase5-cleanup")
        path = second / "source-admission.json"

        def validate(pred=predecessor, selected=pins):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition="bounded-diagnostic-followup")
            digest = self._write_admission(path, admission)
            return self._validate(admission_path=path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        accepted = validate()
        self.assertEqual(accepted["admission"]["disposition"],
                         "bounded-diagnostic-followup")
        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_bytes = terminal_path.read_bytes()
        repair_path = self.root / predecessor["repair_evidence"]["path"]
        repair_bytes = repair_path.read_bytes()
        terminal = json.loads(terminal_bytes)
        repair = json.loads(repair_bytes)
        for field, value in (
                ("failed_lane", "sanitizer"), ("native_lane", "failed"),
                ("sanitizer_lane", "failed"), ("diagnostic_subcase", "stderr-cap"),
                ("failure_exception", "RuntimeError"),
                ("failure_cleanup", "confirmed"),
                ("failure_cleanup_error", "OSError"),
                ("failure_return", "zero"),
                ("failure_result", "success"),
                ("merge_attempted", True),
                ("hosted_cleanup_outcome", "confirmed")):
            changed = {**terminal, field: value}
            self._write_admission(terminal_path, changed)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(terminal_field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid"):
                validate(pred=pred)
        missing_merge = dict(terminal)
        missing_merge.pop("merge_attempted")
        self._write_admission(terminal_path, missing_merge)
        pred = {**predecessor, "terminal_observation": self._reference(
            terminal_path, terminal_path.read_bytes())}
        with self.assertRaisesRegex(ValueError, "diagnostic-classification-invalid"):
            validate(pred=pred)
        terminal_path.write_bytes(terminal_bytes)
        for field, value in (
                ("diagnostic_profile", "phase5-process"),
                ("diagnostic_subcase", "stderr-cap"), ("safety_job_failed", False),
                ("had_safety_job_failure", False), ("hosted_cleanup_outcome", "confirmed"),
                ("live_retry_authorized", True), ("unknown_high_findings", True)):
            changed = {**repair, field: value}
            self._write_admission(repair_path, changed)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(repair_field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid"):
                validate(pred=pred)
        repair_path.write_bytes(repair_bytes)
        log_path = self.root / repair["hosted_log"]["path"]
        log_bytes = log_path.read_bytes()
        for content in (log_bytes.replace(b"stdout-cap", b"stderr-cap"),
                        log_bytes.replace(b"cleanup_error=PermissionError", b"cleanup_error=OSError")):
            log_path.write_bytes(content)
            changed = {**repair, "hosted_log": self._reference(log_path, content)}
            self._write_admission(repair_path, changed)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.assertRaisesRegex(ValueError, "phase5-cleanup-diagnostic-evidence-invalid"):
                validate(pred=pred)
        log_path.write_bytes(log_bytes)
        repair_path.write_bytes(repair_bytes)

        changed_path = next(iter(BATCH.PHASE5_CLEANUP_DIAGNOSTIC_SOURCE_PATHS))
        source_path = self.root / changed_path
        fresh_bytes = source_path.read_bytes()
        source_path.write_bytes(b"# prior diagnostic fixture\n")
        partial = dict(pins)
        partial[changed_path] = self.pins[changed_path]
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=partial)
        source_path.write_bytes(fresh_bytes)

    def test_rss_smoke_diagnostic_requires_exact_roster_receipts_and_four_source_changes(self):
        second, predecessor, pins = self._diagnostic_successor(BATCH.RSS_DIAGNOSTIC_CASE)
        path = second / "source-admission.json"

        def validate(pred=predecessor, disposition="bounded-diagnostic-followup", selected=pins):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
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

    def test_publication_rss_stop_requires_exact_receipt_and_green_pr_evidence(self):
        second, predecessor, pins = self._diagnostic_successor(
            BATCH.PUBLICATION_RSS_OBSERVATION_CASE)
        admission_path = second / "source-admission.json"

        def validate(pred=predecessor, selected=pins, disposition="bounded-diagnostic-followup"):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition=disposition)
            digest = self._write_admission(admission_path, admission)
            return self._validate(admission_path=admission_path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        accepted = validate()
        self.assertEqual(accepted["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")
        self.assertEqual(accepted["admission"]["predecessor"]["disposition"],
                         "bounded-diagnostic-followup")
        with self.assertRaisesRegex(ValueError, "diagnostic-disposition-mismatch"):
            validate(disposition="evidence-backed-infrastructure-retry")

        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_raw = terminal_path.read_bytes()
        terminal = json.loads(terminal_raw)
        terminal_mutations = []
        terminal_mutations.append({**terminal, "local_monitor_safety_issue": False})
        terminal_mutations.append({**terminal, "full_qualification_dispatched": True})
        terminal_mutations.append({**terminal, "workflow_run_id": terminal["workflow_run_id"] + 1})
        bad_run = json.loads(terminal_raw)
        bad_run["workflow_run"]["event"] = "workflow_dispatch"
        terminal_mutations.append(bad_run)
        wrong_pr = json.loads(terminal_raw)
        wrong_pr["pull_request"]["base_sha"] = "e" * 40
        terminal_mutations.append(wrong_pr)
        missing_job = json.loads(terminal_raw)
        missing_job["jobs"].pop()
        terminal_mutations.append(missing_job)
        active_job = json.loads(terminal_raw)
        active_job["jobs"][0]["status"] = "in_progress"
        terminal_mutations.append(active_job)
        non_green = json.loads(terminal_raw)
        next(row for row in non_green["jobs"] if row["name"] == "safety")["conclusion"] = "failure"
        terminal_mutations.append(non_green)
        for altered in terminal_mutations:
            self._write_admission(terminal_path, altered)
            changed_pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(mutated_terminal=altered), self.assertRaises(ValueError):
                validate(pred=changed_pred)
        terminal_path.write_bytes(terminal_raw)

        def reject_capture(name, mutate):
            current = json.loads(terminal_raw)
            reference = current["connector_captures"][name]
            capture_path = self.root / reference["path"]
            original = capture_path.read_bytes()
            value = json.loads(original)
            changed = mutate(value)
            changed_raw = changed if isinstance(changed, bytes) else (
                json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            capture_path.write_bytes(changed_raw)
            current["connector_captures"][name] = self._reference(capture_path, changed_raw)
            self._write_admission(terminal_path, current)
            changed_pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            try:
                with self.assertRaises(ValueError):
                    validate(pred=changed_pred)
            finally:
                capture_path.write_bytes(original)
                terminal_path.write_bytes(terminal_raw)

        reject_capture("pr", lambda value: {**value, "head_sha": "e" * 40})
        reject_capture("workflow_runs", lambda value: {**value,
            "commit_sha": "e" * 40})
        reject_capture("jobs", lambda value: {**value,
            "jobs": [{**row, "run_id": row["run_id"] + 1} if index == 0 else row
                for index, row in enumerate(value["jobs"])]})
        connector_ref = json.loads(terminal_raw)["connector_captures"]["pr"]
        large_capture_path = self.root / connector_ref["path"]
        original_capture = large_capture_path.read_bytes()
        oversized = b"x" * (BATCH.MAX_CONNECTOR_CAPTURE_BYTES + 1)
        large_capture_path.write_bytes(oversized)
        oversized_terminal = json.loads(terminal_raw)
        oversized_terminal["connector_captures"]["pr"] = self._reference(
            large_capture_path, oversized)
        self._write_admission(terminal_path, oversized_terminal)
        oversized_pred = {**predecessor, "terminal_observation": self._reference(
            terminal_path, terminal_path.read_bytes())}
        try:
            with self.assertRaisesRegex(ValueError,
                    "publication-rss-observation-invalid"):
                validate(pred=oversized_pred)
        finally:
            large_capture_path.write_bytes(original_capture)
            terminal_path.write_bytes(terminal_raw)

        repair_path = self.root / predecessor["repair_evidence"]["path"]
        repair_raw = repair_path.read_bytes()
        repair = json.loads(repair_raw)
        receipt_path = self.root / repair["local_monitor_receipt"]["path"]
        receipt_raw = receipt_path.read_bytes()
        receipt = json.loads(receipt_raw)
        receipt_mutations = []
        wrong_argv = json.loads(receipt_raw)
        wrong_argv["argv"][3] = "99"
        receipt_mutations.append(wrong_argv)
        unconfirmed = json.loads(receipt_raw)
        unconfirmed["processes"][0]["process_group_cleanup"] = "unconfirmed"
        receipt_mutations.append(unconfirmed)
        peak_zero = json.loads(receipt_raw)
        peak_zero["processes"][0]["rss_bytes_peak"] = 0
        receipt_mutations.append(peak_zero)
        peak_over = json.loads(receipt_raw)
        peak_over["processes"][0]["rss_bytes_peak"] = 4 * 1024**3 + 1
        receipt_mutations.append(peak_over)
        wrong_reason = json.loads(receipt_raw)
        wrong_reason["processes"][0]["rss_observation_reason"] = "other"
        receipt_mutations.append(wrong_reason)
        wrong_result = json.loads(receipt_raw)
        wrong_result["processes"][0]["rss_observation_result"] = "short"
        receipt_mutations.append(wrong_result)
        pid_mismatch = json.loads(receipt_raw)
        pid_mismatch["processes"][0]["pgid"] += 1
        receipt_mutations.append(pid_mismatch)
        for altered in receipt_mutations:
            self._write_admission(receipt_path, altered)
            changed_repair = {**repair, "local_monitor_receipt": self._reference(
                receipt_path, receipt_path.read_bytes())}
            self._write_admission(repair_path, changed_repair)
            changed_pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(mutated_receipt=altered), self.assertRaises(ValueError):
                validate(pred=changed_pred)
        receipt_path.write_bytes(receipt_raw)

        failure_path = self.root / predecessor["failure"]["path"]
        failure_raw = failure_path.read_bytes()
        failure = json.loads(failure_raw)
        failure["stage"] = "preview-ci"
        self._write_admission(failure_path, failure)
        changed_pred = {**predecessor, "failure": self._reference(failure_path, failure_path.read_bytes())}
        with self.assertRaisesRegex(ValueError,
                "predecessor-artifact-invalid|publication-rss-observation-invalid"):
            validate(pred=changed_pred)
        failure_path.write_bytes(failure_raw)

        journal_path = self.root / predecessor["journal"]["path"]
        journal_raw = journal_path.read_bytes()
        journal = json.loads(journal_raw)
        journal["push_performed"] = False
        self._write_admission(journal_path, journal)
        changed_pred = {**predecessor, "journal": self._reference(journal_path, journal_path.read_bytes())}
        with self.assertRaisesRegex(ValueError,
                "predecessor-artifact-invalid|publication-rss-observation-invalid"):
            validate(pred=changed_pred)
        journal_path.write_bytes(journal_raw)

        unexpected_delivery = self.root / predecessor["attempt_root"] / "source-delivery.json"
        unexpected_delivery.write_text("{}\n")
        with self.assertRaisesRegex(ValueError,
                "predecessor-artifact-invalid|publication-rss-observation-invalid"):
            validate()
        unexpected_delivery.unlink()

        # Any unreviewed source delta beyond the four exact diagnostic files blocks admission.
        extra_path = "scripts/release/v02_qualification.py"
        extra_file = self.root / extra_path
        extra_raw = extra_file.read_bytes()
        extra_file.write_bytes(extra_raw + b"# unexpected source delta\n")
        extra_pins = dict(pins)
        extra_pins[extra_path] = hashlib.sha256(extra_file.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,
                "diagnostic-source-change-unproven|predecessor-artifact-invalid"):
            validate(selected=extra_pins)
        extra_file.write_bytes(extra_raw)

    def test_first_party_cleanup_control_binds_exact_failures_and_fixed_workload(self):
        second, predecessor, pins = self._diagnostic_successor(
            BATCH.FIRST_PARTY_CLEANUP_CONTROL_CASE, "first-party-cleanup-control")
        admission_path = second / "source-admission.json"

        def validate(pred=predecessor, selected=pins):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition="bounded-diagnostic-followup")
            digest = self._write_admission(admission_path, admission)
            return self._validate(admission_path=admission_path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        accepted = validate()
        self.assertEqual(accepted["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")
        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_bytes = terminal_path.read_bytes()
        terminal = json.loads(terminal_bytes)
        terminal_mutations = []
        for field, value in (
                ("owning_case", "NativeParserContract.test_other"),
                ("native_lane", "failed"), ("sanitizer_lane", "passed"),
                ("production_lane", "failed"), ("safety_job_failed", False),
                ("local_monitor_safety_issue", True), ("hosted_cleanup_outcome", "confirmed"),
                ("merge_attempted", True), ("full_qualification_dispatched", True),
                ("failure_exception", "AssertionError"), ("cleanup_queries", 4),
                ("observer_failure_stage", "read"), ("cleanup_signal_phase", "sigterm")):
            terminal_mutations.append({**terminal, field: value})
        missing_fast = json.loads(terminal_bytes)
        missing_fast["jobs"] = [row for row in missing_fast["jobs"] if row["name"] != "phase7-fast"]
        terminal_mutations.append(missing_fast)
        extra_job = json.loads(terminal_bytes)
        extra_job["jobs"].append({"id": 777, "name": "unknown-lane", "status": "completed",
                                  "conclusion": "success"})
        terminal_mutations.append(extra_job)
        wrong_head = json.loads(terminal_bytes)
        wrong_head["pull_request"]["head_sha"] = "e" * 40
        terminal_mutations.append(wrong_head)
        for value in terminal_mutations:
            self._write_admission(terminal_path, value)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(terminal=value), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid|first-party-cleanup-control-invalid"):
                validate(pred=pred)
        terminal_path.write_bytes(terminal_bytes)

        repair_path = self.root / predecessor["repair_evidence"]["path"]
        repair_bytes = repair_path.read_bytes()
        repair = json.loads(repair_bytes)
        for field, value in (
                ("diagnostic_profile", "phase5-cleanup"),
                ("control", {**BATCH.FIRST_PARTY_CLEANUP_CONTROL_METADATA,
                              "child_seconds": 60}),
                ("control", {**BATCH.FIRST_PARTY_CLEANUP_CONTROL_METADATA,
                              "field_limit": 10.0}),
                ("safety_job_failed", False), ("had_safety_job_failure", False),
                ("hosted_cleanup_outcome", "confirmed"), ("qualification_accepted", True),
                ("unknown_high_findings", True), ("live_retry_authorized", True)):
            altered = {**repair, field: value}
            self._write_admission(repair_path, altered)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(repair_field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid|first-party-cleanup-control-invalid"):
                validate(pred=pred)
        repair_path.write_bytes(repair_bytes)

        hosted_logs = repair["hosted_logs"]
        for lane, mutation in (
                ("safety", lambda raw: raw.replace(b"cleanup_queries=3", b"cleanup_queries=4")),
                ("phase7-fast", lambda raw: raw.replace(b"status_reason': 'not-observed'",
                    b"status_reason': 'group-active'")),
                ("phase7-fast", lambda raw: raw.replace(
                    b"Ran 25 tests in 2.945s\n",
                    b"FAIL: test_baseline_fake_cancel_and_setup_failure_always_cleanup "
                    b"(__main__.ProcessAdmissionContract.test_baseline_fake_cancel_and_setup_failure_always_cleanup)\n"
                    b"Ran 25 tests in 2.945s\n")),
                ("phase7-fast", lambda raw: raw.replace(
                    b"FAIL: test_baseline_fake_cancel_and_setup_failure_always_cleanup "
                    b"(__main__.ProcessAdmissionContract.",
                    b"FAIL: test_baseline_fake_cancel_and_setup_failure_always_cleanup "
                    b"(__main__.OtherContract.")),
                ("phase7-fast", lambda raw: raw.replace(
                    b"Ran 25 tests in 2.945s\n",
                    b"FAIL: test_foreign (__main__.OtherContract.test_foreign)\n"
                    b"Ran 25 tests in 2.945s\n")),
                ("phase7-fast", lambda raw: raw + b"ERROR: unexpected owner\n")):
            reference = hosted_logs[lane]
            log_path = self.root / reference["path"]
            original = log_path.read_bytes()
            changed = mutation(original)
            log_path.write_bytes(changed)
            altered_repair = {**repair, "hosted_logs": {**hosted_logs,
                lane: self._reference(log_path, changed)}}
            self._write_admission(repair_path, altered_repair)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.assertRaisesRegex(ValueError, "first-party-cleanup-control-invalid"):
                validate(pred=pred)
            log_path.write_bytes(original)
            repair_path.write_bytes(repair_bytes)

        partial = dict(pins)
        changed_path = "scripts/release/v02_batch.py"
        changed_file = self.root / changed_path
        fresh = changed_file.read_bytes()
        changed_file.write_bytes(b"# prior diagnostic fixture\n")
        partial[changed_path] = self.pins[changed_path]
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=partial)
        changed_file.write_bytes(fresh)

    def test_workflow_timeout_contract_accepts_only_exact_pure_fastlane_failure(self):
        second, predecessor, pins = self._diagnostic_successor(
            BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE, BATCH.WORKFLOW_TIMEOUT_CONTRACT_PROFILE)
        admission_path = second / "source-admission.json"

        def validate(pred=predecessor, selected=pins,
                     disposition="bounded-diagnostic-followup"):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(pred) + ".json")
            claim.unlink(missing_ok=True)
            admission = self._source_admission(selected, attempt_index=2,
                predecessor=pred, disposition=disposition)
            digest = self._write_admission(admission_path, admission)
            return self._validate(admission_path=admission_path, admission_sha=digest,
                journal=second / "hosted-delivery-journal.json",
                publication=second / "candidate/publication-copy",
                preflight=second / "candidate/preparation.json",
                output=second / "candidate/preparation.json")

        result = validate()
        self.assertEqual(result["admission"]["disposition"], "bounded-diagnostic-followup")
        self.assertEqual(result["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")
        with self.assertRaisesRegex(ValueError, "diagnostic-disposition-mismatch"):
            validate(disposition="evidence-backed-infrastructure-retry")

        terminal_path = self.root / predecessor["terminal_observation"]["path"]
        terminal_bytes = terminal_path.read_bytes()
        terminal = json.loads(terminal_bytes)
        mutations = []
        wrong_case = {**terminal, "owning_case": "QualificationCoordinatorContract.test_other"}
        mutations.append(wrong_case)
        wrong_flags = {**terminal, "safety_job_failed": True}
        mutations.append(wrong_flags)
        wrong_merge = {**terminal, "merge_attempted": True}
        mutations.append(wrong_merge)
        wrong_qualification = {**terminal, "qualification_accepted": True}
        mutations.append(wrong_qualification)
        wrong_pr = json.loads(terminal_bytes)
        wrong_pr["pull_request"]["merged"] = True
        mutations.append(wrong_pr)
        missing_lane = json.loads(terminal_bytes)
        missing_lane["jobs"] = [row for row in missing_lane["jobs"] if row["name"] != "desktop"]
        mutations.append(missing_lane)
        active_lane = json.loads(terminal_bytes)
        next(row for row in active_lane["jobs"] if row["name"] == "phase7-fast")["status"] = "in_progress"
        mutations.append(active_lane)
        extra_lane = json.loads(terminal_bytes)
        extra_lane["jobs"].append({"id": 999, "name": "unknown-lane", "status": "completed",
                                   "conclusion": "success"})
        mutations.append(extra_lane)
        failed_safety = json.loads(terminal_bytes)
        next(row for row in failed_safety["jobs"] if row["name"] == "safety")["conclusion"] = "failure"
        mutations.append(failed_safety)
        for value in mutations:
            self._write_admission(terminal_path, value)
            pred = {**predecessor, "terminal_observation": self._reference(
                terminal_path, terminal_path.read_bytes())}
            with self.subTest(terminal=value), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid"):
                validate(pred=pred)
        terminal_path.write_bytes(terminal_bytes)

        repair_path = self.root / predecessor["repair_evidence"]["path"]
        repair_bytes = repair_path.read_bytes()
        repair = json.loads(repair_bytes)
        for field, value in (("diagnostic_profile", "rss-smoke"),
                ("safety_job_failed", True), ("had_safety_job_failure", True),
                ("merge_attempted", True), ("original_failure_cause", "determined"),
                ("hosted_cleanup_outcome", "confirmed"), ("live_retry_authorized", True)):
            changed = {**repair, field: value}
            self._write_admission(repair_path, changed)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.subTest(repair_field=field), self.assertRaisesRegex(ValueError,
                    "diagnostic-classification-invalid"):
                validate(pred=pred)
        repair_path.write_bytes(repair_bytes)

        log_ref = repair["hosted_log"]
        log_path = self.root / log_ref["path"]
        log_bytes = log_path.read_bytes()
        for changed_log in (log_bytes.replace(b"not found in", b"was found in"),
                log_bytes + b"FAIL: test_unrelated (__main__.OtherContract.test_unrelated)\n",
                log_bytes.replace(b"FAILED (failures=1)", b"FAILED (failures=2)")):
            log_path.write_bytes(changed_log)
            changed = {**repair, "hosted_log": self._reference(log_path, changed_log)}
            self._write_admission(repair_path, changed)
            pred = {**predecessor, "repair_evidence": self._reference(
                repair_path, repair_path.read_bytes())}
            with self.assertRaisesRegex(ValueError, "workflow-timeout-contract-invalid"):
                validate(pred=pred)
        log_path.write_bytes(log_bytes)
        repair_path.write_bytes(repair_bytes)

        partial = dict(pins)
        changed_path = next(iter(BATCH.WORKFLOW_TIMEOUT_CONTRACT_SOURCE_PATHS))
        changed_source = self.root / changed_path
        fresh_source_bytes = changed_source.read_bytes()
        changed_source.write_bytes(b"# prior diagnostic fixture\n")
        partial[changed_path] = self.pins[changed_path]
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven|source-pin-stale"):
            validate(selected=partial)
        changed_source.write_bytes(fresh_source_bytes)

        unrelated_path = "scripts/release/v02_qualification.py"
        unrelated_file = self.root / unrelated_path
        unrelated_bytes = unrelated_file.read_bytes()
        unrelated_file.write_bytes(b"# unreviewed additional delta\n")
        extra_delta = dict(pins)
        extra_delta[unrelated_path] = hashlib.sha256(unrelated_file.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "diagnostic-source-change-unproven"):
            validate(selected=extra_delta)
        unrelated_file.write_bytes(unrelated_bytes)

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

    def _write_assessed_preview(self, attempt_root, source_admission_path, public_path,
                                public_admission, pr_number):
        candidate = public_admission["candidate"]
        source_raw = source_admission_path.read_bytes()
        public_raw = public_path.read_bytes()
        head, base = candidate["public_head"], candidate["public_base"]
        journal = {"schema": "genewhip.v02-delivery-journal.v1",
            "repository": "szTheory/genewhip", "source_head": head,
            "public_base_sha": base, "started_at": self.started,
            "diagnostic_only": True, "diagnostic_ci_status": "passed",
            "assessment_required": True, "merge_attempted": False, "pull_request": str(pr_number)}
        journal_path = attempt_root / "hosted-delivery-journal.json"
        self._write_admission(journal_path, journal)
        delivery = {"schema": "genewhip.v02-public-source-delivery.v1",
            "status": "diagnostic-ci-complete", "candidate_sha": head,
            "diagnostic_only": True, "assessment_required": True, "merge_attempted": False}
        delivery_path = attempt_root / "source-delivery.json"
        self._write_admission(delivery_path, delivery)
        failure = {"schema": "genewhip.phase7-fresh-batch-failure.v1",
            "authorization_sha256": BATCH.AUTH_SHA256, "stage": "preview-ci",
            "reason": "diagnostic-ci-complete-assessment-required", "observed_at": self.started}
        failure_path = attempt_root / "failure.json"
        self._write_admission(failure_path, failure)
        self.expected_failure_paths.add(failure_path)
        jobs = [{"id": 123450000000 + index, "name": name, "status": "completed",
            "conclusion": "success" if name in BATCH.PREVIEW_REQUIRED_LANES else "skipped"}
            for index, name in enumerate(sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS))]
        packet = {"schema": "genewhip.phase7-diagnostic-assessment-input.v1",
            "disposition": "diagnostic-preview-green-assessment-required", "qualification_credit": False,
            "source_and_candidate": {"private_source_head": self.source_head,
                "source_admission_path": source_admission_path.relative_to(self.root).as_posix(),
                "source_admission_sha256": hashlib.sha256(source_raw).hexdigest(),
                "public_admission_path": public_path.relative_to(self.root).as_posix(),
                "public_admission_sha256": hashlib.sha256(public_raw).hexdigest(),
                "candidate_head": candidate["public_head"], "public_base": candidate["public_base"],
                "public_tree": candidate["public_tree"], "manifest_sha256": candidate["source_manifest_sha256"],
                "preparation_sha256": candidate["preparation_sha256"],
                "candidate_review_payload_sha256": candidate["candidate_payload_sha256"]},
            "hosted_source_delivery": {"source_delivery_path": delivery_path.relative_to(self.root).as_posix(),
                "source_delivery_sha256": hashlib.sha256(delivery_path.read_bytes()).hexdigest(),
                "journal_path": journal_path.relative_to(self.root).as_posix(),
                "journal_sha256": hashlib.sha256(journal_path.read_bytes()).hexdigest(),
                "failure_latch_path": failure_path.relative_to(self.root).as_posix(),
                "failure_latch_sha256": hashlib.sha256(failure_path.read_bytes()).hexdigest()},
            "github": {"repository": "szTheory/genewhip", "merged": False,
                "pull_request_state": "open", "pull_request": pr_number,
                "head_sha": head, "base_sha": base, "jobs": jobs,
                "workflow_run": {"id": 765430000000 + pr_number, "event": "pull_request",
                    "status": "completed", "conclusion": "success",
                    "workflow_path": ".github/workflows/ci.yml"}}}
        packet_path = attempt_root / "ci-failure/assessment-input.json"
        packet_sha = self._write_admission(packet_path, packet)
        return packet, {"path": packet_path.relative_to(self.root).as_posix(), "sha256": packet_sha}, journal, failure

    def _source_head_reviews(self, prefix, payload_sha):
        result = self._reviews(prefix, payload_sha)
        for ref in result.values():
            path = self.root / ref["path"]
            raw = path.read_text()
            path.write_text(raw.replace("payload_sha256: " + payload_sha,
                "payload_sha256: " + payload_sha + "\nsource_head: " + self.source_head))
            ref["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def _public_admission(self, source_pins=None, *, disposition="routine-source-repair",
                          attempt_index=1, predecessor=None, public_tree="e" * 40):
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
        public_head, public_base = "c" * 40, "d" * 40
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
        source_admission = self._source_admission(source_pins, attempt_index=attempt_index,
            predecessor=predecessor, disposition=disposition)
        source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, attempt_root=self.batch_root.relative_to(self.root).as_posix(),
            attempt_index=attempt_index, predecessor=self.predecessor if predecessor is None else predecessor,
            disposition=disposition, source_pins=source_pins or self.pins)
        candidate_payload = BATCH.candidate_review_payload(source_payload, candidate)
        candidate_payload_sha = hashlib.sha256(BATCH._canonical(candidate_payload)).hexdigest()
        candidate["candidate_payload_sha256"] = candidate_payload_sha
        candidate["candidate_reviews"] = self._reviews("candidate", candidate_payload_sha)
        admission = {**source_admission, "status": "public-effects", "candidate": candidate}
        path = self.batch_root / "public-admission.json"
        digest = self._write_admission(path, admission)
        return path, digest, policy_path

    def _native_readiness_successor(self, *, prior_workflow_timeout=False,
                                    source_overrides=None):
        # Attempt 1 is a green, unmerged diagnostic PR. Its source admission is
        # ordinary repair history; the public stop record explicitly marks the
        # preview as diagnostic and binds the assessment packet.
        prior_root = self.batch_root
        source1 = self._source_admission()
        source1_path = prior_root / "source-admission.json"
        self._write_admission(source1_path, source1)
        claim_identity = BATCH._predecessor_identity_sha256(self.predecessor)
        BATCH._claim_successor(self.root, predecessor_sha256=claim_identity,
            predecessor_record_sha256=hashlib.sha256(BATCH._canonical(self.predecessor)).hexdigest(),
            attempt_root=prior_root.relative_to(self.root).as_posix(),
            source_payload_sha256=source1["source_payload_sha256"])
        public1_path, _, _ = self._public_admission()
        public1 = json.loads(public1_path.read_bytes())
        public1["disposition"] = "bounded-diagnostic-followup"
        self._write_admission(public1_path, public1)
        packet1, packet1_ref, journal1, failure1 = self._write_assessed_preview(
            prior_root, source1_path, public1_path, public1, 41)
        packet1_sha = hashlib.sha256(BATCH._canonical(packet1)).hexdigest()
        repair1 = {"live_retry_authorized": False, "diagnostic_only": True,
            "diagnostic_case": BATCH.NATIVE_CASE_PREPARATION,
            "safety_job_failed": False, "had_safety_job_failure": False,
            "hosted_cleanup_outcome": "unknown", "qualification_accepted": False,
            "unknown_high_findings": False, "full_qualification_dispatched": False,
            "original_failure_cause": "unknown", "diagnostic_assessment": packet1_ref,
            "assessment_reviews": self._source_head_reviews("attempt1-assessment", packet1_sha)}
        terminal1 = {"all_jobs_terminal": True, "event": "pull_request",
            "jobs": [{"id": 123450000100 + index, "name": name, "status": "completed",
                "conclusion": "success" if name in BATCH.PREVIEW_REQUIRED_LANES else "skipped"}
                for index, name in enumerate(sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS))],
            "owning_case": BATCH.NATIVE_CASE_PREPARATION,
            "safety_job_failed": False, "qualification_accepted": False,
            "full_qualification_dispatched": False, "local_monitor_safety_issue": False,
            "hosted_cleanup_outcome": "unknown", "original_failure_cause": "unknown",
            "pull_request": {"number": 41,
                "state": "open", "merged": False, "head_sha": public1["candidate"]["public_head"],
                "base_sha": public1["candidate"]["public_base"]}}
        if prior_workflow_timeout:
            terminal1.update({"owning_case": BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE,
                "failed_lane": "phase7-fast", "safety_job_failed": False,
                "merge_attempted": False,
                "fast_job_failure": {
                    "outer_case": "test_default_unittest_suites_do_not_reach_any_os_process_seam",
                    "inner_case": BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE,
                    "exception": "AssertionError", "expected_literal": "timeout-minutes: 360",
                    "classification": "workflow-timeout-expression-updated",
                    "real_child_in_failing_cases": False}})
            terminal1["jobs"] = [{"id": 124710000000 + index, "name": name,
                "status": "completed", "conclusion":
                    "failure" if name in ("phase7-fast", "required-ci") else
                    "success" if name in BATCH.PREVIEW_REQUIRED_LANES else "skipped"}
                for index, name in enumerate(sorted(BATCH.PREVIEW_REQUIRED_LANES | BATCH.PREVIEW_CONDITIONAL_SKIPS))]
            repair1 = {"live_retry_authorized": False, "diagnostic_only": True,
                "diagnostic_case": BATCH.WORKFLOW_TIMEOUT_CONTRACT_CASE,
                "diagnostic_profile": BATCH.WORKFLOW_TIMEOUT_CONTRACT_PROFILE,
                "safety_job_failed": False, "had_safety_job_failure": False,
                "hosted_cleanup_outcome": "unknown", "qualification_accepted": False,
                "unknown_high_findings": False, "full_qualification_dispatched": False,
                "merge_attempted": False, "original_failure_cause": "unknown"}
            fast_id = next(row["id"] for row in terminal1["jobs"] if row["name"] == "phase7-fast")
            fast_log = prior_root / f"ci-failure/phase7-fast-{fast_id}.log"
            fast_log.parent.mkdir(parents=True, exist_ok=True)
            fast_text = ("FAIL: test_default_unittest_suites_do_not_reach_any_os_process_seam "
                "(__main__.ProcessAdmissionContract.test_default_unittest_suites_do_not_reach_any_os_process_seam)\n"
                "  QualificationCoordinatorContract testMethod=test_workflow_wires_real_product_smoke_and_serial_full_jobs\n"
                "  self.assertIn(\"timeout-minutes: 360\", text)\n"
                "  \\'timeout-minutes: 360\\' not found in\n"
                "AssertionError: Lists differ: nested failure details\n"
                "  QualificationCoordinatorContract testMethod=test_workflow_wires_real_product_smoke_and_serial_full_jobs\n"
                "  self.assertIn(\"timeout-minutes: 360\", text)\n"
                "  \\'timeout-minutes: 360\\' not found in\n"
                "FAILED (failures=1)\n").encode()
            fast_log.write_bytes(fast_text)
            repair1["hosted_log"] = self._reference(fast_log, fast_text)
            journal1 = {"schema": "genewhip.v02-delivery-journal.v1",
                "repository": "szTheory/genewhip",
                "source_head": public1["candidate"]["public_head"],
                "public_base_sha": public1["candidate"]["public_base"],
                "started_at": self.started}
            self._write_admission(prior_root / "hosted-delivery-journal.json", journal1)
            failure1 = {"schema": "genewhip.phase7-fresh-batch-failure.v1",
                "authorization_sha256": BATCH.AUTH_SHA256, "stage": "preview-ci",
                "reason": "pull-request-required-ci-failed", "observed_at": self.started}
            self._write_admission(prior_root / "failure.json", failure1)
        terminal1_path, repair1_path = prior_root / "terminal-observation.json", prior_root / "repair-evidence.json"
        self._write_admission(terminal1_path, terminal1)
        self._write_admission(repair1_path, repair1)
        predecessor2 = {"attempt_index": 1, "attempt_root": prior_root.relative_to(self.root).as_posix(),
            "failure": self._reference(prior_root / "failure.json", (prior_root / "failure.json").read_bytes()),
            "journal": self._reference(prior_root / "hosted-delivery-journal.json",
                (prior_root / "hosted-delivery-journal.json").read_bytes()),
            "terminal_observation": self._reference(terminal1_path, terminal1_path.read_bytes()),
            "repair_evidence": self._reference(repair1_path, repair1_path.read_bytes()),
            "source_admission": self._reference(source1_path, source1_path.read_bytes()),
            "cleanup_evidence": None, "disposition": "bounded-diagnostic-followup",
            "all_ci_terminal": True, "safety_status": "diagnostic-only",
            "cleanup_status": "unknown-hosted-test-outcome", "unknown_high_findings": False}

        # Attempt 2 changes exactly the reviewed native diagnostic path roster.
        native_paths = (set(BATCH.WORKFLOW_TIMEOUT_CONTRACT_SOURCE_PATHS)
            if prior_workflow_timeout else set(BATCH.NATIVE_CASE_PREPARATION_PATHS))
        self.source_paths = set(self.source_paths) | native_paths
        current_pins = dict(self.pins)
        for relative in sorted(native_paths):
            data = (source_overrides or {}).get(relative,
                b"# reviewed native diagnostic source fixture\n")
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            current_pins[relative] = hashlib.sha256(data).hexdigest()
        second = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        second.mkdir()
        self.batch_root, self.predecessor = second, predecessor2
        self.publication = second / "candidate/publication-copy"
        self.preparation = second / "candidate/preparation.json"
        self.journal = second / "hosted-delivery-journal.json"
        self.output = second / "native-diagnostic/result.json"
        public2_path, _, _ = self._public_admission(current_pins,
            disposition="bounded-diagnostic-followup", attempt_index=2, predecessor=predecessor2)
        public2 = json.loads(public2_path.read_bytes())
        source2 = {key: value for key, value in public2.items() if key != "candidate"}
        source2["status"] = "source-preparation"
        source2_path = second / "source-admission.json"
        self._write_admission(source2_path, source2)
        # Current public admission and source admission use the same source payload/reviews.
        public2["source_reviews"] = source2["source_reviews"]
        self._write_admission(public2_path, public2)
        packet2, packet2_ref, journal2, failure2 = self._write_assessed_preview(
            second, source2_path, public2_path, public2, 42)
        ready = {"schema": "genewhip.phase7-native-diagnostic-readiness.v1",
            "diagnostic_only": True, "qualification_accepted": False,
            "plan": BATCH.native_diagnostic_plan(), "started_at": self.started,
            "source_head": self.source_head, "candidate_head": public2["candidate"]["public_head"],
            "public_admission": {"path": public2_path.relative_to(self.root).as_posix(),
                "sha256": hashlib.sha256(public2_path.read_bytes()).hexdigest()},
            "diagnostic_assessment": packet2_ref}
        readiness_payload = dict(ready)
        ready["assessment_reviews"] = self._source_head_reviews("attempt2-assessment",
            hashlib.sha256(BATCH._canonical(readiness_payload)).hexdigest())
        readiness_path = second / "native-diagnostic-readiness.json"
        readiness_sha = self._write_admission(readiness_path, ready)
        return {"root": second, "admission_path": public2_path,
            "admission_sha": hashlib.sha256(public2_path.read_bytes()).hexdigest(),
            "readiness_path": readiness_path, "readiness_sha": readiness_sha,
            "source_pins": current_pins, "predecessor": predecessor2,
            "prior_packet": packet1, "current_packet": packet2,
            "current_journal": journal2, "current_failure": failure2}

    def test_public_admission_reopens_candidate_privacy_policy_and_two_fresh_reviews(self):
        path, digest, _ = self._public_admission()
        result = self._validate(stage="public-effects", admission_path=path, admission_sha=digest,
            output=self.output)
        self.assertEqual(result["started_at"], self.started)

    def test_native_case_readiness_uses_full_production_guard_and_fixed_plan(self):
        fixture = self._native_readiness_successor()
        root = fixture["root"]

        def validate(readiness_path=None, readiness_sha=None, output=None):
            claim = self.root / BATCH.POLICY_ROOT / "successors" / (
                BATCH._predecessor_identity_sha256(fixture["predecessor"]) + ".json")
            claim.unlink(missing_ok=True)
            return self._validate(stage="native-diagnostic",
                admission_path=fixture["admission_path"], admission_sha=fixture["admission_sha"],
                journal=root / "hosted-delivery-journal.json",
                publication=root / "candidate/publication-copy",
                preflight=root / "candidate/preparation.json",
                output=output or root / "native-diagnostic/result.json",
                diagnostic_readiness_path=readiness_path or fixture["readiness_path"],
                diagnostic_readiness_sha=readiness_sha or fixture["readiness_sha"])

        accepted = validate()
        self.assertEqual(accepted["native_diagnostic_readiness"]["plan"], BATCH.native_diagnostic_plan())
        self.assertEqual(accepted["admission"]["disposition"], "bounded-diagnostic-followup")
        self.assertFalse((root / "native-diagnostic/result.json").exists())

        readiness_raw = fixture["readiness_path"].read_bytes()
        readiness = json.loads(readiness_raw)
        for mutate in (
                lambda value: value.update(qualification_accepted=True),
                lambda value: value.update(source_head="f" * 40),
                lambda value: value.update(candidate_head="f" * 40),
                lambda value: value.update(started_at="2026-10-31T12:43:20+00:00"),
                lambda value: value.update(plan={**value["plan"], "case": "other-case"}),
                lambda value: value.update(plan={**value["plan"], "outer_wall_seconds": 1801}),
                lambda value: value.update(assessment_reviews={}),
                lambda value: value["assessment_reviews"]["code"].update(sha256="0" * 64),
                lambda value: value.update(public_admission={**value["public_admission"],
                    "sha256": "0" * 64})):
            altered = json.loads(readiness_raw)
            mutate(altered)
            digest = self._write_admission(fixture["readiness_path"], altered)
            with self.assertRaises(ValueError):
                validate(readiness_sha=digest)
        fixture["readiness_path"].write_bytes(readiness_raw)
        with self.assertRaisesRegex(ValueError, "native-diagnostic-output-layout-invalid"):
            validate(output=root / "native-diagnostic/other.json")
        failure_path = root / BATCH.FAILURE_FILENAME
        failure_raw = failure_path.read_bytes()
        failure_path.unlink()
        with self.assertRaisesRegex(ValueError, "native-diagnostic-assessment-stop-required"):
            validate()
        failure_path.write_bytes(failure_raw)

        packet_ref = readiness["diagnostic_assessment"]
        packet_path = self.root / packet_ref["path"]
        packet_raw = packet_path.read_bytes()
        packet = json.loads(packet_raw)
        for mutate in (
                lambda value: value["github"]["jobs"].pop(),
                lambda value: value["github"]["jobs"].append({"id": 999999,
                    "name": "unexpected", "status": "completed", "conclusion": "success"}),
                lambda value: value["github"]["jobs"][0].update(status="in_progress"),
                lambda value: value["github"]["jobs"][0].update(conclusion="failure"),
                lambda value: value["github"]["workflow_run"].update(event="workflow_dispatch"),
                lambda value: value["source_and_candidate"].update(preparation_sha256="0" * 64),
                lambda value: value["github"].update(merged=True, pull_request_state="closed")):
            altered_packet = json.loads(packet_raw)
            mutate(altered_packet)
            packet_sha = self._write_admission(packet_path, altered_packet)
            altered_ready = json.loads(readiness_raw)
            altered_ready["diagnostic_assessment"] = {"path": packet_ref["path"], "sha256": packet_sha}
            ready_digest = self._write_admission(fixture["readiness_path"], altered_ready)
            # Review payload covers the assessment reference, so rebuild synthetic
            # accepted review fixtures exactly as production requires.
            payload = {key: value for key, value in altered_ready.items() if key != "assessment_reviews"}
            altered_ready["assessment_reviews"] = self._source_head_reviews("mutated-assessment",
                hashlib.sha256(BATCH._canonical(payload)).hexdigest())
            ready_digest = self._write_admission(fixture["readiness_path"], altered_ready)
            with self.assertRaises(ValueError):
                validate(readiness_sha=ready_digest)
        packet_path.write_bytes(packet_raw)
        fixture["readiness_path"].write_bytes(readiness_raw)

    def test_native_case_readiness_accepts_workflow_timeout_predecessor_after_green_pr(self):
        fixture = self._native_readiness_successor(prior_workflow_timeout=True)
        root = fixture["root"]
        claim = self.root / BATCH.POLICY_ROOT / "successors" / (
            BATCH._predecessor_identity_sha256(fixture["predecessor"]) + ".json")
        claim.unlink(missing_ok=True)
        accepted = self._validate(stage="native-diagnostic",
            admission_path=fixture["admission_path"], admission_sha=fixture["admission_sha"],
            journal=root / "hosted-delivery-journal.json",
            publication=root / "candidate/publication-copy",
            preflight=root / "candidate/preparation.json",
            output=root / "native-diagnostic/result.json",
            diagnostic_readiness_path=fixture["readiness_path"],
            diagnostic_readiness_sha=fixture["readiness_sha"])
        self.assertEqual(accepted["native_diagnostic_readiness"]["plan"],
                         BATCH.native_diagnostic_plan())
        self.assertEqual(accepted["admission"]["predecessor"]["disposition"],
                         "bounded-diagnostic-followup")
        self.assertEqual(accepted["admission"]["predecessor"]["cleanup_status"],
                         "unknown-hosted-test-outcome")
        self.assertFalse((root / "native-diagnostic/result.json").exists())

    def test_native_result_handoff_profile_binds_exact_nonqualifying_failure(self):
        self.assertEqual(BATCH.NATIVE_RESULT_HANDOFF_PAYLOAD_SHA256,
            "0c8a7db417e652880dfa4af8f00cde55b861ad67d6070b845c93301eece2ae35")
        self.assertEqual(BATCH.NATIVE_RESULT_HANDOFF_REPORT_SHA256,
            "b61770428f6c3bf4bd5f20d3b441fa9a309460df537305e4f6f29733246cc8f2")
        self.assertEqual(BATCH.NATIVE_RESULT_HANDOFF_RESULT_SHA256,
            "31e4e290553233234d03557fb6378402781ec2484b6d900c1fe04d11c70faaae")
        root = self.root
        attempt = BATCH.POLICY_ROOT / "attempt-0017"
        run_id = BATCH.NATIVE_RESULT_HANDOFF_RUN_ID
        source = BATCH.NATIVE_RESULT_HANDOFF_SOURCE_SHA
        nonce = BATCH.NATIVE_RESULT_HANDOFF_NONCE
        started = "2026-10-31T12:43:19+00:00"

        def write_json(relative, value):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
            path.write_bytes(raw)
            return {"path": Path(relative).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}

        workflow = {"id": run_id, "name": "Plan10 native diagnostic " + nonce,
            "display_title": "Plan10 native diagnostic " + nonce, "event": "workflow_dispatch",
            "status": "completed", "conclusion": "failure", "run_attempt": 1,
            "path": ".github/workflows/ci.yml", "head_sha": source,
            "head_branch": "v0.2-source-" + source[:12],
            "repository": {"full_name": "szTheory/genewhip", "private": False}}
        names = sorted(BATCH.NATIVE_HOST_RUNTIME_JOBS)
        jobs = [{"id": 200000 + index, "run_id": run_id, "name": name,
            "status": "completed", "conclusion": "failure" if name == "v02-runtime" else "skipped"}
            for index, name in enumerate(names)]
        extraction = {"selected_run_id": run_id,
            "source_receipt_sha256": "5bcc27d0678a06ddae652b317d889aa8b4db63bc6ce61a079fed99087b9b98f3"}
        dispatch = {"schema": "genewhip.phase7-native-diagnostic-dispatch.v1", "run_id": run_id,
            "dispatches": 1, "nonce": nonce, "source_sha": source,
            "status": "completed-assessment-required", "qualification_accepted": False,
            "started_at": started}
        downloaded = {"schema": "genewhip-phase7-one-case-diagnostic-v1", "status": "fail",
            "diagnostic_only": True, "qualification_accepted": False, "fixture": "recursion94",
            "case": "withhold-first-plate", "failure_category": None,
            "outer_rejection": None,
            "outer_process": {"status": "completed", "return_code": "zero",
                "cleanup": "confirmed", "bound_violation": False},
            "identity": {"source_sha": source, "head_sha": source,
                "base_sha": "d4865061f524a8637342562710af72dd2d583ae3",
                "run_id": str(run_id), "run_attempt": "1"},
            "stages": [{"name": name, "status": "not-run"} for name in
                ("input-contract", "headless-reference", "native-sdl-comparison")]}
        result = {"schema": "genewhip.phase7-native-diagnostic-result.v1", "status": "fail",
            "qualification_accepted": False, "assessment_required": True,
            "run_id": str(run_id), "source_sha": source, "run_attempt": "1",
            "report_sha256": "0" * 64,
            "report_path": (attempt / "native-diagnostic/download/native-diagnostic.json").as_posix()}
        journal = {"started_at": started, "repository": "szTheory/genewhip"}
        failure = {"schema": "genewhip.phase7-fresh-batch-failure.v1"}
        refs = {
            "workflow_run": write_json(attempt / "ci-failure/native-workflow-run-41260650010.json", workflow),
            "jobs": write_json(attempt / "ci-failure/native-jobs-41260650010.json", {"jobs": jobs}),
            "workflow_extraction": write_json(attempt / "ci-failure/native-workflow-run-extraction.json", extraction),
            "workflow_log": {"path": (attempt / "ci-failure/native-job-124713044938.log").as_posix()},
            "diagnostic_assessment": write_json(attempt / "ci-failure/native-diagnostic-assessment-input.json", {}),
            "dispatch": write_json(attempt / "native-diagnostic/dispatch.json", dispatch),
            "result": write_json(attempt / "native-diagnostic/result.json", result),
            "downloaded_report": write_json(attempt / "native-diagnostic/download/native-diagnostic.json", downloaded)}
        log_path = root / refs["workflow_log"]["path"]
        log_path.write_bytes(b"Run python3 -I scripts/release/v02_qualification.py --mode native-diagnostic\n"
            b"native-diagnostic: fail; qualification_accepted=false\nProcess completed with exit code 1.\n")
        refs["workflow_log"]["sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
        result["report_sha256"] = refs["downloaded_report"]["sha256"]
        result_ref = write_json(attempt / "native-diagnostic/result.json", result)
        refs["result"] = result_ref

        source_admission_path = attempt / "source-admission.json"
        source_admission = {"schema": "genewhip.phase7-public-admission.v1",
            "status": "source-preparation", "source_reviews": {}}
        admission = {**source_admission, "status": "public-effects", "candidate": {}}
        source_admission_ref = write_json(source_admission_path, source_admission)
        source_admission_sha = source_admission_ref["sha256"]
        public_admission_ref = write_json(attempt / "public-admission.json", admission)
        readiness_ref = write_json(attempt / "native-diagnostic-readiness.json", {})
        payload_sha = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        review_refs = {}
        for role, name in (("code", "CODE"), ("security", "SECURITY")):
            path = (Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery")
                / f"attempt17-{name}.md")
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("---\nstatus: accepted\nreviewer_role: " + BATCH.SOURCE_ROLES[role]
                + "\npayload_sha256: " + payload_sha
                + "\nsource_head: d85ac14471964cbde5109b3587b781ab997b9446\n---\n")
            review_refs[role] = {"path": path.as_posix(), "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "reviewer_role": BATCH.SOURCE_ROLES[role], "status": "accepted",
                "payload_sha256": payload_sha}

        terminal = {"all_jobs_terminal": True, "event": "workflow_dispatch", "jobs": jobs,
            "owning_case": BATCH.NATIVE_RESULT_HANDOFF_CASE,
            "diagnostic_profile": BATCH.NATIVE_RESULT_HANDOFF_PROFILE,
            "run_status": "completed", "run_conclusion": "failure", "workflow_run_id": run_id,
            "run_attempt": 1, "head_sha": source, "qualification_accepted": False,
            "full_qualification_dispatched": False, "merge_attempted": False,
            "safety_job_failed": False, "local_monitor_safety_issue": False,
            "hosted_cleanup_outcome": "unknown", "original_failure_cause": "unknown",
            "diagnostic_outer_cleanup": "confirmed", "diagnostic_outer_return": "zero",
            "diagnostic_outer_bound_violation": False, "diagnostic_outer_rejection": None,
            "diagnostic_workload_outcome": "unavailable", "private_collector_rejection_cause": "unknown",
            "private_collector_bytes": "unknown", "source_admission_sha256": source_admission_sha,
            "pull_request": {"number": 42, "merged": False, "state": "open", "head_sha": source,
                "base_sha": "d4865061f524a8637342562710af72dd2d583ae3"},
            "diagnostic_artifacts": {**refs, "public_admission": public_admission_ref,
                "readiness": readiness_ref}}
        repair = {"diagnostic_case": BATCH.NATIVE_RESULT_HANDOFF_CASE,
            "diagnostic_profile": BATCH.NATIVE_RESULT_HANDOFF_PROFILE,
            "diagnostic_only": True, "live_retry_authorized": False,
            "qualification_accepted": False, "unknown_high_findings": False,
            "safety_job_failed": False, "had_safety_job_failure": False,
            "hosted_cleanup_outcome": "unknown", "diagnostic_outer_cleanup": "confirmed",
            "diagnostic_outer_return": "zero", "diagnostic_outer_bound_violation": False,
            "diagnostic_outer_rejection": None, "diagnostic_workload_outcome": "unavailable",
            "private_collector_rejection_cause": "unknown", "private_collector_bytes": "unknown",
            "original_failure_cause": "unknown", "full_qualification_dispatched": False,
            "merge_attempted": False, "result_reviews": review_refs}
        with mock.patch.object(BATCH, "NATIVE_RESULT_HANDOFF_REPORT_SHA256", refs["downloaded_report"]["sha256"]), \
             mock.patch.object(BATCH, "NATIVE_RESULT_HANDOFF_RESULT_SHA256", refs["result"]["sha256"]), \
             mock.patch.object(BATCH, "NATIVE_RESULT_HANDOFF_PAYLOAD_SHA256",
                 payload_sha), \
             mock.patch.object(BATCH, "NATIVE_RESULT_HANDOFF_PUBLIC_ADMISSION_SHA256",
                 public_admission_ref["sha256"]), \
             mock.patch.object(BATCH, "NATIVE_RESULT_HANDOFF_READINESS_SHA256",
                 readiness_ref["sha256"]), \
             mock.patch.object(BATCH, "_validate_native_readiness") as readiness:
            BATCH._validate_native_result_handoff_artifacts(root, expected_root=attempt.as_posix(),
                terminal=terminal, repair=repair, journal=journal, failure=failure)
            readiness.assert_called_once_with(root, root / attempt.as_posix(), admission,
                public_admission_ref["sha256"], root / attempt / "native-diagnostic-readiness.json",
                readiness_ref["sha256"])

            bad_terminal = {**terminal, "diagnostic_workload_outcome": "pass"}
            with self.assertRaisesRegex(ValueError, "native-result-handoff-invalid"):
                BATCH._validate_native_result_handoff_artifacts(root, expected_root=attempt.as_posix(),
                    terminal=bad_terminal, repair=repair, journal=journal, failure=failure)
            bad_repair = {**repair, "private_collector_bytes": 1234567}
            with self.assertRaisesRegex(ValueError, "native-result-handoff-invalid"):
                BATCH._validate_native_result_handoff_artifacts(root, expected_root=attempt.as_posix(),
                    terminal=terminal, repair=bad_repair, journal=journal, failure=failure)

    def test_native_result_handoff_current_source_preparation_requires_exact_six_file_delta(self):
        self.assertEqual(BATCH.NATIVE_RESULT_HANDOFF_SOURCE_PATHS, {
            "scripts/evidence/v02_run.py",
            "scripts/release/v02_qualification.py",
            "scripts/release/v02_batch.py",
            "tests/evidence/phase7_native_diagnostic_contract.py",
            "tests/evidence/v02_qualification_contract.py",
            "tests/evidence/phase7_fresh_batch_contract.py",
        })
        prior_root = self.root / BATCH.POLICY_ROOT / "attempt-0001"
        current_root = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        current_root.mkdir(parents=True)
        original_paths = set(self.source_paths)
        handoff_paths = set(BATCH.NATIVE_RESULT_HANDOFF_SOURCE_PATHS)
        prior_pins = dict(self.pins)
        for relative in handoff_paths - set(prior_pins):
            data = ("prior:" + relative).encode()
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            prior_pins[relative] = hashlib.sha256(data).hexdigest()
        for relative in original_paths - handoff_paths:
            prior_pins[relative] = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
        current_pins = dict(prior_pins)
        prior_source = {"source_head": "b" * 40, "source_pins": prior_pins}
        prior_source_path = prior_root / "source-admission.json"
        prior_source_digest = self._write_admission(prior_source_path, prior_source)

        def write_prior(relative, value):
            path = prior_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            path.write_bytes(raw)
            return self._reference(path, raw)

        failure_ref = write_prior("failure.json", {"schema": "genewhip.phase7-fresh-batch-failure.v1"})
        journal_ref = write_prior("hosted-delivery-journal.json", {"started_at": self.started})
        terminal_ref = write_prior("terminal-observation.json", {})
        handoff_repair = {"diagnostic_case": BATCH.NATIVE_RESULT_HANDOFF_CASE,
            "diagnostic_profile": BATCH.NATIVE_RESULT_HANDOFF_PROFILE,
            "diagnostic_only": True, "live_retry_authorized": False,
            "qualification_accepted": False, "merge_attempted": False,
            "full_qualification_dispatched": False}
        repair_ref = write_prior("repair-evidence.json", handoff_repair)
        predecessor = {"attempt_index": 1, "attempt_root": prior_root.relative_to(self.root).as_posix(),
            "failure": failure_ref, "journal": journal_ref,
            "terminal_observation": terminal_ref, "repair_evidence": repair_ref,
            "cleanup_evidence": None,
            "source_admission": self._reference(prior_source_path, prior_source_path.read_bytes()),
            "disposition": "bounded-diagnostic-followup", "all_ci_terminal": True,
            "safety_status": "diagnostic-only", "cleanup_status": "unknown-hosted-test-outcome",
            "unknown_high_findings": False}

        self.source_paths = original_paths | handoff_paths
        for relative in handoff_paths:
            data = ("reviewed-handoff-fix:" + relative).encode()
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            current_pins[relative] = hashlib.sha256(data).hexdigest()
        self.batch_root = current_root
        self.predecessor = predecessor
        self.journal = current_root / "hosted-delivery-journal.json"
        self.publication = current_root / "candidate/publication-copy"
        self.preparation = current_root / "candidate/preparation.json"
        self.output = self.preparation
        self.source_admission_path = current_root / "source-admission.json"

        def write_current(selected):
            current = self._source_admission(selected, attempt_index=2,
                predecessor=predecessor, disposition="bounded-diagnostic-followup")
            digest = self._write_admission(self.source_admission_path, current)
            return digest

        expected_predecessor_digest = hashlib.sha256(BATCH._canonical(predecessor)).hexdigest()
        with mock.patch.object(BATCH, "_validate_predecessor",
                return_value=(predecessor, expected_predecessor_digest)):
            accepted_digest = write_current(current_pins)
            accepted = self._validate(admission_path=self.source_admission_path,
                admission_sha=accepted_digest, journal=self.journal, publication=self.publication,
                preflight=self.preparation, output=self.preparation)
            self.assertEqual(accepted["admission"]["predecessor"]["attempt_index"], 1)
            self.assertEqual(accepted["admission"]["disposition"], "bounded-diagnostic-followup")

            # A missing reviewed change is rejected even when the reverted bytes
            # and prior digest are internally consistent.
            changed_path = sorted(handoff_paths)[0]
            changed_target = self.root / changed_path
            changed_bytes = changed_target.read_bytes()
            prior_bytes = ("prior:" + changed_path).encode()
            changed_target.write_bytes(prior_bytes)
            missing_delta = dict(current_pins)
            missing_delta[changed_path] = hashlib.sha256(prior_bytes).hexdigest()
            digest = write_current(missing_delta)
            with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-source-change-unproven"):
                self._validate(admission_path=self.source_admission_path,
                    admission_sha=digest, journal=self.journal, publication=self.publication,
                    preflight=self.preparation, output=self.preparation)
            changed_target.write_bytes(changed_bytes)

            # An unrelated seventh change is also rejected.
            extra_path = "scripts/ci/required-gate.sh"
            extra_target = self.root / extra_path
            prior_extra = extra_target.read_bytes()
            extra_changed = b"# unrelated unreviewed change\n"
            extra_target.write_bytes(extra_changed)
            extra_delta = dict(current_pins)
            extra_delta[extra_path] = hashlib.sha256(extra_changed).hexdigest()
            digest = write_current(extra_delta)
            with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-source-change-unproven"):
                self._validate(admission_path=self.source_admission_path,
                    admission_sha=digest, journal=self.journal, publication=self.publication,
                    preflight=self.preparation, output=self.preparation)
            extra_target.write_bytes(prior_extra)

    def test_native_input_mask_alignment_source_preparation_requires_exact_four_file_delta(self):
        expected_paths = {
            "scripts/evidence/v02_run.py",
            "scripts/release/v02_batch.py",
            "tests/evidence/phase7_fresh_batch_contract.py",
            "tests/evidence/phase7_native_diagnostic_contract.py",
        }
        self.assertEqual(BATCH.NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_PATHS, expected_paths)
        prior_root = self.root / BATCH.POLICY_ROOT / "attempt-0001"
        current_root = self.root / BATCH.POLICY_ROOT / "attempt-0002"
        prior_root.mkdir(parents=True, exist_ok=True)
        current_root.mkdir(parents=True)
        original_paths = set(self.source_paths)
        prior_pins = dict(self.pins)
        current_pins = dict(self.pins)
        for relative in expected_paths - set(prior_pins):
            old = ("prior-input-mask-fix:" + relative).encode()
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(old)
            prior_pins[relative] = hashlib.sha256(old).hexdigest()
            current_pins[relative] = prior_pins[relative]
        for relative in original_paths - expected_paths:
            prior_pins[relative] = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()

        def write_prior(relative, value):
            path = prior_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            path.write_bytes(raw)
            return self._reference(path, raw)

        prior_source = {"status": "source-preparation", "source_head": self.source_head,
            "source_pins": prior_pins}
        prior_source_path = prior_root / "source-admission.json"
        prior_source_raw = json.dumps(prior_source, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        prior_source_path.write_bytes(prior_source_raw)
        failure = {"schema": "genewhip.phase7-fresh-batch-failure.v1",
            "authorization_sha256": BATCH.AUTH_SHA256, "stage": "preview-ci",
            "reason": "diagnostic-ci-complete-assessment-required",
            "observed_at": self.started}
        failure_ref = write_prior("failure.json", failure)
        journal_ref = write_prior("hosted-delivery-journal.json", {"started_at": self.started})
        names = sorted(BATCH.NATIVE_HOST_RUNTIME_JOBS)
        jobs = [{"name": name, "status": "completed",
            "conclusion": "failure" if name == "v02-runtime" else "skipped",
            "id": 800000 + index, "run_id": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID}
            for index, name in enumerate(names)]
        terminal = {"all_jobs_terminal": True, "event": "workflow_dispatch", "jobs": jobs,
            "owning_case": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_CASE,
            "diagnostic_profile": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_PROFILE,
            "run_status": "completed", "run_conclusion": "failure",
            "workflow_run_id": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_RUN_ID, "run_attempt": 1,
            "head_sha": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_SOURCE_SHA,
            "qualification_accepted": False, "full_qualification_dispatched": False,
            "merge_attempted": False, "safety_job_failed": False,
            "local_monitor_safety_issue": False, "hosted_cleanup_outcome": "unknown",
            "diagnostic_outer_cleanup": "confirmed", "diagnostic_outer_return": "zero",
            "diagnostic_outer_bound_violation": False, "diagnostic_outer_rejection": None,
            "diagnostic_workload_outcome": "unavailable",
            "private_collector_rejection_cause": "unknown", "private_collector_bytes": "unknown",
            "original_failure_cause": "unknown",
            "pull_request": {"number": 43, "merged": False, "state": "open"}}
        terminal_ref = write_prior("terminal-observation.json", terminal)
        repair = {"diagnostic_case": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_CASE,
            "diagnostic_profile": BATCH.NATIVE_INPUT_MASK_ALIGNMENT_PROFILE,
            "diagnostic_only": True, "live_retry_authorized": False,
            "qualification_accepted": False, "full_qualification_dispatched": False,
            "merge_attempted": False, "safety_job_failed": False,
            "had_safety_job_failure": False, "hosted_cleanup_outcome": "unknown",
            "diagnostic_outer_cleanup": "confirmed", "diagnostic_workload_outcome": "unavailable",
            "private_collector_rejection_cause": "unknown", "private_collector_bytes": "unknown",
            "original_failure_cause": "unknown", "unknown_high_findings": False}
        repair_ref = write_prior("repair-evidence.json", repair)
        predecessor = {"attempt_index": 1, "attempt_root": prior_root.relative_to(self.root).as_posix(),
            "failure": failure_ref, "journal": journal_ref, "terminal_observation": terminal_ref,
            "repair_evidence": repair_ref, "cleanup_evidence": None,
            "source_admission": self._reference(prior_source_path, prior_source_raw),
            "disposition": "bounded-diagnostic-followup", "all_ci_terminal": True,
            "safety_status": "diagnostic-only", "cleanup_status": "unknown-hosted-test-outcome",
            "unknown_high_findings": False}
        expected_predecessor_digest = hashlib.sha256(BATCH._canonical(predecessor)).hexdigest()

        self.source_paths = original_paths | expected_paths
        for relative in expected_paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            new = ("reviewed-input-mask-fix:" + relative).encode()
            target.write_bytes(new)
            current_pins[relative] = hashlib.sha256(new).hexdigest()
        self.batch_root = current_root
        self.predecessor = predecessor
        self.journal = current_root / "hosted-delivery-journal.json"
        self.publication = current_root / "candidate/publication-copy"
        self.preparation = current_root / "candidate/preparation.json"
        self.output = self.preparation
        self.source_admission_path = current_root / "source-admission.json"

        def write_current(selected):
            current = self._source_admission(selected, attempt_index=2,
                predecessor=predecessor, disposition="bounded-diagnostic-followup")
            return self._write_admission(self.source_admission_path, current)

        with mock.patch.object(BATCH, "_validate_predecessor",
                return_value=(predecessor, expected_predecessor_digest)):
            digest = write_current(current_pins)
            accepted = self._validate(admission_path=self.source_admission_path,
                admission_sha=digest, journal=self.journal, publication=self.publication,
                preflight=self.preparation, output=self.preparation)
            self.assertEqual(accepted["admission"]["disposition"], "bounded-diagnostic-followup")

            missing_path = sorted(expected_paths)[0]
            target = self.root / missing_path
            current_bytes = target.read_bytes()
            prior_bytes = ("prior-input-mask-fix:" + missing_path).encode()
            target.write_bytes(prior_bytes)
            missing = dict(current_pins)
            missing[missing_path] = hashlib.sha256(prior_bytes).hexdigest()
            digest = write_current(missing)
            with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-source-change-unproven"):
                self._validate(admission_path=self.source_admission_path, admission_sha=digest,
                    journal=self.journal, publication=self.publication,
                    preflight=self.preparation, output=self.preparation)
            target.write_bytes(current_bytes)

            extra_path = "scripts/ci/required-gate.sh"
            extra_target = self.root / extra_path
            original_extra = extra_target.read_bytes()
            extra_bytes = b"# unreviewed fifth input-mask change\n"
            extra_target.write_bytes(extra_bytes)
            extra = dict(current_pins)
            extra[extra_path] = hashlib.sha256(extra_bytes).hexdigest()
            digest = write_current(extra)
            with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-source-change-unproven"):
                self._validate(admission_path=self.source_admission_path, admission_sha=digest,
                    journal=self.journal, publication=self.publication,
                    preflight=self.preparation, output=self.preparation)
            extra_target.write_bytes(original_extra)

    def test_accepted_native_resumption_requires_exact_source_and_public_tree(self):
        pins = {"scripts/evidence/v02_run.py": "a" * 64,
                "scripts/release/v02_qualification.py": "b" * 64}
        prior = {"status": "source-preparation", "source_head": "c" * 40,
                 "source_pins": dict(pins)}
        repair = {"diagnostic_profile": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE,
                  "diagnostic_public_tree": "d" * 40, "diagnostic_public_base": "e" * 40}
        BATCH._validate_diagnostic_resumption_binding(stage="source-preparation",
            source_head="c" * 40, source_pins=pins, prior_source=prior, repair=repair)
        BATCH._validate_diagnostic_resumption_binding(stage="public-effects",
            source_head="c" * 40, source_pins=pins, prior_source=prior, repair=repair,
            candidate={"public_tree": "d" * 40, "public_base": "e" * 40})
        BATCH._require_diagnostic_successor_disposition(repair, "reviewed-diagnostic-resumption")
        BATCH._require_diagnostic_successor_disposition(
            {"diagnostic_profile": "ordinary-runtime"}, "routine-source-repair")
        with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-resumption-required"):
            BATCH._require_diagnostic_successor_disposition(repair, "routine-source-repair")
        for kwargs in (
                {"stage": "native-diagnostic", "source_head": "c" * 40,
                 "source_pins": pins, "prior_source": prior, "repair": repair},
                {"stage": "source-preparation", "source_head": "f" * 40,
                 "source_pins": pins, "prior_source": prior, "repair": repair},
                {"stage": "source-preparation", "source_head": "c" * 40,
                 "source_pins": {**pins, "scripts/release/v02_batch.py": "f" * 64},
                 "prior_source": prior, "repair": repair},
                {"stage": "public-effects", "source_head": "c" * 40,
                 "source_pins": pins, "prior_source": prior, "repair": repair,
                 "candidate": {"public_tree": "f" * 40, "public_base": "e" * 40}},
                {"stage": "public-effects", "source_head": "c" * 40,
                 "source_pins": pins, "prior_source": prior, "repair": repair,
                 "candidate": {"public_tree": "d" * 40, "public_base": "f" * 40}},
                {"stage": "source-preparation", "source_head": "c" * 40,
                 "source_pins": pins, "prior_source": {**prior, "status": "public-effects"},
                 "repair": repair},
                {"stage": "source-preparation", "source_head": "c" * 40,
                 "source_pins": pins, "prior_source": prior,
                 "repair": {**repair, "diagnostic_profile": BATCH.NATIVE_RESULT_HANDOFF_PROFILE}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                BATCH._validate_diagnostic_resumption_binding(**kwargs)

    def test_accepted_native_resumption_revalidates_real_v2_report_and_stop_artifacts(self):
        native_test_path = ROOT / "tests/evidence/phase7_native_diagnostic_contract.py"
        native_tests = load(native_test_path, "fresh_batch_native_diagnostic_contract")
        native_root = self.root
        runtime_validator_relative = "scripts/evidence/v02_run.py"
        runtime_validator_bytes = (ROOT / runtime_validator_relative).read_bytes()
        fixture = self._native_readiness_successor(source_overrides={
            runtime_validator_relative: runtime_validator_bytes})
        original_root = native_tests.ROOT
        native_tests.ROOT = native_root
        self.addCleanup(setattr, native_tests, "ROOT", original_root)
        attempt = fixture["root"].relative_to(native_root)
        base_path = native_root / attempt
        source_admission = json.loads((base_path / "source-admission.json").read_bytes())
        public_admission = json.loads((base_path / "public-admission.json").read_bytes())
        private_source_head = source_admission["source_head"]
        source_head = public_admission["candidate"]["public_head"]
        public_base = public_admission["candidate"]["public_base"]
        nonce, run_id = "d" * 32, 12345
        source_branch = "v0.2-source-" + source_head[:12]
        native_case = native_tests.NativeDiagnosticContract()
        try:
            result, _calls, _out, fixture_root = native_case.run_pipeline()
            outer = {"returncode": 0, "launch_error": None,
                "process_group_cleanup": "confirmed", "processes": [{
                    "return_code": 0, "status": "completed",
                    "process_group_cleanup": "confirmed", "bound_violation": False}]}
            report = native_tests.NativeDiagnosticContract.public_report(result, outer, fixture_root)
        finally:
            native_case.doCleanups()
        identity = {"source_sha": source_head, "head_sha": source_head,
            "base_sha": public_base, "run_id": str(run_id), "run_attempt": "1"}
        report["identity"] = identity

        def write_json(relative, value):
            path = native_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            path.write_bytes(raw)
            return {"path": Path(relative).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}

        started = source_admission["started_at"]
        candidate = public_admission["candidate"]
        pins = source_admission["source_pins"]
        public_admission_path = base_path / "public-admission.json"
        source_admission_path = base_path / "source-admission.json"
        public_ref = self._reference(public_admission_path, public_admission_path.read_bytes())
        source_raw = source_admission_path.read_bytes()
        source_sha = hashlib.sha256(source_raw).hexdigest()
        readiness_path = base_path / "native-diagnostic-readiness.json"
        readiness_ref = self._reference(readiness_path, readiness_path.read_bytes())
        report_ref = write_json(attempt / "native-diagnostic/download/native-diagnostic.json", report)
        jobs = [{"id": 9000 + index, "name": name, "status": "completed",
            "conclusion": "success" if name == "v02-runtime" else "skipped",
            "run_id": run_id} for index, name in enumerate(sorted(BATCH.NATIVE_HOST_RUNTIME_JOBS))]
        runtime_job = next(row for row in jobs if row["name"] == "v02-runtime")
        run = {"id": run_id, "event": "workflow_dispatch", "status": "completed",
            "conclusion": "success", "path": ".github/workflows/ci.yml",
            "head_sha": source_head, "head_branch": source_branch, "run_attempt": 1,
            "name": f"Plan10 native diagnostic {nonce}",
            "display_title": f"Plan10 native diagnostic {nonce}",
            "repository": {"full_name": "szTheory/genewhip", "private": False}}
        refs = {
            "workflow_run": write_json(attempt / f"ci-failure/native-workflow-run-{run_id}.json", run),
            "jobs": write_json(attempt / f"ci-failure/native-jobs-{run_id}.json", {"jobs": jobs}),
            "workflow_extraction": write_json(attempt / "ci-failure/native-workflow-run-extraction.json",
                {"selected_run_id": run_id, "source_receipt_sha256": "f" * 64}),
            "workflow_log": {"path": (attempt / f"ci-failure/native-job-{runtime_job['id']}.log").as_posix()},
            "dispatch": {}, "result": {}, "downloaded_report": report_ref,
            "public_admission": public_ref, "readiness": readiness_ref}
        log_path = native_root / refs["workflow_log"]["path"]
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = b"native-diagnostic: pass; qualification_accepted=false\n"
        log_path.write_bytes(log)
        refs["workflow_log"]["sha256"] = hashlib.sha256(log).hexdigest()
        dispatch = {"schema": "genewhip.phase7-native-diagnostic-dispatch.v1",
            "run_id": run_id, "dispatches": 1, "nonce": nonce, "source_sha": source_head,
            "status": "completed-assessment-required", "qualification_accepted": False,
            "started_at": started, "readiness_sha256": readiness_ref["sha256"]}
        refs["dispatch"] = write_json(attempt / "native-diagnostic/dispatch.json", dispatch)
        result_value = {"schema": "genewhip.phase7-native-diagnostic-result.v1", "status": "pass",
            "qualification_accepted": False, "assessment_required": True, "run_id": str(run_id),
            "source_sha": source_head, "run_attempt": "1", "report_sha256": report_ref["sha256"],
            "report_path": report_ref["path"], "branch": source_branch}
        refs["result"] = write_json(attempt / "native-diagnostic/result.json", result_value)
        journal = {"repository": "szTheory/genewhip", "source_head": source_head,
            "public_base_sha": public_base, "started_at": started, "diagnostic_only": True,
            "diagnostic_ci_status": "passed", "assessment_required": True,
            "merge_attempted": False, "pull_request": "42"}
        failure = {"authorization_sha256": BATCH.AUTH_SHA256,
            "schema": "genewhip.phase7-fresh-batch-failure.v1",
            "stage": "preview-ci", "reason": "diagnostic-ci-complete-assessment-required",
            "observed_at": "2026-10-31T12:55:00Z"}
        reviews = {}
        result_sha = hashlib.sha256(json.dumps(result_value, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        for key, role in BATCH.SOURCE_ROLES.items():
            review_path = Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery") / f"{key}.md"
            review_file = native_root / review_path
            review_file.parent.mkdir(parents=True, exist_ok=True)
            review_file.write_text("---\nstatus: accepted\nreviewer_role: " + role
                + "\npayload_sha256: " + result_sha + "\nsource_head: " + private_source_head + "\n---\n")
            reviews[key] = {"path": review_path.as_posix(),
                "sha256": hashlib.sha256(review_file.read_bytes()).hexdigest(),
                "reviewer_role": role, "status": "accepted", "payload_sha256": result_sha}
        terminal = {"workflow_run_id": run_id, "runtime_job_id": runtime_job["id"],
            "head_sha": source_head, "diagnostic_nonce": nonce,
            "pull_request": {"number": 42, "base_sha": public_base,
                "merged": False, "state": "open", "head_sha": source_head},
            "diagnostic_artifacts": refs, "source_admission_sha256": source_sha,
            "diagnostic_public_tree": candidate["public_tree"],
            "diagnostic_public_base": public_base,
            "owning_case": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_CASE,
            "diagnostic_profile": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE,
            "qualification_accepted": False, "full_qualification_dispatched": False,
            "merge_attempted": False, "safety_job_failed": False,
            "diagnostic_outer_cleanup": "confirmed", "diagnostic_outer_return": "zero",
            "diagnostic_outer_bound_violation": False, "diagnostic_outer_rejection": None,
            "cleanup_disposition": "confirmed",
            "safety_job_failed": False, "had_safety_job_failure": False,
            "diagnostic_workload_outcome": "pass", "hosted_cleanup_outcome": "confirmed",
            "original_failure_cause": "unknown"}
        repair = {**terminal, "diagnostic_case": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_CASE,
            "diagnostic_only": True, "live_retry_authorized": False,
            "unknown_high_findings": False, "result_reviews": reviews}
        repair["safety_or_cleanup_issue"] = False
        validated = BATCH._validate_accepted_native_diagnostic(native_root,
            expected_root=attempt.as_posix(), terminal=terminal, repair=repair,
            journal=fixture["current_journal"], failure=fixture["current_failure"])
        self.assertEqual(validated["source_admission"], source_admission)
        self.assertEqual(validated["public_tree"], candidate["public_tree"])
        self.assertNotEqual(source_head, private_source_head)
        for changed in (
                {**terminal, "qualification_accepted": True},
                {**terminal, "diagnostic_outer_cleanup": "unknown"},
                {**terminal, "merge_attempted": True},
                {**terminal, "pull_request": {**terminal["pull_request"], "number": True}},
        ):
            with self.subTest(changed=changed), mock.patch.object(BATCH, "_validate_native_readiness"):
                with self.assertRaisesRegex(ValueError, "fresh-batch-accepted-native-diagnostic-invalid"):
                    BATCH._validate_accepted_native_diagnostic(native_root,
                        expected_root=attempt.as_posix(), terminal=changed, repair=repair,
                        journal=fixture["current_journal"], failure=fixture["current_failure"])
        bad_failure = {**failure, "reason": "other"}
        with mock.patch.object(BATCH, "_validate_native_readiness"):
            with self.assertRaisesRegex(ValueError, "fresh-batch-accepted-native-diagnostic-invalid"):
                BATCH._validate_accepted_native_diagnostic(native_root,
                    expected_root=attempt.as_posix(), terminal=terminal, repair=repair,
                    journal=fixture["current_journal"], failure=bad_failure)
        wrong_private_review_path = native_root / reviews["code"]["path"]
        wrong_private_review = wrong_private_review_path.read_bytes()
        wrong_private_review_path.write_bytes(wrong_private_review.replace(
            ("source_head: " + private_source_head).encode(),
            ("source_head: " + "f" * 40).encode()))
        changed_reviews = {**reviews, "code": {**reviews["code"],
            "sha256": hashlib.sha256(wrong_private_review_path.read_bytes()).hexdigest()}}
        try:
            with self.assertRaisesRegex(ValueError, "fresh-batch-accepted-native-diagnostic-invalid"):
                BATCH._validate_accepted_native_diagnostic(native_root,
                    expected_root=attempt.as_posix(), terminal=terminal,
                    repair={**repair, "result_reviews": changed_reviews},
                    journal=fixture["current_journal"], failure=fixture["current_failure"])
        finally:
            wrong_private_review_path.write_bytes(wrong_private_review)

        # Mutating the untrusted public pin and its outer hash cannot authorize
        # importing changed validator bytes. Rebuild the dependent readiness,
        # dispatch and terminal digests too; the source admission stays fixed.
        public_raw = public_admission_path.read_bytes()
        readiness_raw = readiness_path.read_bytes()
        dispatch_path = base_path / "native-diagnostic/dispatch.json"
        dispatch_raw = dispatch_path.read_bytes()
        validator_path = native_root / "scripts/evidence/v02_run.py"
        original_validator = validator_path.read_bytes()
        execution_sentinel = native_root / "untrusted-validator-executed"
        sentinel_code = (
            "\nfrom pathlib import Path\nPath(" + repr(str(execution_sentinel))
            + ").write_text('executed', encoding='utf-8')\n").encode()
        validator_path.write_bytes(original_validator + sentinel_code)
        altered_public = json.loads(public_raw)
        altered_public["source_pins"]["scripts/evidence/v02_run.py"] = hashlib.sha256(
            validator_path.read_bytes()).hexdigest()
        altered_public_raw = json.dumps(altered_public, sort_keys=True,
            separators=(",", ":")).encode() + b"\n"
        public_admission_path.write_bytes(altered_public_raw)
        altered_terminal = json.loads(json.dumps(terminal))
        altered_readiness = json.loads(readiness_raw)
        altered_readiness["public_admission"] = {"path": public_ref["path"],
            "sha256": hashlib.sha256(altered_public_raw).hexdigest()}
        readiness_payload = {key: value for key, value in altered_readiness.items()
            if key != "assessment_reviews"}
        altered_readiness["assessment_reviews"] = self._source_head_reviews(
            "tampered-public-pin-readiness", hashlib.sha256(
                BATCH._canonical(readiness_payload)).hexdigest())
        altered_readiness_raw = json.dumps(altered_readiness, sort_keys=True,
            separators=(",", ":")).encode() + b"\n"
        readiness_path.write_bytes(altered_readiness_raw)
        readiness_sha = hashlib.sha256(altered_readiness_raw).hexdigest()
        altered_dispatch = json.loads(dispatch_raw)
        altered_dispatch["readiness_sha256"] = readiness_sha
        altered_dispatch_raw = json.dumps(altered_dispatch, sort_keys=True,
            separators=(",", ":")).encode() + b"\n"
        dispatch_path.write_bytes(altered_dispatch_raw)
        altered_terminal["diagnostic_artifacts"]["public_admission"] = {
            "path": public_ref["path"], "sha256": hashlib.sha256(altered_public_raw).hexdigest()}
        altered_terminal["diagnostic_artifacts"]["readiness"] = {
            "path": readiness_ref["path"], "sha256": readiness_sha}
        altered_terminal["diagnostic_artifacts"]["dispatch"] = {
            "path": refs["dispatch"]["path"],
            "sha256": hashlib.sha256(altered_dispatch_raw).hexdigest()}
        try:
            with self.assertRaisesRegex(ValueError, "fresh-batch-accepted-native-diagnostic-invalid"):
                BATCH._validate_accepted_native_diagnostic(native_root,
                    expected_root=attempt.as_posix(), terminal=altered_terminal, repair=repair,
                    journal=fixture["current_journal"], failure=fixture["current_failure"])
            self.assertFalse(execution_sentinel.exists())
            self.assertNotIn("gw_phase7_native_report_validator", sys.modules)
        finally:
            public_admission_path.write_bytes(public_raw)
            readiness_path.write_bytes(readiness_raw)
            dispatch_path.write_bytes(dispatch_raw)
            validator_path.write_bytes(original_validator)

    def test_validate_batch_accepts_reviewed_native_successor_at_both_real_stages(self):
        native_tests = load(ROOT / "tests/evidence/phase7_native_diagnostic_contract.py",
            "fresh_batch_native_diagnostic_entry_contract")
        runtime_path = "scripts/evidence/v02_run.py"
        fixture = self._native_readiness_successor(source_overrides={
            runtime_path: (ROOT / runtime_path).read_bytes()})
        self.pins = dict(fixture["source_pins"])
        native_tests.ROOT = self.root
        attempt2 = fixture["root"]
        source2 = json.loads((attempt2 / "source-admission.json").read_bytes())
        public2 = json.loads((attempt2 / "public-admission.json").read_bytes())
        attempt2_identity = BATCH._predecessor_identity_sha256(source2["predecessor"])
        BATCH._claim_successor(self.root, predecessor_sha256=attempt2_identity,
            predecessor_record_sha256=hashlib.sha256(BATCH._canonical(
                source2["predecessor"])).hexdigest(),
            attempt_root=attempt2.relative_to(self.root).as_posix(),
            source_payload_sha256=source2["source_payload_sha256"])
        private_head = source2["source_head"]
        public_head = public2["candidate"]["public_head"]
        public_base = public2["candidate"]["public_base"]
        run_id, nonce = 7654321, "a" * 32
        branch = "v0.2-source-" + public_head[:12]
        native_case = native_tests.NativeDiagnosticContract()
        self.addCleanup(native_case.doCleanups)
        result, _calls, _out, fixture_root = native_case.run_pipeline()
        outer = {"returncode": 0, "launch_error": None, "process_group_cleanup": "confirmed",
            "processes": [{"return_code": 0, "status": "completed",
                "process_group_cleanup": "confirmed", "bound_violation": False}]}
        report = native_tests.NativeDiagnosticContract.public_report(result, outer, fixture_root)
        report["identity"] = {"source_sha": public_head, "head_sha": public_head,
            "base_sha": public_base, "run_id": str(run_id), "run_attempt": "1"}

        def write_json(relative, value):
            path = Path(relative)
            if not path.is_absolute():
                path = self.root / path
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            path.write_bytes(raw)
            return {"path": path.relative_to(self.root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest()}

        source_ref = self._reference(attempt2 / "source-admission.json",
            (attempt2 / "source-admission.json").read_bytes())
        public_ref = self._reference(attempt2 / "public-admission.json",
            (attempt2 / "public-admission.json").read_bytes())
        readiness_path = attempt2 / "native-diagnostic-readiness.json"
        readiness_ref = self._reference(readiness_path, readiness_path.read_bytes())
        report_ref = write_json((attempt2 / "native-diagnostic/download/native-diagnostic.json").relative_to(self.root), report)
        jobs = [{"id": 8100 + index, "name": name, "status": "completed",
            "conclusion": "success" if name == "v02-runtime" else "skipped", "run_id": run_id}
            for index, name in enumerate(sorted(BATCH.NATIVE_HOST_RUNTIME_JOBS))]
        runtime_job = next(row for row in jobs if row["name"] == "v02-runtime")
        run = {"id": run_id, "event": "workflow_dispatch", "status": "completed",
            "conclusion": "success", "path": ".github/workflows/ci.yml", "head_sha": public_head,
            "head_branch": branch, "run_attempt": 1,
            "name": f"Plan10 native diagnostic {nonce}",
            "display_title": f"Plan10 native diagnostic {nonce}",
            "repository": {"full_name": "szTheory/genewhip", "private": False}}
        workflow_ref = write_json(attempt2 / f"ci-failure/native-workflow-run-{run_id}.json", run)
        jobs_ref = write_json(attempt2 / f"ci-failure/native-jobs-{run_id}.json", {"jobs": jobs})
        extraction_ref = write_json(attempt2 / "ci-failure/native-workflow-run-extraction.json",
            {"selected_run_id": run_id, "source_receipt_sha256": "f" * 64})
        log_path = attempt2 / f"ci-failure/native-job-{runtime_job['id']}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_raw = b"native-diagnostic: pass; qualification_accepted=false\n"
        log_path.write_bytes(log_raw)
        refs = {"workflow_run": workflow_ref, "jobs": jobs_ref,
            "workflow_extraction": extraction_ref, "workflow_log": self._reference(log_path, log_raw),
            "dispatch": {}, "result": {}, "downloaded_report": report_ref,
            "public_admission": public_ref, "readiness": readiness_ref}
        dispatch = {"schema": "genewhip.phase7-native-diagnostic-dispatch.v1",
            "run_id": run_id, "dispatches": 1, "nonce": nonce, "source_sha": public_head,
            "status": "completed-assessment-required", "qualification_accepted": False,
            "started_at": self.started, "readiness_sha256": readiness_ref["sha256"]}
        refs["dispatch"] = write_json(attempt2 / "native-diagnostic/dispatch.json", dispatch)
        result_value = {"schema": "genewhip.phase7-native-diagnostic-result.v1", "status": "pass",
            "qualification_accepted": False, "assessment_required": True, "run_id": str(run_id),
            "source_sha": public_head, "run_attempt": "1", "report_sha256": report_ref["sha256"],
            "report_path": report_ref["path"], "branch": branch}
        refs["result"] = write_json(attempt2 / "native-diagnostic/result.json", result_value)
        result_sha = hashlib.sha256(BATCH._canonical(result_value)).hexdigest()
        result_reviews = self._source_head_reviews("accepted-native-result", result_sha)
        terminal = {"all_jobs_terminal": True, "jobs": jobs, "event": "workflow_dispatch",
            "owning_case": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_CASE,
            "diagnostic_profile": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_PROFILE,
            "workflow_run_id": run_id, "runtime_job_id": runtime_job["id"], "run_status": "completed",
            "run_conclusion": "success", "run_attempt": 1, "head_sha": public_head,
            "diagnostic_nonce": nonce, "diagnostic_artifacts": refs,
            "source_admission_sha256": source_ref["sha256"],
            "diagnostic_public_tree": public2["candidate"]["public_tree"],
            "diagnostic_public_base": public_base, "qualification_accepted": False,
            "full_qualification_dispatched": False, "merge_attempted": False,
            "safety_job_failed": False, "had_safety_job_failure": False,
            "diagnostic_outer_cleanup": "confirmed", "diagnostic_outer_return": "zero",
            "diagnostic_outer_bound_violation": False, "diagnostic_outer_rejection": None,
            "cleanup_disposition": "confirmed", "diagnostic_workload_outcome": "pass",
            "hosted_cleanup_outcome": "confirmed", "original_failure_cause": "unknown",
            "pull_request": {"number": 42, "base_sha": public_base, "merged": False,
                "state": "open", "head_sha": public_head}}
        repair = {**terminal, "diagnostic_case": BATCH.NATIVE_DIAGNOSTIC_RESUMPTION_CASE,
            "diagnostic_only": True, "live_retry_authorized": False,
            "safety_or_cleanup_issue": False, "unknown_high_findings": False,
            "result_reviews": result_reviews}
        terminal_path, repair_path = attempt2 / "terminal-observation.json", attempt2 / "repair-evidence.json"
        expected_native_refs = {
            "workflow_run": f"{attempt2.relative_to(self.root).as_posix()}/ci-failure/native-workflow-run-{run_id}.json",
            "jobs": f"{attempt2.relative_to(self.root).as_posix()}/ci-failure/native-jobs-{run_id}.json",
            "workflow_extraction": f"{attempt2.relative_to(self.root).as_posix()}/ci-failure/native-workflow-run-extraction.json",
            "workflow_log": f"{attempt2.relative_to(self.root).as_posix()}/ci-failure/native-job-{runtime_job['id']}.log",
            "dispatch": f"{attempt2.relative_to(self.root).as_posix()}/native-diagnostic/dispatch.json",
            "result": f"{attempt2.relative_to(self.root).as_posix()}/native-diagnostic/result.json",
            "downloaded_report": f"{attempt2.relative_to(self.root).as_posix()}/native-diagnostic/download/native-diagnostic.json",
            "public_admission": f"{attempt2.relative_to(self.root).as_posix()}/public-admission.json",
            "readiness": f"{attempt2.relative_to(self.root).as_posix()}/native-diagnostic-readiness.json"}
        self.assertEqual({key: ref["path"] for key, ref in refs.items()}, expected_native_refs)
        self._write_admission(terminal_path, terminal)
        self._write_admission(repair_path, repair)
        cleanup_path = attempt2 / "cleanup-evidence.json"
        cleanup = {"processes": [{"cleanup_confirmed": True}]}
        self._write_admission(cleanup_path, cleanup)
        predecessor = {"attempt_index": 2, "attempt_root": attempt2.relative_to(self.root).as_posix(),
            "failure": self._reference(attempt2 / "failure.json", (attempt2 / "failure.json").read_bytes()),
            "journal": self._reference(attempt2 / "hosted-delivery-journal.json",
                (attempt2 / "hosted-delivery-journal.json").read_bytes()),
            "terminal_observation": self._reference(terminal_path, terminal_path.read_bytes()),
            "repair_evidence": self._reference(repair_path, repair_path.read_bytes()),
            "cleanup_evidence": self._reference(cleanup_path, cleanup_path.read_bytes()),
            "source_admission": source_ref, "disposition": "reviewed-diagnostic-resumption",
            "all_ci_terminal": True, "safety_status": "clear", "cleanup_status": "confirmed",
            "unknown_high_findings": False}

        attempt3 = self.root / BATCH.POLICY_ROOT / "attempt-0003"
        attempt3.mkdir(parents=True)
        self.batch_root = attempt3
        self.journal = attempt3 / "hosted-delivery-journal.json"
        self.publication = attempt3 / "candidate/publication-copy"
        self.preparation = attempt3 / "candidate/preparation.json"
        self.output = attempt3 / "candidate/result.json"
        source_admission = self._source_admission(self.pins, attempt_index=3,
            predecessor=predecessor, disposition="reviewed-diagnostic-resumption")
        source_path = attempt3 / "source-admission.json"
        digest = self._write_admission(source_path, source_admission)
        accepted = self._validate(admission_path=source_path, admission_sha=digest,
            journal=self.journal, publication=self.publication, preflight=self.preparation,
            output=self.preparation)
        self.assertEqual(accepted["admission"]["disposition"], "reviewed-diagnostic-resumption")
        self.assertEqual(accepted["predecessor_sha256"], hashlib.sha256(
            BATCH._canonical(predecessor)).hexdigest())
        source_admission_raw = source_path.read_bytes()
        wrong_source = self._source_admission(self.pins, attempt_index=3,
            predecessor=predecessor, disposition="routine-source-repair")
        wrong_source_sha = self._write_admission(source_path, wrong_source)
        with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-resumption-required"):
            self._validate(admission_path=source_path, admission_sha=wrong_source_sha,
                journal=self.journal, publication=self.publication, preflight=self.preparation,
                output=self.preparation)
        source_path.write_bytes(source_admission_raw)

        # Public-effects uses the same source/pin/tree binding and the real
        # candidate/privacy/policy validators; only the output path changes.
        claim = self.root / BATCH.POLICY_ROOT / "successors" / (
            BATCH._predecessor_identity_sha256(predecessor) + ".json")
        claim.unlink()
        public_path, public_digest, _policy = self._public_admission(self.pins,
            disposition="reviewed-diagnostic-resumption", attempt_index=3,
            predecessor=predecessor)
        result_path = attempt3 / "candidate/result.json"
        public_accepted = self._validate(stage="public-effects", admission_path=public_path,
            admission_sha=public_digest, journal=self.journal,
            publication=self.publication, preflight=self.preparation, output=result_path)
        self.assertEqual(public_accepted["admission"]["candidate"]["public_tree"],
            public2["candidate"]["public_tree"])
        self.assertEqual(public_accepted["admission"]["disposition"],
            "reviewed-diagnostic-resumption")
        public_claim = self.root / BATCH.POLICY_ROOT / "successors" / (
            BATCH._predecessor_identity_sha256(predecessor) + ".json")
        public_claim.unlink()
        shutil.rmtree(self.publication)
        wrong_tree_path, wrong_tree_sha, _ = self._public_admission(self.pins,
            disposition="reviewed-diagnostic-resumption", attempt_index=3,
            predecessor=predecessor, public_tree="f" * 40)
        with self.assertRaisesRegex(ValueError, "fresh-batch-diagnostic-resumption-binding-invalid"):
            self._validate(stage="public-effects", admission_path=wrong_tree_path,
                admission_sha=wrong_tree_sha, journal=self.journal,
                publication=self.publication, preflight=self.preparation, output=result_path)

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

    def test_public_snapshot_clone_uses_monitored_bounded_child_and_keeps_sanitized_failure(self):
        project_root = self.root / "clone-project"
        project_root.mkdir()
        coordinator_path = project_root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = load(coordinator_path, "gw_fresh_batch_monitored_public_clone")
        coordinator.ROOT = project_root
        coordinator.FRESH_BATCH_POLICY_ROOT = BATCH.POLICY_ROOT
        coordinator.LEGACY_BATCH_ROOTS = (Path("build/v02/batch-closed"),
            Path("build/v02/batch-closed-retry1"), BATCH.POLICY_ROOT)
        scope = project_root / "evidence/v02-execution.json"
        scope.parent.mkdir(parents=True, exist_ok=True)
        scope.write_text(json.dumps({"schema": "genewhip-v02-execution-v1",
            "qualification_batch": {"wall_seconds": 86400, "runtime_wall_seconds": 64800,
                "package_wall_seconds": 14400, "close_wall_seconds": 7200},
            "per_child_limits": {"max_scratch_bytes": 8_000_000_000,
                "max_binary_file_bytes": 2_147_483_648,
                "max_stdout_stderr_bytes": 1_000_000, "max_capture_bytes": 1_000_000,
                "max_retained_bytes": 100_000, "wall_seconds": 900}}) + "\n")
        authorization = project_root / "build/public-authorization.json"
        authorization.parent.mkdir(parents=True, exist_ok=True)
        authorization.write_text(json.dumps({"schema": "genewhip.publication-readiness-packet.v1",
            "history_disposition": "sanitized-snapshots-preserve-local-history",
            "repository": "szTheory/genewhip", "destination": {
                "owner_repository": "szTheory/genewhip", "visibility": "public"}}) + "\n")
        os.environ["GENEWHIP_FRESH_BATCH_RUNTIME"] = "1"
        batch_root = project_root / BATCH.POLICY_ROOT / "attempt-0001"
        batch_root.mkdir(parents=True)
        os.environ["GENEWHIP_FRESH_BATCH_ROOT"] = batch_root.relative_to(project_root).as_posix()
        os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)).isoformat()
        scratch = batch_root / "coordinator-external-attempts"
        fake_case = {"returncode": 17, "cleanup": "confirmed", "error": None,
                     "stderr": "private clone stderr"}
        bounded_calls = []

        def fake_bounded(command, *, limits, scratch: Path, timeout, label, env,
                         cwd, check, scratch_roots, **kwargs):
            self.assertEqual(timeout, 300)
            self.assertEqual(cwd, project_root)
            self.assertIs(check, False)
            self.assertTrue(scratch_roots[-1].is_dir())
            bounded_calls.append((list(command), scratch, label, scratch_roots, limits,
                                  kwargs.get("file_size_limit_bytes")))
            scenario = fake_case
            process = {"status": "failed", "return_code": scenario["returncode"],
                "process_group_cleanup": scenario["cleanup"], "bound_violation":
                    scenario["cleanup"] != "confirmed", "bound_violation_reason":
                    "phase7-child-timeout" if scenario["error"] == "timeout" else None}
            attempt = {"schema": "genewhip.v02-coordinator-child-attempt.v1",
                "label": label, "argv": coordinator._public_argv(command),
                "returncode": scenario["returncode"],
                "launch_error": scenario["error"], "stdout_tail": "",
                "stderr_tail": scenario["stderr"], "processes": [process],
                "streams": {"stdout": {"text": "", "truncated": False,
                    "observed_bytes": 0, "retained_bytes": 0,
                    "sha256": hashlib.sha256(b"").hexdigest()},
                    "stderr": {"text": scenario["stderr"], "truncated": False,
                    "observed_bytes": len(scenario["stderr"].encode()),
                    "retained_bytes": len(scenario["stderr"].encode()),
                    "sha256": hashlib.sha256(scenario["stderr"].encode()).hexdigest()}},
                "process_group_cleanup": scenario["cleanup"], "output": None,
                "output_sha256": None}
            (scratch / f"{label}.attempt.json").write_text(
                json.dumps(attempt, sort_keys=True) + "\n")
            if scenario["error"] == "timeout":
                raise subprocess.TimeoutExpired(command, timeout)
            if scenario["error"] == "oserror":
                raise OSError("private launch detail")
            if scenario["error"] == "cleanup":
                raise RuntimeError("unconfirmed cleanup private detail")
            return attempt

        def fake_git(path, *args, check=True):
            if path == project_root and args == ("rev-parse", "HEAD"):
                return "a" * 40
            if path.name == "success-copy" and args == ("rev-parse", "HEAD"):
                return "not-a-commit"
            raise AssertionError("unexpected Git query outside clone-success continuation")

        def invoke(destination):
            with mock.patch.object(coordinator, "_git", side_effect=fake_git), \
                 mock.patch.object(coordinator, "_publication_paths", return_value=[]), \
                 mock.patch.object(coordinator, "_projection_crosswalk", return_value={}), \
                 mock.patch.object(coordinator, "_bounded_command", side_effect=fake_bounded):
                return coordinator.prepare_public_snapshot(destination, scope,
                    project_root / "out.json", authorization, root=project_root)

        budget_patch = mock.patch.object(coordinator, "_require_hosted_budget",
            wraps=coordinator._require_hosted_budget)
        budget_spy = budget_patch.start()
        self.addCleanup(budget_patch.stop)
        for suffix, error in (("nonzero", None), ("timeout", "timeout"),
                              ("oserror", "oserror"), ("cleanup", "cleanup")):
            fake_case.update({"returncode": 17 if error is None else -15,
                "cleanup": "unconfirmed" if error == "cleanup" else "confirmed",
                "error": error, "stderr": "private clone stderr"})
            destination = project_root / f"build/v02/attempt/candidate/{suffix}"
            with self.subTest(case=suffix), self.assertRaisesRegex(
                    ValueError, "^authorized-public-main-checkout-failed$") as raised:
                invoke(destination)
            self.assertNotIn("private clone stderr", str(raised.exception))
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            command, attempts_dir, label, scratch_roots, limits, clone_limit = bounded_calls[-1]
            self.assertEqual(command, ["git", "clone", "--single-branch", "--no-tags", "--branch",
                "main", "https://github.com/szTheory/genewhip.git", str(destination)])
            self.assertEqual(limits["wall_seconds"], 300)
            self.assertEqual(scratch_roots[-1], destination)
            self.assertEqual(clone_limit, 2_147_483_648)
            attempt_path = attempts_dir / f"{label}.attempt.json"
            self.assertTrue(attempt_path.is_file())
            self.assertIn("private clone stderr", attempt_path.read_text())

        # Existing and symlink destinations are rejected before the launcher.
        prior_calls = len(bounded_calls)
        with self.assertRaisesRegex(ValueError, "public-snapshot-destination-must-be-new-workspace-child"):
            invoke(project_root / "build/v02/attempt/candidate/nonzero")
        symlink_target = project_root / "build/v02/attempt/candidate/symlink-target"
        symlink_target.mkdir(parents=True)
        symlink_destination = project_root / "build/v02/attempt/candidate/symlink-copy"
        symlink_destination.symlink_to(symlink_target)
        with self.assertRaisesRegex(ValueError, "public-snapshot-destination-must-be-new-workspace-child"):
            invoke(symlink_destination)
        self.assertEqual(len(bounded_calls), prior_calls)

        # A successful monitored clone still passes through the unchanged base
        # identity check. The external process helper is fake; no child starts.
        success_destination = project_root / "build/v02/attempt/candidate/success-copy"
        fake_case.update({"returncode": 0, "cleanup": "confirmed", "error": None, "stderr": ""})
        with mock.patch.object(coordinator, "_git", side_effect=fake_git), \
             mock.patch.object(coordinator, "_publication_paths", return_value=[]), \
             mock.patch.object(coordinator, "_projection_crosswalk", return_value={}), \
             mock.patch.object(coordinator, "_bounded_command", side_effect=fake_bounded):
            with self.assertRaisesRegex(ValueError, "^public-snapshot-base-identity-invalid$"):
                coordinator.prepare_public_snapshot(success_destination, scope,
                    project_root / "out.json", authorization, root=project_root)
        command, _, _, scratch_roots, limits, clone_limit = bounded_calls[-1]
        self.assertEqual(command[-1], str(success_destination))
        self.assertEqual(limits["wall_seconds"], 300)
        self.assertEqual(scratch_roots[-1], success_destination)
        self.assertEqual(clone_limit, 2_147_483_648)

        missing_limit_scope = project_root / "evidence/missing-file-limit-scope.json"
        missing_limit_scope.write_text(json.dumps({"schema": "genewhip-v02-execution-v1"}) + "\n")
        missing_scope_destination = project_root / "build/v02/attempt/candidate/missing-limit"
        with self.assertRaisesRegex(ValueError, "public-snapshot-execution-scope-invalid"):
            coordinator.prepare_public_snapshot(missing_scope_destination, missing_limit_scope,
                project_root / "out.json", authorization, root=project_root)
        self.assertFalse(missing_scope_destination.exists())
        self.assertEqual(len(bounded_calls), prior_calls + 1,
            "missing approved scope limit must reject before the child launcher")

        invalid_scratch = project_root / "build/v02/invalid-limit-scratch"
        with mock.patch.object(coordinator, "_bounded_command", side_effect=fake_bounded):
            with self.assertRaisesRegex(ValueError, "hosted-delivery-file-size-limit-invalid"):
                coordinator._external(["git", "clone"], cwd=project_root, timeout=300,
                    check=False, phase="runtime", fresh_batch_scratch=invalid_scratch,
                    file_size_limit_bytes=2_147_483_649)
        self.assertFalse(invalid_scratch.exists(),
            "over-cap override must reject before scratch creation or child launch")
        self.assertEqual(len(bounded_calls), prior_calls + 1)
        self.assertEqual(len(budget_spy.call_args_list), 6)
        self.assertTrue(all(call.kwargs.get("phase") == "runtime"
                            for call in budget_spy.call_args_list))

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
            "scripts/ci/required-gate.sh": ROOT / "scripts/ci/required-gate.sh",
            ".github/workflows/ci.yml": ROOT / ".github/workflows/ci.yml"}
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
