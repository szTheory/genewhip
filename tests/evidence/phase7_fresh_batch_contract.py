#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure authorization/admission and coordinator-boundary contracts for fresh Plan 10."""
from __future__ import annotations

import ctypes
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
DENIALS: list[str] = []
NATIVE_EVENTS: list[str] = []
FIXTURE_ENV_PREFIXES = ("GENEWHIP_QUALIFICATION_", "GENEWHIP_FRESH_BATCH_", "GENEWHIP_RECOVERY_")


def fixture_environment_snapshot() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if key.startswith(FIXTURE_ENV_PREFIXES)}


INITIAL_FIXTURE_ENV = fixture_environment_snapshot()


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
        self.root = Path(self.temp.name)
        self.started = "2026-10-31T12:43:19+00:00"
        self._constant_patches = []

        def trust(name, value):
            patcher = mock.patch.object(BATCH, name, value)
            patcher.start()
            self._constant_patches.append(patcher)
            self.addCleanup(patcher.stop)

        self.batch_path = Path("build/v02/batch-test/authorization.json")
        self.scope_path = Path("evidence/v02-execution.json")
        self.old_campaign_path = Path("build/v02/campaign15/campaign.json")
        self.old_journal_path = Path("build/v02/campaign15/hosted-delivery-journal.json")
        self.previous_batch_root = Path("build/v02/batch-prior")
        self.previous_failure_path = self.previous_batch_root / "failure.json"
        self.previous_journal_path = self.previous_batch_root / "hosted-delivery-journal.json"
        for name, value in (("AUTH_PATH", self.batch_path), ("SCOPE_PATH", self.scope_path),
                            ("OLD_CAMPAIGN_PATH", self.old_campaign_path),
                            ("OLD_JOURNAL_PATH", self.old_journal_path),
                            ("PREVIOUS_BATCH_ROOT", self.previous_batch_root),
                            ("PREVIOUS_FAILURE_PATH", self.previous_failure_path),
                            ("PREVIOUS_JOURNAL_PATH", self.previous_journal_path),
                            ("PREVIOUS_AUTH_SHA256", "1" * 64),
                            ("PREVIOUS_FAILURE_SHA256", "2" * 64),
                            ("PREVIOUS_JOURNAL_SHA256", "3" * 64),
                            ("PREVIOUS_CI_RUN_ID", 42),
                            ("PREVIOUS_PULL_REQUEST", 7)):
            trust(name, value)
        self.batch_root = self.root / BATCH.AUTH_PATH.parent
        self.batch_root.mkdir(parents=True)
        self.auth = self.root / BATCH.AUTH_PATH
        self.auth.parent.mkdir(parents=True, exist_ok=True)
        self.scope_bytes = json.dumps({"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200}}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.old_campaign_bytes = b'{"schema":"synthetic-old-campaign"}\n'
        self.old_journal_bytes = b'{"schema":"synthetic-old-journal"}\n'
        self.previous_failure_bytes = b'{"schema":"synthetic-previous-failure"}\n'
        self.previous_journal_bytes = b'{"schema":"synthetic-previous-journal"}\n'
        trust("PREVIOUS_FAILURE_SHA256", hashlib.sha256(self.previous_failure_bytes).hexdigest())
        trust("PREVIOUS_JOURNAL_SHA256", hashlib.sha256(self.previous_journal_bytes).hexdigest())
        trust("SCOPE_SHA256", hashlib.sha256(self.scope_bytes).hexdigest())
        trust("OLD_CAMPAIGN_SHA256", hashlib.sha256(self.old_campaign_bytes).hexdigest())
        trust("OLD_JOURNAL_SHA256", hashlib.sha256(self.old_journal_bytes).hexdigest())
        self.started_dt = datetime.datetime.fromisoformat(self.started)
        self.auth_value = {"schema": "genewhip.phase7-ci-first-authorization.v1",
            "source_head": "0baeedeab8aadbf09bb2c3a2726c2a05c45eea36",
            "previous_campaign_sha256": BATCH.OLD_CAMPAIGN_SHA256,
            "previous_failed_journal_sha256": BATCH.OLD_JOURNAL_SHA256,
            "scope_path": BATCH.SCOPE_PATH.as_posix(), "scope_sha256": BATCH.SCOPE_SHA256,
            "ci_before_full_qualification": True, "stop_on_failure": True,
            "historical_risk_accepted": False, "next_phase_authorized": False,
            "started_at": self.started,
            "retry_of": {"authorization_sha256": BATCH.PREVIOUS_AUTH_SHA256,
                "batch_root": BATCH.PREVIOUS_BATCH_ROOT.as_posix(),
                "failed_ci_run_id": BATCH.PREVIOUS_CI_RUN_ID,
                "failure_path": BATCH.PREVIOUS_FAILURE_PATH.as_posix(),
                "failure_sha256": BATCH.PREVIOUS_FAILURE_SHA256,
                "journal_path": BATCH.PREVIOUS_JOURNAL_PATH.as_posix(),
                "journal_sha256": BATCH.PREVIOUS_JOURNAL_SHA256,
                "limit_one_further_ci_first_attempt": True,
                "pull_request": BATCH.PREVIOUS_PULL_REQUEST},
            "runtime_cutoff": (self.started_dt + datetime.timedelta(hours=18)).isoformat(),
            "package_cutoff": (self.started_dt + datetime.timedelta(hours=22)).isoformat(),
            "global_cutoff": (self.started_dt + datetime.timedelta(hours=24)).isoformat()}
        auth_bytes = json.dumps(self.auth_value, sort_keys=True, indent=2).encode() + b"\n"
        trust("AUTH_SHA256", hashlib.sha256(auth_bytes).hexdigest())
        self.auth_bytes = auth_bytes
        self.auth.write_bytes(auth_bytes)
        for relative, data in ((BATCH.SCOPE_PATH, self.scope_bytes),
                               (BATCH.OLD_CAMPAIGN_PATH, self.old_campaign_bytes),
                               (BATCH.OLD_JOURNAL_PATH, self.old_journal_bytes),
                               (BATCH.PREVIOUS_FAILURE_PATH, self.previous_failure_bytes),
                               (BATCH.PREVIOUS_JOURNAL_PATH, self.previous_journal_bytes)):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.source_head = "a" * 40
        self.pins = {}
        for name, data in self.source_bytes.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.pins[name] = hashlib.sha256(data).hexdigest()
        self.review_dir = self.root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
        self.review_dir.mkdir(parents=True)
        self.source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, source_pins=self.pins)
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
        self.assertEqual((self.root / BATCH.PREVIOUS_FAILURE_PATH).read_bytes(),
                         self.previous_failure_bytes)
        self.assertEqual((self.root / BATCH.PREVIOUS_JOURNAL_PATH).read_bytes(),
                         self.previous_journal_bytes)

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

    def _source_admission(self, source_pins=None):
        source_pins = source_pins or self.pins
        source_payload = BATCH.source_review_payload(source_head=self.source_head,
            started_at=self.started, source_pins=source_pins)
        payload_sha = hashlib.sha256(BATCH._canonical(source_payload)).hexdigest()
        return {"schema": BATCH.SCHEMA, "status": "source-preparation",
            "authorization_path": BATCH.AUTH_PATH.as_posix(),
            "authorization_sha256": BATCH.AUTH_SHA256,
            "scope_path": BATCH.SCOPE_PATH.as_posix(), "scope_sha256": BATCH.SCOPE_SHA256,
            "batch_root": BATCH.AUTH_PATH.parent.as_posix(), "started_at": self.started,
            "source_head": self.source_head, "source_pins": source_pins,
            "source_payload_sha256": payload_sha,
            "source_reviews": self._reviews("source-refresh", payload_sha)}

    def _write_admission(self, path: Path, value: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        return hashlib.sha256(path.read_bytes()).hexdigest()

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
        previous_failure = self.root / BATCH.PREVIOUS_FAILURE_PATH
        previous_journal = self.root / BATCH.PREVIOUS_JOURNAL_PATH
        previous_failure.write_bytes(self.previous_failure_bytes + b" ")
        with self.assertRaisesRegex(ValueError, "retry-predecessor-changed"):
            self._validate()
        previous_failure.write_bytes(self.previous_failure_bytes)
        previous_journal.write_bytes(self.previous_journal_bytes + b" ")
        with self.assertRaisesRegex(ValueError, "retry-predecessor-changed"):
            self._validate()
        previous_journal.write_bytes(self.previous_journal_bytes)

    def test_ordinary_route_rejects_both_closed_and_current_batch_roots(self):
        coordinator_path = self.root / "scripts/release/v02_qualification.py"
        coordinator_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_qualification.py", coordinator_path)
        coordinator = load(coordinator_path, "gw_fresh_batch_closed_root_contract")
        coordinator.ROOT = self.root
        for batch_root in (coordinator.PREVIOUS_BATCH_ROOT, coordinator.FRESH_BATCH_ROOT):
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
        BATCH.write_failure_sentinel(self.root, stage="preview-ci",
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
            started_at=self.started, source_pins=source_pins or self.pins)
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
        batch_source = (ROOT / "scripts/release/v02_batch.py").read_text()
        replacements = {
            'AUTH_PATH = Path("build/v02/batch-20261031T124319Z-retry1/authorization.json")':
                f'AUTH_PATH = Path("{BATCH.AUTH_PATH.as_posix()}")',
            'AUTH_SHA256 = "b9f6b7fe4b242ec866f04e8c36d5228b0f5af0cc19c78e0af6afc51514684def"':
                f'AUTH_SHA256 = "{BATCH.AUTH_SHA256}"',
            'SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"':
                f'SCOPE_SHA256 = "{BATCH.SCOPE_SHA256}"',
            'OLD_CAMPAIGN_SHA256 = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"':
                f'OLD_CAMPAIGN_SHA256 = "{BATCH.OLD_CAMPAIGN_SHA256}"',
            'OLD_JOURNAL_SHA256 = "085a769ceefe2dbaae88b0fd911fb777213d37ff142c85b2ca9f9ac912a18826"':
                f'OLD_JOURNAL_SHA256 = "{BATCH.OLD_JOURNAL_SHA256}"',
            'PREVIOUS_BATCH_ROOT = Path("build/v02/batch-20261031T124319Z")':
                f'PREVIOUS_BATCH_ROOT = Path("{BATCH.PREVIOUS_BATCH_ROOT.as_posix()}")',
            'PREVIOUS_FAILURE_SHA256 = "e85af97622af00d4968cb9cd2e1f000dfb0a3bab3f453d1f5ac7f7f315d1d95b"':
                f'PREVIOUS_FAILURE_SHA256 = "{BATCH.PREVIOUS_FAILURE_SHA256}"',
            'PREVIOUS_JOURNAL_SHA256 = "f8af02bf4ae791a70552fcfd728200c6578db9466d88a9487fd07d2cb09baf70"':
                f'PREVIOUS_JOURNAL_SHA256 = "{BATCH.PREVIOUS_JOURNAL_SHA256}"',
            'PREVIOUS_AUTH_SHA256 = "ed71b6afb5c0defbeaba4e358c1f4dd635e1fb9ce0b2faf052c567551801ef1f"':
                f'PREVIOUS_AUTH_SHA256 = "{BATCH.PREVIOUS_AUTH_SHA256}"',
            'PREVIOUS_CI_RUN_ID = 41206052510':
                f'PREVIOUS_CI_RUN_ID = {BATCH.PREVIOUS_CI_RUN_ID}',
            'PREVIOUS_PULL_REQUEST = 26':
                f'PREVIOUS_PULL_REQUEST = {BATCH.PREVIOUS_PULL_REQUEST}'}
        for old, new in replacements.items():
            self.assertIn(old, batch_source)
            # Replace production retry pins with self-contained synthetic fixtures.
            if "PREVIOUS_" in old:
                if old.startswith("PREVIOUS_BATCH_ROOT"):
                    replacement = f'PREVIOUS_BATCH_ROOT = Path("{self.previous_batch_root.as_posix()}")'
                elif old.startswith("PREVIOUS_FAILURE_SHA256"):
                    replacement = f'PREVIOUS_FAILURE_SHA256 = "{BATCH.PREVIOUS_FAILURE_SHA256}"'
                elif old.startswith("PREVIOUS_JOURNAL_SHA256"):
                    replacement = f'PREVIOUS_JOURNAL_SHA256 = "{BATCH.PREVIOUS_JOURNAL_SHA256}"'
                elif old.startswith("PREVIOUS_AUTH_SHA256"):
                    replacement = f'PREVIOUS_AUTH_SHA256 = "{BATCH.PREVIOUS_AUTH_SHA256}"'
                elif old.startswith("PREVIOUS_CI_RUN_ID"):
                    replacement = f'PREVIOUS_CI_RUN_ID = {BATCH.PREVIOUS_CI_RUN_ID}'
                elif old.startswith("PREVIOUS_PULL_REQUEST"):
                    replacement = f'PREVIOUS_PULL_REQUEST = {BATCH.PREVIOUS_PULL_REQUEST}'
                else:
                    replacement = new
                new = replacement
            batch_source = batch_source.replace(old, new, 1)
        batch_path = self.root / "scripts/release/v02_batch.py"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        batch_bytes = batch_source.encode()
        batch_path.write_bytes(batch_bytes)
        source_pins = dict(self.pins)
        source_pins["scripts/release/v02_batch.py"] = hashlib.sha256(batch_bytes).hexdigest()
        path, digest, policy_path = self._public_admission(source_pins)
        coordinator = load(coordinator_path, "gw_fresh_batch_positive_composition")
        coordinator.ROOT = self.root.resolve()
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
        coordinator.ROOT = self.root
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

        batch_source = (ROOT / "scripts/release/v02_batch.py").read_text()
        replacements = {
            'AUTH_PATH = Path("build/v02/batch-20261031T124319Z-retry1/authorization.json")':
                f'AUTH_PATH = Path("{BATCH.AUTH_PATH.as_posix()}")',
            'AUTH_SHA256 = "b9f6b7fe4b242ec866f04e8c36d5228b0f5af0cc19c78e0af6afc51514684def"':
                f'AUTH_SHA256 = "{BATCH.AUTH_SHA256}"',
            'SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"':
                f'SCOPE_SHA256 = "{BATCH.SCOPE_SHA256}"',
            'OLD_CAMPAIGN_SHA256 = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"':
                f'OLD_CAMPAIGN_SHA256 = "{BATCH.OLD_CAMPAIGN_SHA256}"',
            'OLD_JOURNAL_SHA256 = "085a769ceefe2dbaae88b0fd911fb777213d37ff142c85b2ca9f9ac912a18826"':
                f'OLD_JOURNAL_SHA256 = "{BATCH.OLD_JOURNAL_SHA256}"'}
        for old, new in replacements.items():
            self.assertIn(old, batch_source)
            batch_source = batch_source.replace(old, new, 1)
        batch_path = self.root / "scripts/release/v02_batch.py"
        batch_path.parent.mkdir(parents=True, exist_ok=True)
        batch_bytes = batch_source.encode()
        batch_path.write_bytes(batch_bytes)
        source_pins["scripts/release/v02_batch.py"] = hashlib.sha256(batch_bytes).hexdigest()
        admission_path, admission_sha, _ = self._public_admission(source_pins)
        coordinator = load(self.root / "scripts/release/v02_qualification.py",
                           "gw_fresh_batch_hosted_api")
        coordinator.ROOT = self.root
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
        shutil.copyfile(ROOT / "scripts/release/v02_batch.py", batch_copy)
        coordinator = load(copy_path, "gw_fresh_batch_push_gate")
        coordinator.ROOT = self.root
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
        shutil.copyfile(ROOT / "scripts/release/v02_batch.py", batch_copy)
        coordinator = load(copy_path, "gw_fresh_batch_push_gate_negative")
        coordinator.ROOT = self.root
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
        self.expected_failure_paths.add(self.root / coordinator.FRESH_BATCH_ROOT / "failure.json")
        self.assertTrue((self.root / coordinator.FRESH_BATCH_ROOT / "failure.json").exists())
        # The sentinel above is isolated to this temporary coordinator root.

    def test_merged_main_push_preview_rejects_a_run_created_before_batch_start(self):
        coordinator_path = ROOT / "scripts/release/v02_qualification.py"
        copy_path = self.root / "scripts/release/v02_qualification.py"
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(coordinator_path, copy_path)
        batch_copy = self.root / "scripts/release/v02_batch.py"
        batch_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/release/v02_batch.py", batch_copy)
        coordinator = load(copy_path, "gw_fresh_batch_push_gate_stale")
        coordinator.ROOT = self.root
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
        self.expected_failure_paths.add(self.root / coordinator.FRESH_BATCH_ROOT / "failure.json")


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
