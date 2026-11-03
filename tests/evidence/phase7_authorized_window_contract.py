#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable contracts for explicitly authorized, date-free Phase 7 windows."""
from __future__ import annotations

import copy
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_window_module():
    path = ROOT / "scripts/release/v02_window.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_authorized_window_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("authorized-window-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WINDOW = load_window_module()
HISTORICAL_SOURCE_HEAD = "f170a81ab2966444db55cfe5187dfc5babe43d1d"
HISTORICAL_SOURCE_ADMISSION = ROOT / (
    "build/v02/phase7-qualification-20261103T000225Z/attempts/attempt-0001/source-admission.json"
)
AUTHORIZED_RUN_PATH = Path(
    "build/v02/phase7-qualification-20261103T023257Z/authorization.json"
)
AUTHORIZED_RUN_SHA256 = "d55775687f940450432026a5e848baea243798886da5a1d9bd74603e695e7386"
AUTHORIZED_RUN_SCOPE_SHA256 = "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a"
AUTHORIZED_RUN_PREDECESSOR = {
    "path": "build/v02/phase7-qualification-20261103T023257Z/operator/predecessor-bundle.json",
    "sha256": "201bb30f61165622962ad04f91a9c5215784cf2a6074959770043aa0ab96419a",
}
AUTHORIZED_RUN_PREDECESSOR_BUNDLE = ROOT / AUTHORIZED_RUN_PREDECESSOR["path"]
AUTHORIZED_RUN_ATTEMPT1_ROOT = Path(
    "build/v02/phase7-qualification-20261103T023257Z/attempts/attempt-0001"
)
AUTHORIZED_RUN_ATTEMPT1_BUNDLE = {
    "path": (AUTHORIZED_RUN_ATTEMPT1_ROOT / "operator/closed-full-failure-bundle.json").as_posix(),
    "sha256": "651ae5632d58f3846c833f64187489a22745511f1a5eb0b1d16d675b6dedc981",
}


def load_batch_module():
    path = ROOT / "scripts/release/v02_batch.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_authorized_window_batch_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("authorized-window-batch-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BATCH = load_batch_module()


def load_qualification_module():
    path = ROOT / "scripts/release/v02_qualification.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_authorized_window_qualification_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("authorized-window-qualification-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def put(root: Path, relative: str, raw: bytes) -> str:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return digest(raw)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()


class AuthorizedWindowContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gw-authorized-window-")
        self.root = Path(self.temporary.name).resolve()
        # The authorized public scope is pinned against the reviewed four-hour
        # policy. Copy that immutable baseline into the isolated repository root.
        baseline = ROOT / WINDOW.SCOPE_PATH
        destination = self.root / WINDOW.SCOPE_PATH
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(baseline, destination)
        self.base_scope = json.loads(destination.read_bytes())
        self.scope = copy.deepcopy(self.base_scope)
        # Retain exact policy content while making this dedicated public scope's
        # byte pin distinct from the historical profile.
        scope_raw = json_bytes(self.scope)
        self.scope_sha = put(self.root, WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(), scope_raw)
        self.assertNotEqual(self.scope_sha, WINDOW.SCOPE_SHA256)

    def tearDown(self):
        self.temporary.cleanup()

    def bundle(self, *, start="2026-11-03T02:32:57+00:00", name="fixture-a",
            scope=None, scope_raw=None):
        if scope is None:
            scope = copy.deepcopy(self.scope)
        raw_scope = json_bytes(scope) if scope_raw is None else scope_raw
        scope_sha = put(self.root, WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(), raw_scope)
        batch = scope["qualification_batch"]
        budget = {key: batch[key] for key in (
            "wall_seconds", "runtime_wall_seconds", "package_wall_seconds",
            "close_wall_seconds")}
        cutoffs = WINDOW._authorized_cutoffs(start, budget)
        directory = f"build/v02/authorized-window-{name}"
        selection_path = f"{directory}/selection.json"
        evidence_path = f"{directory}/evidence.md"
        predecessor_path = f"{directory}/predecessor.json"
        source_ancestor = ("a" if name.endswith("a") else "b") * 40
        selection = {
            "schema": "genewhip.phase7-execution-window-selection.v1",
            "started_at": start,
            "source_ancestor": source_ancestor,
            "runtime_deadline": cutoffs["runtime_cutoff"],
            "package_deadline": cutoffs["package_cutoff"],
            "hard_deadline": cutoffs["global_cutoff"],
            "retries_reset_clock": False,
            "phase_advance_authorized": False,
        }
        selection_sha = put(self.root, selection_path, json_bytes(selection))
        evidence_sha = put(self.root, evidence_path,
            b"Reviewed synthetic contract evidence; no remote action.\n")
        predecessor_sha = put(self.root, predecessor_path,
            json_bytes({"schema": "synthetic-predecessor", "status": "consumed"}))
        authority = {
            "schema": WINDOW.AUTHORIZED_RUN_SCHEMA,
            "repository": WINDOW.REPOSITORY,
            "source_ancestor": source_ancestor,
            "started_at": start,
            **cutoffs,
            "budget": budget,
            "scope_path": WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
            "scope_sha256": scope_sha,
            "attempt_namespace": f"{directory}/attempts",
            "ordinary_ci_retries_approved": True,
            "per_attempt_user_approval": False,
            "per_child_limits_unchanged": True,
            "full_qualification_authorized": True,
            "merge_authorized": True,
            "release_authorized": True,
            "next_phase_authorized": False,
            "historical_risk_accepted": False,
            "safety_stop_required": True,
            "failure_stop_scope": "attempt",
            "selection": {"path": selection_path, "sha256": selection_sha},
            "evidence": {"path": evidence_path, "sha256": evidence_sha},
            "predecessor": {"path": predecessor_path, "sha256": predecessor_sha},
        }
        authority_path = Path(directory) / "authorization.json"
        authority_sha = put(self.root, authority_path.as_posix(), json_bytes(authority))
        return {"authority": authority, "authority_path": authority_path,
            "authority_sha": authority_sha, "selection_path": Path(selection_path),
            "selection": selection, "scope_sha": scope_sha}

    def load(self, bundle):
        return WINDOW.load_authorized_window(self.root,
            authority_path=bundle["authority_path"],
            authority_sha256=bundle["authority_sha"],
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
            scope_sha256=bundle["scope_sha"])

    def rewrite_authority(self, bundle):
        raw = json_bytes(bundle["authority"])
        bundle["authority_sha"] = put(self.root,
            bundle["authority_path"].as_posix(), raw)

    def test_distinct_grants_reuse_identical_date_free_scope_policy(self):
        first = self.bundle(start="2026-11-03T02:32:57+00:00", name="fixture-a")
        second = self.bundle(start="2026-11-04T09:15:00+00:00", name="fixture-b")
        first_window = self.load(first)
        second_window = self.load(second)

        self.assertEqual(first_window["profile_id"], "authorized-run")
        self.assertEqual(second_window["profile_id"], "authorized-run")
        self.assertEqual(first_window["scope"], second_window["scope"])
        self.assertEqual(first_window["scope_sha256"], second_window["scope_sha256"])
        self.assertEqual(first_window["scope_path"], second_window["scope_path"])
        self.assertNotEqual(first_window["started_at"], second_window["started_at"])
        self.assertNotEqual(first_window["attempt_namespace"], second_window["attempt_namespace"])

        for bundle, start in ((first, "2026-11-03T02:32:57+00:00"),
                (second, "2026-11-04T09:15:00+00:00")):
            now = (datetime.datetime.fromisoformat(start)
                + datetime.timedelta(seconds=30)).isoformat()
            created = (datetime.datetime.fromisoformat(start)
                + datetime.timedelta(seconds=5)).isoformat()
            checked = WINDOW.validate_public_clock(self.root,
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                scope_sha256=bundle["scope_sha"], started_at=start,
                phase="runtime", now=now, workflow_created_at=created)
            self.assertEqual(checked["profile_id"], "authorized-run")
            self.assertGreater(checked["remaining_seconds"], 0)

        # Public source events have no private grant pin and must not auto-select
        # the dynamically dated authorization.
        auto = WINDOW.select_public_event_window(self.root,
            workflow_created_at="2026-11-03T02:33:02+00:00",
            now="2026-11-03T02:33:30+00:00")
        self.assertFalse(auto["selected"])
        self.assertEqual(auto["scope_path"], WINDOW.LEGACY_SCOPE_PATH.as_posix())

    def test_wrong_authority_pin_and_changed_public_scope_are_rejected(self):
        bundle = self.bundle()
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-stale"):
            WINDOW.load_authorized_window(self.root,
                authority_path=bundle["authority_path"], authority_sha256="0" * 64,
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH, scope_sha256=bundle["scope_sha"])

        path = self.root / WINDOW.AUTHORIZED_SCOPE_PATH
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "phase7-window-scope-stale"):
            self.load(bundle)

    def test_scope_and_authority_paths_reject_traversal(self):
        bundle = self.bundle()
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-path-invalid"):
            WINDOW.load_authorized_window(self.root,
                authority_path=Path("build/v02/../escape.json"),
                authority_sha256=bundle["authority_sha"],
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH, scope_sha256=bundle["scope_sha"])
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-path-invalid"):
            WINDOW.load_authorized_window(self.root,
                authority_path=bundle["authority_path"],
                authority_sha256=bundle["authority_sha"], scope_path=Path("../scope.json"),
                scope_sha256=bundle["scope_sha"])

        bundle["authority"]["selection"]["path"] = "build/v02/../escape.json"
        self.rewrite_authority(bundle)
        with self.assertRaisesRegex(ValueError, "phase7-window-reference-path-invalid"):
            self.load(bundle)

    def test_budget_mix_and_policy_limit_increase_are_rejected(self):
        bundle = self.bundle()
        bundle["authority"]["budget"]["runtime_wall_seconds"] += 1
        self.rewrite_authority(bundle)
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-budget-invalid"):
            self.load(bundle)

        over_budget = copy.deepcopy(self.scope)
        over_budget["qualification_batch"]["wall_seconds"] += 1
        over_budget["qualification_batch"]["runtime_wall_seconds"] += 1
        bundle = self.bundle(name="over-budget", scope=over_budget)
        with self.assertRaisesRegex(ValueError, "phase7-window-scope-content-invalid"):
            self.load(bundle)

        over_limit = copy.deepcopy(self.scope)
        over_limit["qualification_batch"]["benchmark_sub_batch_seconds"] += 1
        bundle = self.bundle(name="over-limit", scope=over_limit)
        with self.assertRaisesRegex(ValueError, "phase7-window-scope-content-invalid"):
            self.load(bundle)

    def test_future_clocks_and_retry_clock_reset_are_rejected(self):
        bundle = self.bundle()
        start = bundle["authority"]["started_at"]
        before = (datetime.datetime.fromisoformat(start)
            - datetime.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(ValueError, "phase7-window-not-started"):
            WINDOW.validate_public_clock(self.root,
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                scope_sha256=bundle["scope_sha"], started_at=start, phase="preparation",
                now=before)
        after = (datetime.datetime.fromisoformat(start)
            + datetime.timedelta(seconds=5)).isoformat()
        future_created = (datetime.datetime.fromisoformat(start)
            + datetime.timedelta(seconds=6)).isoformat()
        with self.assertRaisesRegex(ValueError, "phase7-window-workflow-clock-invalid"):
            WINDOW.validate_public_clock(self.root,
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                scope_sha256=bundle["scope_sha"], started_at=start, phase="preparation",
                now=after, workflow_created_at=future_created)

        selection = dict(bundle["selection"])
        selection["retries_reset_clock"] = True
        selection_sha = put(self.root, bundle["selection_path"].as_posix(), json_bytes(selection))
        bundle["authority"]["selection"]["sha256"] = selection_sha
        self.rewrite_authority(bundle)
        with self.assertRaisesRegex(ValueError, "phase7-window-selection-invalid"):
            self.load(bundle)

    def test_fixed_historical_readers_do_not_accept_dynamic_identity(self):
        bundle = self.bundle()
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-pin-invalid"):
            WINDOW.load_window(self.root,
                authority_path=bundle["authority_path"],
                authority_sha256=bundle["authority_sha"],
                scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
                scope_sha256=bundle["scope_sha"])

    def test_dispatch_claim_create_verify_close_uses_the_authorized_dynamic_loader(self):
        start = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=60)).replace(microsecond=0).isoformat()
        bundle = self.bundle(start=start, name="claim-lifecycle")
        window = self.load(bundle)
        attempt = self.root / window["attempt_namespace"] / "attempt-0001"
        attempt.mkdir(parents=True)
        admission = {"schema": "synthetic-authorized-claim-admission.v1",
            "status": "public-effects"}
        admission_raw = json_bytes(admission)
        admission_path = attempt / "public-admission.json"
        admission_path.write_bytes(admission_raw)
        batch = {"phase7_window": True, "window": window,
            "attempt_root": attempt, "attempt_index": 1,
            "admission_path": admission_path,
            "admission_sha256": digest(admission_raw), "admission": admission,
            "source_payload_sha256": "e" * 64}
        nonce = "d" * 32
        events = []
        claim_path = BATCH.create_phase7_window_dispatch_claim(self.root, batch, nonce)
        events.append("create")
        try:
            BATCH.verify_phase7_window_dispatch_claim(self.root, batch)
            events.append("verify")
            claim = json.loads(claim_path.read_bytes())
            self.assertEqual(claim["schema"],
                "genewhip.phase7-execution-window-dispatch-claim.v1")
            self.assertEqual(claim["authorization_sha256"], bundle["authority_sha"])
            self.assertEqual(claim["scope_sha256"], bundle["scope_sha"])
            self.assertEqual(claim["attempt_root"], attempt.relative_to(self.root).as_posix())
            self.assertEqual(claim["admission_sha256"], digest(admission_raw))
            self.assertEqual(claim["source_payload_sha256"], "e" * 64)
            self.assertEqual(claim["nonce"], nonce)
            self.assertEqual(claim["started_at"], start)
        finally:
            BATCH.close_phase7_window_dispatch_claim(batch)
            events.append("close")
        self.assertEqual(events, ["create", "verify", "close"])
        self.assertTrue(claim_path.is_file(), "closing the descriptor must preserve the spent claim")
        self.assertNotIn("_dispatch_directory_fd", batch)

    def test_retained_real_authority_reopens_its_dynamic_scope_and_predecessor_pin(self):
        authority_file = ROOT / AUTHORIZED_RUN_PATH
        scope_file = ROOT / WINDOW.AUTHORIZED_SCOPE_PATH
        if not authority_file.is_file() or not scope_file.is_file():
            self.skipTest("private authorized-run evidence is unavailable")
        window = WINDOW.load_authorized_window(ROOT,
            authority_path=AUTHORIZED_RUN_PATH,
            authority_sha256=AUTHORIZED_RUN_SHA256,
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
            scope_sha256=AUTHORIZED_RUN_SCOPE_SHA256)
        self.assertEqual(window["profile_id"], "authorized-run")
        self.assertEqual(window["scope_sha256"], AUTHORIZED_RUN_SCOPE_SHA256)
        self.assertEqual(window["authority"]["predecessor"], AUTHORIZED_RUN_PREDECESSOR)
        self.assertEqual(window["attempt_namespace"],
            "build/v02/phase7-qualification-20261103T023257Z/attempts")
        start = datetime.datetime.fromisoformat(window["started_at"])
        now = (start + datetime.timedelta(seconds=30)).isoformat()
        created = (start + datetime.timedelta(seconds=5)).isoformat()
        public_clock = WINDOW.validate_public_clock(ROOT,
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
            scope_sha256=AUTHORIZED_RUN_SCOPE_SHA256,
            started_at=window["started_at"], phase="runtime", now=now,
            workflow_created_at=created)
        self.assertEqual(public_clock["profile_id"], "authorized-run")
        selected = WINDOW.select_public_event_window(ROOT,
            workflow_created_at=created, now=now)
        self.assertFalse(selected["selected"])


class AuthorizedHistoricalSourcePinContract(unittest.TestCase):
    def test_retained_605_source_pins_are_reopened_from_the_historical_git_tree(self):
        if not HISTORICAL_SOURCE_ADMISSION.is_file():
            self.skipTest("retained authorized-run source admission is unavailable")
        admission = json.loads(HISTORICAL_SOURCE_ADMISSION.read_bytes())
        pins = admission.get("source_pins")
        self.assertEqual(admission.get("attempt_index"), 1)
        self.assertEqual(admission.get("source_head"), HISTORICAL_SOURCE_HEAD)
        self.assertIsInstance(pins, dict)
        self.assertEqual(len(pins), 605)
        available = subprocess.run(["git", "cat-file", "-e",
            f"{HISTORICAL_SOURCE_HEAD}^{{commit}}"], cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20, check=False)
        if available.returncode != 0:
            self.skipTest("historical authorized-run source commit is unavailable")

        historical_tree = subprocess.run(["git", "ls-tree", "-r", "--name-only", "-z",
            HISTORICAL_SOURCE_HEAD], cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        names = [item.decode("utf-8") for item in historical_tree.stdout.split(b"\0") if item]
        qualification_path = ROOT / "scripts/release/v02_qualification.py"
        spec = importlib.util.spec_from_file_location(
            "gw_phase7_authorized_historical_roster", qualification_path
        )
        if spec is None or spec.loader is None:
            self.fail("historical-publication-roster-loader-unavailable")
        qualification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualification)
        expected_paths = set(qualification._publication_paths_from_names(ROOT, names))
        self.assertEqual(len(expected_paths), 605)
        self.assertEqual(set(pins), expected_paths)

        checked = BATCH.phase7_window_validate_git_blob_pins(
            ROOT, HISTORICAL_SOURCE_HEAD, pins, expected_paths=expected_paths
        )
        self.assertEqual(checked, pins)
        changed_worktree_path = "scripts/release/v02_batch.py"
        self.assertIn(changed_worktree_path, pins)
        self.assertNotEqual(hashlib.sha256(
            (ROOT / changed_worktree_path).read_bytes()).hexdigest(),
            pins[changed_worktree_path],
            "current worktree edits must not rebind historical source bytes")

        mutated = dict(pins)
        mutated[changed_worktree_path] = "0" * 64
        with self.assertRaisesRegex(ValueError,
                "phase7-window-historical-source-pins-invalid"):
            BATCH.phase7_window_validate_git_blob_pins(
                ROOT, HISTORICAL_SOURCE_HEAD, mutated, expected_paths=expected_paths)


class AuthorizedRunPredecessorContract(unittest.TestCase):
    def test_spent_full_failure_claim_is_consumed_as_the_exact_no_credit_predecessor(self):
        if not AUTHORIZED_RUN_PREDECESSOR_BUNDLE.is_file():
            self.skipTest("private authorized-run predecessor bundle is unavailable")
        window = WINDOW.load_authorized_window(ROOT,
            authority_path=AUTHORIZED_RUN_PATH,
            authority_sha256=AUTHORIZED_RUN_SHA256,
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
            scope_sha256=AUTHORIZED_RUN_SCOPE_SHA256)
        # Historical replay stays at an instant inside this immutable grant;
        # production must continue rejecting the same grant after its deadline.
        clock_module = BATCH._phase7_window_module()
        real_check = clock_module.check_window
        fixture_now = datetime.datetime.fromisoformat(window["started_at"]) + datetime.timedelta(minutes=2)
        def historical_check(value, **kwargs):
            return real_check(value, **{**kwargs, "now": fixture_now})
        with mock.patch.object(clock_module, "check_window", side_effect=historical_check):
            predecessor = BATCH.phase7_window_authorized_initial_predecessor(ROOT, window)
        bundle = json.loads(AUTHORIZED_RUN_PREDECESSOR_BUNDLE.read_bytes())
        expected = {
            "attempt_index": 1,
            "attempt_root": bundle["attempt_root"],
            "terminal": AUTHORIZED_RUN_PREDECESSOR,
            "status": "settled-full-qualification-failure",
            "qualification_accepted": False,
            "local_cleanup": "settled",
        }
        self.assertEqual(predecessor, expected)
        self.assertEqual(bundle["schema"], "genewhip.phase7-terminal-predecessor-bundle.v1")
        self.assertEqual(bundle["attempt_index"], 1)
        self.assertTrue(bundle["not_retry_admission"])
        self.assertFalse(bundle["qualification_credit"])
        self.assertFalse(bundle["release_credit"])
        self.assertEqual(len(bundle["external_attempts"]), 252)
        self.assertEqual(len(bundle["process_receipts"]), 252)

        def record(name):
            reference = bundle["records"][name]
            relative = Path(reference["path"])
            self.assertFalse(relative.is_absolute())
            self.assertNotIn("..", relative.parts)
            raw = (ROOT / relative).read_bytes()
            self.assertEqual(digest(raw), reference["sha256"])
            return json.loads(raw)

        terminal = record("terminal_observation")
        self.assertEqual(terminal["run_id"], 41555997266)
        self.assertEqual(terminal["run_attempt"], 1)
        self.assertEqual(terminal["status"], "completed")
        self.assertEqual(terminal["conclusion"], "failure")
        self.assertFalse(terminal["qualification_credit"])
        self.assertTrue(terminal["remote_jobs_terminal"])
        self.assertEqual(terminal["remote_job_count"], 16)
        self.assertEqual(len(terminal["jobs"]), 16)
        jobs = record("terminal_jobs")
        self.assertEqual(jobs["total_count"], 16)
        self.assertEqual(len(jobs["jobs"]), 16)

        source_admission = record("source_admission")
        self.assertEqual(source_admission["source_head"], HISTORICAL_SOURCE_HEAD)
        self.assertEqual(len(source_admission["source_pins"]), 605)
        claim = record("claim")
        self.assertEqual(claim["schema"],
            "genewhip.phase7-renewed-two-hour-dispatch-claim.v1")
        self.assertEqual(claim["attempt_index"], 1)
        close = record("window_close")
        self.assertFalse(close["qualification_credit"])
        self.assertTrue(close["recorded_external_cleanup_confirmed"])
        self.assertEqual(close["claim_preserved"]["sha256"],
            bundle["records"]["claim"]["sha256"])
        self.assertEqual(len(close["bound_receipts"]), 1)
        self.assertEqual(close["bound_receipts"][0]["reason"], ["phase7-wall-timeout"])
        timed_out_receipt = Path(close["bound_receipts"][0]["path"])
        timeout_scratch = ROOT / timed_out_receipt.parent / (
            timed_out_receipt.name.removesuffix(".attempt.json") + ".tmp")
        self.assertTrue(timeout_scratch.is_dir())
        self.assertFalse(timeout_scratch.is_symlink())
        self.assertEqual(list(timeout_scratch.iterdir()), [])

    def test_actual_full_failure_bundle_is_the_only_attempt2_predecessor(self):
        if not (ROOT / AUTHORIZED_RUN_ATTEMPT1_BUNDLE["path"]).is_file():
            self.skipTest("private authorized-run attempt-1 bundle is unavailable")
        window = WINDOW.load_authorized_window(ROOT,
            authority_path=AUTHORIZED_RUN_PATH,
            authority_sha256=AUTHORIZED_RUN_SHA256,
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
            scope_sha256=AUTHORIZED_RUN_SCOPE_SHA256)
        expected = {
            "attempt_index": 1,
            "attempt_root": AUTHORIZED_RUN_ATTEMPT1_ROOT.as_posix(),
            "terminal": AUTHORIZED_RUN_ATTEMPT1_BUNDLE,
            "status": "settled-full-qualification-failure",
            "qualification_accepted": False,
            "local_cleanup": "settled",
        }
        clock_module = BATCH._phase7_window_module()
        real_check = clock_module.check_window
        fixture_now = datetime.datetime.fromisoformat(window["started_at"]) + datetime.timedelta(minutes=2)

        def historical_check(value, **kwargs):
            return real_check(value, **{**kwargs, "now": fixture_now})

        with mock.patch.object(clock_module, "check_window", side_effect=historical_check):
            actual = BATCH._phase7_window_predecessor(
                ROOT, {"predecessor": expected}, attempt_index=2, window=window)
        self.assertEqual(actual, expected)

        invalid_predecessors = []
        for key, value in (
            ("attempt_index", 0),
            ("attempt_root", "build/v02/foreign/attempt-0001"),
            ("status", "settled-success"),
            ("qualification_accepted", True),
            ("local_cleanup", "unknown"),
        ):
            mutant = dict(expected)
            mutant[key] = value
            invalid_predecessors.append(mutant)
        for terminal_key, value in (("path", "build/v02/foreign/bundle.json"),
                                    ("sha256", "0" * 64)):
            mutant = dict(expected)
            mutant["terminal"] = dict(expected["terminal"], **{terminal_key: value})
            invalid_predecessors.append(mutant)
        with mock.patch.object(clock_module, "check_window", side_effect=historical_check):
            for mutant in invalid_predecessors:
                with self.subTest(mutant=mutant):
                    with self.assertRaises(ValueError):
                        BATCH._phase7_window_predecessor(
                            ROOT, {"predecessor": mutant}, attempt_index=2, window=window)


class AuthorizedHostedProfileContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gw-authorized-hosted-profile-")
        self.root = Path(self.temporary.name).resolve()
        for relative in (WINDOW.SCOPE_PATH, WINDOW.LEGACY_SCOPE_PATH,
                WINDOW.AUTHORIZED_SCOPE_PATH, Path("scripts/release/v02_window.py")):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.module = load_qualification_module()
        self.module.ROOT = self.root
        self.start = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=60)).replace(microsecond=0).isoformat()
        self.created = (datetime.datetime.fromisoformat(self.start)
            + datetime.timedelta(seconds=5)).isoformat()
        self.now = (datetime.datetime.fromisoformat(self.start)
            + datetime.timedelta(seconds=30)).isoformat()
        self.public_env = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GENEWHIP_QUALIFICATION_SCOPE_PATH": WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
            "GENEWHIP_QUALIFICATION_SCOPE_SHA256": AUTHORIZED_RUN_SCOPE_SHA256,
            "GENEWHIP_QUALIFICATION_STARTED_AT": self.start,
            "GENEWHIP_QUALIFICATION_PHASE": "runtime",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_public_hosted_clock_selects_scope_and_start_without_private_authority(self):
        with mock.patch.dict(os.environ, self.public_env, clear=True):
            profile = self.module._phase7_public_window_profile()
            self.assertEqual(profile["profile_id"], "authorized-run-public")
            self.assertEqual(profile["scope_path"], WINDOW.AUTHORIZED_SCOPE_PATH)
            self.assertEqual(profile["scope_sha256"], AUTHORIZED_RUN_SCOPE_SHA256)
            self.assertEqual(profile["started_at"], self.start)
            self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH", os.environ)
            self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256", os.environ)

            checked = self.module._validate_workflow_clock(
                self.start, self.created, "a" * 32, "b" * 40,
                now=self.now, phase="runtime")
            self.assertEqual(checked, self.start)
            scope = json.loads((self.root / WINDOW.AUTHORIZED_SCOPE_PATH).read_bytes())
            remaining = self.module._require_hosted_budget(
                self.start, self.now, scope, phase="runtime")
            self.assertEqual(remaining, 10800 - 30)

        partial = dict(self.public_env)
        partial.pop("GENEWHIP_QUALIFICATION_SCOPE_SHA256")
        with mock.patch.dict(os.environ, partial, clear=True):
            with self.assertRaisesRegex(ValueError, "phase7-window-scope-or-authority-profile-invalid"):
                self.module._phase7_public_window_profile()

        stale = dict(self.public_env)
        stale["GENEWHIP_QUALIFICATION_SCOPE_SHA256"] = "0" * 64
        with mock.patch.dict(os.environ, stale, clear=True):
            with self.assertRaisesRegex(ValueError, "phase7-window-scope-stale"):
                self.module._phase7_public_window_profile()

        private_mixed = dict(self.public_env)
        private_mixed["GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH"] = "build/v02/private.json"
        private_mixed["GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256"] = "c" * 64
        with mock.patch.dict(os.environ, private_mixed, clear=True):
            with self.assertRaisesRegex(ValueError,
                    "phase7-window-(?:scope-or-authority-profile-invalid|reference-unavailable)"):
                self.module._phase7_public_window_profile()

    def test_bounded_external_uses_public_runtime_clock_and_passes_no_private_authority(self):
        observed = {}
        empty_sha = hashlib.sha256(b"").hexdigest()

        def bounded(command, *, limits, timeout, env, **kwargs):
            observed.update({"command": command, "limits": dict(limits),
                "timeout": timeout, "env": dict(env), "kwargs": kwargs})
            stream = {"text": "", "truncated": False, "observed_bytes": 0,
                "retained_bytes": 0, "sha256": empty_sha}
            return {"returncode": 0, "process_group_cleanup": "confirmed",
                "stdout_tail": "", "stderr_tail": "",
                "streams": {"stdout": stream, "stderr": stream}}

        fixed_now = datetime.datetime.fromisoformat(self.now)
        real_datetime = datetime.datetime

        class FrozenDateTime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now.astimezone(tz) if tz is not None else fixed_now.replace(tzinfo=None)

        with mock.patch.dict(os.environ, self.public_env, clear=True), \
             mock.patch.object(self.module.datetime, "datetime", FrozenDateTime), \
             mock.patch.object(self.module, "_bounded_command", side_effect=bounded):
            result = self.module._external(["bounded-public-clock-fixture"],
                cwd=self.root, timeout=20000, phase="runtime", check=False)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(observed["command"], ["bounded-public-clock-fixture"])
        self.assertEqual(observed["timeout"], 10800 - 30 - 30)
        self.assertEqual(observed["limits"]["wall_seconds"], observed["timeout"])
        self.assertEqual(observed["env"]["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
            WINDOW.AUTHORIZED_SCOPE_PATH.as_posix())
        self.assertEqual(observed["env"]["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
            AUTHORIZED_RUN_SCOPE_SHA256)
        self.assertEqual(observed["env"]["GENEWHIP_QUALIFICATION_STARTED_AT"], self.start)
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH", observed["env"])
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256", observed["env"])

    def test_public_bounded_cmake_cli_and_direct_helper_use_scope_only(self):
        observed = []
        empty_sha = hashlib.sha256(b"").hexdigest()
        stream = {"text": "", "truncated": False, "observed_bytes": 0,
            "retained_bytes": 0, "sha256": empty_sha}

        def bounded(command, *, limits, timeout, env, **kwargs):
            observed.append({"command": list(command), "limits": dict(limits),
                "timeout": timeout, "env": dict(env), "kwargs": kwargs})
            return {"returncode": 0, "process_group_cleanup": "confirmed",
                "stdout_tail": "", "stderr_tail": "",
                "streams": {"stdout": stream, "stderr": stream}}

        build = self.root / "build/v02/authorized-cmake-fixture"
        configure = ["cmake", "-S", ".", "-B", str(build),
            "-DGENEWHIP_BUILD_DESKTOP=OFF"]
        compile_command = ["cmake", "--build", str(build), "--parallel", "2"]
        with mock.patch.dict(os.environ, self.public_env, clear=True), \
             mock.patch.object(self.module.datetime, "datetime",
                self._frozen_datetime(self.now)), \
             mock.patch.object(self.module, "_load_window_for_profile",
                side_effect=AssertionError("private-window-authority-read")), \
             mock.patch.object(self.module, "_bounded_command", side_effect=bounded):
            direct = self.module._run_bounded_phase7_cmake(
                configure, timeout=600, phase="runtime")
            self.assertEqual(direct.returncode, 0)
            for command in (configure, compile_command):
                with self.subTest(command=command[1]):
                    result = self.module.main([
                        "--mode", "bounded-command",
                        "--command-phase", "runtime",
                        "--command-timeout", "600",
                        "--command", *command])
                    self.assertEqual(result, 0)

        self.assertEqual([item["command"] for item in observed],
            [configure, configure, compile_command])
        self.assertTrue(all(item["timeout"] == 600 for item in observed))
        self.assertTrue(all(item["limits"]["wall_seconds"] == 600 for item in observed))
        for item in observed:
            child_env = item["env"]
            self.assertEqual(child_env["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
                WINDOW.AUTHORIZED_SCOPE_PATH.as_posix())
            self.assertEqual(child_env["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
                AUTHORIZED_RUN_SCOPE_SHA256)
            self.assertEqual(child_env["GENEWHIP_QUALIFICATION_STARTED_AT"], self.start)
            self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH", child_env)
            self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256", child_env)

    def test_runtime_cli_reaches_bounded_producer_with_public_deadline(self):
        build = self.root / "build/runtime-fixture"
        build.mkdir(parents=True)
        (build / "CMakeCache.txt").write_text("synthetic build identity\n", encoding="utf-8")
        out = self.root / "build/v02/runtime-fixture.json"
        observed = {}

        def bounded(command, *, limits, timeout, scratch, label, **kwargs):
            observed.update({"command": list(command), "limits": dict(limits),
                "timeout": timeout, "scratch": scratch, "label": label,
                "kwargs": kwargs, "host_env": dict(os.environ)})
            return {"returncode": 1, "process_group_cleanup": "confirmed",
                "processes": [], "streams": {
                    "stdout": {"text": "", "truncated": False,
                        "observed_bytes": 0, "retained_bytes": 0,
                        "sha256": digest(b"")},
                    "stderr": {"text": "", "truncated": False,
                        "observed_bytes": 0, "retained_bytes": 0,
                        "sha256": digest(b"")}}}

        plan = {"identity": {"source_sha": "fixture"},
            "limits": {"runtime_seconds": 10800}}
        with mock.patch.dict(os.environ, self.public_env, clear=True), \
             mock.patch.object(self.module.datetime, "datetime",
                self._frozen_datetime(self.now)), \
             mock.patch.object(self.module, "_load_window_for_profile",
                side_effect=AssertionError("private-window-authority-read")), \
             mock.patch.object(self.module, "qualification_plan", return_value=plan), \
             mock.patch.object(self.module, "_bounded_command", side_effect=bounded), \
             contextlib.redirect_stderr(io.StringIO()):
            result = self.module.main(["--mode", "runtime", "--build", str(build),
                "--scope", WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(), "--out", str(out)])

        self.assertEqual(result, 1)  # The mocked child reports failure after reaching the real guard.
        self.assertEqual(observed["label"], "runtime")
        self.assertEqual(observed["timeout"], 10800 - 30)
        self.assertEqual(observed["limits"]["wall_seconds"], 10800 - 30)
        self.assertEqual(observed["kwargs"], {"file_size_limit_bytes": 2147483648})
        self.assertTrue(out.with_suffix(out.suffix + ".attempt.json").is_file())
        self.assertEqual(observed["host_env"]["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
            WINDOW.AUTHORIZED_SCOPE_PATH.as_posix())
        self.assertEqual(observed["host_env"]["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
            AUTHORIZED_RUN_SCOPE_SHA256)
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH", observed["host_env"])
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256", observed["host_env"])

    def test_package_cli_runs_public_clock_guard_before_package_producer(self):
        scope = json.loads((self.root / WINDOW.AUTHORIZED_SCOPE_PATH).read_bytes())
        package_start = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=scope["qualification_batch"]["runtime_wall_seconds"] + 60))
        started_at = package_start.replace(microsecond=0).isoformat()
        now = (package_start + datetime.timedelta(seconds=scope[
            "qualification_batch"]["runtime_wall_seconds"] + 30)).replace(
                microsecond=0).isoformat()
        env = {**self.public_env, "GENEWHIP_QUALIFICATION_STARTED_AT": started_at,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}
        public_evidence = self.root / "build/v02/public-evidence"
        public_evidence.mkdir(parents=True)
        out = self.root / "build/v02/package-fixture.json"
        produced = {"archives": [], "inventory_sha256": "a" * 64}
        calls = []
        producer_env = []

        def package(evidence_path, output_path):
            calls.append((evidence_path, output_path))
            producer_env.append(dict(os.environ))
            return produced

        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(self.module.datetime, "datetime",
                self._frozen_datetime(now)), \
             mock.patch.object(self.module, "_load_window_for_profile",
                side_effect=AssertionError("private-window-authority-read")), \
             mock.patch.object(self.module, "run_package", side_effect=package), \
             mock.patch.object(self.module, "_check_environment_clock",
                wraps=self.module._check_environment_clock) as checked, \
             contextlib.redirect_stdout(io.StringIO()):
            result = self.module.main(["--mode", "package",
                "--scope", WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                "--public-evidence", str(public_evidence), "--out", str(out)])

        self.assertEqual(result, 0)
        self.assertEqual(calls, [(public_evidence, out)])
        self.assertEqual([call.args[1] for call in checked.call_args_list],
            ["package", "package"])
        self.assertEqual(producer_env[0]["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
            WINDOW.AUTHORIZED_SCOPE_PATH.as_posix())
        self.assertEqual(producer_env[0]["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
            AUTHORIZED_RUN_SCOPE_SHA256)
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH", producer_env[0])
        self.assertNotIn("GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256", producer_env[0])

    def test_stage_public_prepare_cli_uses_paired_authority_and_relative_packet_path(self):
        authority_file = ROOT / AUTHORIZED_RUN_PATH
        if not authority_file.is_file():
            self.skipTest("private authorized-run authority is unavailable")
        window = WINDOW.load_authorized_window(ROOT,
            authority_path=AUTHORIZED_RUN_PATH,
            authority_sha256=AUTHORIZED_RUN_SHA256,
            scope_path=WINDOW.AUTHORIZED_SCOPE_PATH,
            scope_sha256=AUTHORIZED_RUN_SCOPE_SHA256)
        fixture_parent = ROOT / "build/v02"
        with tempfile.TemporaryDirectory(prefix="gw-stage-public-cli-",
                dir=fixture_parent) as temporary:
            fixture_root = Path(temporary)
            destination_packet = fixture_root / "destination-packet.json"
            destination_packet.write_bytes(json_bytes({
                "schema": "genewhip.publication-readiness-packet.v1",
                "history_disposition": "sanitized-snapshots-preserve-local-history",
                "repository": "szTheory/genewhip",
                "destination": {"visibility": "public",
                    "owner_repository": "szTheory/genewhip"}}))
            relative_authorization = destination_packet.relative_to(ROOT).as_posix()
            publication_copy = (fixture_root / "sanitized-public-copy").relative_to(ROOT)
            out = (fixture_root / "preflight.json").relative_to(ROOT)
            env = {
                "CI": "true",
                "GITHUB_ACTIONS": "true",
                "GENEWHIP_QUALIFICATION_SCOPE_PATH": WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": AUTHORIZED_RUN_SCOPE_SHA256,
                "GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH": AUTHORIZED_RUN_PATH.as_posix(),
                "GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256": AUTHORIZED_RUN_SHA256,
                "GENEWHIP_QUALIFICATION_STARTED_AT": window["started_at"],
                "GENEWHIP_QUALIFICATION_PHASE": "preparation",
            }
            captured = []
            prepared = {"status": "prepared", "source_manifest": [],
                "public_identity": {"head_sha": "a" * 40, "base_sha": "b" * 40}}

            def preparation_boundary(copy_path, scope_path, output_path, authorization, **kwargs):
                captured.append((copy_path, scope_path, output_path, authorization,
                    dict(os.environ), kwargs))
                return prepared

            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(self.module, "ROOT", ROOT), \
                 mock.patch.object(self.module,
                    "_phase7_public_window_profile",
                    wraps=self.module._phase7_public_window_profile) as selected, \
                 mock.patch.object(self.module, "prepare_public_snapshot",
                    side_effect=preparation_boundary), \
                 contextlib.redirect_stdout(io.StringIO()):
                profile = self.module._phase7_public_window_profile()
                self.assertEqual(profile["profile_id"], "authorized-run")
                result = self.module.main([
                    "--mode", "stage-public", "--prepare-only",
                    "--scope", WINDOW.AUTHORIZED_SCOPE_PATH.as_posix(),
                    "--publication-copy", publication_copy.as_posix(),
                    "--authorization", relative_authorization,
                    "--out", out.as_posix()])

            self.assertEqual(result, 0)
            self.assertEqual(selected.call_count, 2)
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0][:4], (publication_copy,
                WINDOW.AUTHORIZED_SCOPE_PATH, out, Path(relative_authorization)))
            self.assertEqual(captured[0][4]["GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH"],
                AUTHORIZED_RUN_PATH.as_posix())
            self.assertEqual(captured[0][4]["GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256"],
                AUTHORIZED_RUN_SHA256)
            self.assertEqual(captured[0][4]["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
                WINDOW.AUTHORIZED_SCOPE_PATH.as_posix())
            self.assertEqual(captured[0][4]["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
                AUTHORIZED_RUN_SCOPE_SHA256)
            self.assertEqual(captured[0][4]["GENEWHIP_QUALIFICATION_STARTED_AT"],
                window["started_at"])
            self.assertEqual(set(captured[0][5]), {"single_native_admission",
                "single_native_admission_sha256", "single_native_authority",
                "single_native_authority_sha256"})
            self.assertTrue(all(value is None for value in captured[0][5].values()))

    @staticmethod
    def _frozen_datetime(value):
        fixed = datetime.datetime.fromisoformat(value)
        real_datetime = datetime.datetime

        class FrozenDateTime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed.astimezone(tz) if tz is not None else fixed.replace(tzinfo=None)

        return FrozenDateTime

    def test_workflow_maps_the_public_scope_hash_and_all_cmake_guards(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        mapping = ("inputs.qualification_scope_sha256 == '" + AUTHORIZED_RUN_SCOPE_SHA256
            + "' && '" + WINDOW.AUTHORIZED_SCOPE_PATH.as_posix() + "'")
        self.assertIn(mapping, workflow)
        guard = ("[ \"${GENEWHIP_QUALIFICATION_SCOPE_SHA256:-}\" = '"
            + AUTHORIZED_RUN_SCOPE_SHA256 + "' ]")
        self.assertEqual(workflow.count(guard), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
