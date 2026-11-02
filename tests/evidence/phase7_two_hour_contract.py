#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused contracts for the prospective two-hour Phase 7 window."""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCOPE_SOURCE = ROOT / "evidence/v02-phase7-two-hour-execution-scope.json"
LEGACY_SCOPE_SOURCE = ROOT / "evidence/v02-execution.json"
MODULE_PATH = ROOT / "scripts/release/v02_window.py"
BATCH_MODULE_PATH = ROOT / "scripts/release/v02_batch.py"
QUALIFICATION_MODULE_PATH = ROOT / "scripts/release/v02_qualification.py"
STARTED_AT = "2026-11-02T22:08:29+00:00"
RUNTIME_CUTOFF = "2026-11-02T23:43:29+00:00"
PACKAGE_CUTOFF = "2026-11-03T00:03:29+00:00"
GLOBAL_CUTOFF = "2026-11-03T00:08:29+00:00"
SCOPE_PATH = "evidence/v02-phase7-two-hour-execution-scope.json"
SCOPE_SHA256 = "a72453ee43bceeb16f03a5b023c6f94def38196e5ff23f36c7f2e4a35a99136c"


def load_window_module():
    spec = importlib.util.spec_from_file_location("gw_phase7_two_hour_window_contract", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("two-hour-window-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_batch_module():
    spec = importlib.util.spec_from_file_location("gw_phase7_two_hour_batch_contract",
        BATCH_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("two-hour-batch-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_qualification_module():
    spec = importlib.util.spec_from_file_location("gw_phase7_two_hour_qualification_contract",
        QUALIFICATION_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("two-hour-qualification-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WINDOW = load_window_module()
BATCH = load_batch_module()


def instant(offset_seconds: int) -> str:
    start = datetime.datetime.fromisoformat(STARTED_AT.replace("Z", "+00:00"))
    return (start + datetime.timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


class TwoHourPublicClockContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-phase7-two-hour-clock-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for source, relative in ((SCOPE_SOURCE, SCOPE_PATH),
                                 (LEGACY_SCOPE_SOURCE, "evidence/v02-execution.json")):
            scope = self.root / relative
            scope.parent.mkdir(parents=True, exist_ok=True)
            scope.write_bytes(source.read_bytes())

    def test_public_selection_uses_fixed_two_hour_clock_and_accounts_for_queue_delay(self):
        selected = WINDOW.select_public_event_window(self.root,
            workflow_created_at=instant(30), now=instant(90))
        self.assertEqual(selected["profile_id"], "two-hour")
        self.assertEqual(selected["started_at"], STARTED_AT)
        self.assertEqual(selected["phase_cutoff"], RUNTIME_CUTOFF)
        self.assertEqual(selected["scope_sha256"], SCOPE_SHA256)

        # The provider-created time is retained; queueing consumes the original budget.
        with self.assertRaisesRegex(ValueError, "phase7-window-phase-expired"):
            WINDOW.select_public_event_window(self.root,
                workflow_created_at=instant(45), now=RUNTIME_CUTOFF)

    def test_public_selection_rejects_start_queue_and_deadline_mismatches(self):
        cases = (
            ("created-in-future", instant(120), instant(60), "phase7-window-workflow-clock-invalid"),
            ("runtime-deadline", instant(60), RUNTIME_CUTOFF, "phase7-window-phase-expired"),
            ("hard-deadline", instant(60), GLOBAL_CUTOFF, "phase7-window-phase-expired"),
        )
        for label, created, now, expected in cases:
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, expected):
                WINDOW.select_public_event_window(self.root,
                    workflow_created_at=created, now=now)

        before = WINDOW.select_public_event_window(self.root,
            workflow_created_at=instant(-1), now=instant(60))
        self.assertFalse(before["selected"])
        self.assertIsNone(before["profile_id"])

    def test_public_clock_rejects_scope_start_and_phase_deadline_rebinding(self):
        valid = dict(root=self.root, scope_path=SCOPE_PATH, scope_sha256=SCOPE_SHA256,
            started_at=STARTED_AT, phase="runtime", now=instant(60),
            workflow_created_at=instant(30))
        accepted = WINDOW.validate_public_clock(**valid)
        self.assertEqual(accepted["profile_id"], "two-hour")
        self.assertGreater(accepted["remaining_seconds"], 0)

        for overrides, expected in (
                ({"scope_path": "evidence/v02-execution.json"},
                 "phase7-window-public-scope-pin-invalid"),
                ({"scope_sha256": "0" * 64},
                 "phase7-window-public-scope-pin-invalid"),
                ({"started_at": instant(1)}, "phase7-window-start-replaced"),
                ({"now": PACKAGE_CUTOFF}, "phase7-window-phase-expired")):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, expected):
                WINDOW.validate_public_clock(**(valid | overrides))


class TwoHourRetainedPredecessorContract(unittest.TestCase):
    def test_initial_predecessor_reopens_the_retained_full_failure_and_cleanup_receipts(self):
        authority = ROOT / BATCH.TWO_HOUR_AUTH_PATH
        observation = ROOT / BATCH.TWO_HOUR_INITIAL_PREDECESSOR["terminal"]["path"]
        if not authority.is_file() or not observation.is_file():
            self.skipTest("private retained Phase 7 failure records are unavailable in this checkout")
        window = WINDOW.load_window(ROOT,
            authority_path=WINDOW.TWO_HOUR_AUTH_PATH,
            authority_sha256=WINDOW.TWO_HOUR_AUTH_SHA256,
            scope_path=WINDOW.TWO_HOUR_SCOPE_PATH,
            scope_sha256=WINDOW.TWO_HOUR_SCOPE_SHA256)
        predecessor = BATCH._phase7_window_predecessor(ROOT,
            {"predecessor": BATCH.TWO_HOUR_INITIAL_PREDECESSOR},
            attempt_index=1, window=window)
        self.assertEqual(predecessor, BATCH.TWO_HOUR_INITIAL_PREDECESSOR)
        self.assertEqual(predecessor["status"], "settled-full-qualification-failure")
        self.assertFalse(predecessor["qualification_accepted"])
        self.assertEqual(predecessor["local_cleanup"], "settled")

    def test_rehashed_semantic_mutations_of_the_retained_observation_are_rejected(self):
        authority = ROOT / BATCH.TWO_HOUR_AUTH_PATH
        observation_path = ROOT / BATCH.TWO_HOUR_INITIAL_PREDECESSOR["terminal"]["path"]
        if not authority.is_file() or not observation_path.is_file():
            self.skipTest("private retained Phase 7 failure records are unavailable in this checkout")
        window = WINDOW.load_window(ROOT,
            authority_path=WINDOW.TWO_HOUR_AUTH_PATH,
            authority_sha256=WINDOW.TWO_HOUR_AUTH_SHA256,
            scope_path=WINDOW.TWO_HOUR_SCOPE_PATH,
            scope_sha256=WINDOW.TWO_HOUR_SCOPE_SHA256)
        original = json.loads(observation_path.read_text(encoding="utf-8"))
        base = BATCH.TWO_HOUR_INITIAL_PREDECESSOR
        mutations = (
            ("job-result", lambda value: value["jobs"].update({"v02-runtime": "success"})),
            ("claim-preservation", lambda value: value.update(dispatch_claim_preserved=False)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = json.loads(json.dumps(original))
                mutate(changed)
                raw = (json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
                reference = {"path": base["terminal"]["path"],
                    "sha256": hashlib.sha256(raw).hexdigest()}
                self.assertEqual(reference["sha256"], hashlib.sha256(raw).hexdigest())
                changed_predecessor = {**base, "terminal": reference}

                def reopened(_root, _reference, **_kwargs):
                    return changed, raw

                with mock.patch.object(BATCH, "TWO_HOUR_INITIAL_PREDECESSOR",
                        changed_predecessor), \
                     mock.patch.object(BATCH, "_read_reference", side_effect=reopened):
                    with self.assertRaisesRegex(ValueError,
                            "phase7-window-two-hour-predecessor-invalid"):
                        BATCH._phase7_window_predecessor(ROOT,
                            {"predecessor": changed_predecessor},
                            attempt_index=1, window=window)


class TwoHourSourceGuardContract(unittest.TestCase):
    def test_full_public_source_guard_accepts_the_real_current_tracked_roster(self):
        if os.environ.get("GENEWHIP_PROCESS_CONTEXT") != "host-cleanup-v1":
            self.skipTest("the source-roster read requires the explicit host process context")
        roster = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
        if len(roster.stdout) > 8 * 1024 * 1024:
            self.fail("current source roster exceeded its bounded capture")
        names = [item.decode("utf-8") for item in roster.stdout.split(b"\0") if item]
        qualification = load_qualification_module()
        source_paths = set(qualification._publication_paths_from_names(ROOT, names))
        # This new test is an untracked working-tree addition until the parent commits it.
        source_paths.add("tests/evidence/phase7_two_hour_contract.py")

        with tempfile.TemporaryDirectory(prefix="gw-phase7-two-hour-source-guard-") as temporary:
            root = Path(temporary).resolve()
            for relative in source_paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            scope = root / BATCH.TWO_HOUR_SCOPE_PATH
            scope.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / BATCH.TWO_HOUR_SCOPE_PATH, scope)
            attempt = root / BATCH.TWO_HOUR_ATTEMPT_NAMESPACE / "attempt-0001"
            attempt.mkdir(parents=True)

            profile = BATCH.WINDOW_PROFILES["two-hour"]
            window = {"profile_id": "two-hour",
                "authority": {"schema": "fixture-only-two-hour-authority"},
                "authority_path": profile["authority_path"].as_posix(),
                "authority_sha256": profile["authority_sha256"],
                "scope_path": profile["scope_path"].as_posix(),
                "scope_sha256": profile["scope_sha256"],
                "attempt_namespace": profile["attempt_namespace"].as_posix(),
                "started_at": profile["started_at"],
                "source_ancestor": "208da236ecd5ef9cddd59556324fbb4b1deeabdf"}
            source_head = "a" * 40
            pins = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in sorted(source_paths)}
            attempt_rel = attempt.relative_to(root).as_posix()
            payload = BATCH.phase7_window_source_admission_payload(
                attempt_root=attempt_rel, attempt_index=1,
                predecessor=BATCH.TWO_HOUR_INITIAL_PREDECESSOR,
                disposition="routine-source-repair", source_head=source_head,
                source_pins=pins, window=window)
            payload_sha = hashlib.sha256(BATCH._canonical(payload)).hexdigest()
            review_refs = {}
            for key, role in BATCH.SOURCE_ROLES.items():
                review_path = (root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
                    / f"07-10-TWO-HOUR-SOURCE-{key.upper()}.md")
                review_path.parent.mkdir(parents=True, exist_ok=True)
                raw = (f"---\nreviewer_role: {role}\nstatus: accepted\n"
                    f"payload_sha256: {payload_sha}\n---\nAccepted source review fixture.\n").encode()
                review_path.write_bytes(raw)
                review_refs[key] = {"path": review_path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                    "status": "accepted", "payload_sha256": payload_sha}
            admission = {"schema": BATCH.SCHEMA, "status": "source-preparation",
                "authorization_path": profile["authority_path"].as_posix(),
                "authorization_sha256": profile["authority_sha256"],
                "scope_path": profile["scope_path"].as_posix(),
                "scope_sha256": profile["scope_sha256"], "batch_root": attempt_rel,
                "attempt_index": 1, "attempt_root": attempt_rel,
                "predecessor": BATCH.TWO_HOUR_INITIAL_PREDECESSOR,
                "disposition": "routine-source-repair", "started_at": profile["started_at"],
                "source_head": source_head, "source_pins": pins,
                "source_payload_sha256": payload_sha, "source_reviews": review_refs}
            admission_path = attempt / "source-admission.json"
            admission_bytes = BATCH._canonical(admission) + b"\n"
            admission_path.write_bytes(admission_bytes)
            candidate_root = attempt / "candidate"
            publication = candidate_root / "publication-copy"
            publication.mkdir(parents=True)
            preflight = candidate_root / "preparation.json"
            policy_path = candidate_root / "repository-policy.json"
            public_head, public_base, public_tree = "f" * 40, "e" * 40, "d" * 40
            manifest_sha = "c" * 64
            preparation = {"status": "prepared",
                "source_identity": {"private_git_head": source_head},
                "publication_copy": publication.relative_to(root).as_posix(),
                "repository_preflight": policy_path.relative_to(root).as_posix(),
                "public_identity": {"head_sha": public_head, "base_sha": public_base,
                    "tree_sha": public_tree},
                "source_manifest_sha256": manifest_sha,
                "privacy": {"status": "pass"}, "blockers": []}
            policy = {"repository_observations": {"ready": True},
                "privacy_scan": {"publication_copy": {"status": "pass"}}}
            preparation_bytes = BATCH._canonical(preparation) + b"\n"
            policy_bytes = BATCH._canonical(policy) + b"\n"
            preflight.write_bytes(preparation_bytes)
            policy_path.write_bytes(policy_bytes)
            candidate = {"preparation_path": preflight.relative_to(root).as_posix(),
                "preparation_sha256": hashlib.sha256(preparation_bytes).hexdigest(),
                "publication_path": publication.relative_to(root).as_posix(),
                "repository_policy_path": policy_path.relative_to(root).as_posix(),
                "repository_policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
                "public_head": public_head, "public_base": public_base,
                "public_tree": public_tree, "source_manifest_sha256": manifest_sha}
            candidate_payload = BATCH.phase7_window_candidate_review_payload(
                payload, candidate, window=window)
            candidate_payload_sha = hashlib.sha256(
                BATCH._canonical(candidate_payload)).hexdigest()
            candidate_reviews = {}
            for key, role in BATCH.CANDIDATE_ROLES.items():
                review_path = (root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
                    / f"07-10-TWO-HOUR-CANDIDATE-{key.upper()}.md")
                raw = (f"---\nreviewer_role: {role}\nstatus: accepted\n"
                    f"payload_sha256: {candidate_payload_sha}\n---\nAccepted candidate review fixture.\n").encode()
                review_path.write_bytes(raw)
                candidate_reviews[key] = {"path": review_path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                    "status": "accepted", "payload_sha256": candidate_payload_sha}
            candidate["candidate_payload_sha256"] = candidate_payload_sha
            candidate["candidate_reviews"] = candidate_reviews
            public_admission = {**admission, "status": "public-effects", "candidate": candidate}
            public_path = attempt / "public-admission.json"
            public_bytes = BATCH._canonical(public_admission) + b"\n"
            public_path.write_bytes(public_bytes)
            batch_module = BATCH._phase7_window_module()
            with mock.patch.object(batch_module, "load_window", return_value=window), \
                 mock.patch.object(BATCH, "_phase7_window_predecessor",
                    return_value=BATCH.TWO_HOUR_INITIAL_PREDECESSOR), \
                 mock.patch.dict(os.environ,
                    {"GENEWHIP_QUALIFICATION_STARTED_AT": profile["started_at"]}):
                accepted = BATCH.validate_phase7_window_batch(root,
                    profile["authority_path"], profile["authority_sha256"],
                    admission_path, hashlib.sha256(admission_bytes).hexdigest(),
                    stage="source-preparation", source_head=source_head,
                    now=datetime.datetime.fromisoformat("2026-11-02T22:10:00+00:00"),
                    scope_path=scope,
                    journal_path=attempt / "hosted-delivery-journal.json",
                    publication_copy=attempt / "candidate/publication-copy",
                    preflight_path=attempt / "candidate/preparation.json",
                    output_path=attempt / "source-validation.json",
                    source_is_ancestor=lambda ancestor, descendant:
                        ancestor == window["source_ancestor"] and descendant == source_head,
                    expected_source_paths=source_paths, window=window)
                public_accepted = BATCH.validate_phase7_window_batch(root,
                    profile["authority_path"], profile["authority_sha256"],
                    public_path, hashlib.sha256(public_bytes).hexdigest(),
                    stage="public-effects", source_head=source_head,
                    now=datetime.datetime.fromisoformat("2026-11-02T22:10:00+00:00"),
                    scope_path=scope,
                    journal_path=attempt / "hosted-delivery-journal.json",
                    publication_copy=publication, preflight_path=preflight,
                    output_path=candidate_root / "result.json",
                    source_is_ancestor=lambda ancestor, descendant:
                        ancestor == window["source_ancestor"] and descendant == source_head,
                    expected_source_paths=source_paths, window=window)

            self.assertTrue(accepted["phase7_window"])
            self.assertEqual(accepted["window_profile"], "two-hour")
            self.assertEqual(accepted["attempt_root"], attempt.resolve())
            self.assertEqual(accepted["source_payload_sha256"], payload_sha)
            self.assertEqual(accepted["candidate_payload_sha256"], None)
            self.assertEqual(public_accepted["window_profile"], "two-hour")
            self.assertEqual(public_accepted["candidate_payload_sha256"], candidate_payload_sha)


if __name__ == "__main__":
    unittest.main(verbosity=2)
