#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for the renewed two-hour Phase 7 continuation route."""
from __future__ import annotations

import hashlib
import datetime
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_SOURCE_HEAD = "27b67e6b92fba562603fac0aceffaa581236903a"
HISTORICAL_ATTEMPT2 = ROOT / (
    "build/v02/phase7-qualification-20261102T220829Z/attempts/attempt-0002"
)
PREDECESSOR_OBSERVATION_PATH = ROOT / (
    "build/v02/phase7-qualification-20261103T000225Z/operator/predecessor-observation.json"
)


def load_batch_module():
    path = ROOT / "scripts/release/v02_batch.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_renewed_window_batch_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("renewed-window-batch-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BATCH = load_batch_module()


def load_window_module():
    path = ROOT / "scripts/release/v02_window.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_renewed_window_clock_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("renewed-window-clock-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WINDOW = load_window_module()


def load_qualification_module():
    path = ROOT / "scripts/release/v02_qualification.py"
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_renewed_window_qualification_contract", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("renewed-window-qualification-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUALIFICATION = load_qualification_module()


class RenewedWindowProfileContract(unittest.TestCase):
    def test_explicit_real_root_clock_selects_the_new_profile_without_rebinding_old_windows(self):
        profile = WINDOW._PROFILES["renewed-two-hour"]
        with tempfile.TemporaryDirectory(prefix="gw-renewed-window-public-clock-") as temporary:
            root = Path(temporary).resolve()
            for source, relative in (
                    (ROOT / profile["scope_path"], profile["scope_path"]),
                    (ROOT / "evidence/v02-execution.json", Path("evidence/v02-execution.json"))):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

            self.assertEqual(profile["started_at"], "2026-11-03T00:02:25+00:00")
            self.assertEqual(profile["runtime_cutoff"], "2026-11-03T01:37:25+00:00")
            self.assertEqual(profile["package_cutoff"], "2026-11-03T01:57:25+00:00")
            self.assertEqual(profile["global_cutoff"], "2026-11-03T02:02:25+00:00")
            window = WINDOW.validate_public_clock(root,
                scope_path=profile["scope_path"].as_posix(),
                scope_sha256=profile["scope_sha256"], started_at=profile["started_at"],
                phase="runtime", now="2026-11-03T00:03:00+00:00",
                workflow_created_at="2026-11-03T00:02:30+00:00")
            self.assertEqual(window["profile_id"], "renewed-two-hour")
            self.assertGreater(window["remaining_seconds"], 0)

            selected = WINDOW.select_public_event_window(root,
                workflow_created_at="2026-11-03T00:02:30+00:00",
                now="2026-11-03T00:03:00+00:00")
            self.assertTrue(selected["selected"])
            self.assertEqual(selected["profile_id"], "renewed-two-hour")
            self.assertEqual(selected["scope_sha256"], profile["scope_sha256"])

            with self.assertRaisesRegex(ValueError, "phase7-window-public-scope-pin-invalid"):
                WINDOW.validate_public_clock(root,
                    scope_path=profile["scope_path"].as_posix(),
                    scope_sha256=WINDOW.TWO_HOUR_SCOPE_SHA256,
                    started_at=profile["started_at"], phase="runtime",
                    now="2026-11-03T00:03:00+00:00",
                    workflow_created_at="2026-11-03T00:02:30+00:00")

            expired = datetime.datetime.fromisoformat(profile["runtime_cutoff"])
            with self.assertRaisesRegex(ValueError, "phase7-window-phase-expired"):
                WINDOW.check_window(window, phase="runtime", now=expired)

        self.assertNotEqual(profile["scope_sha256"], WINDOW.TWO_HOUR_SCOPE_SHA256)

    def test_private_authority_reader_reopens_exact_renewed_profile_when_available(self):
        profile = WINDOW._PROFILES["renewed-two-hour"]
        authority = ROOT / profile["authority_path"]
        if not authority.is_file():
            self.skipTest("private renewed-window authorization is unavailable")
        window = WINDOW.load_window(ROOT,
            authority_path=profile["authority_path"],
            authority_sha256=profile["authority_sha256"],
            scope_path=profile["scope_path"], scope_sha256=profile["scope_sha256"])
        self.assertEqual(window["profile_id"], "renewed-two-hour")
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-pin-invalid"):
            WINDOW.load_window(ROOT, authority_path=profile["authority_path"],
                authority_sha256=profile["authority_sha256"],
                scope_path=profile["scope_path"],
                scope_sha256=WINDOW.TWO_HOUR_SCOPE_SHA256)

    def test_production_scope_resolver_uses_new_root_profile_pins(self):
        profile = QUALIFICATION.PHASE7_WINDOW_PROFILES[-1]
        scope = ROOT / profile["scope_path"]
        if not scope.is_file():
            self.fail("public renewed-window scope must be checked into the source tree")
        environment = {
            "GENEWHIP_QUALIFICATION_SCOPE_PATH": profile["scope_path"].as_posix(),
            "GENEWHIP_QUALIFICATION_SCOPE_SHA256": profile["scope_sha256"],
        }
        with mock.patch.dict("os.environ", environment, clear=True):
            selected = QUALIFICATION._phase7_window_profile()
            resolved = QUALIFICATION.phase7_execution_scope_path(
                root=ROOT, explicit=profile["scope_path"]
            )
        self.assertEqual(selected["profile_id"], "renewed-two-hour")
        self.assertEqual(resolved, scope)


class HistoricalSourcePinContract(unittest.TestCase):
    def test_git_blob_pin_reader_uses_historical_commit_bytes_in_a_portable_fixture(self):
        with tempfile.TemporaryDirectory(prefix="gw-renewed-window-git-blobs-") as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "--quiet", str(root)], check=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15)
            originals = {
                "scripts/release/v02_batch.py": b"historical validator\n",
                "evidence/contract.json": b'{"fixture":true}\n',
            }
            for name, content in originals.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            subprocess.run(["git", "-C", str(root), "add", "--", *originals], check=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Contract Fixture",
                "-c", "user.email=contract@example.invalid", "commit", "--quiet", "-m",
                "historical source fixture"], check=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            source_head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15).stdout.strip()
            pins = {name: hashlib.sha256(content).hexdigest()
                for name, content in originals.items()}
            expected_paths = set(originals)

            (root / "scripts/release/v02_batch.py").write_bytes(b"working tree changed\n")
            checked = BATCH.phase7_window_validate_git_blob_pins(
                root, source_head, pins, expected_paths=expected_paths)
            self.assertEqual(checked, pins)
            swapped = dict(pins)
            swapped.pop("evidence/contract.json")
            swapped["evidence/replaced.json"] = hashlib.sha256(b"other\n").hexdigest()
            with self.assertRaisesRegex(ValueError,
                    "phase7-window-historical-source-pins-invalid"):
                BATCH.phase7_window_validate_git_blob_pins(
                    root, source_head, swapped, expected_paths=expected_paths)
            changed = dict(pins)
            changed["scripts/release/v02_batch.py"] = "0" * 64
            with self.assertRaisesRegex(ValueError,
                    "phase7-window-historical-source-pins-invalid"):
                BATCH.phase7_window_validate_git_blob_pins(
                    root, source_head, changed, expected_paths=expected_paths)

    def test_prior_attempt2_pins_reopen_as_git_blobs_not_current_worktree(self):
        admission_path = HISTORICAL_ATTEMPT2 / "source-admission.json"
        if not admission_path.is_file():
            self.skipTest("private retained attempt-2 evidence is unavailable")
        admission = json.loads(admission_path.read_bytes())
        pins = admission.get("source_pins")
        if (admission.get("attempt_index") != 2
                or admission.get("source_head") != HISTORICAL_SOURCE_HEAD
                or not isinstance(pins, dict) or len(pins) != 603):
            self.fail("retained attempt-2 source identity or 603-pin roster changed")
        try:
            available = subprocess.run(
                ["git", "cat-file", "-e", f"{HISTORICAL_SOURCE_HEAD}^{{commit}}"],
                cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("historical source commit is unavailable in this checkout")
        if available.returncode != 0:
            self.skipTest("historical source commit is unavailable in this checkout")

        historical_tree = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "-z", HISTORICAL_SOURCE_HEAD],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20, check=True,
        )
        historical_names = [item.decode("utf-8") for item in historical_tree.stdout.split(b"\0")
            if item]
        expected_paths = set(QUALIFICATION._publication_paths_from_names(ROOT, historical_names))
        self.assertEqual(len(expected_paths), 603)
        self.assertEqual(set(pins), expected_paths)

        checked = BATCH.phase7_window_validate_git_blob_pins(
            ROOT, HISTORICAL_SOURCE_HEAD, pins, expected_paths=expected_paths
        )
        self.assertEqual(checked, pins)
        changed_worktree_path = "scripts/release/v02_batch.py"
        self.assertIn(changed_worktree_path, pins)
        self.assertNotEqual(
            hashlib.sha256((ROOT / changed_worktree_path).read_bytes()).hexdigest(),
            pins[changed_worktree_path],
            "the fixture must prove that current working-tree edits cannot rebind history",
        )

        mutated = dict(pins)
        mutated[changed_worktree_path] = "0" * 64
        with self.assertRaisesRegex(
            ValueError, "phase7-window-historical-source-pins-invalid"
        ):
            BATCH.phase7_window_validate_git_blob_pins(
                ROOT, HISTORICAL_SOURCE_HEAD, mutated, expected_paths=expected_paths
            )


class PriorAttemptExternalReceiptContract(unittest.TestCase):
    def test_exact_external_receipt_contract_is_portable_and_rejects_identity_mutations(self):
        with tempfile.TemporaryDirectory(prefix="gw-renewed-window-receipts-") as temporary:
            root = Path(temporary).resolve()
            external_directory = root / BATCH.RENEWED_TWO_HOUR_EXTERNAL_DIR
            external_directory.mkdir(parents=True)
            sidecar_directory = external_directory / "process-receipts"
            sidecar_directory.mkdir()
            refs = {}
            sequence = 1000
            for command, count in BATCH.RENEWED_TWO_HOUR_EXTERNAL_COMMANDS.items():
                for _ in range(count):
                    label = f"external-21895-{sequence}"
                    sequence += 1
                    relative = (BATCH.RENEWED_TWO_HOUR_EXTERNAL_DIR /
                        f"{label}.attempt.json").as_posix()
                    process = {"status": "completed", "return_code": 0,
                        "process_group_cleanup": "confirmed", "bound_violation": False}
                    receipt = {
                        "schema": "genewhip.v02-coordinator-child-attempt.v1",
                        "label": label, "argv": list(command), "returncode": 0,
                        "launch_error": None, "process_group_cleanup": "confirmed",
                        "processes": [process],
                    }
                    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
                    (root / relative).write_bytes(raw)
                    sidecar_name = hashlib.sha256(relative.encode()).hexdigest()[:32] + ".json"
                    sidecar_raw = json.dumps({"processes": [process]}, sort_keys=True,
                        separators=(",", ":")).encode()
                    (sidecar_directory / sidecar_name).write_bytes(sidecar_raw)
                    refs[relative] = {"bytes": len(raw), "path": relative,
                        "sha256": hashlib.sha256(raw).hexdigest()}

            validated = BATCH._phase7_window_validate_renewed_external_receipts(root, refs)
            self.assertEqual(len(validated), 10)
            self.assertEqual(
                {tuple(row["argv"]) for row in validated},
                set(BATCH.RENEWED_TWO_HOUR_EXTERNAL_COMMANDS),
            )

            foreign = external_directory / "external-99999-10000.attempt.json"
            foreign.write_bytes(next(external_directory.glob("external-*.attempt.json")).read_bytes())
            with self.assertRaisesRegex(ValueError,
                    "phase7-window-renewed-external-receipts-invalid"):
                BATCH._phase7_window_validate_renewed_external_receipts(root, refs)
            foreign.unlink()

            first_name = sorted(refs)[0]
            first_path = root / first_name
            receipt = json.loads(first_path.read_bytes())
            receipt["argv"] = ["git", "status"]
            altered_raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            first_path.write_bytes(altered_raw)
            altered_refs = copy.deepcopy(refs)
            altered_refs[first_name]["bytes"] = len(altered_raw)
            altered_refs[first_name]["sha256"] = hashlib.sha256(altered_raw).hexdigest()
            with self.assertRaisesRegex(ValueError,
                    "phase7-window-renewed-external-receipts-invalid"):
                BATCH._phase7_window_validate_renewed_external_receipts(root, altered_refs)

    def test_all_ten_external_receipts_are_exact_and_foreign_controller_pid_is_rejected(self):
        if not PREDECESSOR_OBSERVATION_PATH.is_file():
            self.skipTest("private renewed-window predecessor evidence is unavailable")
        observation = json.loads(PREDECESSOR_OBSERVATION_PATH.read_bytes())
        refs = observation.get("refs")
        if not isinstance(refs, dict):
            self.fail("retained predecessor reference roster is malformed")
        self.assertEqual(
            len([name for name in refs if "/coordinator-external-attempts/external-" in name]),
            10,
        )

        validated = BATCH._phase7_window_validate_renewed_external_receipts(ROOT, refs)
        self.assertEqual(len(validated), 10)
        self.assertEqual(
            {row["label"] for row in validated},
            {Path(name).stem.removesuffix(".attempt") for name in refs
                if "/coordinator-external-attempts/external-" in name},
        )

        external_directory = ROOT / BATCH.RENEWED_TWO_HOUR_EXTERNAL_DIR
        if not external_directory.is_dir():
            self.skipTest("private external-attempt records are unavailable")
        with tempfile.TemporaryDirectory(prefix="gw-renewed-window-foreign-pid-") as temporary:
            scratch = Path(temporary).resolve()
            scratch_external = scratch / BATCH.RENEWED_TWO_HOUR_EXTERNAL_DIR
            shutil.copytree(external_directory, scratch_external)
            first = next(scratch_external.glob("external-*.attempt.json"))
            shutil.copyfile(first, scratch_external / "external-99999-1111111111111111.attempt.json")
            with self.assertRaisesRegex(
                ValueError, "phase7-window-renewed-external-receipts-invalid"
            ):
                BATCH._phase7_window_validate_renewed_external_receipts(scratch, refs)


class RenewedCancellationAggregateContract(unittest.TestCase):
    @staticmethod
    def _jobs_fixture():
        run_id = 41540001234
        jobs = []
        for index, name in enumerate(BATCH.TWO_HOUR_JOB_RESULTS, start=1):
            conclusion = "failure" if name == "required-ci" else "cancelled"
            steps = ([{"name": "Reject incomplete or stale required lanes",
                "status": "completed", "conclusion": "failure"}]
                if name == "required-ci" else [])
            jobs.append({"id": index, "name": name, "run_id": run_id,
                "run_attempt": 1, "status": "completed", "conclusion": conclusion,
                "steps": steps})
        return run_id, {"total_count": len(jobs), "jobs": jobs}

    def test_cancelled_aggregate_is_new_profile_only_and_has_one_exact_failure(self):
        run_id, valid = self._jobs_fixture()
        accepted = QUALIFICATION._phase7_window_push_jobs(valid, run_id=run_id,
            run_attempt=1, state="cancelled-aggregate",
            controller_cancel_confirmed=True, profile_id="renewed-two-hour")
        self.assertEqual(len(accepted), 16)
        self.assertEqual(sum(row["conclusion"] == "FAILURE" for row in accepted), 1)

        mutations = (
            ("missing-job", lambda value: value["jobs"].pop(), True, "renewed-two-hour"),
            ("foreign-run", lambda value: value["jobs"][0].update(run_id=run_id + 1),
                True, "renewed-two-hour", "phase7-merge-push-job-record-invalid"),
            ("unfinished-job", lambda value: value["jobs"][0].update(status="in_progress"),
                True, "renewed-two-hour"),
            ("other-job-failure", lambda value: value["jobs"][0].update(conclusion="failure"),
                True, "renewed-two-hour"),
            ("wrong-required-step", lambda value: value["jobs"][11]["steps"][0].update(
                name="Some other failed step"), True, "renewed-two-hour"),
            ("second-failing-step", lambda value: value["jobs"][11]["steps"].append(
                {"name": "extra", "status": "completed", "conclusion": "failure"}),
                True, "renewed-two-hour"),
            ("failed-step-not-terminal", lambda value: value["jobs"][11]["steps"][0].update(
                status="in_progress"), True, "renewed-two-hour"),
            ("controller-cancel-unconfirmed", lambda value: None,
                False, "renewed-two-hour"),
            ("legacy-profile", lambda value: None, True, "two-hour"),
        )
        for case in mutations:
            label, mutate, confirmed, profile, *error_pattern = case
            changed = copy.deepcopy(valid)
            mutate(changed)
            changed["total_count"] = len(changed["jobs"])
            expected = error_pattern[0] if error_pattern else (
                "phase7-merge-push-cancelled-aggregate-invalid")
            with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError, expected):
                QUALIFICATION._phase7_window_push_jobs(changed, run_id=run_id,
                    run_attempt=1, state="cancelled-aggregate",
                    controller_cancel_confirmed=confirmed, profile_id=profile)

        with self.assertRaisesRegex(ValueError,
                "phase7-merge-push-terminal-roster-unsettled"):
            QUALIFICATION._phase7_window_push_jobs(valid, run_id=run_id,
                run_attempt=1, state="cancelled")


class RenewedPredecessorContract(unittest.TestCase):
    def test_previous_attempt2_is_reopened_as_preclaim_failure_and_cannot_roll_over(self):
        profile = WINDOW._PROFILES["renewed-two-hour"]
        if not PREDECESSOR_OBSERVATION_PATH.is_file():
            self.skipTest("private renewed-window predecessor evidence is unavailable")
        window = WINDOW.load_window(ROOT,
            authority_path=profile["authority_path"],
            authority_sha256=profile["authority_sha256"],
            scope_path=profile["scope_path"],
            scope_sha256=profile["scope_sha256"])
        # This retained historical reader is time bounded in production. Pin its
        # contract clock inside the original authorized interval so CI remains
        # deterministic after the historical window itself has elapsed.
        clock_module = BATCH._phase7_window_module()
        check_window = clock_module.check_window
        with mock.patch.object(clock_module, "check_window",
                side_effect=lambda value, **kwargs: check_window(value,
                    now="2026-11-03T00:03:00+00:00", **kwargs)):
            predecessor = BATCH.renewed_two_hour_initial_predecessor(ROOT, window)
        self.assertEqual(predecessor, BATCH.RENEWED_TWO_HOUR_PREDECESSOR)
        self.assertEqual(predecessor["attempt_index"], 2)
        self.assertEqual(predecessor["attempt_root"], HISTORICAL_ATTEMPT2.relative_to(ROOT).as_posix())
        self.assertEqual(predecessor["status"], "settled-preclaim-route-rejection-no-qualification-credit")
        self.assertFalse(predecessor["qualification_accepted"])
        self.assertEqual(predecessor["local_cleanup"], "settled")

        with mock.patch.object(clock_module, "check_window",
                side_effect=lambda value, **kwargs: check_window(value,
                    now="2026-11-03T00:03:00+00:00", **kwargs)):
            with self.assertRaisesRegex(ValueError, "phase7-window-renewed-predecessor-invalid"):
                BATCH._phase7_window_predecessor(ROOT,
                    {"predecessor": predecessor}, attempt_index=2, window=window)

        observation = json.loads(PREDECESSOR_OBSERVATION_PATH.read_bytes())
        for mutation in (
            lambda value: value.update({"dispatch_claim_observed": True}),
            lambda value: value.update({"full_qualification_dispatched": True}),
            lambda value: value.update({"qualification_credit": True}),
        ):
            changed = copy.deepcopy(observation)
            mutation(changed)
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError,
                        "phase7-window-renewed-predecessor-invalid"):
                    BATCH._phase7_window_validate_renewed_predecessor(ROOT, changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
