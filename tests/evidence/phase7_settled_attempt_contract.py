#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure contracts for reusable, no-credit Phase 7 full-failure predecessors."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_batch_module():
    spec = importlib.util.spec_from_file_location(
        "gw_phase7_settled_attempt_contract_batch",
        ROOT / "scripts/release/v02_batch.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("settled-attempt-batch-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BATCH = load_batch_module()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(root: Path, relative: Path, value: object) -> tuple[dict[str, str], bytes]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json_bytes(value)
    path.write_bytes(raw)
    return {"path": relative.as_posix(), "sha256": digest(raw)}, raw


class FakeWindowModule:
    def __init__(self, current: dict, prior: dict):
        self.current = current
        self.prior = prior

    def load_authorized_window(self, _root, *, authority_path, **_kwargs):
        if Path(authority_path) == Path(self.current["authority_path"]):
            return self.current
        if Path(authority_path) == Path(self.prior["authority_path"]):
            return self.prior
        raise ValueError("fixture-window-not-registered")

    @staticmethod
    def check_window(_window, **_kwargs):
        return {"remaining_seconds": 3600}


class SettledAttemptFixture:
    """Small synthetic run with the same record joins as a full failed attempt."""

    def __init__(self, defect: str | None = None):
        self.temporary = tempfile.TemporaryDirectory(prefix="gw-settled-attempt-")
        self.root = Path(self.temporary.name).resolve()
        self.attempt = Path("build/v02/prior-batch/attempts/attempt-0002")
        self.attempt_dir = self.root / self.attempt
        self.attempt_dir.mkdir(parents=True)
        self.started_at = "2026-10-30T00:00:00+00:00"
        self.close_at = "2026-10-31T01:00:00+00:00"
        self.current_started_at = "2026-11-01T00:00:00+00:00"
        self.nonce = "a" * 32
        self.source_head = "1" * 40
        self.public_head = "2" * 40
        self.public_base = "3" * 40
        self.public_tree = "4" * 40
        self.source_sha = "5" * 40
        self.source_pins = {"README.md": "6" * 64}
        self.prior_auth = Path("build/v02/prior-batch/authorization.json")
        self.prior_scope = BATCH._phase7_window_module().AUTHORIZED_SCOPE_PATH
        self.prior_scope_raw = (ROOT / self.prior_scope).read_bytes()
        self.prior_scope_sha = digest(self.prior_scope_raw)
        self.scope_value = json.loads(self.prior_scope_raw)
        self.current_auth = Path("build/v02/standing/batches/batch-0001/authorization.json")
        self.current_auth_sha = "9" * 64
        self.current_scope = self.prior_scope
        self.current_scope_sha = self.prior_scope_sha
        self.current_namespace = Path("build/v02/standing/batches/batch-0001/attempts")
        self.bundle_path = Path("build/v02/standing/operator/settled-attempt2-predecessor.json")

        prior_auth_ref, _ = write_json(self.root, self.prior_auth,
            {"schema": "fixture-authorization"})
        prior_scope_path = self.root / self.prior_scope
        prior_scope_path.parent.mkdir(parents=True, exist_ok=True)
        prior_scope_path.write_bytes(self.prior_scope_raw)
        self.prior_auth_sha = prior_auth_ref["sha256"]
        write_json(self.root, self.current_auth, {"schema": "fixture-current-authorization"})

        self.prior = self._window(self.prior_auth, self.prior_auth_sha,
            self.prior_scope, self.prior_scope_sha,
            Path("build/v02/prior-batch/attempts"), self.started_at)
        self.current = self._window(self.current_auth, self.current_auth_sha,
            self.current_scope, self.current_scope_sha,
            self.current_namespace, self.current_started_at)
        self.window_module = FakeWindowModule(self.current, self.prior)

        self._write_admissions()
        self._write_claim_failure_journal(defect)
        self._write_controller_and_provider(defect)
        self._write_external_receipts(defect)
        self._write_close_observation(defect)
        bundle = BATCH.phase7_window_build_settled_full_failure_bundle(
            self.root, self.attempt)
        if defect == "bundle-schema":
            bundle["schema"] = "genewhip.phase7-unsettled.v1"
        self.bundle_ref, _ = write_json(self.root, self.bundle_path, bundle)
        self.current["authority"]["predecessor"] = self.bundle_ref

    def _window(self, authority_path, authority_sha, scope_path, scope_sha,
            namespace, started_at):
        return {"profile_id": "authorized-run", "authority_path": authority_path.as_posix(),
            "authority_sha256": authority_sha, "scope_path": scope_path.as_posix(),
            "scope_sha256": scope_sha, "scope": copy.deepcopy(self.scope_value),
            "attempt_namespace": namespace.as_posix(),
            "started_at": started_at, "runtime_cutoff": "2026-10-30T01:00:00+00:00",
            "global_cutoff": "2026-10-30T02:00:00+00:00", "source_ancestor": "b" * 40,
            "authority": {"schema": "genewhip.phase7-execution-window.v1",
                "predecessor": None}}

    def _write_admissions(self):
        self.source_payload = BATCH.phase7_window_source_admission_payload(
            attempt_root=self.attempt.as_posix(), attempt_index=2,
            predecessor={"attempt_index": 1}, disposition="routine-source-repair",
            source_head=self.source_head, source_pins=self.source_pins, window=self.prior)
        self.source_payload_sha = digest(BATCH._canonical(self.source_payload))
        self.reviews = {key: {"fixture": key} for key in BATCH.SOURCE_ROLES}
        common = {"schema": BATCH.SCHEMA, "authorization_path": self.prior_auth.as_posix(),
            "authorization_sha256": self.prior_auth_sha,
            "scope_path": self.prior_scope.as_posix(), "scope_sha256": self.prior_scope_sha,
            "batch_root": self.attempt.as_posix(), "attempt_index": 2,
            "attempt_root": self.attempt.as_posix(), "predecessor": {"attempt_index": 1},
            "disposition": "routine-source-repair", "started_at": self.started_at,
            "source_head": self.source_head, "source_pins": self.source_pins,
            "source_payload_sha256": self.source_payload_sha,
            "source_reviews": self.reviews}
        self.source_ref, _ = write_json(self.root, self.attempt / "source-admission.json",
            {**common, "status": "source-preparation"})

        preparation_path = self.attempt / "candidate/preparation.json"
        policy_path = self.attempt / "candidate/repository-preflight-test/policy.json"
        publication_path = self.attempt / "candidate/publication-copy"
        (self.root / publication_path).mkdir(parents=True)
        preparation = {"status": "prepared", "source_identity": {"private_git_head": self.source_head},
            "publication_copy": publication_path.as_posix(),
            "repository_preflight": policy_path.as_posix(),
            "source_manifest_sha256": "c" * 64,
            "public_identity": {"head_sha": self.public_head,
                "base_sha": self.public_base, "tree_sha": self.public_tree},
            "privacy": {"status": "pass"}, "blockers": []}
        policy = {"repository_observations": {"ready": True},
            "privacy_scan": {"publication_copy": {"status": "pass", "findings": []}}}
        prep_ref, prep_raw = write_json(self.root, preparation_path, preparation)
        policy_ref, policy_raw = write_json(self.root, policy_path, policy)
        candidate = {"preparation_path": prep_ref["path"],
            "preparation_sha256": prep_ref["sha256"],
            "publication_path": publication_path.as_posix(),
            "repository_policy_path": policy_ref["path"],
            "repository_policy_sha256": policy_ref["sha256"],
            "public_head": self.public_head, "public_base": self.public_base,
            "public_tree": self.public_tree, "source_manifest_sha256": "c" * 64,
            "candidate_reviews": {key: {"fixture": key} for key in BATCH.CANDIDATE_ROLES}}
        candidate_payload = BATCH.phase7_window_candidate_review_payload(
            self.source_payload, candidate, window=self.prior)
        candidate["candidate_payload_sha256"] = digest(BATCH._canonical(candidate_payload))
        self.public_ref, self.public_raw = write_json(self.root,
            self.attempt / "public-admission.json",
            {**common, "status": "public-effects", "candidate": candidate})

    def _write_claim_failure_journal(self, defect):
        nonce = "d" * 32 if defect == "claim-nonce" else self.nonce
        self.claim = {"schema": "genewhip.phase7-execution-window-dispatch-claim.v1",
            "authorization_sha256": self.prior_auth_sha, "scope_sha256": self.prior_scope_sha,
            "attempt_index": 2, "attempt_root": self.attempt.as_posix(),
            "admission_sha256": digest(self.public_raw),
            "source_payload_sha256": self.source_payload_sha,
            "nonce": nonce, "started_at": self.started_at}
        self.claim_ref, _ = write_json(self.root, self.attempt / "dispatch-claim.json", self.claim)
        failure = {"schema": "genewhip.phase7-execution-window-attempt-failure.v1",
            "authorization_sha256": self.prior_auth_sha, "scope_sha256": self.prior_scope_sha,
            "attempt_index": 2, "attempt_root": self.attempt.as_posix(),
            "stage": "preview-ci" if defect == "failure-stage" else "qualification",
            "reason": "fresh-batch-qualification-failed", "observed_at": self.close_at}
        write_json(self.root, self.attempt / "failure.json", failure)
        self.journal = {"schema": "genewhip.v02-delivery-journal.v1",
            "repository": "szTheory/genewhip", "started_at": self.started_at,
            "qualification_started_at": self.started_at,
            "qualification_dispatch_nonce": self.nonce,
            "qualification_dispatch_requested": True,
            "qualification_dispatch_submitted": True, "push_performed": True,
            "candidate_sha": self.public_head, "source_head": self.public_head,
            "public_source_sha": self.source_sha, "public_base_sha": self.public_base,
            "tree_sha": self.public_tree, "merge_strategy": "squash",
            "merge_parents": [self.public_base], "branch": "v0.2-source-" + self.public_head[:12]}
        write_json(self.root, self.attempt / "hosted-delivery-journal.json", self.journal)

    def _write_controller_and_provider(self, defect):
        window_receipt = {"authority_path": self.prior_auth.as_posix(),
            "authority_sha256": self.prior_auth_sha,
            "scope_path": self.prior_scope.as_posix(),
            "scope_sha256": self.prior_scope_sha, "started_at": self.started_at,
            "runtime_cutoff": "2026-10-30T01:00:00+00:00",
            "global_cutoff": "2026-10-30T02:00:00+00:00"}
        self.controller_refs = {}
        for kind, mode, controller_pid, process_pid, started_at, controller_at, finished_at, code in (
                ("prepare", "stage-public", 11, 101, "2026-10-30T00:10:00+00:00",
                    "2026-10-30T00:10:01+00:00", "2026-10-30T00:20:00+00:00", 0),
                ("hosted", "hosted", 22, 102, "2026-10-30T00:25:00+00:00",
                    "2026-10-30T00:25:01+00:00", "2026-10-31T00:45:00+00:00", 1)):
            command = ["python3", "-B", "-I", "/tmp/genewhip/scripts/release/v02_qualification.py",
                "--mode", mode]
            if kind == "prepare":
                command.append("--prepare-only")
            else:
                command.extend(["--preflight", (self.attempt / "candidate/preparation.json").as_posix()])
            command.extend(["--scope", self.prior_scope.as_posix(), "--publication-copy",
                (self.attempt / "candidate/publication-copy").as_posix(), "--journal",
                (self.attempt / "hosted-delivery-journal.json").as_posix(), "--out",
                (self.attempt / ("candidate/preparation.json" if kind == "prepare"
                    else "hosted-qualification.json")).as_posix(), "--batch-authorization",
                self.prior_auth.as_posix(), "--batch-authorization-sha256", self.prior_auth_sha,
                "--batch-admission", (self.attempt / ("source-admission.json" if kind == "prepare"
                    else "public-admission.json")).as_posix(), "--batch-admission-sha256",
                (self.source_ref if kind == "prepare" else self.public_ref)["sha256"]])
            if defect == "controller-argv" and kind == "hosted":
                command[command.index("--mode") + 1] = "unexpected"
            started = {"pid": process_pid, "started_at": started_at,
                "argv_sha256": digest(json_bytes(command)), "source_head": self.source_head,
                "deadline_owner": "fixture authorized process bound", "window": window_receipt}
            exited = {"pid": process_pid, "controller_pid": controller_pid,
                "started_at": started_at, "finished_at": finished_at,
                "argv_sha256": digest(json_bytes(command)), "source_head": self.source_head,
                "deadline_owner": started["deadline_owner"], "window": window_receipt,
                "exit_code": code, "error": None, "cleanup_established_by_recorder": False}
            controller = {"pid": controller_pid, "started_at": controller_at}
            self.controller_refs[kind] = {
                "argv": write_json(self.root, self.attempt / f"operator/{kind}-argv.json", command)[0],
                "started": write_json(self.root, self.attempt / f"operator/{kind}-argv-started.json", started)[0],
                "exit": write_json(self.root, self.attempt / f"operator/{kind}-argv-exit.json", exited)[0],
                "controller": write_json(self.root, self.attempt / f"operator/{kind}-argv-controller.json", controller)[0],
                "command": command, "started_doc": started, "exit_doc": exited}
        self.controller_exit = self.controller_refs["hosted"]["exit_doc"]
        self.controller_ref = self.controller_refs["hosted"]["exit"]

        names = sorted(BATCH.NATIVE_HOST_RUNTIME_OUTCOMES)
        outcomes = dict(BATCH.NATIVE_HOST_RUNTIME_OUTCOMES)
        if defect == "provider-incomplete":
            outcomes.pop(names[-1])
        if defect == "provider-no-failure":
            outcomes = {name: "success" for name in names}
        if defect == "provider-wrong-outcome":
            name = names[0]
            outcomes[name] = "failure" if outcomes[name] != "failure" else "success"
        jobs = [{"id": index + 1, "run_id": 12345, "run_attempt": 1,
            "head_sha": self.source_sha, "head_branch": "main", "status": "completed",
            "name": name, "conclusion": outcomes[name]}
            for index, name in enumerate(sorted(outcomes))]
        run = {"id": 12345, "run_attempt": 1, "status": "completed", "conclusion": "failure",
            "event": "workflow_dispatch", "head_branch": "main", "head_sha": self.source_sha,
            "created_at": "2026-10-30T00:46:00Z", "run_started_at": "2026-10-30T00:46:01Z",
            "updated_at": "2026-10-31T00:50:00Z",
            "head_commit": {"id": self.source_sha, "tree_id": self.public_tree},
            "path": ".github/workflows/ci.yml@main",
            "repository": {"full_name": "szTheory/genewhip"},
            "display_title": "Plan10 qualification " + self.nonce}
        if defect == "run-before-claim":
            run["created_at"] = "2026-10-29T23:59:59Z"
        if defect == "run-updated-after-terminal":
            run["updated_at"] = "2026-10-31T00:51:00Z"
        run_path = self.attempt / "operator/qualification-settlement/initial-run.json"
        jobs_path = self.attempt / "operator/qualification-settlement/terminal-jobs.json"
        run_ref, run_raw = write_json(self.root, run_path, run)
        jobs_ref, jobs_raw = write_json(self.root, jobs_path,
            {"jobs": jobs, "total_count": len(jobs)})
        self.run = run
        self.run_raw = run_raw
        self.jobs_doc = {"jobs": jobs, "total_count": len(jobs)}
        self.jobs_raw = jobs_raw
        self.terminal = {"schema": "genewhip.phase7-execution-window-full-terminal-observation.v1",
            "status": "completed", "conclusion": "failure", "claim_preserved": True,
            "cancel_issued_by_this_close": False, "not_retry_admission": True,
            "qualification_credit": defect == "qualification-credit",
            "source_sha": self.source_sha, "remote_jobs_terminal": True,
            "remote_job_count": len(jobs), "run_id": 12345, "run_attempt": 1,
            "observed_at": "2026-10-31T00:50:00+00:00",
            "jobs": {job["name"]: job["conclusion"] for job in jobs},
            "refs": {
                "initial-run.json": {"bytes": len(run_raw), **run_ref},
                "terminal-jobs.json": {"bytes": len(jobs_raw), **jobs_ref}}}
        if defect == "qualification-credit":
            self.terminal["qualification_credit"] = True
        self.terminal_ref, _ = write_json(self.root,
            self.attempt / "operator/qualification-settlement/terminal-observation.json",
            self.terminal)

    def _write_external_receipts(self, defect):
        external_dir = self.attempt / "coordinator-external-attempts"
        sidecar_dir = external_dir / "process-receipts"
        (self.root / sidecar_dir).mkdir(parents=True)
        run_endpoint = "repos/szTheory/genewhip/actions/runs/12345"
        jobs_endpoint = run_endpoint + "/attempts/1/jobs?per_page=100"
        rows = [
            (11, 101, ["git", "ls-files", "-z"], None),
            (22, 102, ["git", "remote", "get-url", "origin"], None),
            (33, 103, ["gh", "api", run_endpoint], (self.run, self.run_raw)),
            (33, 104, ["gh", "api", jobs_endpoint], (self.jobs_doc, self.jobs_raw)),
        ]
        if defect == "duplicate-terminal-query":
            rows.append((33, 105, ["gh", "api", run_endpoint], (self.run, self.run_raw)))
        self.receipt_refs, self.sidecar_refs = [], []
        for owner, child_pid, argv, response in rows:
            if defect == "command-not-allowed" and owner == 22:
                argv = ["git", "status", "--porcelain"]
            if defect == "controller-owner" and owner == 22:
                owner = 23
            process = {"pid": child_pid, "pgid": child_pid, "status": "completed",
                "return_code": 0, "process_group_cleanup": "confirmed",
                "bound_violation": False, "rss_bytes_observed": 0,
                "rss_bytes_peak": 1024 * 1024}
            receipt = {"schema": "genewhip.v02-coordinator-child-attempt.v1",
                "label": f"external-{owner}-{child_pid}", "returncode": 0,
                "launch_error": None, "process_group_cleanup": "confirmed",
                "argv": argv, "processes": [process]}
            if response is not None:
                response_value, response_raw = response
                if defect == "terminal-query-output" and response_value is self.run:
                    response_raw = json_bytes({"id": -1})
                receipt["streams"] = {"stdout": {"text": response_raw.decode(),
                    "truncated": False, "retained_bytes": len(response_raw),
                    "observed_bytes": len(response_raw), "sha256": digest(response_raw)}}
            receipt_ref, _ = write_json(self.root,
                external_dir / f"external-{owner}-{child_pid}.attempt.json", receipt)
            sidecar = {"processes": [copy.deepcopy(process)]}
            if defect == "sidecar-mismatch" and owner == 11:
                sidecar["processes"][0]["return_code"] = 8
            sidecar_ref, _ = write_json(self.root,
                sidecar_dir / (f"{child_pid:032x}.json"), sidecar)
            self.receipt_refs.append(receipt_ref)
            self.sidecar_refs.append(sidecar_ref)
        self.receipt_refs.sort(key=lambda item: item["path"])
        self.sidecar_refs.sort(key=lambda item: item["path"])
        self.receipt_ref, self.sidecar_ref = self.receipt_refs[0], self.sidecar_refs[0]

    def _write_close_observation(self, defect):
        external_receipts = self.receipt_refs
        external_sidecars = self.sidecar_refs
        if defect == "omitted-receipt":
            external_receipts = []
        if defect == "pin-count":
            pin_count = 0
        else:
            pin_count = len(self.source_pins)
        close = {"schema": "genewhip.phase7-execution-window-close-observation.v1",
            "attempt_index": 2, "observed_at": self.close_at,
            "source_head": self.source_head, "claim_preserved": self.claim_ref,
            "controller_exit": {"path": self.controller_ref["path"],
                "sha256": self.controller_ref["sha256"], "exit_code": 1,
                "leader_reaped": True, "recorder_does_not_establish_group_cleanup": True},
            "provider_terminal": self.terminal_ref,
            "external_receipt_count": len(external_receipts),
            "external_receipts": external_receipts,
            "sidecar_count": len(external_sidecars), "external_sidecars": external_sidecars,
            "bound_receipts": [], "not_retry_admission": True,
            "qualification_credit": False, "recorded_external_cleanup_confirmed": True,
            "source_pins_git_verified": pin_count,
            "source_pins_worktree_changed_after_exit": [],
            "unrelated_inputs_unchanged": 3, "v01_local_baseline_unchanged": True,
            "remote_inner_receipts": "unavailable; partial runtime reports were not uploaded"}
        runtime_path = self.attempt / "operator/full-runtime-job.log"
        runtime_ref, _ = write_json(self.root, runtime_path, {"fixture": "runtime output"})
        close["runtime_log"] = runtime_ref
        if defect == "runtime-log-hash":
            close["runtime_log"]["sha256"] = "0" * 64
        if defect == "unrelated-count":
            close["unrelated_inputs_unchanged"] = 0
        if defect == "release-credit":
            close["release_credit"] = True
        if defect == "remote-inner-unavailable":
            close["remote_inner_receipts"] = "unavailable; terminal provider roster is retained"
        self.close_ref, _ = write_json(self.root,
            self.attempt.parents[1] / "operator/attempt2-close-observation.json", close)

    def close(self):
        self.temporary.cleanup()


class SettledAttemptPredecessorContract(unittest.TestCase):
    def make_fixture(self, defect=None):
        fixture = SettledAttemptFixture(defect)
        self.addCleanup(fixture.close)
        return fixture

    def run_guarded(self, fixture, expected):
        with mock.patch.object(BATCH, "_phase7_window_module",
                return_value=fixture.window_module), \
             mock.patch.object(BATCH, "_check_review", return_value=None), \
             mock.patch.object(BATCH.subprocess, "run",
                side_effect=AssertionError("settled predecessor must not spawn a process")), \
             mock.patch.object(socket.socket, "connect",
                side_effect=AssertionError("settled predecessor must not connect to the network")):
            return BATCH._phase7_window_predecessor(fixture.root,
                {"predecessor": expected}, attempt_index=1, window=fixture.current)

    def expected_predecessor(self, fixture):
        return {"attempt_index": 2, "attempt_root": fixture.attempt.as_posix(),
            "terminal": fixture.bundle_ref, "status": "settled-full-qualification-failure",
            "qualification_accepted": False, "local_cleanup": "settled"}

    def assert_rejected(self, fixture):
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, self.expected_predecessor(fixture))

    def test_real_batch_dispatch_route_consumes_a_reopened_no_credit_predecessor(self):
        fixture = self.make_fixture()
        with mock.patch.object(BATCH, "_phase7_window_module",
                return_value=fixture.window_module), \
             mock.patch.object(BATCH, "_check_review", return_value=None), \
             mock.patch.object(BATCH.subprocess, "run",
                side_effect=AssertionError("settled predecessor must not spawn a process")), \
             mock.patch.object(socket.socket, "connect",
                side_effect=AssertionError("settled predecessor must not connect to the network")):
            expected = BATCH.phase7_window_settled_predecessor(
                fixture.root, fixture.current)
            self.assertEqual(expected, {
                "attempt_index": 2, "attempt_root": fixture.attempt.as_posix(),
                "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})
            self.assertEqual(BATCH._phase7_window_predecessor(fixture.root,
                {"predecessor": expected}, attempt_index=1, window=fixture.current), expected)

    def test_successor_attempt_uses_the_same_contract_for_the_prior_attempt_root(self):
        fixture = self.make_fixture()
        with mock.patch.object(BATCH, "_phase7_window_module",
                return_value=fixture.window_module), \
             mock.patch.object(BATCH, "_check_review", return_value=None), \
             mock.patch.object(BATCH.subprocess, "run",
                side_effect=AssertionError("settled predecessor must not spawn a process")), \
             mock.patch.object(socket.socket, "connect",
                side_effect=AssertionError("settled predecessor must not connect to the network")):
            expected = BATCH.phase7_window_settled_predecessor(
                fixture.root, fixture.current)
            fixture.current["attempt_namespace"] = fixture.attempt.parent.as_posix()
            self.assertEqual(BATCH._phase7_window_predecessor(fixture.root,
                {"predecessor": expected}, attempt_index=3, window=fixture.current), expected)

    def test_claim_nonce_must_join_delivery_journal(self):
        fixture = self.make_fixture("claim-nonce")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_only_a_full_qualification_failure_can_be_a_retry_predecessor(self):
        fixture = self.make_fixture("failure-stage")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_missing_external_receipt_is_not_hidden_by_a_summary_count(self):
        fixture = self.make_fixture("omitted-receipt")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_source_pin_verification_count_must_cover_the_admitted_pin_roster(self):
        fixture = self.make_fixture("pin-count")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_provider_roster_must_be_complete_and_failure_bearing(self):
        fixture = self.make_fixture("provider-incomplete")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_provider_success_cannot_be_promoted_to_failed_predecessor_with_credit(self):
        fixture = self.make_fixture("provider-no-failure")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_external_sidecars_must_match_every_owned_process_row(self):
        fixture = self.make_fixture("sidecar-mismatch")
        with self.assertRaisesRegex(ValueError, "settled-full-failure"):
            self.run_guarded(fixture, {"attempt_index": 2,
                "attempt_root": fixture.attempt.as_posix(), "terminal": fixture.bundle_ref,
                "status": "settled-full-qualification-failure",
                "qualification_accepted": False, "local_cleanup": "settled"})

    def test_external_commands_must_be_in_the_recorded_q_command_allowlist(self):
        self.assert_rejected(self.make_fixture("command-not-allowed"))

    def test_external_owner_pid_must_join_a_recorded_controller_or_terminal_query(self):
        self.assert_rejected(self.make_fixture("controller-owner"))

    def test_terminal_query_stdout_must_match_the_pinned_provider_document(self):
        self.assert_rejected(self.make_fixture("terminal-query-output"))

    def test_terminal_queries_must_be_exactly_one_per_provider_record(self):
        self.assert_rejected(self.make_fixture("duplicate-terminal-query"))

    def test_run_must_be_created_after_the_spent_claim(self):
        self.assert_rejected(self.make_fixture("run-before-claim"))

    def test_terminal_observation_must_follow_the_final_provider_update(self):
        self.assert_rejected(self.make_fixture("run-updated-after-terminal"))

    def test_job_conclusions_must_match_the_exact_qualification_matrix(self):
        self.assert_rejected(self.make_fixture("provider-wrong-outcome"))

    def test_runtime_log_hash_must_match_close_reference(self):
        self.assert_rejected(self.make_fixture("runtime-log-hash"))

    def test_positive_unrelated_count_and_exact_remote_inner_note_are_required(self):
        self.assert_rejected(self.make_fixture("unrelated-count"))
        self.assert_rejected(self.make_fixture("remote-inner-unavailable"))

    def test_release_credit_cannot_be_set_true(self):
        self.assert_rejected(self.make_fixture("release-credit"))

    def test_controller_argv_must_be_attributed_to_the_recorded_attempt(self):
        self.assert_rejected(self.make_fixture("controller-argv"))

    def test_unsupported_bundle_schema_does_not_enter_new_reader(self):
        fixture = self.make_fixture("bundle-schema")
        expected = {"attempt_index": 2, "attempt_root": fixture.attempt.as_posix(),
            "terminal": fixture.bundle_ref, "status": "settled-full-qualification-failure",
            "qualification_accepted": False, "local_cleanup": "settled"}
        with mock.patch.object(BATCH, "_phase7_window_module",
                return_value=fixture.window_module), \
             mock.patch.object(BATCH, "phase7_window_settled_predecessor",
                side_effect=AssertionError("unsupported schema entered the new reader")), \
             mock.patch.object(BATCH, "phase7_window_authorized_initial_predecessor",
                return_value=expected) as legacy:
            self.assertEqual(BATCH._phase7_window_predecessor(fixture.root,
                {"predecessor": expected}, attempt_index=1, window=fixture.current), expected)
            legacy.assert_called_once_with(fixture.root, fixture.current)


if __name__ == "__main__":
    unittest.main(verbosity=2)
