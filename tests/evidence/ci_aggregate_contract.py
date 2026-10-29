#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Required CI aggregate contract with named state and identity controls."""
import importlib.util
import hashlib
import json
import os
import re
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
AGGREGATE = ROOT / "scripts/ci/aggregate.py"
ATTESTATION_INPUTS = ROOT / "scripts/ci/verify_attestation_inputs.py"
LANES = ("safety", "gameplay", "desktop", "package", "performance", "product-smoke", "phase7-fast")
SOURCE_SHA = "1" * 40
HEAD_SHA = "2" * 40
BASE_SHA = "3" * 40


def load_aggregate(test):
    if not AGGREGATE.is_file():
        test.fail("aggregate-validator-missing")
    spec = importlib.util.spec_from_file_location("gw_ci_aggregate", AGGREGATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def passing_needs(attestation_result="skipped"):
    needs = {name: {"result": "success", "outputs": {
        "source_sha": SOURCE_SHA, "head_sha": HEAD_SHA, "base_sha": BASE_SHA}}
        for name in LANES}
    needs["v02-release-qualification"] = {"result":"skipped", "outputs": {
        "source_sha":SOURCE_SHA,"head_sha":HEAD_SHA,"base_sha":BASE_SHA,
        "run_id":"123","run_attempt":"2","event_name":"pull_request"}}
    needs["attestation"] = {"result": attestation_result, "outputs": {
        "source_sha": SOURCE_SHA, "head_sha": SOURCE_SHA, "base_sha": BASE_SHA}}
    return needs


class AggregateContract(unittest.TestCase):
    def test_required_roster_rejects_missing_failed_cancelled_and_skipped_jobs(self):
        module = load_aggregate(self)
        self.assertEqual(module.REQUIRED_LANES, LANES, "required-roster-code-mismatch")
        needs = passing_needs()
        self.assertEqual(module.validate_lanes(needs, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA), [])

        for lane, result in (("safety", "missing"), ("gameplay", "failure"),
                             ("desktop", "cancelled"), ("package", "skipped"),
                             ("performance", "neutral")):
            with self.subTest(lane=lane, result=result):
                mutated = {key: dict(value) for key, value in needs.items()}
                if result == "missing":
                    del mutated[lane]
                else:
                    mutated[lane]["result"] = result
                reasons = module.validate_lanes(mutated, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA)
                self.assertIn(f"required-lane-{result}:{lane}", reasons)

        self.assertIn("unexpected-lane:optional-looking-pass",
                      module.validate_lanes({**needs, "optional-looking-pass": needs["safety"]},
                                            "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA))
        self.assertIn("unsupported-event", module.validate_lanes(
            needs, "pull_request_target", SOURCE_SHA, HEAD_SHA, BASE_SHA))
        self.assertIn("expected-source-sha-invalid", module.validate_lanes(
            needs, "pull_request", "integration-123", HEAD_SHA, BASE_SHA))

    def test_attestation_is_typed_skip_for_pr_and_fresh_success_for_trusted_main_push(self):
        module = load_aggregate(self)
        needs = passing_needs()
        self.assertEqual(module.validate_lanes(needs, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA,
                                               "refs/pull/7/merge"), [])
        needs["attestation"]["result"] = "success"
        self.assertIn("attestation-job-must-skip-untrusted:success",
                      module.validate_lanes(needs, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA,
                                            "refs/pull/7/merge"))
        trusted = passing_needs("success")
        for lane in LANES:
            trusted[lane]["outputs"]["head_sha"] = SOURCE_SHA
        trusted["attestation"]["outputs"] = {"source_sha": SOURCE_SHA, "head_sha": SOURCE_SHA,
                                               "base_sha": BASE_SHA}
        self.assertEqual(module.validate_lanes(trusted, "push", SOURCE_SHA, SOURCE_SHA, BASE_SHA,
                                               "refs/heads/main"), [])
        for changed in ("failure", "skipped"):
            bad = dict(trusted)
            bad["attestation"] = {**trusted["attestation"], "result": changed}
            self.assertIn(f"attestation-job-{changed}:trusted-main-push",
                          module.validate_lanes(bad, "push", SOURCE_SHA, SOURCE_SHA, BASE_SHA,
                                                "refs/heads/main"))
        stale = dict(trusted)
        stale["attestation"] = {"result": "success", "outputs": {
            "source_sha": "f" * 40, "head_sha": SOURCE_SHA, "base_sha": BASE_SHA}}
        self.assertIn("attestation-stale-source", module.validate_lanes(
            stale, "push", SOURCE_SHA, SOURCE_SHA, BASE_SHA, "refs/heads/main"))
        skipped_package = dict(trusted)
        skipped_package["package"] = {**trusted["package"], "result": "skipped"}
        self.assertIn("required-lane-skipped:package", module.validate_lanes(
            skipped_package, "push", SOURCE_SHA, SOURCE_SHA, BASE_SHA, "refs/heads/main"))

        dispatched = passing_needs("success")
        for lane in LANES:
            dispatched[lane]["outputs"].update(head_sha=SOURCE_SHA,
                run_id="123", run_attempt="2", event_name="workflow_dispatch")
        dispatched["v02-release-qualification"]["result"] = "success"
        dispatched["v02-release-qualification"]["outputs"].update(
            head_sha=SOURCE_SHA, event_name="workflow_dispatch")
        dispatched["attestation"]["outputs"] = {"source_sha": SOURCE_SHA,
            "head_sha": SOURCE_SHA, "base_sha": BASE_SHA}
        self.assertEqual(module.validate_lanes(dispatched, "workflow_dispatch", SOURCE_SHA,
            SOURCE_SHA, BASE_SHA, "refs/heads/main", "123", "2"), [])

    def test_aggregate_cli_requires_attestation_only_for_trusted_main_push(self):
        module = load_aggregate(self)
        values = {"NEEDS_JSON": json.dumps(passing_needs()), "EVENT_NAME": "pull_request",
                  "EVENT_REF": "refs/pull/7/merge", "EXPECTED_SOURCE_SHA": SOURCE_SHA,
                  "EXPECTED_HEAD_SHA": HEAD_SHA, "EXPECTED_BASE_SHA": BASE_SHA}
        with mock.patch.dict(os.environ, values):
            self.assertEqual(module.main(), 0)
        trusted = passing_needs("success")
        for lane in LANES:
            trusted[lane]["outputs"]["head_sha"] = SOURCE_SHA
        values.update(NEEDS_JSON=json.dumps(trusted), EVENT_NAME="push", EVENT_REF="refs/heads/main",
                      EXPECTED_HEAD_SHA=SOURCE_SHA)
        with mock.patch.dict(os.environ, values):
            self.assertEqual(module.main(), 0)
        trusted["attestation"]["result"] = "skipped"
        values["NEEDS_JSON"] = json.dumps(trusted)
        with mock.patch.dict(os.environ, values):
            self.assertEqual(module.main(), 1)

    def test_required_lanes_reject_stale_source_head_and_base_identity(self):
        module = load_aggregate(self)
        for field, expected, reason in (("source_sha", "4" * 40, "stale-source"),
                                        ("head_sha", "5" * 40, "stale-head"),
                                        ("base_sha", "6" * 40, "stale-base")):
            with self.subTest(field=field):
                needs = passing_needs()
                needs["desktop"]["outputs"][field] = expected
                reasons = module.validate_lanes(needs, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA)
                self.assertIn(f"{reason}:desktop", reasons)

    def test_new_required_lanes_reject_wrong_event_run_and_attempt(self):
        module = load_aggregate(self)
        needs = passing_needs()
        for lane in ("product-smoke", "phase7-fast"):
            needs[lane]["outputs"].update(run_id="123", run_attempt="2", event_name="pull_request")
        self.assertEqual(module.validate_lanes(needs, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA,
                                               "refs/pull/7/merge", "123", "2"), [])
        for field, value in (("run_id", "124"), ("run_attempt", "1"), ("event_name", "push")):
            changed = json.loads(json.dumps(needs))
            changed["product-smoke"]["outputs"][field] = value
            self.assertIn(f"lane-event-identity-mismatch:product-smoke:{field}", module.validate_lanes(
                changed, "pull_request", SOURCE_SHA, HEAD_SHA, BASE_SHA,
                "refs/pull/7/merge", "123", "2"))

    def test_workflow_runs_all_required_lanes_and_always_aggregates_the_current_event(self):
        text = WORKFLOW.read_text()
        for lane in LANES:
            self.assertRegex(text, rf"(?m)^  {lane}:\s*$", f"required-lane-job-missing:{lane}")
        self.assertRegex(text, r"(?ms)^  required-aggregate:\n(?:(?!^  [a-z0-9_-]+:\n).)*?if: always\(\)",
                         "aggregate-must-run-after-failures")
        self.assertIn("needs: [safety, gameplay, desktop, package, performance, product-smoke, phase7-fast, v02-release-qualification, attestation]", text,
                      "aggregate-required-roster-mismatch")
        for identity in ("source_sha", "head_sha", "base_sha"):
            self.assertGreaterEqual(text.count(identity), len(LANES),
                                    f"per-lane-{identity}-binding-missing")
        self.assertIn("EXPECTED_SOURCE_SHA", text, "aggregate-source-identity-missing")
        self.assertIn("EXPECTED_HEAD_SHA", text, "aggregate-head-identity-missing")
        self.assertIn("EXPECTED_BASE_SHA", text, "aggregate-base-identity-missing")
        self.assertGreaterEqual(text.count('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'),
                                len(LANES) + 1, "event-integration-source-checkout-missing")
        self.assertRegex(text, r"(?m)^  merge_group:\s*$", "merge-group-trigger-missing")
        self.assertRegex(text, r"(?m)^  pull_request:\s*$", "pull-request-trigger-missing")

    def test_untrusted_workflow_has_read_only_token_and_pinned_actions(self):
        text = WORKFLOW.read_text()
        self.assertNotIn("pull_request_target", text, "privileged-fork-event-present")
        self.assertNotRegex(text, r"secrets\.[A-Za-z_]+", "fork-visible-secret-reference")
        self.assertIn("persist-credentials: false", text, "checkout-credentials-persist")
        for action in re.findall(r"uses:\s*([^\s]+)", text):
            if action.startswith("./"):
                self.assertTrue((ROOT / action[2:] / "action.yml").is_file(), f"local-action-missing:{action}")
                continue
            owner, separator, revision = action.partition("@")
            self.assertTrue(separator and re.fullmatch(r"[0-9a-f]{40}", revision),
                            f"action-not-immutable:{action}")
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n  actions: read\s*$",
                         "workflow-token-not-minimal")
        self.assertIn("macos-26", text, "locked-arm64-macos-runner-not-selected")

    def test_attestation_permissions_are_isolated_to_trusted_main_job(self):
        text = WORKFLOW.read_text()
        package = re.search(r"(?ms)^  package:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)", text)
        attest = re.search(r"(?ms)^  attestation:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)", text)
        aggregate = re.search(r"(?ms)^  required-aggregate:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)", text)
        self.assertIsNotNone(package, "package-job-missing")
        self.assertIsNotNone(attest, "attestation-job-missing")
        self.assertIsNotNone(aggregate, "required-aggregate-missing")
        package_body, attest_body, aggregate_body = package["body"], attest["body"], aggregate["body"]
        self.assertRegex(package_body, r"(?ms)^    permissions:\n      contents: read\n")
        for permission in ("attestations: write", "artifact-metadata: write", "id-token: write"):
            self.assertNotIn(permission, package_body, f"package-job-retains-{permission}")
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", attest_body,
                      "attestation-not-main-push-bound")
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", attest_body,
                      "attestation-not-main-dispatch-bound")
        self.assertIn("needs: [package, v02-package, v02-release-qualification]", attest_body,
                      "attestation-does-not-depend-on-qualified-v02-producer")
        self.assertIn("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093", attest_body,
                      "attestation-does-not-download-producer-artifact")
        self.assertIn("verify_attestation_inputs.py verify", attest_body,
                      "attestation-input-identity-not-verified")
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", attest_body,
                      "attestation-action-missing-from-trusted-job")
        self.assertIn("needs: [safety, gameplay, desktop, package, performance, product-smoke, phase7-fast, v02-release-qualification, attestation]", aggregate_body,
                      "required-aggregate-does-not-wait-for-attestation")
        self.assertIn("EVENT_REF", aggregate_body, "aggregate-does-not-type-attestation-policy-by-ref")

    def test_dispatch_jobs_share_validated_journal_clock_and_exact_nonce(self):
        text = WORKFLOW.read_text()
        self.assertIn("qualification_started_at:", text)
        self.assertIn("qualification_base_sha:", text)
        self.assertIn("qualification_nonce:", text)
        self.assertIn("Plan10 qualification {0}", text)
        self.assertGreaterEqual(text.count("uses: ./.github/actions/qualification-clock"), 15)
        self.assertIn('GENEWHIP_QUALIFICATION_STARTED_AT: ${{ inputs.qualification_started_at }}', text)
        self.assertIn('GENEWHIP_QUALIFICATION_NONCE: ${{ inputs.qualification_nonce }}', text)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", text)
        self.assertIn("if: github.event_name == 'schedule'", text)

    def test_attestation_input_cli_accepts_exact_data_and_rejects_stale_run_or_bytes(self):
        spec = importlib.util.spec_from_file_location("attestation_inputs", ATTESTATION_INPUTS)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = SOURCE_SHA
        expected = module.identity("example/genewhip", source, "12345", "2", "push",
                                   "refs/heads/main", "Required preview checks")
        environment = {"GITHUB_REPOSITORY": expected["repository"], "GITHUB_SHA": source,
                       "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2",
                       "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
                       "GITHUB_WORKFLOW": "Required preview checks"}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, environment):
            directory = Path(temporary)
            identity_directory = directory / "identity"
            assets = {}
            suffix = "-" + source[:12] + ".tar.gz"
            for target in module.PACKAGE_TARGETS:
                name = f"genewhip-0.1.0-{target}{suffix}"
                data = ("already-built:" + target).encode()
                (directory / name).write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                (directory / (name + ".sha256")).write_text(f"{digest}  {name}\n")
                (directory / (name + ".qualification.json")).write_text(json.dumps({
                    "schema": "genewhip-local-package-qualification", "outcome": "pass",
                    "source_revision": source, "archive": name, "archive_sha256": digest}))
                for ending in ("", ".sha256", ".qualification.json"):
                    filename = name + ending
                    content = (directory / filename).read_bytes()
                    assets[filename] = {"size": len(content),
                                        "sha256": hashlib.sha256(content).hexdigest()}
            (directory / "inventory.json").write_text(json.dumps({
                "schema": "genewhip.release-inventory.v1", "version": "0.1.0",
                "source_revision": source, "assets": assets}))
            self.assertEqual(module.main(["write-identity", "--directory", str(identity_directory)]), 0)
            verify_args = ["verify", "--directory", str(directory), "--identity-directory",
                           str(identity_directory)]
            self.assertEqual(module.main(verify_args), 0)
            dispatch_expected = module.identity("example/genewhip", source, "12345", "2",
                "workflow_dispatch", "refs/heads/main", "Required preview checks",
                qualification_started_at="2026-10-29T00:00:00Z",
                qualification_nonce="a" * 32, base_sha=BASE_SHA)
            identity_path = identity_directory / "_ci-identity.json"
            identity_path.write_text(json.dumps(dispatch_expected))
            self.assertEqual(module.validate_inputs(directory, dispatch_expected, identity_directory), [])
            with self.assertRaisesRegex(ValueError, "qualification-identity-invalid"):
                module.identity("example/genewhip", source, "12345", "2", "workflow_dispatch",
                    "refs/heads/main", "Required preview checks", qualification_nonce="a" * 32,
                    base_sha=BASE_SHA)
            os.environ["GITHUB_EVENT_NAME"] = "pull_request"
            self.assertEqual(module.main(["write-identity", "--directory", str(identity_directory)]), 0)
            self.assertEqual(module.main(verify_args), 1)
            os.environ["GITHUB_EVENT_NAME"] = "push"
            self.assertEqual(module.main(["write-identity", "--directory", str(identity_directory)]), 0)
            identity_path = identity_directory / "_ci-identity.json"
            identity_value = json.loads(identity_path.read_text())
            identity_value["run_attempt"] = "1"
            identity_path.write_text(json.dumps(identity_value))
            self.assertEqual(module.main(verify_args), 1)
            identity_path.write_text(json.dumps(expected))
            archive = directory / next(iter(assets))
            archive.write_bytes(b"tampered")
            self.assertEqual(module.main(verify_args), 1)

    def test_package_clean_source_gate_still_rejects_public_changes(self):
        package = (ROOT / "scripts/package_desktop.py").read_text()
        self.assertIn('raise ValueError("source-dirty: commit public inputs before packaging")', package,
                      "package-source-dirty-check-removed")
        self.assertIn('not p[3:].startswith(".planning/")', package,
                      "package-source-dirty-check-no-longer-excludes-only-planning-notes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
