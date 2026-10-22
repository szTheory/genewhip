#!/usr/bin/env python3
"""Contract checks for source-bound hosted delivery and release adoption."""
import json
import hashlib
import pathlib
import sys
import tempfile
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.release import qualify_delivery as delivery


class DeliveryContract(unittest.TestCase):
    def test_github_api_404_is_distinguished_from_transport_failure(self):
        result = delivery.subprocess.CompletedProcess([], 1, "", "gh: Branch not protected (HTTP 404)\n")
        with unittest.mock.patch.object(delivery.subprocess, "run", return_value=result):
            with self.assertRaises(delivery.repository_preflight.ServiceError) as caught:
                delivery._gh_api_json("repos/szTheory/genewhip/branches/main/protection")
        self.assertEqual(caught.exception.status, 404)

    def test_preflight_requires_selected_public_destination_and_clean_copy(self):
        packet = {
            "schema": "genewhip.publication-readiness-packet.v1",
            "repository": "szTheory/genewhip",
            "destination": {"owner_repository": "szTheory/genewhip", "visibility": "public"},
            "history_disposition": "sanitized-snapshots-preserve-local-history",
            "privacy_scan": {"publication_copy": {"status": "pass", "findings": []}},
            "repository_observations": {"ready": True},
        }
        self.assertEqual(delivery.validate_preflight(packet, "szTheory/genewhip"), [])
        packet["privacy_scan"]["publication_copy"]["findings"] = [
            {"path": "docs/example.md", "reasons": ["personal-path"]}]
        self.assertEqual(delivery.validate_preflight(packet, "szTheory/genewhip"),
                         ["publication-privacy-findings"])

    def test_pull_request_head_and_base_are_rechecked_without_review_invention(self):
        current = {"state": "OPEN", "isDraft": False, "baseRefName": "main",
                   "baseRefOid": "b" * 40, "headRefOid": "a" * 40,
                   "statusCheckRollup": [{"name": "required-ci", "conclusion": "SUCCESS"}],
                   "reviewDecision": None}
        self.assertEqual(delivery.validate_pull_request(current, "a" * 40, "b" * 40), [])
        current["baseRefOid"] = "c" * 40
        self.assertIn("pull-request-base-moved",
                      delivery.validate_pull_request(current, "a" * 40, "b" * 40))

    def test_required_aggregate_must_be_successful(self):
        self.assertEqual(delivery.validate_status_checks([
            {"name": "required-ci", "conclusion": "SUCCESS"}]), [])
        self.assertEqual(delivery.validate_status_checks([
            {"name": "required-ci", "conclusion": "FAILURE"}]), ["required-ci-not-success"])
        self.assertEqual(delivery.validate_status_checks([
            {"name": "required-ci", "status": "IN_PROGRESS", "conclusion": None}]),
            ["required-ci-pending"])
        self.assertEqual(delivery.validate_status_checks([]), ["required-ci-missing"])

    def test_main_run_requires_current_sha_and_all_qualification_lanes(self):
        names = ["required-ci", "safety", "gameplay", "desktop", "package", "performance",
                 "attestation"]
        run = {"event": "push", "status": "completed", "conclusion": "success",
               "headSha": "d" * 40,
               "jobs": [{"name": name, "conclusion": "success"} for name in names]}
        self.assertEqual(delivery.validate_main_run(run, "d" * 40), [])
        run["jobs"] = run["jobs"][:-1]
        self.assertEqual(delivery.validate_main_run(run, "d" * 40),
                         ["main-run-qualification-job-missing"])

    def test_hosted_checkout_preserves_history_for_provenance_scan(self):
        for workflow in (ROOT / ".github/workflows/ci.yml",
                         ROOT / ".github/workflows/release.yml"):
            text = workflow.read_text()
            blocks = text.split("uses: actions/checkout@")
            self.assertGreater(len(blocks), 1)
            for block in blocks[1:]:
                checkout = block.split("\n      - ", 1)[0].split("\n      uses:", 1)[0]
                self.assertIn("fetch-depth: 0", checkout, workflow.name)

    def test_hosted_runs_are_bound_to_the_authored_workflow_path(self):
        run = {"path": ".github/workflows/ci.yml", "head_sha": "a" * 40,
               "event": "push", "status": "completed", "conclusion": "success"}
        self.assertEqual(delivery.validate_workflow_identity(
            run, ".github/workflows/ci.yml", "a" * 40, "push"), [])
        self.assertEqual(delivery.validate_workflow_identity(
            run, ".github/workflows/release.yml", "a" * 40, "push"),
            ["workflow-path-mismatch"])

    def test_publisher_run_is_bound_to_dispatch_source_and_promotion_job(self):
        run = {"event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "headSha": "e" * 40, "jobs": [{"name": "promote", "conclusion": "success"}]}
        run["displayTitle"] = delivery.publisher_display_title("e" * 40, "1234", 2, "a" * 32)
        self.assertEqual(delivery.validate_publisher_run(run, "e" * 40, "1234", 2, "a" * 32), [])
        self.assertEqual(delivery.validate_publisher_run(run, "f" * 40, "1234", 2, "a" * 32),
                         ["publisher-run-source-mismatch"])
        # Same source and successful promotion, but an overlapping dispatch selected a
        # different qualification attempt. The source-only check used to accept this.
        wrong_qualification = dict(run, displayTitle=delivery.publisher_display_title(
            "e" * 40, "9999", 3, "b" * 32))
        self.assertEqual(delivery.validate_publisher_run(
            wrong_qualification, "e" * 40, "1234", 2, "a" * 32),
            ["publisher-run-dispatch-identity-mismatch"])
        wrong_attempt = dict(run, displayTitle=delivery.publisher_display_title(
            "e" * 40, "1234", 3, "a" * 32))
        self.assertEqual(delivery.validate_publisher_run(
            wrong_attempt, "e" * 40, "1234", 2, "a" * 32),
            ["publisher-run-dispatch-identity-mismatch"])
        wrong_correlation = dict(run, displayTitle=delivery.publisher_display_title(
            "e" * 40, "1234", 2, "c" * 32))
        self.assertEqual(delivery.validate_publisher_run(
            wrong_correlation, "e" * 40, "1234", 2, "a" * 32),
            ["publisher-run-dispatch-identity-mismatch"])

    def test_publisher_code_sha_is_separate_from_qualified_artifact_source(self):
        qualified_source = "e" * 40
        publisher_sha = "f" * 40
        run = {"event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "headSha": publisher_sha, "jobs": [{"name": "promote", "conclusion": "success"}]}
        run["displayTitle"] = delivery.publisher_display_title(qualified_source, "1234", 2, "a" * 32)
        self.assertEqual(delivery.validate_publisher_run(
            run, publisher_sha, "1234", 2, "a" * 32,
            qualified_source_sha=qualified_source), [])
        self.assertEqual(delivery.validate_publisher_run(
            dict(run, headSha="d" * 40), publisher_sha, "1234", 2, "a" * 32,
            qualified_source_sha=qualified_source), ["publisher-run-source-mismatch"])
        self.assertEqual(delivery.validate_publisher_run(
            run, publisher_sha, "1234", 2, "a" * 32,
            qualified_source_sha="c" * 40), ["publisher-run-dispatch-identity-mismatch"])

    def test_publisher_workflow_identity_requires_protected_main_branch(self):
        run = {"head_sha": "f" * 40, "head_branch": "main"}
        self.assertEqual(delivery.validate_publisher_branch_identity(run, "f" * 40), [])
        self.assertEqual(delivery.validate_publisher_branch_identity(
            dict(run, head_branch="feature/untrusted"), "f" * 40),
            ["publisher-workflow-not-main-branch"])
        self.assertEqual(delivery.validate_publisher_branch_identity(
            dict(run, head_sha="e" * 40), "f" * 40),
            ["publisher-workflow-source-mismatch"])

    def test_release_workflow_publishes_dispatch_inputs_in_run_identity(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("run-name:", workflow)
        for field in ("inputs.source_sha", "inputs.run_id", "inputs.run_attempt",
                      "inputs.correlation_id"):
            self.assertIn("${{ " + field + " }}", workflow)
        self.assertIn("correlation_id:\n", workflow)

    def test_self_test_is_never_hosted_evidence(self):
        result = delivery.self_test()
        self.assertEqual(result["kind"], "synthetic_contract_only")
        self.assertEqual(result["hosted_evidence"],
                         {"outcome": "not_run", "qualifies_rel_03": False})
        self.assertEqual(result["mutations_performed"], 0)

    def test_release_requires_public_asset_urls_digests_and_exact_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            source = "a" * 40
            assets = {"asset-" + str(index): {"size": 1, "sha256": "0" * 64}
                      for index in range(6)}
            inventory = {"source_revision": source, "assets": assets}
            (directory / "inventory.json").write_text(json.dumps(inventory))
            names = list(assets) + ["inventory.json", "SHA256SUMS"]
            for name in assets:
                (directory / name).write_bytes(b"x")
            (directory / "SHA256SUMS").write_text("mock\n")
            digests = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                       for name in names}
            rows = [{"name": name, "state": "uploaded", "size": (directory / name).stat().st_size,
                     "digest": "sha256:" + digests[name],
                     "browser_download_url": f"https://github.com/szTheory/genewhip/releases/download/v0.1.0/{name}"}
                    for name in names]
            release = {"tag_name": "v0.1.0", "draft": False, "prerelease": True,
                       "html_url": "https://github.com/szTheory/genewhip/releases/tag/v0.1.0",
                       "assets": rows}
            from unittest.mock import patch
            with patch.object(delivery.promote, "validate_release_inventory", return_value=(digests, [])), \
                    patch.object(delivery.promote, "validate_qualified_inventory", return_value=[]):
                result = delivery.validate_release(release, "szTheory/genewhip", "v0.1.0",
                                                   directory, source)
                self.assertEqual(result["source_sha"], source)
                rows[0]["digest"] = "sha256:" + "f" * 64
                with self.assertRaisesRegex(delivery.DeliveryError,
                                            "release-asset-server-digest-mismatch"):
                    delivery.validate_release(release, "szTheory/genewhip", "v0.1.0",
                                              directory, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
