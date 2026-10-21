#!/usr/bin/env python3
"""Contract checks for source-bound hosted delivery and release adoption."""
import json
import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.release import qualify_delivery as delivery


class DeliveryContract(unittest.TestCase):
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
        self.assertEqual(delivery.validate_publisher_run(run, "e" * 40), [])
        self.assertEqual(delivery.validate_publisher_run(run, "f" * 40),
                         ["publisher-run-source-mismatch"])

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
