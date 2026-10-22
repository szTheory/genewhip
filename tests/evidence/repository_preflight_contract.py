#!/usr/bin/env python3
"""Contract checks for honest, read-only GitHub repository preflight."""

import unittest
from unittest.mock import patch
from pathlib import Path
import sys
import hashlib
import io
import json
import subprocess
import tempfile
import tarfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

import repository_preflight as preflight
import public_hygiene


class RepositoryPreflightContract(unittest.TestCase):
    def test_history_scan_finds_deleted_secret_without_echoing_secret_bytes(self):
        scanner = getattr(public_hygiene, "scan_git_history", None)
        self.assertTrue(callable(scanner), "history-scan-missing")

        with tempfile.TemporaryDirectory(prefix="gw-history-scan-") as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            identity = ["git", "-C", str(root), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid"]
            marker = "ghp_" + "a" * 36
            (root / "historical-note.txt").write_text(f"credential={marker}\n")
            subprocess.run(identity + ["add", "historical-note.txt"], check=True)
            subprocess.run(identity + ["commit", "-qm", "add historical fixture"], check=True)
            (root / "historical-note.txt").unlink()
            subprocess.run(identity + ["add", "-u"], check=True)
            subprocess.run(identity + ["commit", "-qam", "remove historical fixture"], check=True)

            result = scanner(root)
            self.assertEqual(result["commits_scanned"], 2)
            self.assertEqual(result["finding_counts"], {"secret": 1})
            self.assertEqual(result["findings"], [{
                "path": "historical-note.txt", "reasons": ["secret"], "blob_versions": 1
            }])
            self.assertNotIn(marker, json.dumps(result))

    def test_history_scan_tracks_manifest_admitted_fixture_binaries_as_provenance(self):
        with tempfile.TemporaryDirectory(prefix="gw-history-rom-") as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            fixture = root / "fixtures"
            fixture.mkdir()
            (root / "LICENSE").write_text("Permission is hereby granted.\n")
            source = fixture / "original.s"
            source.write_text("original source\n")
            rom = fixture / "original.bin"
            rom.write_bytes(b"original rom bytes")
            notice = fixture / "NOTICES.md"
            notice.write_text("This fixture was solely authored for Genewhip under the repository MIT license.\n")
            manifest = {
                "fixtures": [{
                    "kind": "original-rom", "rom": "fixtures/original.bin",
                    "source": "fixtures/original.s", "notices": ["fixtures/NOTICES.md"],
                    "status": "admitted", "outcome": "pass", "project": "Genewhip",
                    "license": "MIT", "assets": [],
                    "sha256": hashlib.sha256(rom.read_bytes()).hexdigest(),
                    "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }]
            }
            (fixture / "manifest.json").write_text(json.dumps(manifest))
            identity = ["git", "-C", str(root), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid"]
            subprocess.run(identity + ["add", "LICENSE", "fixtures/original.s",
                                       "fixtures/original.bin", "fixtures/NOTICES.md",
                                       "fixtures/manifest.json"], check=True)
            subprocess.run(identity + ["commit", "-qm", "add licensed fixture"], check=True)

            result = public_hygiene.scan_git_history(root)
            self.assertEqual(result["finding_counts"], {})
            self.assertEqual(result["historical_binary_versions"], [{
                "path": "fixtures/original.bin", "blob_versions": 1,
                "current_fixture_provenance_verified": True,
            }])

    def test_archive_scan_reports_private_path_pattern_without_copying_matched_bytes(self):
        scanner = getattr(public_hygiene, "scan_archive", None)
        self.assertTrue(callable(scanner), "archive-scan-missing")
        marker = "/" + "Users/private-user/build/output"
        with tempfile.TemporaryDirectory(prefix="gw-archive-scan-") as temporary:
            archive_path = Path(temporary) / "fixture.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                data = marker.encode("ascii")
                member = tarfile.TarInfo("package/metadata.txt")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            result = scanner(archive_path)
            self.assertEqual(result, [{
                "member": "package/metadata.txt", "reasons": ["personal-path"]
            }])
            self.assertNotIn(marker, json.dumps(result))

    def test_publication_packet_keeps_destination_history_and_settings_unselected(self):
        builder = getattr(preflight, "build_publication_packet", None)
        self.assertTrue(callable(builder), "publication-packet-builder-missing")
        packet = builder(
            {
                "branch": "gsd/phase-04-narrow-playable-release",
                "head": "a" * 40,
                "phase3_base": "b" * 40,
                "commit_count": 12,
                "dirty_paths": [".planning/phases/example/notes.md"],
                "remote_count": 0,
            },
            {"account_connected": True, "repository_search": "timeout", "identity": "must-not-copy"},
            {"tracked_file_count": 4, "working_tree_hygiene": "pass",
             "history_blob_count": 8, "history_findings": []},
            {"archives": [], "logs": []},
            {"commit": "8b40428", "path": "packaging/dependencies/sdl3-release-keys.asc",
             "classification": "upstream_pgp_public_key", "removed_in": "950dc83"},
        )
        self.assertEqual(packet["destination"], {"owner_repository": None, "visibility": None})
        self.assertIsNone(packet["history_disposition"])
        self.assertEqual(packet["settings_delta"]["observed"], "not_observable_without_destination")
        self.assertIn("active effective rules targeting main",
                      packet["settings_delta"]["desired"]["default_branch_policy"])
        self.assertIn("no Administration permission",
                      packet["settings_delta"]["desired"]["release_policy_read"])
        self.assertTrue(packet["account_observations"]["account_connected"])
        self.assertNotIn("identity", packet["account_observations"])
        self.assertIn("destination_and_visibility_required", packet["blockers"])
        self.assertIn("history_disposition_required", packet["blockers"])
        self.assertNotIn("must-not-copy", json.dumps(packet))

    def test_ignored_local_log_privacy_finding_is_inventory_only(self):
        packet = preflight.build_publication_packet(
            {"branch": "topic", "head": "a" * 40, "phase3_base": "b" * 40},
            {}, {"working_tree_hygiene": "pass", "history_findings": []},
            {"archive_content_findings": [], "log_content_findings": [
                {"path": "build/phase4/Testing/Temporary/LastTest.log",
                 "reasons": ["personal-path"]}
            ]}, {},
        )
        self.assertEqual(packet["excluded_local_log_finding_count"], 1)
        self.assertNotIn("archive_or_log_privacy_findings_require_review", packet["blockers"])
        self.assertNotIn("archive_privacy_findings_require_review", packet["blockers"])

    def test_preflight_module_exists_with_explicit_inspection_contract(self):
        module = ROOT / "scripts" / "ci" / "repository_preflight.py"
        self.assertTrue(
            module.is_file(),
            "repository-preflight-missing: expected read-only repository policy inspector",
        )

    def test_synthetic_self_test_keeps_hosted_evidence_unknown(self):
        result = preflight.self_test()
        self.assertTrue(result["pass"])
        self.assertEqual(result["kind"], "synthetic_contract_only")
        self.assertEqual(result["hosted_evidence"], {"outcome": "not_run", "qualifies_rel_03": False})
        self.assertEqual(result["mutations_performed"], 0)
        self.assertTrue(result["synthetic_policy_shape_parsed"])
        self.assertEqual(
            result["typed_errors"],
            {
                "permission_denied": "repository_permission_denied",
                "unsupported_service": "repository_unsupported_service",
                "transport_error": "repository_transport_error",
                "missing_protection": "default_branch_protection_missing",
            },
        )

    def test_inspection_requires_explicit_owner_repository(self):
        for repository in ("", "owner", "owner/repo/extra", "../repo", "owner/../repo"):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                preflight.inspect_repository(repository, preflight.GitHubClient(lambda _: {}))

    def test_repository_readiness_does_not_claim_unobserved_hosted_capability(self):
        fixture = preflight._fixtures()
        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(fixture.__getitem__), "a" * 40, "b" * 40
        )
        self.assertNotIn("hosted_macos_capability_unverified", result["blockers"])
        self.assertTrue(result["ready_for_hosted_qualification"])
        self.assertEqual(result["observations"]["native_macos_capability"]["status"], "unverified")
        self.assertEqual(result["hosted_evidence"]["outcome"], "not_run")
        self.assertEqual(result["observations"]["branch_protection"]["required_status_checks"], ["required-ci"])
        self.assertEqual(result["observations"]["permitted_merge_methods"], ["squash", "rebase"])

    def test_repository_readiness_requires_public_visibility_and_native_auto_merge(self):
        fixture = preflight._fixtures()
        fixture["/repos/acme/genewhip"]["visibility"] = "private"
        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(fixture.__getitem__), "a" * 40, "b" * 40
        )
        self.assertIn("repository_visibility_not_public", result["blockers"])
        fixture["/repos/acme/genewhip"]["visibility"] = "public"
        fixture["/repos/acme/genewhip"]["allow_auto_merge"] = False
        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(fixture.__getitem__), "a" * 40, "b" * 40
        )
        self.assertIn("auto_merge_disabled_or_unknown", result["blockers"])

    def test_missing_protection_and_required_aggregate_are_precise_blockers(self):
        fixture = preflight._fixtures()

        def get_json(path):
            if path.endswith("/protection"):
                raise preflight.ServiceError("not_found", 404)
            return fixture[path]

        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(get_json), "a" * 40, "b" * 40
        )
        self.assertIn("default_branch_protection_missing", result["blockers"])
        self.assertIn("required_aggregate_missing", result["blockers"])

    def test_active_default_branch_ruleset_can_supply_required_check_and_review(self):
        fixture = preflight._fixtures()
        fixture["/repos/acme/genewhip/rules/branches/main"] = [
            {"type": "required_status_checks", "ruleset_source_type": "Repository",
             "ruleset_id": 17, "parameters": {
                 "required_status_checks": [{"context": "required-ci"}],
             }},
            {"type": "pull_request", "ruleset_source_type": "Organization",
             "ruleset_id": 29, "parameters": {
                 "required_approving_review_count": 1,
             }},
        ]

        def get_json(path):
            if path.endswith("/protection"):
                raise preflight.ServiceError("not_found", 404)
            return fixture[path]

        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(get_json), "a" * 40, "b" * 40
        )
        self.assertNotIn("default_branch_protection_missing", result["blockers"])
        self.assertNotIn("required_aggregate_missing", result["blockers"])
        self.assertNotIn("required_review_policy_missing", result["blockers"])
        self.assertEqual(result["observations"]["rulesets"]["applicable_active_count"], 2)

    def test_pull_request_and_required_check_policy_does_not_invent_human_approval(self):
        fixture = preflight._fixtures()
        fixture["/repos/acme/genewhip/branches/main/protection"] = None
        fixture["/repos/acme/genewhip/rules/branches/main"] = [
            {"type": "required_status_checks", "ruleset_source_type": "Repository",
             "ruleset_id": 17, "parameters": {
                 "required_status_checks": [{"context": "required-ci"}],
             }},
            {"type": "pull_request", "ruleset_source_type": "Repository",
             "ruleset_id": 17, "parameters": {"required_approving_review_count": 0}},
        ]

        def get_json(path):
            if path.endswith("/protection"):
                raise preflight.ServiceError("not_found", 404)
            return fixture[path]

        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(get_json), "a" * 40, "b" * 40
        )
        self.assertNotIn("required_aggregate_missing", result["blockers"])
        self.assertNotIn("required_review_policy_missing", result["blockers"])
        self.assertTrue(result["observations"]["branch_protection"]["pull_request_required"])
        self.assertFalse(result["observations"]["branch_protection"]["required_reviews"])

    def test_effective_rules_cover_classic_protection_permission_denial(self):
        fixture = preflight._fixtures()
        fixture["/repos/acme/genewhip/branches/main/protection"] = None
        fixture["/repos/acme/genewhip/rules/branches/main"] = [
            {"type": "required_status_checks", "ruleset_source_type": "Repository",
             "ruleset_id": 17, "parameters": {
                 "required_status_checks": [{"context": "required-ci"}],
             }},
            {"type": "pull_request", "ruleset_source_type": "Repository",
             "ruleset_id": 17, "parameters": {"required_approving_review_count": 1}},
        ]

        def get_json(path):
            if path.endswith("/branches/main/protection"):
                raise preflight.ServiceError("permission_denied", 403)
            return fixture[path]

        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(get_json), "a" * 40, "b" * 40
        )
        self.assertNotIn("branch_protection_permission_denied_without_equivalent_effective_rules",
                         result["blockers"])
        self.assertNotIn("required_aggregate_missing", result["blockers"])
        self.assertNotIn("required_review_policy_missing", result["blockers"])
        self.assertEqual(result["observations"]["rulesets"]["effective_sources"], [
            {"type": "Repository", "id": "17"},
        ])

    def test_rules_access_failure_and_mismatched_effective_branch_remain_blockers(self):
        fixture = preflight._fixtures()

        def denied(path):
            if path.endswith("/rules/branches/main"):
                raise preflight.ServiceError("permission_denied", 403)
            return fixture[path]

        denied_result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(denied), "a" * 40, "b" * 40
        )
        self.assertIn("effective_branch_rules_permission_denied", denied_result["blockers"])

        fixture["/repos/acme/genewhip"]["default_branch"] = "trunk"

        def wrong_branch(path):
            if path.endswith("/git/ref/heads/trunk") or path.endswith("/rules/branches/trunk"):
                raise preflight.ServiceError("not_found", 404)
            if path.endswith("/branches/trunk/protection"):
                raise preflight.ServiceError("not_found", 404)
            return fixture[path]

        wrong_branch_result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(wrong_branch), "a" * 40, "b" * 40
        )
        self.assertIn("default_branch_ref_not_found", wrong_branch_result["blockers"])
        self.assertIn("required_aggregate_missing", wrong_branch_result["blockers"])

    def test_network_request_uses_get_and_never_prints_token(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self):
                return b'{"ok": true}'

        with patch.object(preflight.urllib.request, "urlopen", return_value=Response()) as opened:
            self.assertEqual(preflight._http_get("/repos/acme/genewhip", "token-secret"), {"ok": True})
        request = opened.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer token-secret")

    def test_permission_unsupported_and_transport_failures_remain_typed(self):
        expected = {
            "permission_denied": "repository_permission_denied",
            "unsupported_service": "repository_unsupported_service",
            "transport_error": "repository_transport_error",
        }
        for kind, blocker in expected.items():
            with self.subTest(kind=kind):
                def get_json(_path, kind=kind):
                    raise preflight.ServiceError(kind)

                result = preflight.inspect_repository(
                    "acme/genewhip", preflight.GitHubClient(get_json), "a" * 40, "b" * 40
                )
                self.assertIn(blocker, result["blockers"])
                self.assertFalse(result["ready_for_hosted_qualification"])
                self.assertFalse(result["hosted_evidence"]["qualifies_rel_03"])

    def test_expected_identity_is_not_inferred_from_a_mock(self):
        fixture = preflight._fixtures()
        result = preflight.inspect_repository("acme/genewhip", preflight.GitHubClient(fixture.__getitem__))
        self.assertIsNone(result["observations"]["expected_identity"]["head"])
        self.assertIsNone(result["observations"]["expected_identity"]["base"])
        self.assertIn("expected_head_missing_or_invalid", result["blockers"])
        self.assertIn("expected_base_missing_or_invalid", result["blockers"])

    def test_expected_base_must_match_observed_default_branch(self):
        fixture = preflight._fixtures()
        result = preflight.inspect_repository(
            "acme/genewhip", preflight.GitHubClient(fixture.__getitem__), "a" * 40, "c" * 40
        )
        self.assertEqual(
            result["observations"]["expected_identity"]["observed_default_branch_sha"], "b" * 40
        )
        self.assertIn("expected_base_does_not_match_default_branch", result["blockers"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
