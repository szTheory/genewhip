#!/usr/bin/env python3
"""Synthetic identity and inventory rejection controls for release promotion."""
import copy
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from scripts.release import promote
from scripts.release.promote import validate_provenance, validate_live_repository_policy, verify_run_event


EXPECTED = {
    "repository": "example/genewhip",
    "workflow": ".github/workflows/ci.yml",
    "ref": "refs/heads/main",
    "sha": "a" * 40,
    "run_id": "12345",
    "run_attempt": 2,
    "event": "push",
    "conclusion": "success",
    "qualification": "success",
    "assets": {"sdk.tar.gz": "1" * 64, "desktop.tar.gz": "2" * 64,
               "inventory.json": "3" * 64},
}


def statement():
    return copy.deepcopy(EXPECTED)


class PromotionContract(unittest.TestCase):
    def test_draft_release_lookup_falls_back_to_unique_tag_in_release_list(self):
        client = promote.GitHub.__new__(promote.GitHub)
        expected = {"id": 42, "tag_name": "v0.1.0", "draft": True, "assets": []}
        calls = []

        def get(path):
            calls.append(path)
            if path.endswith("/releases/tags/v0.1.0"):
                raise promote.PromotionError("not-found")
            if path.endswith("/releases?per_page=100&page=1"):
                return [{"id": 41, "tag_name": "v0.0.9", "draft": False}, expected]
            if path.endswith("/releases?per_page=100&page=2"):
                return []
            raise AssertionError("unexpected GitHub API request")

        client.repository = "example/genewhip"
        client.get = get
        self.assertEqual(client.release_by_tag("v0.1.0"), expected)
        self.assertEqual(calls, ["/repos/example/genewhip/releases/tags/v0.1.0",
                                 "/repos/example/genewhip/releases?per_page=100&page=1"])

    def test_draft_release_lookup_rejects_ambiguous_tag_matches(self):
        client = promote.GitHub.__new__(promote.GitHub)

        def get(path):
            if path.endswith("/releases/tags/v0.1.0"):
                raise promote.PromotionError("not-found")
            if path.endswith("/releases?per_page=100&page=1"):
                return [{"id": 42, "tag_name": "v0.1.0"}, {"id": 43, "tag_name": "v0.1.0"}]
            if path.endswith("/releases?per_page=100&page=2"):
                return []
            raise AssertionError("unexpected GitHub API request")

        client.repository = "example/genewhip"
        client.get = get
        with self.assertRaisesRegex(promote.PromotionError, "release-tag-lookup-ambiguous"):
            client.release_by_tag("v0.1.0")

    def test_draft_release_lookup_checks_later_pages_for_match_and_duplicate(self):
        client = promote.GitHub.__new__(promote.GitHub)
        expected = {"id": 42, "tag_name": "v0.1.0", "draft": True}
        client.repository = "example/genewhip"
        calls = []

        def get(path):
            calls.append(path)
            if path.endswith("/releases/tags/v0.1.0"):
                raise promote.PromotionError("not-found")
            if path.endswith("page=1"):
                return [{"id": index, "tag_name": f"v0.0.{index}"} for index in range(100)]
            if path.endswith("page=2"):
                return [expected] + [{"id": index + 100, "tag_name": f"v0.0.{index + 100}"}
                                      for index in range(99)]
            if path.endswith("page=3"):
                return []
            raise AssertionError("unexpected GitHub API request")

        client.get = get
        self.assertEqual(client.release_by_tag("v0.1.0"), expected)
        self.assertEqual(len(calls), 4)

        def duplicate_on_later_page(path):
            if path.endswith("/releases/tags/v0.1.0"):
                raise promote.PromotionError("not-found")
            if path.endswith("page=1"):
                return [{"id": index, "tag_name": f"v0.0.{index}"} for index in range(100)]
            if path.endswith("page=2"):
                return [expected] + [{"id": index + 100, "tag_name": f"v0.0.{index + 100}"}
                                      for index in range(99)]
            if path.endswith("page=3"):
                return [{"id": 43, "tag_name": "v0.1.0"}]
            raise AssertionError("unexpected GitHub API request")

        client.get = duplicate_on_later_page
        with self.assertRaisesRegex(promote.PromotionError, "release-tag-lookup-ambiguous"):
            client.release_by_tag("v0.1.0")

    def test_release_job_does_not_request_administration_or_an_extra_credential(self):
        workflow = (pathlib.Path(__file__).resolve().parents[2] /
                    ".github/workflows/release.yml").read_text()
        self.assertRegex(workflow, r"(?ms)^    permissions:\n      actions: read\n"
                         r"      attestations: read\n      contents: write\n")
        self.assertNotRegex(workflow, r"(?im)^\s+administration:\s*(?:read|write)\b")
        self.assertIn("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", workflow)
        self.assertNotRegex(workflow, r"(?i)(PERSONAL_ACCESS_TOKEN|APP_PRIVATE_KEY|APP_ID)")

    def test_workflow_permission_parser_is_scoped_to_promote_job(self):
        repository = EXPECTED["repository"]
        workflow_ref = f"{repository}/.github/workflows/release.yml@refs/heads/main"
        declares = "jobs:\n  promote:\n    permissions:\n      contents: write\n    steps:\n      - run: true\n"
        self.assertTrue(promote.workflow_declares_contents_write(
            declares, repository, workflow_ref, "refs/heads/main", "workflow_dispatch"))
        for changed_text, changed_ref, changed_git_ref, changed_event in (
            ("jobs:\n  promote:\n    permissions:\n      contents: read\n", workflow_ref,
             "refs/heads/main", "workflow_dispatch"),
            (declares, f"{repository}/.github/workflows/release.yml@refs/heads/feature", "refs/heads/feature",
             "workflow_dispatch"),
            (declares, workflow_ref, "refs/heads/main", "push"),
            ("jobs:\n  other:\n    permissions:\n      contents: write\n  promote:\n    steps:\n      - run: true\n",
             workflow_ref, "refs/heads/main", "workflow_dispatch"),
        ):
            self.assertFalse(promote.workflow_declares_contents_write(
                changed_text, repository, changed_ref, changed_git_ref, changed_event))

    def test_accepts_exact_trusted_run_and_complete_inventory(self):
        self.assertEqual(validate_provenance(statement(), EXPECTED), [])

    def test_rejects_wrong_repository_by_name(self):
        value = statement(); value["repository"] = "attacker/fork"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-repository-mismatch"])

    def test_rejects_wrong_workflow_by_name(self):
        value = statement(); value["workflow"] = ".github/workflows/fork.yml"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-workflow-mismatch"])

    def test_rejects_wrong_ref_by_name(self):
        value = statement(); value["ref"] = "refs/pull/8/merge"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-ref-mismatch"])

    def test_rejects_wrong_source_sha_by_name(self):
        value = statement(); value["sha"] = "b" * 40
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-sha-mismatch"])

    def test_rejects_wrong_run_id_by_name(self):
        value = statement(); value["run_id"] = "12346"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-run-id-mismatch"])

    def test_rejects_wrong_attempt_by_name(self):
        value = statement(); value["run_attempt"] = 1
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-run-attempt-mismatch"])

    def test_rejects_fork_event_by_name(self):
        value = statement(); value["event"] = "pull_request"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-event-mismatch"])

    def test_rejects_unsuccessful_qualification_by_name(self):
        value = statement(); value["qualification"] = "skipped"
        self.assertEqual(validate_provenance(value, EXPECTED), ["qualification-not-success"])

    def test_rejects_incomplete_inventory_by_name(self):
        value = statement(); del value["assets"]["desktop.tar.gz"]
        self.assertEqual(validate_provenance(value, EXPECTED), ["inventory-incomplete"])

    def test_rejects_changed_asset_digest_by_name(self):
        value = statement(); value["assets"]["sdk.tar.gz"] = "f" * 64
        self.assertEqual(validate_provenance(value, EXPECTED), ["inventory-digest-mismatch"])

    def test_rejects_failed_required_run_by_name(self):
        value = statement(); value["conclusion"] = "failure"
        self.assertEqual(validate_provenance(value, EXPECTED), ["provenance-run-not-success"])

    def test_rejects_fork_workflow_run_from_event_payload(self):
        repo = {"id": 1, "full_name": EXPECTED["repository"]}
        event = {"workflow_run": {"id": 12345, "run_attempt": 2, "name": "Required preview checks",
                                  "event": "push", "head_branch": "main", "head_sha": EXPECTED["sha"],
                                  "status": "completed", "conclusion": "success", "repository": repo,
                                  "head_repository": {"id": 2}}}
        run, blockers = verify_run_event(event, EXPECTED["repository"], EXPECTED["sha"], "12345", 2)
        self.assertIsNone(run)
        self.assertEqual(blockers, ["provenance-fork-source"])

    def test_rejects_wrong_run_attempt_in_event_payload(self):
        repo = {"id": 1, "full_name": EXPECTED["repository"]}
        event = {"workflow_run": {"id": 12345, "run_attempt": 1, "name": "Required preview checks",
                                  "event": "push", "head_branch": "main", "head_sha": EXPECTED["sha"],
                                  "status": "completed", "conclusion": "success", "repository": repo,
                                  "head_repository": repo}}
        run, blockers = verify_run_event(event, EXPECTED["repository"], EXPECTED["sha"], "12345", 2)
        self.assertIsNone(run)
        self.assertEqual(blockers, ["provenance-run-attempt-mismatch"])

    def test_live_policy_requires_current_destination_checks_reviews_and_write_access(self):
        repo = {"full_name": EXPECTED["repository"], "default_branch": "main",
                "permissions": {"push": True}}
        protection = {"required_status_checks": {"contexts": ["required-ci"]},
                      "required_pull_request_reviews": {"required_approving_review_count": 1}}
        self.assertEqual(validate_live_repository_policy(EXPECTED["repository"], repo, protection, []), [])
        self.assertEqual(validate_live_repository_policy(EXPECTED["repository"], repo, None, [
            {"type": "required_status_checks", "parameters": {"required_status_checks": [
                {"context": "required-ci"}]}},
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
        ]), [])
        for changed, wanted in (
            ({**repo, "full_name": "other/repo"}, "publication-destination-mismatch"),
            ({**repo, "default_branch": "trunk"}, "publication-default-branch-mismatch"),
            ({**repo, "permissions": {"push": False, "admin": False}},
             "publication-write-permission-unavailable"),
        ):
            self.assertEqual(validate_live_repository_policy(EXPECTED["repository"], changed,
                             protection, []), [wanted])
        self.assertIn("publication-protection-missing", validate_live_repository_policy(
            EXPECTED["repository"], repo, None, []))
        self.assertIn("publication-required-ci-policy-missing", validate_live_repository_policy(
            EXPECTED["repository"], repo, {"required_pull_request_reviews": {
                "required_approving_review_count": 1}}, []))
        self.assertIn("publication-required-pull-request-policy-missing", validate_live_repository_policy(
            EXPECTED["repository"], repo, {"required_status_checks": {"contexts": ["required-ci"]}}, []))

    def test_live_policy_allows_automation_first_pr_policy_without_forcing_approval(self):
        repo = {"full_name": EXPECTED["repository"], "default_branch": "main",
                "permissions": {"push": True}}
        rules = [
            {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "required-ci"}]}},
            {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
        ]
        self.assertEqual(validate_live_repository_policy(EXPECTED["repository"], repo, None, rules), [])

    def test_live_policy_uses_explicit_workflow_contents_write_when_api_omits_user_permissions(self):
        repo = {"full_name": EXPECTED["repository"], "default_branch": "main"}
        rules = [
            {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "required-ci"}]}},
            {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
        ]
        self.assertEqual(validate_live_repository_policy(
            EXPECTED["repository"], repo, None, rules),
            ["publication-write-permission-unavailable"])
        self.assertEqual(validate_live_repository_policy(
            EXPECTED["repository"], repo, None, rules, publisher_contents_write=True), [])
        explicit_denial = {**repo, "permissions": {"push": False, "admin": False}}
        self.assertEqual(validate_live_repository_policy(
            EXPECTED["repository"], explicit_denial, None, rules,
            publisher_contents_write=True), ["publication-write-permission-unavailable"])
        malformed = {**repo, "permissions": None}
        self.assertEqual(validate_live_repository_policy(
            EXPECTED["repository"], malformed, None, rules,
            publisher_contents_write=True), ["publication-write-permission-unavailable"])

    def test_publish_rechecks_real_service_path_before_visibility_transition(self):
        source_sha = EXPECTED["sha"]
        repository = EXPECTED["repository"]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            assets = root / "assets"
            assets.mkdir()
            members = {
                "native macOS arm64 desktop archive": {"LICENSE", "SDL3-LICENSE.txt",
                    "THIRD-PARTY-ymfm.txt", "phase4-evidence.json", "phase4-gameplay.json", "manifest.json"},
                "SDL-free API 4 SDK archive": {"SingleStepTests-LICENSE", "THIRD-PARTY-ymfm.txt",
                    "diagnostic-evidence.json", "metadata.json"},
            }
            names = {}
            for kind, required in members.items():
                label = "playable-preview-macos-arm64" if "desktop" in kind else "sdk-diagnostic-darwin-arm64"
                name = f"genewhip-0.1.0-{label}-{source_sha[:12]}.tar.gz"
                names[kind] = name
                archive_buffer = io.BytesIO()
                with tarfile.open(fileobj=archive_buffer, mode="w:gz") as package:
                    for member_name in sorted(required):
                        info = tarfile.TarInfo(member_name)
                        info.size = 1
                        package.addfile(info, io.BytesIO(b"x"))
                data = archive_buffer.getvalue()
                (assets / name).write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                (assets / (name + ".sha256")).write_text(f"{digest}  {name}\n")
                (assets / (name + ".qualification.json")).write_text(json.dumps({
                    "schema": "genewhip-local-package-qualification", "outcome": "pass",
                    "kind": kind, "source_revision": source_sha, "archive": name,
                    "archive_sha256": digest,
                }))
            rows = {}
            for path in assets.iterdir():
                data = path.read_bytes()
                rows[path.name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            inventory = {"schema": "genewhip.release-inventory.v1", "version": "0.1.0",
                         "source_revision": source_sha, "assets": dict(sorted(rows.items()))}
            inventory_data = promote._json_bytes(inventory)
            (assets / "inventory.json").write_bytes(inventory_data)
            checksums = {name: row["sha256"] for name, row in rows.items()}
            checksums["inventory.json"] = hashlib.sha256(inventory_data).hexdigest()
            (assets / "SHA256SUMS").write_text("".join(
                f"{digest}  {name}\n" for name, digest in sorted(checksums.items())))
            event_path = root / "event.json"
            event_path.write_text(json.dumps({"repository": {"full_name": repository}, "inputs": {
                "source_sha": source_sha, "run_id": "12345", "run_attempt": "2"}}))

            class MockGitHub(promote.GitHub):
                def __init__(self, token, selected_repository):
                    super().__init__(token, selected_repository)
                    self.patches = []
                    self.release = {"id": 9, "tag_name": "v0.1.0", "draft": True,
                        "name": "0.1.0", "body": "Qualified preview draft", "prerelease": True,
                        "assets": [{"name": name, "size": len(name), "state": "uploaded",
                                    "digest": "sha256:" + row["sha256"]}
                                   for name, row in rows.items()] + [{
                        "name": "inventory.json", "size": len(inventory_data), "state": "uploaded",
                            "digest": "sha256:" + checksums["inventory.json"]}],
                        "upload_url": "https://uploads.github.com/example"}

                def get(self, path):
                    if path.startswith("/repos/example/genewhip/actions/runs/12345/attempts/2/jobs"):
                        return {"jobs": [{"name": name, "status": "completed", "conclusion": "success"}
                                          for name in ("required-ci", "attestation")]}
                    if path == "/repos/example/genewhip/actions/runs/12345/attempts/2":
                        repo = {"id": 1, "full_name": repository}
                        return {"id": 12345, "run_attempt": 2, "name": "Required preview checks",
                            "event": "push", "head_branch": "main", "head_sha": source_sha,
                            "status": "completed", "conclusion": "success", "repository": repo,
                            "head_repository": repo, "workflow_id": 42}
                    if path == "/repos/example/genewhip/actions/workflows/42":
                        return {"path": promote.WORKFLOW_PATH}
                    if path == "/repos/example/genewhip":
                        return {"full_name": repository, "default_branch": "main",
                                "permissions": copy.deepcopy(self.repo_permissions),
                                "current_tip_for_test": "b" * 40}
                    if path == "/repos/example/genewhip/branches/main/protection":
                        if self.protection_access_denied:
                            raise promote.PromotionError("permission-denied")
                        if not self.policy_ok:
                            raise promote.PromotionError("not-found")
                        return {"required_status_checks": {"contexts": ["required-ci"]},
                                "required_pull_request_reviews": {"required_approving_review_count": 1}}
                    if path == "/repos/example/genewhip/rules/branches/main":
                        if self.rules_access_denied:
                            raise promote.PromotionError("permission-denied")
                        return copy.deepcopy(self.effective_rules)
                    raise AssertionError("unexpected GitHub API request: " + path)

                policy_ok = True
                protection_access_denied = False
                rules_access_denied = False
                effective_rules = []
                repo_permissions = {"push": True, "admin": False}
                write_probe_denied = False
                probe_response_override = None
                probe_readback_mutation = None
                move_tag_after_probe = False
                tag_moved = False

                def tag_commit(self, tag):
                    return "c" * 40 if self.tag_moved else source_sha

                def release_by_tag(self, tag):
                    return self.release

                def release_assets(self, release):
                    return [{"name": row["name"], "sha256": row["digest"][7:]}
                            for row in release["assets"]]

                def patch(self, path, value):
                    self.patches.append((path, value))
                    if "draft" not in value and self.write_probe_denied:
                        raise promote.PromotionError("permission-denied")
                    is_probe = "draft" not in value
                    if is_probe and self.move_tag_after_probe:
                        self.tag_moved = True
                    if "draft" in value:
                        self.release["draft"] = value["draft"]
                    self.release.update({key: value[key] for key in ("name", "body") if key in value})
                    if is_probe and self.probe_readback_mutation:
                        self.probe_readback_mutation(self.release)
                    if is_probe and self.probe_response_override is not None:
                        return self.probe_response_override(copy.deepcopy(self.release))
                    return copy.deepcopy(self.release)

            statement = {"predicate": {"runDetails": {"metadata": {
                "invocationId": f"https://github.com/{repository}/actions/runs/12345/attempts/2"}}}}
            gh_output = json.dumps([{"verificationResult": {"statement": statement}}])
            instance = MockGitHub("token", repository)
            def publish_with_mock_attestation():
                with mock.patch.object(promote, "GitHub", return_value=instance), \
                        mock.patch.object(promote.subprocess, "run", return_value=promote.subprocess.CompletedProcess(
                            args=["gh"], returncode=0, stdout=gh_output, stderr="")):
                    return promote.publish(repository, source_sha, "12345", 2, event_path, assets, "token")
            with mock.patch.object(promote, "GitHub", return_value=instance), \
                    mock.patch.object(promote.subprocess, "run", return_value=promote.subprocess.CompletedProcess(
                        args=["gh"], returncode=0, stdout=gh_output, stderr="")):
                with self.assertRaisesRegex(promote.PromotionError, "publication-protection-missing"):
                    instance.policy_ok = False
                    promote.publish(repository, source_sha, "12345", 2, event_path, assets, "token")
                self.assertEqual(instance.patches, [], "policy rejection must happen before public PATCH")
                instance.policy_ok = True
                result = promote.publish(repository, source_sha, "12345", 2, event_path, assets, "token")
            self.assertEqual(result, "published-complete-inventory")
            self.assertEqual(len(instance.patches), 1)

            # When metadata denies push, verify actual GITHUB_TOKEN write access by
            # updating only the existing private draft's unchanged name and body.
            instance.release["draft"] = True
            instance.patches.clear()
            instance.repo_permissions = {"push": False, "admin": False}
            result = publish_with_mock_attestation()
            self.assertEqual(result, "published-complete-inventory")
            self.assertEqual(len(instance.patches), 2)
            self.assertEqual(instance.patches[0][1], {
                "name": "0.1.0", "body": "Qualified preview draft"})
            self.assertNotIn("draft", instance.patches[0][1])
            self.assertEqual(instance.patches[1][1], {"draft": False})

            # Malformed asset identity, changed API response, and changed readback
            # state must all fail before a public visibility transition.
            instance.release["draft"] = True
            instance.patches.clear()
            instance.release["assets"][0]["name"] = None
            with self.assertRaisesRegex(promote.PromotionError, "release-assets-malformed"):
                instance.verify_draft_write_access(instance.release, "v0.1.0")
            instance.release["assets"][0]["name"] = next(iter(rows))

            instance.probe_response_override = lambda response: {**response, "name": "changed"}
            with self.assertRaisesRegex(promote.PromotionError,
                                        "publication-write-probe-result-invalid"):
                instance.verify_draft_write_access(instance.release, "v0.1.0")
            instance.probe_response_override = None

            def change_readback_asset(release):
                release["assets"][0]["digest"] = "sha256:" + ("0" * 64)
            instance.probe_readback_mutation = change_readback_asset
            with self.assertRaisesRegex(promote.PromotionError,
                                        "publication-write-probe-state-changed"):
                instance.verify_draft_write_access(instance.release, "v0.1.0")
            instance.probe_readback_mutation = None
            self.assertTrue(instance.release["draft"])
            self.assertTrue(all("draft" not in patch for _, patch in instance.patches))
            instance = MockGitHub("token", repository)
            instance.repo_permissions = {"push": False, "admin": False}

            # A denied metadata write must leave the draft private and stop before
            # the separate visibility transition.
            instance.release["draft"] = True
            instance.patches.clear()
            instance.write_probe_denied = True
            with self.assertRaisesRegex(promote.PromotionError,
                                        "publication-write-permission-unavailable"):
                publish_with_mock_attestation()
            self.assertTrue(instance.release["draft"])
            self.assertEqual(len(instance.patches), 1)
            self.assertNotIn("draft", instance.patches[0][1])
            instance.write_probe_denied = False
            instance.repo_permissions = {"push": True, "admin": False}

            # The immutable qualified source tag is rechecked after the network
            # probe, immediately before the public visibility transition.
            instance = MockGitHub("token", repository)
            instance.repo_permissions = {"push": False, "admin": False}
            instance.move_tag_after_probe = True
            with self.assertRaisesRegex(promote.PromotionError,
                                        "tag-source-conflict-before-publish"):
                publish_with_mock_attestation()
            self.assertTrue(instance.release["draft"])
            self.assertEqual(len(instance.patches), 1)
            self.assertNotIn("draft", instance.patches[0][1])
            instance = MockGitHub("token", repository)

            # The release workflow's standard token cannot read classic protection. An
            # effective ruleset read is sufficient only when it confirms both required
            # policy rules for the selected default branch.
            instance.release["draft"] = True
            instance.patches.clear()
            instance.policy_ok = False
            instance.protection_access_denied = True
            instance.effective_rules = [
                {"type": "required_status_checks", "parameters": {
                    "required_status_checks": [{"context": "required-ci"}]}},
                {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
            ]
            result = publish_with_mock_attestation()
            self.assertEqual(result, "published-complete-inventory")
            self.assertEqual(len(instance.patches), 1)

            def assert_policy_rejected(*, rules, expected_reason,
                                       access_denied=False, default_branch="main"):
                instance.release["draft"] = True
                instance.patches.clear()
                instance.effective_rules = copy.deepcopy(rules)
                instance.rules_access_denied = access_denied
                instance.release["assets"] = [{"name": name, "state": "uploaded",
                    "digest": "sha256:" + row["sha256"]} for name, row in rows.items()] + [{
                    "name": "inventory.json", "state": "uploaded",
                    "digest": "sha256:" + checksums["inventory.json"]}]
                original_get = instance.get

                def branch_override(path):
                    if path == "/repos/example/genewhip":
                        return {"full_name": repository, "default_branch": default_branch,
                                "permissions": {"push": True, "admin": False}}
                    if path == "/repos/example/genewhip/rules/branches/trunk":
                        return []
                    if path == "/repos/example/genewhip/branches/trunk/protection":
                        raise promote.PromotionError("not-found")
                    return original_get(path)

                with mock.patch.object(instance, "get", side_effect=branch_override):
                    with self.assertRaisesRegex(promote.PromotionError, expected_reason):
                        publish_with_mock_attestation()
                self.assertEqual(instance.patches, [], "policy rejection must happen before public PATCH")

            for omitted in ("missing", "disabled", "wrong-branch"):
                with self.subTest(effective_rule_set=omitted):
                    # The effective-rules endpoint returns [] for absent, disabled,
                    # evaluating, or nonmatching rulesets on the requested main branch.
                    assert_policy_rejected(rules=[],
                        expected_reason="publication-protection-missing")
            assert_policy_rejected(rules=[{"type": "pull_request", "parameters": {
                "required_approving_review_count": 1}}],
                expected_reason="publication-required-ci-policy-missing")
            assert_policy_rejected(rules=[], access_denied=True,
                expected_reason="publication-effective-rules-unavailable")
            assert_policy_rejected(rules=[], default_branch="trunk",
                expected_reason="publication-default-branch-mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
