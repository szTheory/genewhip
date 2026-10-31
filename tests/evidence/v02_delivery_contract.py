#!/usr/bin/env python3
"""Versioned v0.2 promotion and downloaded-byte adoption contracts."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.release import promote
from scripts.release import qualify_delivery
from scripts.release import v02_qualification
from scripts.ci import verify_attestation_inputs

SOURCE = "a" * 40


class V02PublisherContract(unittest.TestCase):
    def test_v2_production_validator_is_available(self):
        self.assertTrue(hasattr(promote, "validate_v02_inventory"),
                        "v0.2 inventory must have a production-owned validator")

    def test_accepts_exact_v2_inventory_and_qualified_public_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = self.make_inventory(directory)
            self.assertEqual(promote.validate_v02_inventory(directory, inventory, SOURCE), [])
            _, blockers = promote.validate_release_inventory(directory, inventory)
            self.assertEqual(blockers, [])

    def test_recovery_exception_is_legacy_only(self):
        self.assertEqual(promote.validate_recovery_version("0.2.0", 420400458),
                         ["release-draft-recovery-version-forbidden"])
        self.assertEqual(promote.validate_recovery_version("0.2.0", 0), [])

    def test_prepare_emits_exact_eight_v2_assets_and_rejects_development_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, output = root / "source", root / "output"
            source.mkdir()
            self.make_inventory(source)
            prepared = promote.prepare_assets(source, output, SOURCE, "0.2.0")
            self.assertEqual(prepared["schema"], "genewhip.release-inventory.v2")
            self.assertEqual(len(promote.expected_asset_names(prepared)), 8)
            receipt_path = next(source.glob("*.qualification.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["source_state"] = "development-only"
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(promote.PromotionError, "package-source-not-public"):
                promote.prepare_assets(source, root / "rejected", SOURCE, "0.2.0")

    def test_v2_rejects_wrong_schema_source_roster_and_development_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = self.make_inventory(directory)
            changed = copy.deepcopy(inventory)
            changed["schema"] = "genewhip.release-inventory.v1"
            self.assertEqual(promote.validate_v02_inventory(directory, changed, SOURCE),
                             ["inventory-version-invalid"])
            changed = copy.deepcopy(inventory)
            changed["source_revision"] = "b" * 40
            self.assertEqual(promote.validate_v02_inventory(directory, changed, SOURCE),
                             ["inventory-source-mismatch"])
            changed = copy.deepcopy(inventory)
            changed["assets"].pop(next(iter(changed["assets"])))
            self.assertEqual(promote.validate_v02_inventory(directory, changed, SOURCE),
                             ["inventory-package-roster-incomplete"])
            receipt_path = next(directory.glob("*.qualification.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["source_state"] = "development-only"
            receipt_path.write_text(json.dumps(receipt))
            self.refresh_inventory(directory, inventory)
            self.assertEqual(promote.validate_v02_inventory(directory, inventory, SOURCE),
                             ["inventory-package-source-not-public"])

    def test_attestation_input_verifier_dispatches_by_explicit_inventory_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            directory = root / "assets"
            directory.mkdir()
            inventory = self.make_inventory(directory)
            identity_dir = root / "identity"
            identity_dir.mkdir()
            expected = verify_attestation_inputs.identity(
                "example/genewhip", SOURCE, "12345", "2", "push", "refs/heads/main",
                "Required preview checks")
            (identity_dir / "_ci-identity.json").write_text(json.dumps(expected))
            self.assertEqual(verify_attestation_inputs.validate_inputs(directory, expected, identity_dir), [])
            changed = copy.deepcopy(inventory)
            changed["version"] = "0.1.0"
            (directory / "inventory.json").write_text(json.dumps(changed))
            blockers = verify_attestation_inputs.validate_inputs(directory, expected, identity_dir)
            self.assertEqual(blockers, ["attestation-input-inventory-source-mismatch"])

    def test_dispatch_release_input_bytes_join_after_authenticated_transfer(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        legacy = workflow.split("  package:\n", 1)[1].split("  attestation:\n", 1)[0]
        self.assertIn("if: github.event_name != 'workflow_dispatch'", legacy)
        self.assertIn("name: release-input-${{ github.run_id }}-${{ github.run_attempt }}", legacy)
        self.assertIn("path: |\n            build/release-assets/*.tar.gz", legacy)
        v02 = workflow.split("  v02-package:\n", 1)[1].split("  v02-release-qualification:\n", 1)[0]
        self.assertIn("prepare-package --root . --out build/v02/package-transfer --source-sha", v02)
        self.assertIn("path: build/v02/package-transfer/payload/artifacts/release-assets/*", v02)
        self.assertEqual(v02.count("name: release-input-${{ github.run_id }}-${{ github.run_attempt }}"), 1)
        self.assertIn("verify_attestation_inputs.py write-identity", v02)
        qualification = workflow.split("  v02-release-qualification:\n", 1)[1].split(
            "  required-aggregate:\n", 1)[0]
        self.assertIn("needs: [v02-runtime, v02-benchmark-control, v02-benchmark-recursion94, v02-benchmark-tank-battle, v02-package]", qualification)
        attestation = workflow.split("  attestation:\n", 1)[1].split("  performance:\n", 1)[0]
        self.assertIn("needs: [package, v02-package, v02-release-qualification]", attestation)
        self.assertIn("github.event_name == 'workflow_dispatch'", attestation)
        self.assertIn("name: release-input-${{ github.run_id }}-${{ github.run_attempt }}", attestation)
        self.assertIn("verify_attestation_inputs.py verify", attestation)
        aggregate = workflow.split("  required-aggregate:\n", 1)[1].split("  extended:\n", 1)[0]
        self.assertIn("v02-release-qualification, attestation", aggregate)

        qualification_spec = importlib.util.spec_from_file_location(
            "gw_v02_qualification_consumer", ROOT / "scripts/release/v02_qualification.py")
        qualification_module = importlib.util.module_from_spec(qualification_spec)
        qualification_spec.loader.exec_module(qualification_module)
        with tempfile.TemporaryDirectory(prefix="gw-qualified-v02-release-input-") as temporary:
            root = pathlib.Path(temporary)
            transfer_root = root / "transfer/payload/artifacts/release-assets"
            transfer_root.mkdir(parents=True)
            staged = root / "staged-v02"
            staged.mkdir()
            inventory = self.make_inventory(staged)
            for member in ("inventory.json", "SHA256SUMS", *inventory["assets"]):
                (transfer_root / member).write_bytes((staged / member).read_bytes())
            transfer_members = {}
            for path in transfer_root.iterdir():
                data = path.read_bytes()
                transfer_members["artifacts/release-assets/" + path.name] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

            # upload-artifact strips the declared common root, so download places
            # those exact producer bytes at the release-input artifact root.
            release_input = root / "release-input"
            release_input.mkdir()
            for path in transfer_root.iterdir():
                (release_input / path.name).write_bytes(path.read_bytes())
            identity_dir = root / "release-identity"
            identity_dir.mkdir()
            expected = verify_attestation_inputs.identity("example/genewhip", SOURCE,
                "12345", "2", "workflow_dispatch", "refs/heads/main",
                "Required preview checks", qualification_started_at="2026-10-29T00:00:00Z",
                qualification_nonce="a" * 32, base_sha="b" * 40)
            (identity_dir / "_ci-identity.json").write_text(json.dumps(expected))
            self.assertEqual(verify_attestation_inputs.validate_inputs(
                release_input, expected, identity_dir), [])
            joined = qualification_module._validate_hosted_release_inputs(
                release_input, SOURCE, transfer_members)
            self.assertEqual(set(joined[2]), set(inventory["assets"]) | {"inventory.json", "SHA256SUMS"})
            for name in joined[2]:
                self.assertEqual((release_input / name).read_bytes(),
                    (transfer_root / name).read_bytes(), name)

            changed_name = next(iter(inventory["assets"]))
            changed = bytearray((release_input / changed_name).read_bytes())
            changed[-1] ^= 1
            (release_input / changed_name).write_bytes(changed)
            self.refresh_inventory(release_input, inventory)
            with self.assertRaisesRegex(ValueError,
                    "hosted-release-input-differs-from-authenticated-package-transfer"):
                qualification_module._validate_hosted_release_inputs(
                    release_input, SOURCE, transfer_members)

            # A complete legacy v0.1 input remains valid on its legacy lane,
            # but the v0.2 receiver rejects that inventory before joining bytes.
            legacy_input = root / "legacy-release-input"
            legacy_input.mkdir()
            legacy_assets = {}
            suffix = "-" + SOURCE[:12] + ".tar.gz"
            for target in verify_attestation_inputs.PACKAGE_TARGETS:
                archive_name = f"genewhip-0.1.0-{target}{suffix}"
                archive = ("legacy:" + target).encode()
                digest = hashlib.sha256(archive).hexdigest()
                receipt = {"schema": "genewhip-local-package-qualification", "outcome": "pass",
                    "source_revision": SOURCE, "archive": archive_name, "archive_sha256": digest}
                rows = ((archive_name, archive), (archive_name + ".sha256",
                    f"{digest}  {archive_name}\n".encode()),
                    (archive_name + ".qualification.json", json.dumps(receipt).encode()))
                for name, data in rows:
                    (legacy_input / name).write_bytes(data)
                    legacy_assets[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            legacy_inventory = {"schema": "genewhip.release-inventory.v1", "version": "0.1.0",
                "source_revision": SOURCE, "assets": legacy_assets}
            (legacy_input / "inventory.json").write_text(json.dumps(legacy_inventory))
            (legacy_input / "SHA256SUMS").write_text("legacy checksums\n")
            self.assertEqual(verify_attestation_inputs.validate_inputs(
                legacy_input, expected, identity_dir), [])
            with self.assertRaisesRegex(ValueError, "hosted-release-inventory-roster-invalid"):
                qualification_module._validate_hosted_release_inputs(
                    legacy_input, SOURCE, transfer_members)

    def test_required_run_must_have_exact_v2_qualification_job(self):
        api = promote.GitHub.__new__(promote.GitHub)
        api.repository = "example/genewhip"
        jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                for name in ("required-ci", "attestation")]
        api.get = lambda path: {"jobs": jobs}
        with self.assertRaisesRegex(promote.PromotionError, "v02-qualification-job-not-success"):
            api.verify_required_check("12345", 2, "0.2.0")
        jobs.append({"name": "v02-release-qualification", "status": "completed", "conclusion": "success"})
        api.verify_required_check("12345", 2, "0.2.0")

    def test_release_dispatch_is_typed_and_download_pins_exact_run_attempt(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertRegex(workflow, r"(?ms)^      release_version:\n.*?type: choice\n.*?0\.2\.0")
        self.assertIn("name: release-input-${{ inputs.run_id }}-${{ inputs.run_attempt }}", workflow)
        self.assertIn("run-id: ${{ inputs.run_id }}", workflow)
        self.assertNotRegex(workflow, r"(?im)^\s+artifact-id:")
        self.assertIn("fa0a91b85d4f404e444e00e005971372dc801d16", workflow)

    @staticmethod
    def make_inventory(directory):
        member_roster = json.loads((ROOT / "packaging/v02-members.json").read_text())
        packages = [
            ("sdk", "genewhip-0.2.0-sdk-diagnostic-darwin-arm64", "SDL-free SDK/diagnostic archive"),
            ("desktop", "genewhip-0.2.0-playable-preview-macos-arm64", "curated SDL3 desktop archive"),
        ]
        asset_rows = {}
        for role, prefix, kind in packages:
            archive_name = prefix + "-" + SOURCE[:12] + ".tar.gz"
            roster = member_roster[role]["members"]
            performance_path = "share/genewhip/evidence/performance.json"
            performance_bytes = b'{"schema":"test-performance"}'
            performance_digest = hashlib.sha256(performance_bytes).hexdigest()
            metadata_bytes = json.dumps({"performance_evidence_digest": performance_digest},
                sort_keys=True).encode()
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for row in roster:
                    path = row["path"]
                    content = (performance_bytes if path == performance_path else
                               metadata_bytes if path == "metadata.json" else path.encode())
                    item = tarfile.TarInfo("package/" + path)
                    item.size = len(content)
                    archive.addfile(item, io.BytesIO(content))
            data = buffer.getvalue()
            digest = hashlib.sha256(data).hexdigest()
            checksum = f"{digest}  {archive_name}\n".encode()
            receipt = {"schema": "genewhip-local-package-qualification", "version": 2,
                       "release_version": "0.2.0", "kind": kind, "outcome": "pass",
                       "source_revision": SOURCE, "source_state": "clean",
                       "archive": archive_name, "archive_sha256": digest,
                       "performance_evidence_digest": performance_digest,
                       "smoke": {"outcome": "pass"}}
            for name, content in ((archive_name, data), (archive_name + ".sha256", checksum),
                                  (archive_name + ".qualification.json", json.dumps(
                                      receipt, sort_keys=True).encode() + b"\n")):
                (directory / name).write_bytes(content)
                asset_rows[name] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        inventory = {"schema": "genewhip.release-inventory.v2", "version": "0.2.0",
                     "source_revision": SOURCE, "assets": dict(sorted(asset_rows.items()))}
        data = promote._json_bytes(inventory)
        (directory / "inventory.json").write_bytes(data)
        rows = {name: row["sha256"] for name, row in asset_rows.items()}
        rows["inventory.json"] = hashlib.sha256(data).hexdigest()
        sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(rows.items())).encode()
        (directory / "SHA256SUMS").write_bytes(sums)
        return inventory

    @staticmethod
    def refresh_inventory(directory, inventory):
        for name in list(inventory["assets"]):
            path = directory / name
            if not path.exists():
                del inventory["assets"][name]
            else:
                data = path.read_bytes()
                inventory["assets"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        inventory["assets"] = dict(sorted(inventory["assets"].items()))
        data = promote._json_bytes(inventory)
        (directory / "inventory.json").write_bytes(data)
        rows = {name: row["sha256"] for name, row in inventory["assets"].items()}
        rows["inventory.json"] = hashlib.sha256(data).hexdigest()
        (directory / "SHA256SUMS").write_bytes("".join(
            f"{digest}  {name}\n" for name, digest in sorted(rows.items())).encode())

    @staticmethod
    def make_packet():
        publisher_sha = "c" * 40
        prefixes = ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64",
                    "genewhip-0.2.0-playable-preview-macos-arm64")
        digests = {name: f"{number:064x}" for number, name in enumerate(
            [item for prefix in prefixes for item in (
                f"{prefix}-{SOURCE[:12]}.tar.gz",
                f"{prefix}-{SOURCE[:12]}.tar.gz.sha256",
                f"{prefix}-{SOURCE[:12]}.tar.gz.qualification.json")]
             + ["inventory.json", "SHA256SUMS"], 1)}
        preflight = {"schema": "genewhip.publication-readiness-packet.v1",
                     "repository": "example/genewhip",
                     "destination": {"owner_repository": "example/genewhip", "visibility": "public"},
                     "history_disposition": "sanitized-snapshots-preserve-local-history",
                     "privacy_scan": {"publication_copy": {"status": "pass", "findings": []}},
                     "repository_observations": {"ready": True},
                     "expected_identity": {"head": SOURCE, "base": "b" * 40}}
        return {"schema": "genewhip.v02-publisher-packet.v1", "repository": "example/genewhip",
                "preflight": preflight, "release_tag": "v0.2.0", "source_sha": SOURCE,
                "qualification": {"run_id": "12345", "run_attempt": 2, "source_sha": SOURCE,
                                  "workflow_path": ".github/workflows/ci.yml",
                                  "ref": "refs/heads/main", "event": "push"},
                "publisher": {"run_id": "67890", "run_attempt": 1, "source_sha": publisher_sha,
                              "workflow_path": ".github/workflows/release.yml",
                              "ref": "refs/heads/main", "event": "workflow_dispatch"},
                "publisher_correlation_id": "dispatch-abc", "inventory_sha256": digests["inventory.json"],
                "asset_digests": digests,
                "prepublication_scope": "publisher-readiness",
                "prepublication_outcomes": {name: "pass" for name in qualify_delivery.V02_REQUIREMENTS}}


class V02DownloadContract(unittest.TestCase):
    def setUp(self):
        self.packet = V02PublisherContract.make_packet()

    def identities(self):
        source = self.packet["source_sha"]
        publisher_sha = self.packet["publisher"]["source_sha"]
        correlation = self.packet["publisher_correlation_id"]
        qualification = {"event": "push", "headSha": source, "status": "completed",
                         "conclusion": "success", "databaseId": "12345", "attempt": 2,
                         "jobs": [{"name": name, "status": "completed", "conclusion": "success"}
                                  for name in ("required-ci", "attestation", "v02-release-qualification")]}
        qualification_identity = {"path": ".github/workflows/ci.yml", "head_sha": source,
                                  "event": "push", "status": "completed", "conclusion": "success",
                                  "id": 12345, "run_attempt": 2}
        publisher = {"event": "workflow_dispatch", "headSha": publisher_sha, "status": "completed",
                     "conclusion": "success", "databaseId": "67890", "attempt": 1,
                     "displayTitle": qualify_delivery.publisher_display_title(
                         source, "12345", 2, correlation),
                     "jobs": [{"name": "promote", "conclusion": "success"}]}
        publisher_identity = {"path": ".github/workflows/release.yml", "head_sha": publisher_sha,
                              "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
                              "head_branch": "main", "id": 67890, "run_attempt": 1}
        return qualification, qualification_identity, publisher, publisher_identity

    def test_authenticated_packet_reopens_exact_service_attempts_and_workflows(self):
        self.assertEqual(qualify_delivery.validate_v02_publisher_packet(self.packet), [])
        self.assertNotIn("requirement_outcomes", self.packet)
        facts = self.identities()
        self.assertEqual(qualify_delivery.validate_v02_authenticated_packet(
            self.packet, self.packet["repository"], *facts), [])
        changed = copy.deepcopy(self.packet)
        changed["publisher"]["run_attempt"] = 2
        self.assertEqual(qualify_delivery.validate_v02_authenticated_packet(
            changed, changed["repository"], *facts), ["v02-publisher-run-attempt-mismatch"])

    def test_cancelled_or_missing_v02_qualification_and_each_unproven_claim_reject(self):
        changed = copy.deepcopy(self.packet)
        changed["prepublication_outcomes"]["PERF-03"] = "skipped"
        self.assertEqual(qualify_delivery.validate_v02_publisher_packet(changed),
                         ["v02-publisher-packet-prepublication-readiness-incomplete"])
        changed = copy.deepcopy(self.packet)
        changed["requirement_outcomes"] = {name: "pass" for name in qualify_delivery.V02_REQUIREMENTS}
        self.assertEqual(qualify_delivery.validate_v02_publisher_packet(changed),
                         ["v02-publisher-packet-final-claims-forbidden"])
        changed = copy.deepcopy(self.packet)
        changed["final_qualified"] = False
        self.assertEqual(qualify_delivery.validate_v02_publisher_packet(changed),
                         ["v02-publisher-packet-final-claims-forbidden"])
        run = self.identities()[0]
        run["jobs"] = [row for row in run["jobs"] if row["name"] != "v02-release-qualification"]
        self.assertEqual(qualify_delivery.validate_v02_qualification_run(run, SOURCE),
                         ["v02-qualification-job-missing-or-ambiguous"])
        run = self.identities()[0]
        next(row for row in run["jobs"] if row["name"] == "v02-release-qualification")["conclusion"] = "cancelled"
        self.assertEqual(qualify_delivery.validate_v02_qualification_run(run, SOURCE),
                         ["v02-qualification-job-not-success"])

    def test_packet_shape_does_not_authorize_download_when_service_facts_disagree(self):
        calls = []
        qualification, qualification_identity, publisher, publisher_identity = self.identities()
        service = {"12345": qualification, "67890": publisher}
        identities = {"repos/example/genewhip/actions/runs/12345/attempts/2": qualification_identity,
                      "repos/example/genewhip/actions/runs/67890/attempts/1": publisher_identity,
                      "repos/example/genewhip/releases/tags/v0.2.0": {"tag_name": "v0.2.0"},
                      "repos/example/genewhip/git/ref/tags/v0.2.0": {
                          "object": {"type": "commit", "sha": SOURCE}}}

        def gh_json(command):
            calls.append(command)
            if isinstance(command, list) and command[0] == "run":
                return service[command[2]]
            return identities[command[1]]

        with mock.patch.object(qualify_delivery, "_gh_json", side_effect=gh_json), \
                mock.patch.object(qualify_delivery, "_inspect_live_repository", return_value={}):
            facts = qualify_delivery.authenticate_v02_publisher_packet(self.packet)
        self.assertEqual(facts["tag_sha"], SOURCE)
        self.assertEqual(len(calls), 6)

        publisher_identity["run_attempt"] = 9
        with mock.patch.object(qualify_delivery, "_gh_json", side_effect=gh_json), \
                mock.patch.object(qualify_delivery, "_inspect_live_repository", return_value={}):
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "v02-publisher-workflow-attempt-mismatch"):
                qualify_delivery.authenticate_v02_publisher_packet(self.packet)

    def test_download_receipt_is_external_and_requires_all_claims_plus_exact_public_adoption(self):
        packet = copy.deepcopy(self.packet)
        release_info = {"tag": "v0.2.0", "assets": [
            {"name": name, "sha256": digest} for name, digest in packet["asset_digests"].items()]}
        docs = {"outcome": "pass", "mode": "public-downloaded", "local_source_identity": SOURCE,
                "commands": {name: "pass" for name in ("play", "build", "embed", "offline_source_core_build", "errors")},
                "packages": {
                    role: {"source_revision": SOURCE, "source_state": "clean",
                           "archive": ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
                                       "genewhip-0.2.0-playable-preview-macos-arm64-") + SOURCE[:12] + ".tar.gz",
                           "archive_sha256": packet["asset_digests"][
                               ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
                                "genewhip-0.2.0-playable-preview-macos-arm64-") + SOURCE[:12] + ".tar.gz"]}
                    for role in ("sdk", "desktop")},
                "processes": [{"process_group_cleanup": "confirmed"}]}
        receipt = qualify_delivery.make_v02_adoption_receipt(packet, release_info, docs)
        self.assertEqual(receipt["schema"], "genewhip-v02-downloaded-adoption-v1")
        self.assertTrue(receipt["final_qualified"])
        self.assertEqual(receipt["requirement_outcomes"],
                         {name: "pass" for name in qualify_delivery.V02_REQUIREMENTS})
        self.assertEqual(len(receipt["asset_digests"]), 8)
        self.assertNotIn("genewhip-v02-downloaded-adoption-v1", receipt["asset_digests"])
        docs["packages"]["sdk"]["source_state"] = "development-only"
        with self.assertRaisesRegex(qualify_delivery.DeliveryError, "downloaded-adoption-not-qualified"):
            qualify_delivery.make_v02_adoption_receipt(packet, release_info, docs)

    def test_failed_actual_adoption_writes_external_nonqualified_receipt(self):
        packet = copy.deepcopy(self.packet)
        inventory = b"synthetic inventory after publisher authentication"
        packet["inventory_sha256"] = hashlib.sha256(inventory).hexdigest()
        packet["asset_digests"]["inventory.json"] = packet["inventory_sha256"]
        with tempfile.TemporaryDirectory(dir=ROOT / "build/v02") as temporary:
            root = pathlib.Path(temporary)
            packet_path = root / "publisher-packet.json"
            packet_path.write_text(json.dumps(packet))
            download = root / "downloads"
            release_info = {"tag": "v0.2.0", "assets": [
                {"name": name, "sha256": digest} for name, digest in packet["asset_digests"].items()]}
            facts = {"release": {"draft": False}}
            args = argparse.Namespace(packet=packet, repository=packet["repository"],
                                      evidence=packet_path, evidence_out=root / "adoption.json",
                                      download_dir=download, authenticated_facts=facts)
            def fake_download(*_args):
                (download / "inventory.json").write_bytes(inventory)

            with mock.patch.object(qualify_delivery, "_gh", side_effect=fake_download), \
                    mock.patch.object(qualify_delivery, "verify_v02_subject_attestations"), \
                    mock.patch.object(qualify_delivery, "validate_release", return_value=release_info), \
                    mock.patch.object(qualify_delivery.subprocess, "run",
                                      return_value=mock.Mock(returncode=1, stdout="", stderr="")):
                with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                            "downloaded-package-adoption-smoke-failed"):
                    qualify_delivery.verify_v02_download(args)
            failure = json.loads((root / "adoption.json").read_text())
            self.assertFalse(failure["final_qualified"])
            self.assertEqual(failure["outcome"], "failed")
            self.assertEqual(failure["requirement_outcomes"],
                             {name: "not-qualified" for name in qualify_delivery.V02_REQUIREMENTS})

    def test_download_context_requires_authenticated_packet_before_repository_resolution(self):
        args = argparse.Namespace(version="0.2.0", release_tag="v0.2.0", evidence_out="build/v02/out.json",
                                  evidence="build/v02/publisher.json", source_sha=None, preflight=None,
                                  repository=None)
        with mock.patch.object(qualify_delivery, "_read_json", return_value=self.packet), \
                mock.patch.object(qualify_delivery, "authenticate_v02_publisher_packet",
                                  return_value={"trusted": True}) as auth:
            resolved = qualify_delivery.resolve_v02_download_context(args)
        self.assertEqual(resolved["repository"], "example/genewhip")
        self.assertEqual(args.repository, "example/genewhip")
        auth.assert_called_once_with(self.packet, "example/genewhip")
        args.repository = "attacker/fork"
        with mock.patch.object(qualify_delivery, "_read_json", return_value=self.packet):
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "v02-publisher-packet-repository-mismatch"):
                qualify_delivery.resolve_v02_download_context(args)

    def test_download_release_validator_checks_the_complete_v2_asset_roster_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = V02PublisherContract.make_inventory(directory)
            digests, blockers = promote.validate_release_inventory(directory, inventory)
            self.assertEqual(blockers, [])

            def release_value():
                assets = []
                for name, digest in digests.items():
                    path = directory / name
                    if name == "inventory.json":
                        size = (directory / name).stat().st_size
                    elif name == "SHA256SUMS":
                        size = (directory / name).stat().st_size
                    else:
                        size = inventory["assets"][name]["size"]
                    assets.append({"name": name, "size": size, "state": "uploaded",
                                   "digest": "sha256:" + digest,
                                   "browser_download_url":
                                       f"https://github.com/example/genewhip/releases/download/v0.2.0/{name}"})
                return {"tag_name": "v0.2.0", "draft": False, "prerelease": True,
                        "html_url": "https://github.com/example/genewhip/releases/tag/v0.2.0",
                        "assets": assets}

            info = qualify_delivery.validate_release(release_value(), "example/genewhip", "v0.2.0",
                                                      directory, SOURCE, "0.2.0")
            self.assertEqual(len(info["assets"]), 8)
            receipt_path = next(directory.glob("*.qualification.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["source_state"] = "development-only"
            receipt_path.write_text(json.dumps(receipt))
            V02PublisherContract.refresh_inventory(directory, inventory)
            digests, blockers = promote.validate_release_inventory(directory, inventory)
            self.assertEqual(blockers, [])
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "inventory-package-source-not-public"):
                qualify_delivery.validate_release(release_value(), "example/genewhip", "v0.2.0",
                                                   directory, SOURCE, "0.2.0")

    def test_authentication_precedes_provenance_verifier_and_every_asset_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            assets = self.packet["asset_digests"]
            for name in assets:
                (directory / name).write_bytes(name.encode())
                assets[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            assets["inventory.json"] = hashlib.sha256((directory / "inventory.json").read_bytes()).hexdigest()
            self.packet["inventory_sha256"] = assets["inventory.json"]
            calls = []
            with mock.patch.object(promote, "verify_attestation",
                                   side_effect=lambda *args: calls.append(args) or {"outcome": "verified"}):
                qualify_delivery.verify_v02_subject_attestations(directory, self.packet)
            self.assertEqual([call[0].name for call in calls], [
                name for name in assets if name.endswith(".tar.gz")] + ["inventory.json"])
            self.assertEqual(len(calls), 3)
            (directory / next(name for name in assets if name.endswith(".tar.gz"))).write_bytes(b"changed")
            calls.clear()
            with mock.patch.object(promote, "verify_attestation",
                                   side_effect=lambda *args: calls.append(args)):
                with self.assertRaisesRegex(qualify_delivery.DeliveryError, "release-asset-digest-mismatch"):
                    qualify_delivery.verify_v02_subject_attestations(directory, self.packet)
            self.assertEqual(calls, [])

    def test_attested_asset_size_is_bounded_before_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            for name in self.packet["asset_digests"]:
                (directory / name).write_bytes(b"small")
            oversized = next(name for name in self.packet["asset_digests"] if name.endswith(".tar.gz"))
            with mock.patch.object(promote, "MAX_RELEASE_ASSET_BYTES", 4):
                with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                            "release-asset-missing-or-invalid"):
                    qualify_delivery.verify_v02_subject_attestations(directory, self.packet)

    def test_public_docs_path_rejects_development_receipt_before_archive_verifier(self):
        spec = importlib.util.spec_from_file_location("gw_test_docs_commands",
                                                       ROOT / "tests/package/docs_commands.py")
        docs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(docs)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            name = f"genewhip-0.2.0-sdk-diagnostic-darwin-arm64-{SOURCE[:12]}.tar.gz"
            archive = directory / name
            archive.write_bytes(b"authenticated-by-caller-before-this-contract")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {name}\n")
            receipt_path = directory / (name + ".qualification.json")
            receipt = {"schema": "genewhip-local-package-qualification", "version": 2,
                       "release_version": "0.2.0", "source_revision": SOURCE,
                       "source_state": "development-only", "outcome": "pass", "archive": name,
                       "archive_sha256": digest, "smoke": {"outcome": "pass"}}
            receipt_path.write_text(json.dumps(receipt))
            with mock.patch.object(docs._SDK, "inspect_v02_archive") as verifier:
                with self.assertRaisesRegex(ValueError, "public-package-receipt-invalid"):
                    docs.verify_public_archive(directory, name, "sdk", SOURCE)
            verifier.assert_not_called()

    def test_public_docs_path_authenticates_before_any_package_verifier_or_command(self):
        spec = importlib.util.spec_from_file_location("gw_test_docs_commands_auth",
                                                       ROOT / "tests/package/docs_commands.py")
        docs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(docs)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/v02") as temporary:
            directory = pathlib.Path(temporary)
            packet_path = directory / "publisher-packet.json"
            packet_path.write_text(json.dumps(self.packet))
            with mock.patch.object(docs._DELIVERY, "validate_v02_publisher_packet", return_value=[]), \
                    mock.patch.object(docs.subprocess, "check_output", return_value=SOURCE), \
                    mock.patch.object(docs._DELIVERY, "authenticate_v02_publisher_packet",
                                      side_effect=qualify_delivery.DeliveryError("publisher-run-mismatch")), \
                    mock.patch.object(docs._SDK, "inspect_v02_archive") as verifier, \
                    mock.patch.object(docs, "run_bounded_anchor") as command:
                with self.assertRaisesRegex(qualify_delivery.DeliveryError, "publisher-run-mismatch"):
                    docs.run_v02(directory, offline=True, public_download=True,
                                 publisher_packet=packet_path)
            verifier.assert_not_called()
            command.assert_not_called()

    @staticmethod
    def refresh_inventory(directory, inventory):
        for name in list(inventory["assets"]):
            path = directory / name
            if not path.exists():
                del inventory["assets"][name]
            else:
                data = path.read_bytes()
                inventory["assets"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        inventory["assets"] = dict(sorted(inventory["assets"].items()))
        data = promote._json_bytes(inventory)
        (directory / "inventory.json").write_bytes(data)
        rows = {name: row["sha256"] for name, row in inventory["assets"].items()}
        rows["inventory.json"] = hashlib.sha256(data).hexdigest()
        (directory / "SHA256SUMS").write_bytes("".join(
            f"{digest}  {name}\n" for name, digest in sorted(rows.items())).encode())


if __name__ == "__main__":
    if "--publisher" in sys.argv:
        unittest.main(argv=[sys.argv[0], "V02PublisherContract"])
    elif "--download" in sys.argv:
        unittest.main(argv=[sys.argv[0], "V02DownloadContract"])
    else:
        unittest.main()
