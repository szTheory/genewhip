#!/usr/bin/env python3
"""Release inventory and retry state machine contract, with no live API claims."""
import json
import io
import pathlib
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from scripts.release.promote import (release_plan, sha256_bytes,
                                     validate_qualified_inventory, validate_release_inventory)


SOURCE = "a" * 40
ASSETS = {"sdk.tar.gz": "1" * 64, "desktop.tar.gz": "2" * 64,
          "inventory.json": "3" * 64, "SHA256SUMS": "4" * 64}


def release(rows=None, published=False, tag_sha=SOURCE):
    return {"tag_sha": tag_sha, "published": published,
            "assets": list(rows if rows is not None else
                           ({"name": name, "sha256": digest} for name, digest in ASSETS.items()))}


class ReleaseRetryContract(unittest.TestCase):
    def qualified_package_fixture(self, directory):
        packages = {
            "SDL-free API 4 SDK archive": ("sdk-diagnostic-darwin-arm64", {
                "SingleStepTests-LICENSE", "THIRD-PARTY-ymfm.txt", "diagnostic-evidence.json", "metadata.json"}),
            "native macOS arm64 desktop archive": ("playable-preview-macos-arm64", {
                "LICENSE", "SDL3-LICENSE.txt", "THIRD-PARTY-ymfm.txt", "phase4-evidence.json",
                "phase4-gameplay.json", "manifest.json"}),
        }
        assets = {}
        for kind, (name, members) in packages.items():
            archive = f"genewhip-0.1.0-{name}-{SOURCE[:12]}.tar.gz"
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w:gz") as tar:
                for member_name in sorted(members):
                    content = member_name.encode()
                    info = tarfile.TarInfo(member_name)
                    info.size = len(content)
                    tar.addfile(info, io.BytesIO(content))
            data = payload.getvalue()
            digest = sha256_bytes(data)
            receipt = {"schema": "genewhip-local-package-qualification", "outcome": "pass",
                       "kind": kind, "source_revision": SOURCE, "archive": archive,
                       "archive_sha256": digest}
            (directory / archive).write_bytes(data)
            (directory / (archive + ".sha256")).write_text(f"{digest}  {archive}\n")
            receipt_name = archive + ".qualification.json"
            (directory / receipt_name).write_text(json.dumps(receipt))
            for filename, content in ((archive, data), (archive + ".sha256", f"{digest}  {archive}\n".encode()),
                                      (receipt_name, (directory / receipt_name).read_bytes())):
                assets[filename] = {"sha256": sha256_bytes(content), "size": len(content)}
        return {"schema": "genewhip.release-inventory.v1", "version": "0.1.0",
                "source_revision": SOURCE, "assets": assets}

    def test_zero_assets_never_create_a_publishable_release(self):
        result = release_plan(None, None, SOURCE, {})
        self.assertEqual(result["reason"], "inventory-empty")
        self.assertFalse(result["publish"])

    def test_one_uploaded_asset_resumes_only_missing_assets(self):
        result = release_plan(release([{"name": "sdk.tar.gz", "sha256": ASSETS["sdk.tar.gz"]}]),
                              SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["state"], "resume-draft")
        self.assertEqual(result["upload"], sorted(set(ASSETS) - {"sdk.tar.gz"}))
        self.assertFalse(result["publish"])

    def test_complete_draft_becomes_publishable_only_after_all_assets_exist(self):
        result = release_plan(release(), SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["state"], "resume-draft")
        self.assertEqual(result["upload"], [])
        self.assertTrue(result["publish"])

    def test_identical_published_inventory_is_a_no_op(self):
        result = release_plan(release(published=True), SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["state"], "no-op")
        self.assertFalse(result["publish"])

    def test_published_partial_inventory_fails_without_upload(self):
        result = release_plan(release([{"name": "sdk.tar.gz", "sha256": ASSETS["sdk.tar.gz"]}], True),
                              SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["reason"], "published-inventory-incomplete")
        self.assertEqual(result["upload"], [])

    def test_wrong_tag_source_fails_without_mutation(self):
        result = release_plan(None, "b" * 40, SOURCE, ASSETS)
        self.assertEqual(result["reason"], "tag-source-conflict")
        self.assertEqual(result["upload"], [])

    def test_release_source_conflict_fails_without_overwrite(self):
        result = release_plan(release(tag_sha="b" * 40), SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["reason"], "release-source-conflict")

    def test_conflicting_asset_digest_fails_by_name(self):
        result = release_plan(release([{"name": "sdk.tar.gz", "sha256": "f" * 64}]),
                              SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["reason"], "release-asset-conflict")

    def test_duplicate_asset_names_fail_even_when_digests_match(self):
        rows = [{"name": "sdk.tar.gz", "sha256": ASSETS["sdk.tar.gz"]}] * 2
        result = release_plan(release(rows), SOURCE, SOURCE, ASSETS)
        self.assertEqual(result["reason"], "release-duplicate-asset-name")

    def test_asset_response_order_does_not_change_retry_decision(self):
        rows = [{"name": name, "sha256": digest} for name, digest in ASSETS.items()]
        forward = release_plan(release(rows), SOURCE, SOURCE, ASSETS)
        reverse = release_plan(release(list(reversed(rows))), SOURCE, SOURCE, ASSETS)
        self.assertEqual(forward, reverse)

    def test_retried_ambiguous_public_transition_converges_to_no_op(self):
        after_response_timeout = release_plan(release(published=True), SOURCE, SOURCE, ASSETS)
        self.assertEqual(after_response_timeout["state"], "no-op")

    def test_empty_or_partial_local_inventory_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = {"schema": "genewhip.release-inventory.v1", "assets": {}}
            _, empty_blockers = validate_release_inventory(directory, inventory)
            self.assertEqual(empty_blockers, ["inventory-empty"])
            inventory["assets"] = {"sdk.tar.gz": {"sha256": "1" * 64, "size": 1}}
            (directory / "sdk.tar.gz").write_bytes(b"x")
            _, partial_blockers = validate_release_inventory(directory, inventory)
            self.assertEqual(partial_blockers, ["inventory-incomplete"])

    def test_complete_local_inventory_checks_bytes_checksum_and_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            values = {"sdk.tar.gz": b"sdk", "desktop.tar.gz": b"desktop"}
            rows = {name: {"sha256": sha256_bytes(data), "size": len(data)}
                    for name, data in values.items()}
            inventory = {"schema": "genewhip.release-inventory.v1", "assets": rows}
            inventory_data = (json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n").encode()
            values["inventory.json"] = inventory_data
            sums = {name: sha256_bytes(data) for name, data in values.items()}
            values["SHA256SUMS"] = "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())).encode()
            for name, data in values.items():
                (directory / name).write_bytes(data)
            digests, blockers = validate_release_inventory(directory, inventory)
            self.assertEqual(blockers, [])
            self.assertEqual(set(digests), set(values))

    def test_modified_local_asset_is_rejected_by_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            original = b"original"
            inventory = {"schema": "genewhip.release-inventory.v1",
                         "assets": {"sdk.tar.gz": {"sha256": sha256_bytes(original),
                                                    "size": len(original)}}}
            inventory_data = (json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n").encode()
            sums = {"sdk.tar.gz": sha256_bytes(original), "inventory.json": sha256_bytes(inventory_data)}
            (directory / "inventory.json").write_bytes(inventory_data)
            (directory / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())))
            (directory / "sdk.tar.gz").write_bytes(b"changed")
            _, blockers = validate_release_inventory(directory, inventory)
            self.assertEqual(blockers, ["inventory-digest-mismatch"])

    def test_incomplete_sdk_desktop_qualification_roster_is_rejected(self):
        sdk = "genewhip-0.1.0-sdk-diagnostic-darwin-arm64-" + SOURCE[:12] + ".tar.gz"
        inventory = {"schema": "genewhip.release-inventory.v1", "version": "0.1.0",
                     "source_revision": SOURCE,
                     "assets": {name: {"sha256": "1" * 64, "size": 1}
                                for name in (sdk, sdk + ".sha256", sdk + ".qualification.json")}}
        blockers = validate_qualified_inventory(pathlib.Path("."), inventory, SOURCE)
        self.assertEqual(blockers, ["inventory-package-roster-incomplete"])

    def test_exact_sdk_desktop_roster_requires_matching_receipts_and_package_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = self.qualified_package_fixture(directory)
            self.assertEqual(validate_qualified_inventory(directory, inventory, SOURCE), [])

    def test_receipt_bound_to_another_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            inventory = self.qualified_package_fixture(directory)
            receipt_path = next(directory.glob("*sdk*.qualification.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["source_revision"] = "b" * 40
            receipt_path.write_text(json.dumps(receipt))
            inventory["assets"][receipt_path.name] = {
                "sha256": sha256_bytes(receipt_path.read_bytes()), "size": receipt_path.stat().st_size}
            self.assertEqual(validate_qualified_inventory(directory, inventory, SOURCE),
                             ["inventory-package-receipt-invalid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
