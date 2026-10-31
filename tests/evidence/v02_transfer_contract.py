#!/usr/bin/env python3
"""Privacy and exact-member contracts for the scheduled runtime artifact export."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
import io
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gw_v02_transfer_contract", ROOT / "scripts/release/v02_transfer.py")
TRANSFER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFER)


class RuntimeTransferContract(unittest.TestCase):
    def _fixture(self, root, *, payload=bytes(320 * 224 * 4), unsafe_path=None):
        image_name = unsafe_path or "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
        image = root / image_name
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(payload)
        for name in TRANSFER.DIRECT_MEMBERS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name.endswith("runtime-identity.json"):
                body = json.dumps({"schema": "genewhip-v02-runtime-identity-v1",
                    "source_sha256": "a" * 64, "git_head": "a" * 40, "base_sha": "a" * 40,
                    "run_id": "123", "run_attempt": "4"}).encode()
            elif name.endswith("core-report.json"):
                body = json.dumps({"schema": "genewhip-phase6-product-report-v1", "runs": [
                    {"image": {"path": image_name, "sha256": hashlib.sha256(payload).hexdigest()}}]}).encode()
            elif name.endswith("runtime-observation.json"):
                body = json.dumps({"schema": "genewhip-v02-runtime-observation-v1", "status": "pass",
                    "observed": {}}).encode()
            elif name.endswith("execution-scope.json"):
                body = json.dumps({"schema": "genewhip-v02-execution-v1", "scope_id": "fixture"}).encode()
            elif name.endswith("candidate.json"):
                body = json.dumps({"schema": "genewhip-phase6-candidate-v1"}).encode()
            elif name.endswith("media-report.json"):
                body = json.dumps({"schema": "genewhip-phase6-media-v1", "result": "pass"}).encode()
            elif name.endswith(("host-software.json", "host-native.json")):
                body = json.dumps({"schema": "genewhip-phase6-host-v1", "backend": "software",
                    "outcome": "pass-diagnostic"}).encode()
            elif name.endswith("safety.json"):
                body = json.dumps({"schema": "genewhip-phase6-safety-v1", "status": "pass"}).encode()
            elif name.endswith("chunk.json"):
                body = json.dumps({"schema": "genewhip-phase6-chunk-v1", "status": "pass"}).encode()
            elif "/runtime/input-contract/" in name:
                body = json.dumps({"schema": "genewhip-phase6-sdl-virtual-input-contract-v1", "outcome": "pass"}).encode()
            elif name.endswith("safety-build-evidence.json"):
                body = json.dumps({"schema": "genewhip.v02-safety-build-evidence.v2", "entries": []}).encode()
            elif name.endswith("inventory.json"):
                body = json.dumps({"schema": "fixture-inventory"}).encode()
            else:
                body = json.dumps({"schema": "fixture-public", "outcome": "pass"}).encode()
            path.write_bytes(body)

    def test_export_preserves_all_dimension_inputs_and_exact_references(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            result = TRANSFER.export(root, out)
            self.assertGreaterEqual(result["member_count"], len(TRANSFER.DIRECT_MEMBERS) + 1)
            self.assertEqual(TRANSFER.verify(out / "payload", out / "inventory.json"), result)
            expected = {"build/v02/runtime-observation/core-report.json",
                "build/v02/runtime-observation/host-software.json",
                "build/v02/runtime-observation/host-native.json",
                "build/v02/runtime-observation/media-report.json",
                "build/v02/runtime-observation/safety.json",
                "build/v02/runtime-observation/chunk.json",
                "build/v02/runtime/input-contract/software.json",
                "build/v02/runtime/input-contract/native.json",
                "build/v02/public/manifest.json",
                "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"}
            self.assertTrue(expected.issubset(result["members"]))
            field_path = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
            self.assertEqual((out / "payload" / field_path).read_bytes(), bytes(320 * 224 * 4))
            installed = pathlib.Path(temp) / "installed"
            installed.mkdir()
            TRANSFER.install(out / "payload", out / "inventory.json", installed)
            self.assertEqual((installed / field_path).read_bytes(), bytes(320 * 224 * 4))

    def test_export_rejects_private_path_secret_and_unsafe_reference(self):
        cases = ((b"/" + b"Users" + b"/alice/private/project", "transfer-private-path"),
                 (b"ghp_" + b"abcdefghijklmnopqrstuvwxyz0123456789", "transfer-secret-pattern"),
                 (b"github_pat_" + b"a" * 40, "transfer-secret-pattern"),
                 (b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----", "transfer-secret-pattern"))
        for index, (payload, reason) in enumerate(cases):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-reject-") as temp:
                root = pathlib.Path(temp) / "project"
                root.mkdir()
                self._fixture(root, payload=payload.ljust(320 * 224 * 4, b"\x00"))
                with self.assertRaisesRegex(ValueError, reason):
                    TRANSFER.export(root, root / "build/v02/runtime-transfer")
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-path-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root, unsafe_path="../outside.bin")
            with self.assertRaisesRegex(ValueError, "transfer-reference-role-or-identity-invalid"):
                TRANSFER.export(root, root / "build/v02/runtime-transfer")
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-private-field-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            observation = root / "build/v02/runtime-observation.json"
            document = json.loads(observation.read_text())
            document["token"] = "fixture-token-value"
            observation.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "transfer-private-field:token"):
                TRANSFER.export(root, root / "build/v02/runtime-transfer")

    def test_download_verifier_rejects_unlisted_or_unsafe_member(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-unlisted-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            (out / "payload/build/v02/runtime/unlisted.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "transfer-unlisted-or-missing-member"):
                TRANSFER.verify(out / "payload", out / "inventory.json")

    def test_pinned_artifact_relative_root_installs_from_download_directory(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-artifact-layout-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            transfer_root = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, transfer_root)

            # upload-artifact v4 preserves paths relative to the least common
            # ancestor of the supplied paths: runtime-transfer here.
            extracted = pathlib.Path(temp) / "consumer/build/v02/runtime-transfer"
            extracted.mkdir(parents=True)
            for source in (transfer_root / "payload", transfer_root / "inventory.json"):
                destination = extracted / source.relative_to(transfer_root)
                if source.is_dir():
                    import shutil
                    shutil.copytree(source, destination)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
            installed = pathlib.Path(temp) / "consumer"
            self.assertEqual(TRANSFER.install(extracted / "payload", extracted / "inventory.json", installed)["member_count"],
                TRANSFER.verify(extracted / "payload", extracted / "inventory.json")["member_count"])

    def test_package_artifact_layout_verifies_before_install_and_rejects_unlisted_rom(self):
        with tempfile.TemporaryDirectory(prefix="gw-package-artifact-layout-") as temp:
            source_sha = "a" * 40  # Git revision, not the product-content digest.
            content_sha = "b" * 64
            runtime_identity = {"schema": "genewhip-v02-runtime-identity-v1",
                "source_sha256": content_sha, "git_head": source_sha, "base_sha": "c" * 40,
                "run_id": "123", "run_attempt": "2", "scope_sha256": "d" * 64,
                "candidate_sha256": "e" * 64, "build_identity": {key: "f" * 64 for key in
                    ("cmake_cache_sha256", "configuration_sha256", "headless_sha256", "desktop_sha256")}}
            identity = {"source_sha": source_sha, "head_sha": source_sha, "base_sha": "c" * 40,
                "run_id": "123", "run_attempt": "2"}
            candidate_name = "build/v02/runtime-observation/candidate.json"
            candidate_bytes = json.dumps({"schema": "genewhip-phase6-candidate-v1"}).encode()
            closure_paths = {candidate_name}
            payload = pathlib.Path(temp) / "producer/build/v02/package-transfer/payload"
            payload.mkdir(parents=True)
            names = TRANSFER.expected_package_members(source_sha, closure_paths)
            members = {}
            archive_bytes = io.BytesIO()
            with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                item = tarfile.TarInfo("README.txt")
                item.size = 7
                archive.addfile(item, io.BytesIO(b"offline\n"))
            for name in names:
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name.endswith(".tar.gz"):
                    data = archive_bytes.getvalue()
                elif name == "artifacts/release-assets/inventory.json":
                    data = json.dumps({"source_revision": source_sha,
                        "assets": {item: {} for item in TRANSFER._package_asset_names(source_sha)}}).encode()
                elif name == "build/v02/runtime-identity.json":
                    data = json.dumps(runtime_identity).encode()
                elif name == candidate_name:
                    data = candidate_bytes
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["core"]:
                    data = json.dumps({"schema": "genewhip-phase6-product-report-v1",
                        "candidate_manifest": {"path": candidate_name,
                            "sha256": hashlib.sha256(candidate_bytes).hexdigest()}}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["host"]:
                    data = json.dumps({"schema": "genewhip-phase6-host-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["host-native"]:
                    data = json.dumps({"schema": "genewhip-phase6-host-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["media"]:
                    data = json.dumps({"schema": "genewhip-phase6-media-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["safety"]:
                    data = json.dumps({"schema": "genewhip-phase6-safety-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["determinism"]:
                    data = json.dumps({"schema": "genewhip-phase6-chunk-v1"}).encode()
                else:
                    data = b"{}"
                path.write_bytes(data)
                members[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": identity,
                "dimensions": {name: {"path": TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS[name],
                    "sha256": members[TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS[name]]["sha256"], "identity": identity}
                    for name in TRANSFER.DIMENSIONS},
                "referenced_files": {candidate_name: hashlib.sha256(candidate_bytes).hexdigest()}}
            closure_bytes = json.dumps(closure).encode()
            closure_path = payload / "build/v02/qualification-evidence-closure.json"
            closure_path.write_bytes(closure_bytes)
            members["build/v02/qualification-evidence-closure.json"] = {
                "sha256": hashlib.sha256(closure_bytes).hexdigest(), "size": len(closure_bytes)}
            produced_names, produced_git, produced_content, _ = TRANSFER._package_files(payload,
                expected_git_revision=source_sha, expected_product_content_sha256=content_sha)
            self.assertEqual((produced_git, produced_content), (source_sha, content_sha))
            self.assertIn(candidate_name, produced_names)
            inventory = {"schema": "genewhip.v02-package-transfer.v1", "source_sha": source_sha,
                "product_content_sha256": content_sha,
                "members": members, "member_count": len(members),
                "total_bytes": sum(row["size"] for row in members.values())}
            self.assertEqual(inventory["source_sha"], source_sha)
            self.assertEqual(inventory["product_content_sha256"], content_sha)
            transfer_root = pathlib.Path(temp) / "producer/build/v02/package-transfer"
            inventory_path = transfer_root / "inventory.json"
            inventory_path.write_text(json.dumps(inventory))

            # Mirror the pinned upload-artifact root and download directory.
            extracted = pathlib.Path(temp) / "consumer/build/v02/package-transfer"
            import shutil
            shutil.copytree(transfer_root, extracted)
            consumer = pathlib.Path(temp) / "consumer"
            TRANSFER.install_package(extracted / "payload", extracted / "inventory.json", consumer,
                expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            self.assertTrue((consumer / "artifacts/release-assets/inventory.json").is_file())
            self.assertEqual((consumer / candidate_name).read_bytes(), candidate_bytes)

            for field, wrong in (("source_sha", content_sha), ("product_content_sha256", "9" * 64)):
                changed_identity = json.loads(json.dumps(inventory))
                changed_identity[field] = wrong
                inventory_path.write_text(json.dumps(changed_identity))
                with self.assertRaisesRegex(ValueError, "transfer-package-inventory-schema-or-roster"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            inventory_path.write_text(json.dumps(inventory))
            identity_path = extracted / "payload/build/v02/runtime-identity.json"
            for field, wrong in (("git_head", "9" * 40), ("source_sha256", "8" * 64)):
                changed_runtime_identity = dict(runtime_identity)
                changed_runtime_identity[field] = wrong
                changed_bytes = json.dumps(changed_runtime_identity).encode()
                identity_path.write_bytes(changed_bytes)
                changed_inventory = json.loads(json.dumps(inventory))
                changed_inventory["members"]["build/v02/runtime-identity.json"] = {
                    "sha256": hashlib.sha256(changed_bytes).hexdigest(), "size": len(changed_bytes)}
                changed_inventory["total_bytes"] = sum(row["size"] for row in changed_inventory["members"].values())
                inventory_path.write_text(json.dumps(changed_inventory))
                with self.assertRaisesRegex(ValueError, "transfer-package-source-identity-mismatch"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            identity_path.write_bytes(json.dumps(runtime_identity).encode())
            inventory_path.write_text(json.dumps(inventory))

            incomplete = json.loads(json.dumps(inventory))
            closure["referenced_files"] = {}
            changed_closure = json.dumps(closure).encode()
            closure_path.write_bytes(changed_closure)
            incomplete["members"].pop(candidate_name)
            incomplete["members"]["build/v02/qualification-evidence-closure.json"] = {
                "sha256": hashlib.sha256(changed_closure).hexdigest(), "size": len(changed_closure)}
            incomplete["member_count"] = len(incomplete["members"])
            incomplete["total_bytes"] = sum(row["size"] for row in incomplete["members"].values())
            (extracted / "payload" / candidate_name).unlink()
            (extracted / "inventory.json").write_text(json.dumps(incomplete))
            with self.assertRaisesRegex(ValueError, "transfer-package-evidence-reference-inventory-mismatch"):
                TRANSFER.verify_package(extracted / "payload", extracted / "inventory.json",
                    expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            closure_path.write_bytes(closure_bytes)
            shutil.rmtree(extracted)
            shutil.copytree(transfer_root, extracted)

            receipt_name = "artifacts/release-assets/SHA256SUMS"
            receipt_path = extracted / "payload" / receipt_name
            for secret in (b"/" + b"Users" + b"/alice/private/project", b"github_pat_" + b"a" * 40,
                           b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"):
                body = json.dumps({"evidence": secret.decode("ascii")}).encode()
                receipt_path.write_bytes(body)
                inventory["members"][receipt_name] = {"sha256": hashlib.sha256(body).hexdigest(),
                    "size": len(body)}
                inventory["total_bytes"] = sum(row["size"] for row in inventory["members"].values())
                inventory_path.write_text(json.dumps(inventory))
                with self.assertRaisesRegex(ValueError, "transfer-private-path|transfer-secret-pattern"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)

            private = extracted / "payload/build/v02/runtime-observation/private.rom"
            private.write_bytes(b"private")
            with self.assertRaisesRegex(ValueError, "transfer-package-unlisted-or-unsafe-member"):
                TRANSFER.verify_package(extracted / "payload", extracted / "inventory.json",
                    expected_source_sha=source_sha, expected_product_content_sha256=content_sha)

    def test_recomputed_inventory_and_reference_cannot_admit_private_rom(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-reference-mutant-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            payload = out / "payload"
            inventory_path = out / "inventory.json"
            inventory = json.loads(inventory_path.read_text())
            core_rel = "build/v02/runtime-observation/core-report.json"
            core_path = payload / core_rel
            report = json.loads(core_path.read_text())
            private_name = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/private.rom"
            private_data = b"private synthetic ROM member"
            private_path = payload / private_name
            private_path.parent.mkdir(parents=True, exist_ok=True)
            private_path.write_bytes(private_data)
            report["runs"][0]["image"] = {"path": private_name,
                "sha256": hashlib.sha256(private_data).hexdigest()}
            core_bytes = json.dumps(report).encode()
            core_path.write_bytes(core_bytes)
            inventory["members"][core_rel] = {"sha256": hashlib.sha256(core_bytes).hexdigest(), "size": len(core_bytes)}
            inventory["members"][private_name] = {"sha256": hashlib.sha256(private_data).hexdigest(),
                "size": len(private_data)}
            inventory["member_count"] = len(inventory["members"])
            inventory["total_bytes"] = sum(row["size"] for row in inventory["members"].values())
            inventory_path.write_text(json.dumps(inventory))
            with self.assertRaisesRegex(ValueError, "transfer-reference-role-or-identity-invalid|transfer-unsafe-entry|transfer-member-path-invalid"):
                TRANSFER.verify(payload, inventory_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
