#!/usr/bin/env python3
"""Contracts for exact-source downloaded Linux Libretro qualification."""
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.release import qualify_delivery

SOURCE = "a" * 40


def qualified_delivery_record():
    version = "0.3.0"
    tag = "v" + version
    repository = "szTheory/genewhip"
    archive = f"genewhip-{version}-linux-x86_64-libretro.tar.gz"
    names = {archive, archive + ".sha256", archive + ".qualification.json",
             "inventory.json", "SHA256SUMS"}
    hashes = {name: chr(ord("a") + index) * 64 for index, name in enumerate(sorted(names))}
    assets = [{"name": name, "sha256": hashes[name],
               "url": f"https://github.com/{repository}/releases/download/{tag}/{name}"}
              for name in sorted(names)]
    return {"schema": "genewhip-v03-libretro-delivery-v1", "outcome": "qualified",
            "repository": repository, "version": version, "release_tag": tag,
            "source_sha": SOURCE,
            "qualification": {"run_id": "12345", "run_attempt": 2,
                              "workflow": ".github/workflows/ci.yml"},
            "publisher": {"run_id": "77", "run_attempt": 1,
                          "workflow": ".github/workflows/release.yml",
                          "correlation_id": "corr-id-1234"},
            "asset_digests": hashes,
            "release": {"tag": tag, "version": version, "source_sha": SOURCE,
                        "release_url": f"https://github.com/{repository}/releases/tag/{tag}",
                        "assets": assets},
            "downloaded_bytes": "verified", "linux_adoption": "pass",
            "adoption": {"outcome": "pass", "host": "linux-x86_64-libretro_host",
                         "fixture": "generated-public-diagnostic", "source_sha": SOURCE,
                         "downloaded_archive_sha256": hashes[archive],
                         "downloaded_module_sha256": "f" * 64, "module_sha256": "f" * 64,
                         "adoption_workflow": ".github/workflows/libretro-adoption.yml@refs/heads/main",
                         "adoption_run_id": "88", "adoption_run_attempt": "1",
                         "qualification_run_id": "12345", "qualification_run_attempt": 2}}


class LibretroDeliveryContract(unittest.TestCase):
    def test_download_preflights_exact_server_roster_and_size_limits(self):
        evidence = qualified_delivery_record()
        rows = [{"name": row["name"], "size": 1, "state": "uploaded",
                 "browser_download_url": row["url"], "digest": "sha256:" + row["sha256"]}
                for row in evidence["release"]["assets"]]
        release = {"tag_name": "v0.3.0", "draft": False, "prerelease": True,
                   "html_url": evidence["release"]["release_url"], "assets": rows}
        qualify_delivery.preflight_v03_release_assets(release, "szTheory/genewhip", "v0.3.0", "0.3.0")
        oversized = [dict(row) for row in rows]
        oversized[0]["size"] = qualify_delivery.promote.MAX_LIBRETRO_ARCHIVE_BYTES + 1
        release["assets"] = oversized
        with self.assertRaisesRegex(qualify_delivery.DeliveryError, "release-asset-size-or-state-mismatch"):
            qualify_delivery.preflight_v03_release_assets(release, "szTheory/genewhip", "v0.3.0", "0.3.0")
        release["assets"] = rows[:-1]
        with self.assertRaisesRegex(qualify_delivery.DeliveryError, "release-asset-roster-mismatch"):
            qualify_delivery.preflight_v03_release_assets(release, "szTheory/genewhip", "v0.3.0", "0.3.0")

    def test_v03_download_cli_accepts_exact_qualification_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = [
                "qualify_delivery.py", "--verify", "--download-only",
                "--version", "0.3.0", "--repository", "example/genewhip",
                "--release-tag", "v0.3.0", "--source-sha", SOURCE,
                "--run-id", "12345", "--run-attempt", "2",
                "--download-dir", str(root / "download"),
                "--evidence-out", str(root / "delivery.json"),
            ]
            with mock.patch.object(sys, "argv", args), \
                    mock.patch.object(qualify_delivery, "resolve_v03_download_context",
                                      create=True, return_value={}) as resolve, \
                    mock.patch.object(qualify_delivery, "resolve_v02_download_context",
                                      return_value={}), \
                    mock.patch.object(qualify_delivery, "verify_release",
                                      return_value={"outcome": "pass"}), \
                    mock.patch("builtins.print"):
                try:
                    result = qualify_delivery.main()
                except SystemExit as error:
                    result = error.code
            self.assertEqual(result, 0)
            resolve.assert_called_once()
            parsed = resolve.call_args.args[0]
            self.assertEqual(parsed.repository, "example/genewhip")
            self.assertEqual(parsed.source_sha, SOURCE)
            self.assertEqual(parsed.run_id, "12345")
            self.assertEqual(parsed.run_attempt, 2)

    def test_v03_adoption_subprocesses_do_not_receive_github_token(self):
        import argparse
        import io
        import tarfile
        from unittest import mock
        (qualify_delivery.ROOT / "build/phase9").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=qualify_delivery.ROOT / "build/phase9") as temporary:
            root = pathlib.Path(temporary)
            download_dir = root / "download"
            download_dir.mkdir()
            archive_path = download_dir / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                payload = b"fixture module bytes"
                member = tarfile.TarInfo("genewhip_libretro.so")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            evidence = qualified_delivery_record()
            evidence["linux_adoption"] = "not_run"
            evidence.pop("adoption")
            expected_assets = set(evidence["asset_digests"])
            for name in expected_assets - {archive_path.name}:
                (download_dir / name).write_bytes(("verified " + name).encode())
            evidence["asset_digests"] = {
                path.name: __import__("hashlib").sha256(path.read_bytes()).hexdigest()
                for path in download_dir.iterdir()}
            evidence["release"]["assets"] = [
                {"name": name, "sha256": evidence["asset_digests"][name],
                 "url": f"https://github.com/szTheory/genewhip/releases/download/v0.3.0/{name}"}
                for name in sorted(expected_assets)]
            download_evidence = root / "download-evidence.json"
            evidence_out = root / "adoption.json"
            download_evidence.write_text(qualify_delivery.json.dumps(evidence))
            source_tree = root / "source"
            source_tree.mkdir()
            args = argparse.Namespace(version="0.3.0", release_tag="v0.3.0",
                repository="szTheory/genewhip", source_sha=SOURCE, run_id="12345",
                run_attempt=2, source_tree=source_tree, evidence=download_evidence,
                evidence_out=evidence_out, download_dir=download_dir)
            calls = []
            def fake_run(command, **kwargs):
                calls.append(kwargs)
                if command[:2] == ["git", "rev-parse"]:
                    return type("Result", (), {"stdout": SOURCE})()
                return type("Result", (), {"returncode": 0})()
            with mock.patch.dict(qualify_delivery.os.environ,
                                 {"GH_TOKEN": "test-token", "GITHUB_RUN_ID": "88",
                                  "GITHUB_RUN_ATTEMPT": "1",
                                  "GITHUB_WORKFLOW_REF": ".github/workflows/libretro-adoption.yml@refs/heads/main"}), \
                 mock.patch.object(qualify_delivery.platform, "system", return_value="Linux"), \
                 mock.patch.object(qualify_delivery.platform, "machine", return_value="x86_64"):
                with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                            "linux-adoption-requires-credential-free-process"):
                    qualify_delivery.run_v03_linux_adoption(args, download_dir, evidence)
            self.assertEqual(calls, [], "credentialed process must not launch native code")
            calls.clear()
            clean_env = {key: value for key, value in qualify_delivery.os.environ.items()
                         if key != "GH_TOKEN"}
            clean_env.update({"GITHUB_RUN_ID": "88", "GITHUB_RUN_ATTEMPT": "1",
                              "GITHUB_WORKFLOW_REF": ".github/workflows/libretro-adoption.yml@refs/heads/main"})
            with mock.patch.dict(qualify_delivery.os.environ, clean_env, clear=True), \
                 mock.patch.object(qualify_delivery.platform, "system", return_value="Linux"), \
                 mock.patch.object(qualify_delivery.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(qualify_delivery.subprocess, "run", side_effect=fake_run), \
                 mock.patch.object(qualify_delivery, "_gh", side_effect=AssertionError("network not allowed")), \
                 mock.patch.object(qualify_delivery, "_gh_json", side_effect=AssertionError("network not allowed")):
                receipt = qualify_delivery.adopt_verified_v03(args)
            self.assertEqual(receipt["linux_adoption"], "pass")
            self.assertEqual(receipt["outcome"], "qualified")
            self.assertEqual(len(calls), 4)
            self.assertTrue(all("GH_TOKEN" not in call["env"] for call in calls))
            self.assertTrue(evidence_out.is_file())
            (download_dir / "SHA256SUMS").write_text("tampered", encoding="utf-8")
            calls.clear()
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "verified-download-asset-digest-mismatch"):
                qualify_delivery.adopt_verified_v03(args)
            self.assertEqual(calls, [], "tampered-download-must-be-rejected-before-build")

    def test_v03_adopt_verified_cli_uses_local_identity_and_source_tree(self):
        from unittest import mock
        args = ["qualify_delivery.py", "--adopt-verified", "--version", "0.3.0",
                "--release-tag", "v0.3.0", "--repository", "szTheory/genewhip",
                "--source-sha", SOURCE, "--run-id", "12345", "--run-attempt", "2",
                "--source-tree", "build/phase9/source",
                "--download-dir", "build/phase9/downloaded-release",
                "--evidence", "build/phase9/downloaded-release-evidence.json",
                "--evidence-out", "build/phase9/libretro-adoption.json"]
        with mock.patch.object(sys, "argv", args), \
             mock.patch.object(qualify_delivery, "adopt_verified_v03",
                               return_value={"outcome": "qualified"}) as adopt, \
             mock.patch("builtins.print"):
            self.assertEqual(qualify_delivery.main(), 0)
        received = adopt.call_args.args[0]
        self.assertEqual(received.repository, "szTheory/genewhip")
        self.assertEqual(received.source_sha, SOURCE)
        self.assertEqual(received.source_tree, pathlib.Path("build/phase9/source"))
        self.assertTrue(received.adopt_verified)

    def test_v03_source_run_requires_exact_push_source_and_single_successful_jobs(self):
        args = type("Args", (), {"version": "0.3.0", "release_tag": "v0.3.0",
                                  "repository": "example/genewhip", "source_sha": SOURCE,
                                  "run_id": "12345", "run_attempt": 2,
                                  "evidence_out": pathlib.Path("build/phase9/evidence.json"),
                                  "download_dir": pathlib.Path("build/phase9/download")})()
        good_run = {"event": "push", "headSha": SOURCE, "status": "completed",
                    "conclusion": "success", "databaseId": 12345, "attempt": 2,
                    "jobs": [{"name": name, "status": "completed", "conclusion": "success"}
                             for name in ("required-ci", "libretro", "attestation")]}
        good_identity = {"path": ".github/workflows/ci.yml", "head_sha": SOURCE, "event": "push",
                         "status": "completed", "conclusion": "success", "head_branch": "main",
                         "id": 12345, "run_attempt": 2}
        with mock.patch.object(qualify_delivery, "_gh_json", side_effect=[good_run, good_identity]):
            self.assertEqual(qualify_delivery.resolve_v03_download_context(args)["run"], good_run)
        bad = dict(good_run, event="pull_request")
        with mock.patch.object(qualify_delivery, "_gh_json", return_value=bad):
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "libretro-source-run-identity-invalid"):
                qualify_delivery.resolve_v03_download_context(args)

    def test_v03_provenance_verifies_before_production_archive_parser(self):
        order = []
        pathlib.Path("build/phase9").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=pathlib.Path("build/phase9")) as temporary:
            root = pathlib.Path(temporary)
            source_dir, directory = root / "source", root / "download"
            source_dir.mkdir()
            directory.mkdir()
            archive = source_dir / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz"
            archive.write_bytes(b"x")
            sidecar = source_dir / (archive.name + ".sha256")
            sidecar.write_bytes(b"x")
            receipt = source_dir / (archive.name + ".qualification.json")
            receipt.write_bytes(b"{}")
            (source_dir / "SHA256SUMS").write_bytes(b"x")
            inventory = {"version": "0.3.0", "run_id": "12345", "run_attempt": "2",
                         "assets": {p.name: {"size": p.stat().st_size,
                            "sha256": qualify_delivery.hashlib.sha256(p.read_bytes()).hexdigest()}
                            for p in (archive, sidecar, receipt)}}
            (source_dir / "inventory.json").write_text(qualify_delivery.json.dumps(inventory))
            remote_assets = [{"name": path.name, "size": path.stat().st_size, "state": "uploaded",
                              "browser_download_url": f"https://github.com/example/genewhip/releases/download/v0.3.0/{path.name}",
                              "digest": "sha256:" + qualify_delivery.hashlib.sha256(path.read_bytes()).hexdigest()}
                             for path in source_dir.iterdir()]
            def download(*_args):
                for path in source_dir.iterdir():
                    (directory / path.name).write_bytes(path.read_bytes())
            args = type("Args", (), {"v03_context": {}, "repository": "example/genewhip",
                "version": "0.3.0", "release_tag": "v0.3.0", "source_sha": SOURCE,
                "run_id": "12345", "run_attempt": 2, "download_dir": directory,
                "evidence_out": pathlib.Path("build/phase9/evidence.json"), "linux_adoption": False})()
            with mock.patch.object(qualify_delivery, "resolve_v03_download_context", return_value={}), \
                    mock.patch.object(qualify_delivery, "_safe_path", return_value=directory), \
                    mock.patch.object(qualify_delivery, "_gh_json", side_effect=[
                        {"tag_name": "v0.3.0", "draft": False, "prerelease": True,
                         "html_url": "https://github.com/example/genewhip/releases/tag/v0.3.0",
                         "assets": remote_assets},
                        {"workflow_runs": [{"display_title": f"Preview release for {SOURCE} (qualification 12345 attempt 2; dispatch corr-id-1234)",
                            "status": "completed", "conclusion": "success", "head_branch": "main",
                            "path": ".github/workflows/release.yml", "id": 77, "run_attempt": 1,
                            "head_sha": SOURCE}]},
                        {"path": ".github/workflows/release.yml", "head_sha": SOURCE,
                         "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
                         "head_branch": "main", "id": 77, "run_attempt": 1},
                        {"event": "workflow_dispatch", "headSha": SOURCE, "status": "completed",
                         "conclusion": "success", "databaseId": 77, "attempt": 1,
                         "displayTitle": f"Preview release for {SOURCE} (qualification 12345 attempt 2; dispatch corr-id-1234)",
                         "jobs": [{"name": "promote", "conclusion": "success"}]},
                        {"object": {"sha": SOURCE}}]), \
                    mock.patch.object(qualify_delivery, "_gh", side_effect=download), \
                    mock.patch.object(qualify_delivery.promote, "verify_attestation",
                                      side_effect=lambda *a, **k: order.append("attestation") or {}), \
                    mock.patch.object(qualify_delivery.promote, "validate_v03_libretro_inventory",
                                      side_effect=lambda *a: order.append("archive-parser") or []), \
                    mock.patch.object(qualify_delivery, "validate_release", return_value={"tag": "v0.3.0",
                        "version": "0.3.0", "source_sha": SOURCE, "release_url": "https://example.invalid",
                        "assets": []}), \
                    mock.patch.object(qualify_delivery, "_write_json"):
                qualify_delivery.verify_v03_download(args)
            self.assertEqual(order[-1], "archive-parser")
            self.assertTrue(all(value == "attestation" for value in order[:-1]))

    def test_complete_delivery_record_has_exact_release_and_adoption_identities(self):
        evidence = qualified_delivery_record()
        self.assertEqual(qualify_delivery.validate_v03_delivery_record(evidence), [])
        evidence["outcome"] = "failed"
        self.assertEqual(qualify_delivery.validate_v03_delivery_record(evidence),
                         ["libretro-evidence-release-identity-invalid"])

    def test_incomplete_evidence_is_not_accepted_as_release_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "evidence.json"
            path.write_text('{"schema":"genewhip-v03-libretro-delivery-v1",'
                            '"outcome":"qualified","downloaded_bytes":"verified"}')
            output = []
            with mock.patch.object(sys, "argv", ["qualify_delivery.py", "--validate-libretro-evidence", str(path)]), \
                    mock.patch("builtins.print", side_effect=lambda value, **_kwargs: output.append(value)):
                self.assertEqual(qualify_delivery.main(), 1)
            self.assertIn("BLOCKED: libretro-evidence-release-identity-invalid", output[0])

    def test_evidence_cli_marks_external_claims_as_not_reverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "evidence.json"
            path.write_text(qualify_delivery.json.dumps(qualified_delivery_record()))
            output = []
            with mock.patch.object(sys, "argv", ["qualify_delivery.py", "--validate-libretro-evidence", str(path)]), \
                    mock.patch("builtins.print", side_effect=lambda value, **_kwargs: output.append(value)):
                self.assertEqual(qualify_delivery.main(), 0)
            result = qualify_delivery.json.loads(output[0])
            self.assertTrue(result["record_complete"])
            self.assertFalse(result["external_claims_reverified"])

    def test_non_linux_host_cannot_receive_linux_adoption_credit(self):
        args = type("Args", (), {"source_sha": SOURCE})()
        with mock.patch.object(qualify_delivery.platform, "system", return_value="Darwin"), \
                mock.patch.object(qualify_delivery.subprocess, "run") as run:
            with self.assertRaisesRegex(qualify_delivery.DeliveryError,
                                        "linux-adoption-requires-linux-x86_64"):
                qualify_delivery.run_v03_linux_adoption(args, pathlib.Path("unused"), {})
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
