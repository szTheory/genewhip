#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run anchored adoption examples against local source and exact packages."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_SDK_SPEC = importlib.util.spec_from_file_location("gw_docs_sdk", ROOT / "tests/package/smoke.py")
_SDK = importlib.util.module_from_spec(_SDK_SPEC)
_SDK_SPEC.loader.exec_module(_SDK)
_DESKTOP_SPEC = importlib.util.spec_from_file_location("gw_docs_desktop", ROOT / "tests/package/desktop_smoke.py")
_DESKTOP = importlib.util.module_from_spec(_DESKTOP_SPEC)
_DESKTOP_SPEC.loader.exec_module(_DESKTOP)


def fresh_scratch(parent):
    """Create a unique directory for one docs-command invocation."""
    return pathlib.Path(tempfile.mkdtemp(prefix="gw-doc-command-", dir=parent))


def run_isolated(parent, action):
    """Run action in disposable scratch, cleaning it even when interrupted."""
    scratch = fresh_scratch(parent)
    try:
        return action(scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def anchored_shell_block(markdown, anchor):
    """Return the first sh block following an explicit HTML anchor."""
    marker = f'<a id="{anchor}"></a>'
    position = markdown.find(marker)
    if position < 0:
        raise ValueError("documented-command-anchor-missing:" + anchor)
    fence_start = markdown.find("```sh\n", position + len(marker))
    if fence_start < 0:
        raise ValueError("documented-command-block-missing:" + anchor)
    body_start = fence_start + len("```sh\n")
    fence_end = markdown.find("\n```", body_start)
    if fence_end < 0:
        raise ValueError("documented-command-block-unclosed:" + anchor)
    return markdown[body_start:fence_end] + "\n"


def run_documented_shell(markdown_path, anchor, env, *, audio_dummy=False, timeout=300):
    block = anchored_shell_block(pathlib.Path(markdown_path).read_text(), anchor)
    command_env = dict(os.environ, **env)
    if audio_dummy:
        command_env.update(SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
    result = subprocess.run(["bash", "-euo", "pipefail", "-c", block], cwd=ROOT,
                            env=command_env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("documented-command-failed:" + anchor + ":exit=" + str(result.returncode))
    return result.stdout


def resolve_package_names(inventory, source_revision):
    if not isinstance(source_revision, str) or len(source_revision) != 40 \
            or any(char not in "0123456789abcdef" for char in source_revision):
        raise ValueError("package-source-revision")
    if inventory is not None and (inventory.get("source_revision") != source_revision
                                  or inventory.get("version") != "0.1.0"):
        raise ValueError("package-inventory-source")
    assets = inventory.get("assets") if inventory is not None else None
    if inventory is not None and not isinstance(assets, dict):
        raise ValueError("package-inventory-assets")
    names = {
        "sdk": f"genewhip-0.1.0-sdk-diagnostic-darwin-arm64-{source_revision[:12]}.tar.gz",
        "desktop": f"genewhip-0.1.0-playable-preview-macos-arm64-{source_revision[:12]}.tar.gz",
    }
    for name in names.values():
        if assets is not None and (name not in assets or name + ".sha256" not in assets
                                   or name + ".qualification.json" not in assets):
            raise ValueError("package-inventory-roster")
    return names


def validate_release_url(release_url):
    expected = "https://github.com/szTheory/genewhip/releases/tag/v0.1.0"
    if release_url != expected:
        raise ValueError("release-url-identity")
    return expected


def verify_published_download(artifact_dir, release_url):
    """Execute the documented GitHub release acquisition and compare every byte."""
    validate_release_url(release_url)
    artifact_dir = pathlib.Path(artifact_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="gw-release-download-") as temporary:
        result = subprocess.run(["gh", "release", "download", "v0.1.0", "--repo",
                                 "szTheory/genewhip", "--dir", temporary], cwd=ROOT,
                                capture_output=True, text=True, timeout=300, check=False)
        if result.returncode:
            raise RuntimeError("published-download-command-failed")
        downloaded = pathlib.Path(temporary)
        expected_names = {path.name for path in artifact_dir.iterdir() if path.is_file()}
        actual_names = {path.name for path in downloaded.iterdir() if path.is_file()}
        if actual_names != expected_names:
            raise ValueError("published-download-roster")
        for name in expected_names:
            if hashlib.sha256((downloaded / name).read_bytes()).digest() != \
                    hashlib.sha256((artifact_dir / name).read_bytes()).digest():
                raise ValueError("published-download-byte-mismatch")


def verify_receipt(archive, receipt_path, expected_name, source_revision):
    receipt = json.loads(receipt_path.read_text())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if receipt.get("outcome") != "pass" or receipt.get("archive") != expected_name:
        raise ValueError("local-receipt-identity")
    if receipt.get("source_revision") != source_revision or receipt.get("archive_sha256") != digest:
        raise ValueError("local-receipt-identity")
    if not str(receipt.get("publication", "")).startswith("not published"):
        raise ValueError("local-receipt-publication")
    with tarfile.open(archive, "r:*") as tar:
        root = pathlib.PurePosixPath(next(m.name for m in tar.getmembers() if m.isfile())).parts[0]
        inventory = tar.extractfile(root + "/checksums.json").read()
    if hashlib.sha256(inventory).hexdigest() != receipt.get("inventory_sha256"):
        raise ValueError("local-receipt-inventory")
    sidecar = archive.with_suffix(archive.suffix + ".sha256")
    line = sidecar.read_text().split()
    if len(line) < 2 or line[0] != digest or line[1] != archive.name:
        raise ValueError("local-sidecar-checksum")
    return receipt, digest


def verify_wrong_checksum(archive, revision, checker):
    try:
        checker(archive, "0" * 64, revision)
    except ValueError as error:
        if str(error) != "archive-checksum":
            raise ValueError("wrong-checksum-reason:" + str(error)) from error
    else:
        raise ValueError("wrong-checksum-not-rejected")


def run_package_smoke(script, archive, digest, revision, expected_fields=None):
    result = subprocess.run([os.sys.executable, str(script), str(archive), digest, revision],
                            cwd=ROOT, capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError("package-smoke-failed:" + script.name + ":exit=" + str(result.returncode))
    report = json.loads(result.stdout.splitlines()[-1])
    if report.get("outcome") != "pass":
        raise ValueError("package-smoke-outcome")
    if expected_fields is not None and (report.get("game_cases") != 6 or report.get("game_fields") != expected_fields):
        raise ValueError("package-game-denominator")
    return report


def run_all(artifact_dir, release_url=None):
    artifact_dir = pathlib.Path(artifact_dir).resolve()
    inventory_path = artifact_dir / "inventory.json"
    inventory = json.loads(inventory_path.read_text()) if inventory_path.is_file() else None
    source_revision = (inventory.get("source_revision") if inventory is not None else
                       subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                               text=True).strip())
    names = resolve_package_names(inventory, source_revision)
    if release_url:
        verify_published_download(artifact_dir, release_url)
    sdk_name, desktop_name = names["sdk"], names["desktop"]
    sdk_archive = artifact_dir / sdk_name
    desktop_archive = artifact_dir / desktop_name
    sdk_receipt, sdk_digest = verify_receipt(
        sdk_archive, artifact_dir / (sdk_name + ".qualification.json"), sdk_name, source_revision)
    desktop_receipt, desktop_digest = verify_receipt(
        desktop_archive, artifact_dir / (desktop_name + ".qualification.json"), desktop_name, source_revision)
    with tempfile.TemporaryDirectory(prefix="gw-doc-commands-") as outer:
        parent = pathlib.Path(outer)
        # Execute the exact documented source build and relocated consumer command.
        source_report = run_isolated(parent, lambda scratch: run_documented_shell(
            ROOT / "README.md", "source-build", {"BUILD_DIR": str(scratch / "source-build")}, timeout=300))
        # Execute exact local checksum/extract examples from both package guides.
        run_documented_shell(ROOT / "packaging/README.md", "sdk-local-verify-extract",
                             {"ARTIFACT_DIR": str(artifact_dir), "EXTRACT_DIR": str(parent / "sdk-extract"),
                              "SDK_ARCHIVE": sdk_name})
        run_documented_shell(ROOT / "packaging/desktop/README.md", "desktop-local-verify-extract-run",
                             {"ARTIFACT_DIR": str(artifact_dir), "EXTRACT_DIR": str(parent / "desktop-extract"),
                              "DESKTOP_ARCHIVE": desktop_name},
                             audio_dummy=True)
        sdk_smoke = run_package_smoke(ROOT / "tests/package/smoke.py", sdk_archive,
                                      sdk_digest, source_revision)
        desktop_smoke = run_package_smoke(ROOT / "tests/package/desktop_smoke.py", desktop_archive,
                                          desktop_digest, source_revision, expected_fields=840)
        if sdk_smoke.get("c_consumer") != "pass" or sdk_smoke.get("cpp_header") != "pass":
            raise ValueError("sdk-external-consumer-not-verified")
        if desktop_smoke.get("negative_controls") != 12 or desktop_smoke.get("truncated_cartridge") != "rejected":
            raise ValueError("desktop-package-negative-control-not-verified")
        verify_wrong_checksum(sdk_archive, source_revision, _SDK.inspect_archive)
        verify_wrong_checksum(desktop_archive, source_revision, _DESKTOP.validate_archive)
    return {
        "schema": "genewhip-adoption-doc-commands", "version": 1, "outcome": "pass",
        "source_build_consumer": "pass", "sdk_c_cpp_consumer": sdk_smoke.get("c_consumer") == "pass"
        and sdk_smoke.get("cpp_header") == "pass", "sdk_archive": sdk_digest,
        "desktop_archive": desktop_digest, "desktop_cases": desktop_smoke["game_cases"],
        "desktop_fields": desktop_smoke["game_fields"], "wrong_checksum": "archive-checksum",
        "incompatible_api": sdk_smoke.get("incompatible_api"),
        "incompatible_input_log": desktop_smoke.get("incompatible_input_log"),
        "drop_reload": desktop_smoke.get("drop_reload"),
        "truncated_cartridge": desktop_smoke.get("truncated_cartridge"),
        "negative_controls": desktop_smoke.get("negative_controls"),
        "qualified_archive_negative_controls": desktop_receipt["smoke"].get("negative_controls"),
        "release_download": release_url or "pending: no published asset or URL",
        "source_build_output_bytes": len(source_report.encode("utf-8")),
        "source_revision": source_revision,
        "release_claim": "published exact qualified archives" if release_url else "local exact archives only; not published",
    }


class DocumentationCommandContract(unittest.TestCase):
    def test_resolves_source_bound_package_roster_from_inventory(self):
        source = "a" * 40
        names = resolve_package_names({
            "version": "0.1.0", "source_revision": source,
            "assets": {name: {} for name in (
                f"genewhip-0.1.0-sdk-diagnostic-darwin-arm64-{source[:12]}.tar.gz",
                f"genewhip-0.1.0-playable-preview-macos-arm64-{source[:12]}.tar.gz",
                f"genewhip-0.1.0-sdk-diagnostic-darwin-arm64-{source[:12]}.tar.gz.sha256",
                f"genewhip-0.1.0-sdk-diagnostic-darwin-arm64-{source[:12]}.tar.gz.qualification.json",
                f"genewhip-0.1.0-playable-preview-macos-arm64-{source[:12]}.tar.gz.sha256",
                f"genewhip-0.1.0-playable-preview-macos-arm64-{source[:12]}.tar.gz.qualification.json",
            )},
        }, source)
        self.assertTrue(names["sdk"].endswith(source[:12] + ".tar.gz"))
        self.assertTrue(names["desktop"].endswith(source[:12] + ".tar.gz"))

    def test_rejects_inventory_from_a_different_source_revision(self):
        with self.assertRaisesRegex(ValueError, "package-inventory-source"):
            resolve_package_names({"version": "0.1.0", "source_revision": "b" * 40,
                                   "assets": {}}, "a" * 40)

    def test_published_download_only_accepts_the_recorded_public_release_url(self):
        self.assertEqual(validate_release_url(
            "https://github.com/szTheory/genewhip/releases/tag/v0.1.0"),
            "https://github.com/szTheory/genewhip/releases/tag/v0.1.0")
        with self.assertRaisesRegex(ValueError, "release-url-identity"):
            validate_release_url("https://example.invalid/download")

    def test_each_invocation_gets_an_independent_scratch_directory(self):
        with tempfile.TemporaryDirectory(prefix="gw-doc-command-contract-") as parent:
            barrier = threading.Barrier(2)

            def capture_scratch(_):
                return run_isolated(parent, lambda scratch: (barrier.wait(timeout=10), str(scratch))[1])

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first, second = list(pool.map(capture_scratch, range(2)))
            self.assertNotEqual(first, second, "docs-command-scratch-not-isolated")

    def test_interruption_preserves_inputs_and_retry_uses_new_scratch(self):
        with tempfile.TemporaryDirectory(prefix="gw-doc-command-contract-") as parent:
            root = pathlib.Path(parent)
            source = root / "source.txt"
            asset = root / "archive.tar.gz"
            source.write_bytes(b"source")
            asset.write_bytes(b"qualified asset")
            before = (hashlib.sha256(source.read_bytes()).digest(), hashlib.sha256(asset.read_bytes()).digest())
            created = []

            def interrupted(scratch):
                created.append(scratch)
                (scratch / "partial").write_text("partial run")
                raise InterruptedError("injected interruption")

            with self.assertRaises(InterruptedError):
                run_isolated(root, interrupted)
            self.assertEqual(before, (hashlib.sha256(source.read_bytes()).digest(),
                                      hashlib.sha256(asset.read_bytes()).digest()))
            self.assertFalse(created[-1].exists())
            retried = run_isolated(root, lambda scratch: (created.append(scratch), "pass")[1])
            self.assertEqual(retried, "pass")
            self.assertNotEqual(created[0], created[1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-artifacts", type=pathlib.Path, required=True)
    parser.add_argument("--release-url")
    args = parser.parse_args()
    print(json.dumps(run_all(args.local_artifacts, args.release_url), sort_keys=True))


if __name__ == "__main__":
    if os.sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[os.sys.argv[0]])
    else:
        try:
            main()
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
                subprocess.CalledProcessError, tarfile.TarError, json.JSONDecodeError) as error:
            print("REJECT: " + str(error), file=os.sys.stderr)
            raise SystemExit(1)
