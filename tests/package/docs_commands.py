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
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_DELIVERY_SPEC = importlib.util.spec_from_file_location(
    "gw_docs_delivery", ROOT / "scripts/release/qualify_delivery.py")
_DELIVERY = importlib.util.module_from_spec(_DELIVERY_SPEC)
_DELIVERY_SPEC.loader.exec_module(_DELIVERY)
_SDK_SPEC = importlib.util.spec_from_file_location("gw_docs_sdk", ROOT / "tests/package/smoke.py")
_SDK = importlib.util.module_from_spec(_SDK_SPEC)
_SDK_SPEC.loader.exec_module(_SDK)
_DESKTOP_SPEC = importlib.util.spec_from_file_location("gw_docs_desktop", ROOT / "tests/package/desktop_smoke.py")
_DESKTOP = importlib.util.module_from_spec(_DESKTOP_SPEC)
_DESKTOP_SPEC.loader.exec_module(_DESKTOP)
_ROUTE_SPEC = importlib.util.spec_from_file_location(
    "gw_docs_bounded_runner", ROOT / "tests/session/phase6_route_contract.py")
_ROUTE = importlib.util.module_from_spec(_ROUTE_SPEC)
_ROUTE_SPEC.loader.exec_module(_ROUTE)
_PACKAGE_SPEC = importlib.util.spec_from_file_location(
    "gw_docs_v02_package_contract", ROOT / "tests/evidence/v02_package_contract.py")
_PACKAGE = importlib.util.module_from_spec(_PACKAGE_SPEC)
_PACKAGE_SPEC.loader.exec_module(_PACKAGE)


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
    positions = [match.start() for match in re.finditer(re.escape(marker), markdown)]
    if not positions:
        raise ValueError("documented-command-anchor-missing:" + anchor)
    if len(positions) != 1:
        raise ValueError("documented-command-anchor-ambiguous:" + anchor)
    position = positions[0]
    fence_start = markdown.find("```sh\n", position + len(marker))
    if fence_start < 0:
        raise ValueError("documented-command-block-missing:" + anchor)
    body_start = fence_start + len("```sh\n")
    fence_end = markdown.find("\n```", body_start)
    if fence_end < 0:
        raise ValueError("documented-command-block-unclosed:" + anchor)
    return markdown[body_start:fence_end] + "\n"


def validate_anchor_command(markdown, anchor, allowed_variables):
    block = anchored_shell_block(markdown, anchor)
    if re.search(r"(?:^|[\s=])/(?:Users|home)/[^\s\"']+", block) or "$HOME" in block or "~/" in block:
        raise ValueError("documented-command-private-path")
    assigned = set(re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=", block))
    referenced = set(re.findall(r"\$([A-Z][A-Z0-9_]*)|\$\{([A-Z][A-Z0-9_]*)", block))
    referenced = {name for pair in referenced for name in pair if name}
    undeclared = sorted(referenced - set(allowed_variables) - assigned)
    if undeclared:
        raise ValueError("documented-command-undeclared-variable:" + ",".join(undeclared))
    return block


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


def verify_local_archive(artifact_dir, archive_name, role, *, version="0.2.0", expected_source=None,
                        expected_state="development-only"):
    """Validate local receipt, sidecar, archive digest and trusted member contract before use."""
    artifact_dir = pathlib.Path(artifact_dir).resolve()
    if version != "0.2.0" or role not in ("sdk", "desktop"):
        raise ValueError("local-package-version-or-role")
    if pathlib.Path(archive_name).name != archive_name or not archive_name.endswith(".tar.gz"):
        raise ValueError("local-archive-name")
    archive = artifact_dir / archive_name
    if not archive.is_file():
        raise ValueError("local-archive-missing")
    receipt_path = artifact_dir / (archive_name + ".qualification.json")
    if not receipt_path.is_file():
        raise ValueError("local-receipt-missing")
    receipt = json.loads(receipt_path.read_text())
    revision = receipt.get("source_revision")
    role_prefix = ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
                   "genewhip-0.2.0-playable-preview-macos-arm64-")
    if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision) or
            archive_name != role_prefix + revision[:12] + ".tar.gz"):
        raise ValueError("local-receipt-identity")
    if expected_source is not None and expected_source != revision:
        raise ValueError("local-expected-source")
    if (receipt.get("outcome") != "pass" or receipt.get("archive") != archive_name or
            receipt.get("release_version") != "0.2.0" or
            receipt.get("source_state") != expected_state or
            not str(receipt.get("publication", "")).startswith("not published")):
        raise ValueError("local-receipt-identity")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if receipt.get("archive_sha256") != digest:
        raise ValueError("local-receipt-identity")
    sidecar = archive.with_suffix(archive.suffix + ".sha256")
    try:
        parts = sidecar.read_text().split()
    except OSError as error:
        raise ValueError("local-sidecar-missing") from error
    if len(parts) != 2 or parts[0] != digest or parts[1] != archive_name:
        raise ValueError("local-sidecar-checksum")
    if role == "sdk":
        _SDK.inspect_v02_archive(archive, digest, revision, ROOT / "packaging/v02-members.json")
    else:
        _DESKTOP.validate_v02_archive(archive, digest, revision, ROOT / "packaging/v02-members.json")
    return {"archive": archive, "receipt_path": receipt_path, "receipt": receipt,
            "source_revision": revision, "sha256": digest, "role": role}


def verify_public_archive(artifact_dir, archive_name, role, expected_source):
    """Validate a public receipt and exact archive bytes after authenticated provenance."""
    artifact_dir = pathlib.Path(artifact_dir).resolve()
    if role not in ("sdk", "desktop") or not re.fullmatch(r"[0-9a-f]{40}", str(expected_source)):
        raise ValueError("public-package-identity-invalid")
    archive = artifact_dir / archive_name
    receipt_path = artifact_dir / (archive_name + ".qualification.json")
    expected_prefix = ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
                       "genewhip-0.2.0-playable-preview-macos-arm64-")
    if (pathlib.Path(archive_name).name != archive_name or not archive_name.startswith(expected_prefix)
            or archive_name != expected_prefix + expected_source[:12] + ".tar.gz"):
        raise ValueError("public-package-name-mismatch")
    if archive.is_symlink() or receipt_path.is_symlink() or not archive.is_file() or not receipt_path.is_file():
        raise ValueError("public-package-asset-missing-or-invalid")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if (not isinstance(receipt, dict) or receipt.get("schema") != "genewhip-local-package-qualification"
            or receipt.get("version") != 2 or receipt.get("release_version") != "0.2.0"
            or receipt.get("source_revision") != expected_source or receipt.get("source_state") != "clean"
            or receipt.get("outcome") != "pass" or receipt.get("archive") != archive_name
            or receipt.get("archive_sha256") != digest or not isinstance(receipt.get("smoke"), dict)
            or receipt["smoke"].get("outcome") != "pass"):
        raise ValueError("public-package-receipt-invalid")
    sidecar = archive.with_suffix(archive.suffix + ".sha256")
    if sidecar.is_symlink() or not sidecar.is_file() \
            or sidecar.read_text(encoding="utf-8") != f"{digest}  {archive_name}\n":
        raise ValueError("public-package-sidecar-invalid")
    roster = ROOT / "packaging/v02-members.json"
    if role == "sdk":
        _SDK.inspect_v02_archive(archive, digest, expected_source, roster)
    else:
        _DESKTOP.validate_v02_archive(archive, digest, expected_source, roster)
    return {"archive": archive, "receipt_path": receipt_path, "receipt": receipt,
            "source_revision": expected_source, "sha256": digest, "role": role}


def _select_local_archive(artifact_dir, role, expected_source=None, expected_state="development-only"):
    prefix = ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
              "genewhip-0.2.0-playable-preview-macos-arm64-")
    candidates = sorted(artifact_dir.glob(prefix + "*.tar.gz"),
                        key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)
    if expected_source is not None:
        candidates = [path for path in candidates if path.name.endswith(expected_source[:12] + ".tar.gz")]
    if not candidates:
        raise ValueError("local-archive-missing")
    selected = candidates[0]
    return verify_local_archive(artifact_dir, selected.name, role, expected_source=expected_source,
                                expected_state=expected_state)


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


def _phase7_child_limits():
    limits = json.loads((ROOT / "evidence/v02-execution.json").read_text()).get("per_child_limits")
    required = {"wall_seconds", "cleanup_grace_seconds", "max_rss_bytes",
                "max_stdout_stderr_bytes", "max_json_bytes", "max_binary_file_bytes",
                "max_capture_bytes", "max_scratch_bytes", "max_retained_bytes",
                "max_fields", "max_calls"}
    if not isinstance(limits, dict) or set(limits) != required:
        raise ValueError("docs-child-limits-invalid")
    return limits


def persist_bounded_output(output_root, repository_root, anchor, streams, process):
    """Retain capped command output and its private receipt under build/v02."""
    output_root = pathlib.Path(output_root)
    repository_root = pathlib.Path(repository_root)
    if not re.fullmatch(r"[a-z0-9-]+", anchor):
        raise ValueError("docs-output-anchor-invalid")
    if output_root.is_symlink():
        raise ValueError("docs-output-root-symlink")
    output_root.mkdir(parents=True, exist_ok=True)
    root_info = output_root.lstat()
    if not output_root.is_dir() or root_info.st_uid != os.getuid():
        raise ValueError("docs-output-root-not-owned-directory")
    directory = pathlib.Path(tempfile.mkdtemp(prefix="docs-" + anchor + "-", dir=output_root))
    try:
        file_metadata = {}
        for name in ("stdout", "stderr"):
            content = str(streams.get(name, {}).get("text", ""))
            target = directory / (name + ".txt")
            with target.open("x", encoding="utf-8", newline="") as output:
                output.write(content)
            target.chmod(0o600)
            file_metadata[name] = {
                "file": target.name,
                "retained_bytes": streams.get(name, {}).get("retained_bytes", len(content.encode("utf-8"))),
                "observed_bytes": streams.get(name, {}).get("observed_bytes", len(content.encode("utf-8"))),
                "truncated": streams.get(name, {}).get("truncated", False),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        process["private_output_dir"] = directory.relative_to(repository_root).as_posix()
        process["private_output_files"] = file_metadata
        receipt = directory / "receipt.json"
        with receipt.open("x", encoding="utf-8", newline="") as output:
            output.write(json.dumps(process, sort_keys=True, indent=2) + "\n")
        receipt.chmod(0o600)
        return directory
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def _redacted_output_tail(streams, scratch):
    output = streams.get("stdout", {}).get("text", "") + "\n" + streams.get("stderr", {}).get("text", "")
    replacements = ((str(ROOT), "<checkout>"), (str(pathlib.Path.home()), "<user-home>"),
                    (str(scratch.parent), "<docs-scratch>"), (str(scratch), "<command-scratch>"))
    for value, label in replacements:
        if value:
            output = output.replace(value, label)
    return output[-1800:]


def run_bounded_anchor(markdown_path, anchor, env, scratch, process_runs, *, offline=True,
                       monitored_files=()):
    if not offline or platform.system() != "Darwin" or not shutil.which("sandbox-exec"):
        raise ValueError("required-network-denial-capability-unavailable")
    block = validate_anchor_command(pathlib.Path(markdown_path).read_text(), anchor, env.keys())
    home = scratch.parent / (scratch.name + "-empty-home")
    cache = scratch.parent / (scratch.name + "-empty-cache")
    home.mkdir()
    cache.mkdir()
    inherited = {name: os.environ[name] for name in
                 ("PATH", "LANG", "LC_ALL", "TMPDIR", "DEVELOPER_DIR", "SDKROOT",
                  "CC", "CXX", "CFLAGS", "CXXFLAGS", "AR", "MACOSX_DEPLOYMENT_TARGET")
                 if name in os.environ}
    command_env = dict(inherited, **env, HOME=str(home), XDG_CACHE_HOME=str(cache),
                       CMAKE_DISABLE_FIND_PACKAGE_SDL3="TRUE",
                       CMAKE_FIND_USE_PACKAGE_REGISTRY="FALSE", CMAKE_USER_PACKAGE_REGISTRY="",
                       CMAKE_PACKAGE_REGISTRY="", SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
    command = [shutil.which("sandbox-exec"), "-p", "(version 1)(allow default)(deny network*)",
               "bash", "-euo", "pipefail", "-c", block]
    report = scratch.parent / (scratch.name + "-process.json")
    scratch_diagnostics = []
    streams = {}
    try:
        result = _ROUTE._run_client(pathlib.Path(command[0]), command, process_runs,
                                   report=report, timeout=600, cwd=ROOT, env=command_env,
                                   retained_streams=streams, monitored_files=tuple(monitored_files),
                                   limits=_phase7_child_limits(), scratch_roots=(scratch,),
                                   scratch_diagnostics=scratch_diagnostics)
    except BaseException:
        process = process_runs[-1] if process_runs else {"status": "runner-failed-before-launch"}
        if scratch_diagnostics:
            process["scratch_scan_diagnostics"] = scratch_diagnostics
        persist_bounded_output(ROOT / "build/v02", ROOT, anchor, streams, process)
        raise
    process = process_runs[-1] if process_runs else {}
    if scratch_diagnostics:
        process["scratch_scan_diagnostics"] = scratch_diagnostics
    persist_bounded_output(ROOT / "build/v02", ROOT, anchor, streams, process)
    if (result.returncode != 0 or process.get("process_group_cleanup") != "confirmed" or
            process.get("bound_violation")):
        raise RuntimeError("documented-command-failed:" + anchor + ":exit=" + str(result.returncode) +
                           ":cleanup=" + str(process.get("process_group_cleanup")) +
                           ":bound=" + str(process.get("bound_violation")) +
                           ":output-tail=" + _redacted_output_tail(streams, pathlib.Path(scratch)))
    return result.stdout + result.stderr


def _receipt_for_artifact(artifact):
    return {"archive": artifact["archive"].name,
            "archive_sha256": artifact["sha256"],
            "source_revision": artifact["source_revision"],
            "source_state": artifact["receipt"].get("source_state"),
            "public_evidence_digest": artifact["receipt"].get("public_evidence_digest")}


def run_v02(artifact_dir, *, expected_source=None, refresh_local=False, offline=False, out=None,
            public_download=False, publisher_packet=None, require_clean_local=False):
    artifact_dir = pathlib.Path(artifact_dir).resolve()
    if require_clean_local and (public_download or refresh_local):
        raise ValueError("clean-local-docs-reject-public-download-or-refresh")
    try:
        artifact_dir.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError("package-path-outside-checkout") from error
    if not offline:
        raise ValueError("v02-documentation-requires-offline-mode")
    if public_download:
        if refresh_local or not publisher_packet:
            raise ValueError("public-download-requires-publisher-packet-and-no-refresh")
        packet = json.loads(pathlib.Path(publisher_packet).read_text(encoding="utf-8"))
        problems = _DELIVERY.validate_v02_publisher_packet(packet)
        if problems:
            raise ValueError("public-publisher-packet-invalid:" + problems[0])
        source = packet["source_sha"]
        if expected_source is not None and expected_source != source:
            raise ValueError("public-download-source-mismatch")
        current_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                                 text=True).strip()
        if current_source != source:
            raise ValueError("public-doc-command-source-mismatch")
        facts = _DELIVERY.authenticate_v02_publisher_packet(packet, packet["repository"])
        _DELIVERY.verify_v02_subject_attestations(artifact_dir, packet)
        release_info = _DELIVERY.validate_release(facts["release"], packet["repository"],
                                                  packet["release_tag"], artifact_dir, source, "0.2.0")
        if ({row["name"]: row["sha256"] for row in release_info["assets"]}
                != packet["asset_digests"]):
            raise ValueError("public-download-asset-digest-mismatch")
    refreshed = {}
    if refresh_local and public_download:
        raise ValueError("public-download-refresh-forbidden")
    if refresh_local:
        for role in ("sdk", "desktop"):
            refreshed[role] = _PACKAGE.execute_local_package(role, ROOT / "build/v02/public", artifact_dir)
    artifacts = {}
    for role in ("sdk", "desktop"):
        if role in refreshed:
            name = pathlib.Path(refreshed[role]["archive"]).name
            artifacts[role] = verify_local_archive(artifact_dir, name, role, expected_source=expected_source)
        elif public_download:
            prefix = ("genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" if role == "sdk" else
                      "genewhip-0.2.0-playable-preview-macos-arm64-")
            artifacts[role] = verify_public_archive(
                artifact_dir, prefix + packet["source_sha"][:12] + ".tar.gz", role, packet["source_sha"])
        else:
            artifacts[role] = _select_local_archive(artifact_dir, role, expected_source,
                "clean" if require_clean_local else "development-only")
    if artifacts["sdk"]["source_revision"] == artifacts["desktop"]["source_revision"]:
        local_source_identity = artifacts["sdk"]["source_revision"]
    else:
        local_source_identity = None
    process_runs = []
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="gw-docs-v02-") as tmp:
        root = pathlib.Path(tmp)
        play = root / "play"
        play.mkdir()
        outputs["play"] = run_bounded_anchor(
            ROOT / "packaging/desktop/README.md", "v02-play",
            {"CHECKOUT": str(ROOT), "ARTIFACT_DIR": str(artifact_dir),
             "DESKTOP_ARCHIVE": artifacts["desktop"]["archive"].name,
             "EXTRACT_DIR": str(play / "extract"), "PACKAGE_DIR": str(play / "unused-package")},
            play, process_runs, offline=offline,
            monitored_files=((artifacts["desktop"]["archive"], _DESKTOP.MAX_V02_ARCHIVE_BYTES),
                             (artifacts["desktop"]["receipt_path"], 1024 * 1024)))

        for name, anchor in (("build", "v02-build-core"), ("embed", "v02-embed")):
            scratch = root / name
            scratch.mkdir()
            outputs[name] = run_bounded_anchor(
                ROOT / ("packaging/README.md" if name == "build" else "docs/core.md"), anchor,
                {"CHECKOUT": str(ROOT), "ARTIFACT_DIR": str(artifact_dir),
                 "SDK_ARCHIVE": artifacts["sdk"]["archive"].name,
                 "EXTRACT_DIR": str(scratch / "extract"), "SDK_DIR": str(scratch / "unused-sdk"),
                 "BUILD_DIR": str(scratch / "build"), "INSTALL_DIR": str(scratch / "install"),
                 "ROM_PATH": str(scratch / "unused-rom")},
                scratch, process_runs, offline=offline,
                monitored_files=((artifacts["sdk"]["archive"], _DESKTOP.MAX_V02_ARCHIVE_BYTES),
                                 (artifacts["sdk"]["receipt_path"], 1024 * 1024)))

        source_build = root / "source-build"
        source_build.mkdir()
        outputs["offline_source_core_build"] = run_bounded_anchor(
            ROOT / "README.md", "source-build", {"BUILD_DIR": str(source_build / "build")},
            source_build, process_runs, offline=offline)

        desktop = artifacts["desktop"]
        roster, files, package_root = _DESKTOP.validate_v02_archive(
            desktop["archive"], desktop["sha256"], desktop["source_revision"],
            ROOT / "packaging/v02-members.json")
        input_dir = root / "error-inputs"
        input_dir.mkdir()
        package_dir = _DESKTOP.extract_verified(desktop["archive"], files, package_root, input_dir)
        _DESKTOP._PACKAGE.check_staged_inventory(package_dir)
        share = package_dir / "share/genewhip"
        valid_rom = share / "tank-battle.bin"
        truncated_rom = input_dir / "truncated.bin"
        truncated_rom.write_bytes(valid_rom.read_bytes()[:512])
        unsupported_log = input_dir / "unsupported.log"
        unsupported_log.write_text("genewhip-input-log 99\n")
        drop_script = input_dir / "drop.script"
        drop_script.write_text("1 drop " + str(truncated_rom) + "\n30 quit\n")
        error_output = root / "errors"
        error_output.mkdir()
        outputs["errors"] = run_bounded_anchor(
            ROOT / "docs/desktop.md", "v02-errors",
            {"CHECKOUT": str(ROOT), "ARTIFACT_DIR": str(artifact_dir),
             "DESKTOP_ARCHIVE": desktop["archive"].name, "PACKAGE_DIR": str(package_dir),
             "ROM": str(valid_rom), "MISSING_ROM": str(input_dir / "missing.bin"),
             "TRUNCATED_ROM": str(truncated_rom), "UNSUPPORTED_LOG": str(unsupported_log),
             "DROP_SCRIPT": str(drop_script), "ERROR_LOG": str(error_output / "errors.log")},
            error_output, process_runs, offline=offline,
            monitored_files=((desktop["archive"], _DESKTOP.MAX_V02_ARCHIVE_BYTES),
                             (desktop["receipt_path"], 1024 * 1024),
                             (valid_rom, valid_rom.stat().st_size),
                             (truncated_rom, 512), (unsupported_log, 1024), (drop_script, 4096)))
    if any(item.get("process_group_cleanup") != "confirmed" for item in process_runs):
        raise ValueError("documented-command-cleanup-unconfirmed")
    receipt = {
        "schema": "genewhip-docs-command-qualification-v2", "version": "0.2.0",
        "outcome": "pass", "mode": "public-downloaded" if public_download else
            "clean-local-qualified" if require_clean_local else "local-development-only",
        "local_source_identity": local_source_identity,
        "packages": {role: _receipt_for_artifact(item) for role, item in artifacts.items()},
        "commands": {name: "pass" for name in outputs},
        "offline_network_denial": "sandbox-exec-deny-network",
        "cache": "fresh-empty-home-and-xdg-cache",
        "desktop_errors": {"missing": "rejected", "unsupported_input_log": "rejected",
                            "truncated_rom": "rejected", "failed_drop_session_preserved": "pass"},
        "processes": process_runs,
        "release_claim": ("exact authenticated public release downloads; external adoption only"
                          if public_download else
                          "local exact-byte documentation checks only; not published"),
    }
    if out is not None:
        output_path = pathlib.Path(out).resolve()
        try:
            output_path.relative_to(ROOT.resolve())
        except ValueError as error:
            raise ValueError("docs-receipt-outside-checkout") from error
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_name(output_path.name + ".tmp")
        temporary.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        os.replace(temporary, output_path)
    return receipt


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
    def test_v02_entry_paths_link_to_stable_play_build_and_embed_contracts(self):
        readme = (ROOT / "README.md").read_text()
        required_links = (
            "[Play](packaging/desktop/README.md#v02-play)",
            "[Build](packaging/README.md#v02-build-core)",
            "[Embed](docs/core.md#v02-embed)",
        )
        for link in required_links:
            self.assertIn(link, readme, "missing-v02-entry-link:" + link)
        self.assertEqual((ROOT / "packaging/desktop/README.md").read_text().count(
            '<a id="v02-play"></a>'), 1)
        self.assertEqual((ROOT / "packaging/README.md").read_text().count(
            '<a id="v02-build-core"></a>'), 1)
        self.assertEqual((ROOT / "docs/core.md").read_text().count(
            '<a id="v02-embed"></a>'), 1)

    def test_v02_documentation_uses_pending_publication_and_tested_scope(self):
        readme = (ROOT / "README.md").read_text()
        desktop = (ROOT / "packaging/desktop/README.md").read_text()
        sdk = (ROOT / "packaging/README.md").read_text()
        consumer = (ROOT / "tests/consumer/CMakeLists.txt").read_text()
        self.assertIn("v0.2.0", readme)
        self.assertIn("development-only", readme)
        self.assertIn("v0.2.0", desktop)
        self.assertIn("v0.2.0", sdk)
        self.assertIn("unsigned", desktop.lower())
        self.assertIn("macOS 26.6.2", desktop)
        self.assertIn("Open Anyway", desktop)
        self.assertIn("VA3", readme)
        self.assertIn("unknown", readme.lower())
        self.assertIn("find_package(Genewhip 0.2.0 EXACT CONFIG REQUIRED)", consumer)

    def test_contract_selector_reports_selected_assertion_count(self):
        report = run_contracts("0.2.0")
        self.assertEqual(report["outcome"], "pass")
        self.assertEqual(report["selected_tests"], 9)

    def test_v02_controls_and_recovery_match_runner_source(self):
        docs = (ROOT / "packaging/desktop/README.md").read_text()
        source = (ROOT / "tools/desktop/main_sdl.c").read_text()
        for fragment in ("arrows move", "Z is A", "X is B", "C is C", "Return is Start",
                         "west face button for A", "south for B", "east for C",
                         "P or Space", "R requests a console reset", "M toggles mute", "Escape exits",
                         "keeps the current session", "audio=off"):
            self.assertIn(fragment, docs, "missing-observed-control-or-recovery:" + fragment)
        for fragment in ("SDL_SCANCODE_UP", "SDL_SCANCODE_Z", "SDL_SCANCODE_X", "SDL_SCANCODE_C",
                         "SDL_GAMEPAD_BUTTON_WEST", "SDL_GAMEPAD_BUTTON_SOUTH", "SDL_GAMEPAD_BUTTON_EAST",
                         "SDLK_SPACE", "SDLK_R", "SDLK_M", "SDLK_ESCAPE", "failure keeps the running session"):
            self.assertIn(fragment, source, "runner-source-contract-missing:" + fragment)

    def test_command_anchor_rejects_missing_ambiguous_and_undeclared_paths(self):
        with self.assertRaisesRegex(ValueError, "anchor-missing"):
            anchored_shell_block("no command", "v02-play")
        duplicate = '<a id="v02-play"></a>\n```sh\necho ok\n```\n<a id="v02-play"></a>'
        with self.assertRaisesRegex(ValueError, "anchor-ambiguous"):
            anchored_shell_block(duplicate, "v02-play")
        private = '<a id="v02-play"></a>\n```sh\nprintf %s "$HOME/archive"\n```'
        with self.assertRaisesRegex(ValueError, "private-path"):
            validate_anchor_command(private, "v02-play", ())
        undeclared = '<a id="v02-play"></a>\n```sh\nprintf %s "$UNKNOWN_DIR"\n```'
        with self.assertRaisesRegex(ValueError, "undeclared-variable"):
            validate_anchor_command(undeclared, "v02-play", ())

    def test_v02_command_anchors_have_declared_portable_inputs(self):
        contracts = (
            ("packaging/desktop/README.md", "v02-play", {"CHECKOUT", "ARTIFACT_DIR", "DESKTOP_ARCHIVE", "EXTRACT_DIR", "PACKAGE_DIR"}),
            ("packaging/README.md", "v02-build-core", {"CHECKOUT", "ARTIFACT_DIR", "SDK_ARCHIVE", "EXTRACT_DIR", "SDK_DIR", "BUILD_DIR"}),
            ("docs/core.md", "v02-embed", {"CHECKOUT", "ARTIFACT_DIR", "SDK_ARCHIVE", "EXTRACT_DIR", "SDK_DIR", "BUILD_DIR"}),
            ("docs/desktop.md", "v02-errors", {"CHECKOUT", "ARTIFACT_DIR", "DESKTOP_ARCHIVE", "PACKAGE_DIR", "ROM", "MISSING_ROM", "TRUNCATED_ROM", "UNSUPPORTED_LOG", "DROP_SCRIPT", "ERROR_LOG"}),
        )
        for relative, anchor, variables in contracts:
            markdown = (ROOT / relative).read_text()
            validate_anchor_command(markdown, anchor, variables)

    def test_v02_adoption_commands_verify_before_extracting_or_running_members(self):
        cases = ((ROOT / "packaging/desktop/README.md", "v02-play"),
                 (ROOT / "packaging/README.md", "v02-build-core"),
                 (ROOT / "docs/core.md", "v02-embed"))
        for path, anchor in cases:
            block = anchored_shell_block(path.read_text(), anchor)
            verifier = block.index("--verify-local")
            self.assertLess(block.index('cd "$ARTIFACT_DIR"'), block.index("shasum -a 256 -c"),
                            anchor + ":local-checksum-must-run-from-archive-directory")
            extract = block.index("tar -x")
            self.assertLess(verifier, extract, anchor + ":verifier-must-precede-extraction")
            self.assertLess(extract, block.index("cmake -S") if "cmake -S" in block else block.index('"$PACKAGE_DIR/bin/'),
                            anchor + ":extract-must-precede-consumer")
        play = anchored_shell_block((ROOT / "packaging/desktop/README.md").read_text(), "v02-play")
        self.assertLess(play.index('cd "$ARTIFACT_DIR"'), play.index("shasum -a 256 -c"),
                        "local-checksum-must-run-from-archive-directory")

    def test_v02_local_verifier_rejects_missing_archive_with_named_reason(self):
        with tempfile.TemporaryDirectory(prefix="gw-doc-v02-reject-") as directory:
            artifact_dir = pathlib.Path(directory)
            command = [os.sys.executable, "-I", str(ROOT / "tests/package/docs_commands.py"),
                       "--verify-local", "--local-artifacts", str(artifact_dir),
                       "--archive", "genewhip-0.2.0-playable-preview-macos-arm64-" + "a" * 12 + ".tar.gz",
                       "--role", "desktop", "--version", "0.2.0"]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("REJECT: local-archive-missing", result.stderr)

    def test_v02_local_verifier_separates_wrong_source_and_sidecar_identity(self):
        with tempfile.TemporaryDirectory(prefix="gw-doc-v02-identity-") as directory:
            artifact_dir = pathlib.Path(directory)
            revision = "a" * 40
            name = "genewhip-0.2.0-sdk-diagnostic-darwin-arm64-" + revision[:12] + ".tar.gz"
            archive = artifact_dir / name
            body = b"not an archive; identity gates must run first"
            archive.write_bytes(body)
            digest = hashlib.sha256(body).hexdigest()
            receipt = {"outcome": "pass", "release_version": "0.2.0", "archive": name,
                       "source_revision": revision, "source_state": "development-only",
                       "archive_sha256": digest, "publication": "not published; local"}
            (artifact_dir / (name + ".qualification.json")).write_text(json.dumps(receipt))
            sidecar = archive.with_suffix(archive.suffix + ".sha256")
            sidecar.write_text(digest + "  " + name + "\n")
            with self.assertRaisesRegex(ValueError, "^local-expected-source$"):
                verify_local_archive(artifact_dir, name, "sdk", expected_source="b" * 40)
            sidecar.write_text("0" * 64 + "  " + name + "\n")
            with self.assertRaisesRegex(ValueError, "^local-sidecar-checksum$"):
                verify_local_archive(artifact_dir, name, "sdk")

    def test_clean_local_docs_mode_rejects_refresh_and_public_download(self):
        with tempfile.TemporaryDirectory(prefix="gw-docs-clean-local-") as directory:
            with self.assertRaisesRegex(ValueError, "clean-local-docs-reject-public-download-or-refresh"):
                run_v02(directory, expected_source="a" * 40, refresh_local=True,
                        offline=True, require_clean_local=True)
            with self.assertRaisesRegex(ValueError, "clean-local-docs-reject-public-download-or-refresh"):
                run_v02(directory, expected_source="a" * 40, public_download=True,
                        publisher_packet="unused", offline=True, require_clean_local=True)

    def test_v02_bounded_failure_persists_private_logs_and_receipt(self):
        with tempfile.TemporaryDirectory(prefix="gw-doc-private-output-") as directory:
            root = pathlib.Path(directory)
            streams = {
                "stdout": {"text": "cmake output\n", "retained_bytes": 13,
                           "observed_bytes": 13, "truncated": False},
                "stderr": {"text": "CTest failed\n", "retained_bytes": 13,
                           "observed_bytes": 13, "truncated": False},
            }
            process = {"return_code": 8, "process_group_cleanup": "confirmed"}
            private_dir = persist_bounded_output(root, root, "source-build", streams, process)
            self.assertEqual((private_dir / "stdout.txt").read_text(), streams["stdout"]["text"])
            self.assertEqual((private_dir / "stderr.txt").read_text(), streams["stderr"]["text"])
            self.assertEqual(json.loads((private_dir / "receipt.json").read_text()), process)
            self.assertEqual(process["private_output_dir"], private_dir.relative_to(root).as_posix())

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
    parser.add_argument("--local-artifacts", type=pathlib.Path)
    parser.add_argument("--public-download", action="store_true")
    parser.add_argument("--publisher-packet", type=pathlib.Path)
    parser.add_argument("--contracts-only", action="store_true")
    parser.add_argument("--verify-local", action="store_true")
    parser.add_argument("--archive")
    parser.add_argument("--role", choices=("sdk", "desktop"))
    parser.add_argument("--version")
    parser.add_argument("--expected-source")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh-local", action="store_true")
    parser.add_argument("--require-clean-local", action="store_true")
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--release-url")
    args = parser.parse_args()
    if args.contracts_only:
        print(json.dumps(run_contracts(args.version), sort_keys=True))
        return
    if args.verify_local:
        if args.local_artifacts is None or not args.archive or args.version != "0.2.0" or not args.role:
            parser.error("--verify-local requires --local-artifacts, --archive, --role, and --version 0.2.0")
        print(json.dumps(_receipt_for_artifact(verify_local_archive(
            args.local_artifacts, args.archive, args.role, version=args.version,
            expected_source=args.expected_source)), sort_keys=True))
        return
    if args.local_artifacts is None:
        parser.error("--local-artifacts is required unless --contracts-only is selected")
    if args.version == "0.2.0":
        if args.public_download and (args.publisher_packet is None or args.refresh_local):
            parser.error("--public-download requires --publisher-packet and forbids --refresh-local")
        if not args.public_download and args.publisher_packet is not None:
            parser.error("--publisher-packet requires --public-download")
        print(json.dumps(run_v02(args.local_artifacts, expected_source=args.expected_source,
                                 refresh_local=args.refresh_local, offline=args.offline,
                                 out=args.out, public_download=args.public_download,
                                 publisher_packet=args.publisher_packet,
                                 require_clean_local=args.require_clean_local), sort_keys=True))
        return
    if args.public_download or args.publisher_packet:
        parser.error("--public-download is available only for version 0.2.0")
    if args.refresh_local or args.offline or args.expected_source or args.out or args.require_clean_local:
        parser.error("v0.2-only options require --version 0.2.0")
    print(json.dumps(run_all(args.local_artifacts, args.release_url), sort_keys=True))


def run_contracts(version):
    if version != "0.2.0":
        raise ValueError("unsupported-documentation-version")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DocumentationCommandContract)
    selected = unittest.TestSuite(test for test in suite
                                   if test._testMethodName.startswith("test_v02_") or
                                   test._testMethodName in {
                                       "test_command_anchor_rejects_missing_ambiguous_and_undeclared_paths",
                                       "test_v02_command_anchors_have_declared_portable_inputs",
                                       "test_v02_local_verifier_rejects_missing_archive_with_named_reason",
                                       "test_clean_local_docs_mode_rejects_refresh_and_public_download",
                                   })
    result = unittest.TextTestRunner(verbosity=0).run(selected)
    if not result.wasSuccessful():
        raise ValueError("documentation-contract-failed")
    return {"schema": "genewhip-docs-contract", "version": version,
            "outcome": "pass", "selected_tests": result.testsRun,
            "failures": len(result.failures) + len(result.errors)}


if __name__ == "__main__":
    if not any(flag in os.sys.argv for flag in ("--contract", "--contracts-only")):
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    if os.sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[os.sys.argv[0]])
    else:
        try:
            main()
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
                subprocess.CalledProcessError, tarfile.TarError, json.JSONDecodeError) as error:
            print("REJECT: " + str(error), file=os.sys.stderr)
            raise SystemExit(1)
