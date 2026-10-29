#!/usr/bin/env python3
"""Contract tests and isolated local qualification entry point for v0.2 packages."""
import json
import importlib.util
import argparse
import hashlib
import gzip
import io
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
TASK_INPUTS = (
    "packaging/v02-members.json", "CMakeLists.txt", "scripts/package_sdk.py", "scripts/package_archive.py",
    "tests/package/smoke.py", "tests/evidence/v02_package_contract.py",
    "scripts/package_desktop.py", "tests/package/desktop_smoke.py",
    "README.md", "packaging/README.md", "packaging/desktop/README.md",
    "docs/desktop.md", "docs/core.md", "docs/input.md", "docs/delivery.md",
    "tests/package/docs_commands.py",
)


class V02PackageContract(unittest.TestCase):
    def test_sdk_consumer_accepts_the_selected_exact_package_version(self):
        spec = importlib.util.spec_from_file_location("gw_selected_consumer_version", ROOT / "scripts/package_sdk.py")
        package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory(prefix="gw-legacy-consumer-version-") as directory:
            root = pathlib.Path(directory)
            for version in ("0.1.0", "0.2.0"):
                with self.subTest(version=version):
                    version_root = root / version
                    version_root.mkdir()
                    consumer = version_root / "consumer"
                    package._stage_consumer(ROOT / "tests/consumer", consumer, version)
                    prefix = version_root / "prefix"
                    config = prefix / "lib/cmake/Genewhip"
                    config.mkdir(parents=True)
                    (config / "GenewhipConfig.cmake").write_text("add_library(Genewhip::core INTERFACE IMPORTED)\n")
                    (config / "GenewhipConfigVersion.cmake").write_text(
                        f'set(PACKAGE_VERSION "{version}")\n'
                        'if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)\n'
                        '  set(PACKAGE_VERSION_EXACT TRUE)\n'
                        '  set(PACKAGE_VERSION_COMPATIBLE TRUE)\n'
                        'endif()\n')
                    result = subprocess.run(["cmake", "-S", str(consumer), "-B", str(version_root / "build"),
                        "-DCMAKE_PREFIX_PATH=" + str(prefix), "-DGW_ROM=" + str(ROOT / "fixtures/diagnostic.bin")],
                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    self.assertEqual(result.returncode, 0, result.stdout)

    def test_sdk_inspector_rejects_rehashed_forged_rights_and_notice(self):
        smoke_spec = importlib.util.spec_from_file_location("gw_sdk_smoke_contract", ROOT / "tests/package/smoke.py")
        smoke = importlib.util.module_from_spec(smoke_spec)
        smoke_spec.loader.exec_module(smoke)
        sdk = importlib.util.spec_from_file_location("gw_sdk_roster_contract", ROOT / "scripts/package_sdk.py")
        package_sdk = importlib.util.module_from_spec(sdk)
        sdk.loader.exec_module(package_sdk)
        roster = package_sdk._load_v02_roster()
        revision = "a" * 40
        root = f"genewhip-0.2.0-sdk-diagnostic-{__import__('platform').system().lower()}-{__import__('platform').machine()}-{revision[:12]}"
        member_rows = roster["sdk"]["members"]
        required = sorted(row["path"] for row in member_rows if row["path"] not in ("metadata.json", "checksums.json"))
        rights = {row["path"]: row["rights"] for row in member_rows
                  if row["path"] not in ("metadata.json", "checksums.json")}
        closure = {"closure_id": "b" * 64}
        def make_archive(overrides=None):
            files = {}
            for row in member_rows:
                path = row["path"]
                if path in ("metadata.json", "checksums.json"):
                    continue
                if overrides and path in overrides:
                    body = overrides[path]
                elif path == "share/genewhip/evidence/manifest.json":
                    body = json.dumps(closure).encode()
                elif path == "share/genewhip/evidence/performance.json":
                    body = b"performance-projection"
                elif row["role"] == "notice":
                    body = (ROOT / row["source"]).read_bytes()
                else:
                    body = ("payload:" + path).encode()
                files[path] = body
            meta = {"release_version": "0.2.0", "source_revision": revision,
                "api_version": 4, "input_log_version": 1, "source_state": "clean",
                "required_members": required,
                "member_rights": (overrides or {}).get("member_rights", rights),
                "performance_evidence_digest": hashlib.sha256(files["share/genewhip/evidence/performance.json"]).hexdigest(),
                "public_evidence_digest": closure["closure_id"]}
            files["metadata.json"] = json.dumps(meta).encode()
            files["checksums.json"] = json.dumps({name: hashlib.sha256(body).hexdigest()
                for name, body in files.items()}, sort_keys=True).encode()
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                for name, body in files.items():
                    item = tarfile.TarInfo(root + "/" + name)
                    item.size = len(body)
                    archive.addfile(item, io.BytesIO(body))
            return output.getvalue()
        with tempfile.TemporaryDirectory(prefix="gw-rights-mutant-") as directory:
            archive_path = pathlib.Path(directory) / "sdk.tar.gz"
            def inspect(data):
                archive_path.write_bytes(data)
                return smoke.inspect_v02_archive(archive_path, hashlib.sha256(data).hexdigest(),
                    revision, ROOT / "packaging/v02-members.json")
            inspect(make_archive())
            forged = dict(rights)
            forged[next(iter(forged))] = "forged-right"
            with self.assertRaisesRegex(ValueError, "package-member-rights"):
                inspect(make_archive({"member_rights": forged}))
            notice = "share/genewhip/LICENSE"
            with self.assertRaisesRegex(ValueError, "package-notice-content-identity"):
                inspect(make_archive({notice: b"empty forged notice"}))

    def test_archive_preflight_bounds_member_count_and_pax_headers(self):
        spec = importlib.util.spec_from_file_location("gw_package_archive_limits",
            ROOT / "scripts/package_archive.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="gw-tar-preflight-") as directory:
            ordinary = pathlib.Path(directory) / "ordinary.tar.gz"
            with tarfile.open(ordinary, "w:gz") as archive:
                for name in ("one", "two", "three"):
                    payload = name.encode()
                    item = tarfile.TarInfo(name)
                    item.size = len(payload)
                    archive.addfile(item, io.BytesIO(payload))
            self.assertEqual(module.preflight_tar_gz(ordinary, max_members=3,
                max_expanded_bytes=4096), (3, 3072))
            with self.assertRaisesRegex(ValueError, "archive-member-count-limit"):
                module.preflight_tar_gz(ordinary, max_members=2, max_expanded_bytes=4096)

            extended = pathlib.Path(directory) / "extended.tar.gz"
            with tarfile.open(extended, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                item = tarfile.TarInfo("payload")
                item.pax_headers = {"comment": "x" * 70000}
                payload = b"safe"
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            with self.assertRaisesRegex(ValueError, "archive-extended-header-limit"):
                module.preflight_tar_gz(extended, max_members=10, max_expanded_bytes=1_000_000)

    def test_archive_preflight_counts_physical_pax_headers_and_decoded_bytes(self):
        spec = importlib.util.spec_from_file_location("gw_package_archive_chain_limits",
            ROOT / "scripts/package_archive.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

        def header(name, kind, size):
            block = bytearray(512)
            block[:len(name)] = name
            block[100:108] = b"0000644\0"
            block[108:116] = b"0000000\0"
            block[116:124] = b"0000000\0"
            block[124:136] = f"{size:011o}\0".encode()
            block[136:148] = b"00000000000\0"
            block[148:156] = b"        "
            block[156:157] = kind
            block[257:263] = b"ustar\0"
            block[263:265] = b"00"
            checksum = sum(block)
            block[148:156] = f"{checksum:06o}\0 ".encode()
            return bytes(block)

        payload = b"6 x=y\n"
        pax = header(b"PaxHeader", b"x", len(payload)) + payload + bytes(506)
        body = header(b"one-byte-file", b"0", 1) + b"x" + bytes(511) + bytes(1024)
        archive = gzip.compress(pax * 1100 + body, mtime=0)
        self.assertEqual(len(gzip.decompress(archive)), 1_128_448)
        with self.assertRaisesRegex(ValueError, "archive-member-count-limit|archive-expanded-size-limit"):
            module.preflight_tar_gz(archive, max_members=2, max_expanded_bytes=1024)

    def test_desktop_sdl_pin_is_valid_and_any_local_archive_matches(self):
        archive = pinned_sdl_archive(required=False)
        dependency = json.loads((ROOT / "packaging/dependencies/sdl3.json").read_text())
        self.assertRegex(dependency.get("sha256", ""), r"^[0-9a-f]{64}$")
        self.assertTrue(dependency.get("url", "").startswith("https://"))
        if archive is not None:
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), dependency["sha256"])
        spec = importlib.util.spec_from_file_location("gw_sdl_pin_consumer",
                                                       ROOT / "scripts/package_desktop.py")
        package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory(prefix="gw-sdl-pin-mutant-") as temporary:
            sandbox = pathlib.Path(temporary)
            descriptor = sandbox / "packaging/dependencies/sdl3.json"
            descriptor.parent.mkdir(parents=True)
            descriptor.write_text(json.dumps({"version": "3.4.18", "url": "https://invalid.example/sdl.tar.gz",
                                              "sha256": "a" * 64}))
            synthetic = sandbox / "synthetic-sdl.tar.gz"
            synthetic.write_bytes(b"synthetic mismatched SDL bytes")
            package.ROOT = sandbox
            with patch.dict(os.environ, {"GENEWHIP_SDL3_ARCHIVE": str(synthetic)}):
                with self.assertRaisesRegex(ValueError, "pinned-sdl3-local-archive-unavailable-or-mismatched"):
                    package._v02_sdl_route()

    def test_sdk_builder_has_explicit_v02_and_staging_options(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/package_sdk.py"), "--release-version", "0.2.0", "--help"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        for option in ("--release-version", "--source-sha", "--public-evidence", "--output-dir"):
            self.assertIn(option, result.stdout)

    def test_desktop_builder_has_explicit_v02_and_staging_options(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/package_desktop.py"),
                                 "--release-version", "0.2.0", "--help"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        for option in ("--release-version", "--source-sha", "--public-evidence", "--output-dir"):
            self.assertIn(option, result.stdout)

    def test_desktop_roster_has_no_legacy_proof_or_duplicate_members(self):
        roster = json.loads((ROOT / "packaging/v02-members.json").read_text())
        rows = roster["desktop"]["members"]
        paths = [row["path"] for row in rows]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertFalse(any("phase4-" in path for path in paths))
        self.assertIn("share/genewhip/tank-battle.bin", paths)
        self.assertIn("share/genewhip/recursion94.bin", paths)


    def test_reviewed_roster_closes_every_member_to_a_notice_and_right(self):
        spec = importlib.util.spec_from_file_location("gw_package_sdk_contract", ROOT / "scripts/package_sdk.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        roster = module._load_v02_roster()
        self.assertEqual(roster["release_version"], "0.2.0")
        self.assertEqual(len(roster["sdk"]["members"]), len({row["path"] for row in roster["sdk"]["members"]}))
        self.assertEqual(len(roster["desktop"]["members"]), len({row["path"] for row in roster["desktop"]["members"]}))

    def test_roster_rejects_an_unreviewed_path_after_input_digest_change(self):
        spec = importlib.util.spec_from_file_location("gw_package_sdk_mutation", ROOT / "scripts/package_sdk.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        roster = json.loads((ROOT / "packaging/v02-members.json").read_text())
        roster["sdk"]["members"][0]["path"] = "../outside"
        with tempfile.TemporaryDirectory(prefix="gw-v02-package-roster-") as directory:
            path = pathlib.Path(directory) / "roster.json"
            path.write_text(json.dumps(roster))
            with self.assertRaisesRegex(ValueError, "package-roster-unsafe-path"):
                module._load_v02_roster(path)

    def test_local_snapshot_is_clean_and_does_not_claim_the_checkout_head(self):
        with tempfile.TemporaryDirectory(prefix="gw-v02-source-snapshot-") as directory:
            source, revision = stage_source_snapshot(pathlib.Path(directory) / "source")
            main_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            self.assertRegex(revision, r"^[0-9a-f]{40}$")
            self.assertNotEqual(revision, main_head)
            status = subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True)
            self.assertEqual(status, "")
            self.assertIn("--stage-local", (source / "tests/evidence/v02_package_contract.py").read_text())

    def test_local_snapshot_identity_is_reproducible_across_package_kinds(self):
        with tempfile.TemporaryDirectory(prefix="gw-v02-snapshot-pair-") as directory:
            first, first_sha = stage_source_snapshot(pathlib.Path(directory) / "first")
            second, second_sha = stage_source_snapshot(pathlib.Path(directory) / "second")
            self.assertEqual(first_sha, second_sha)
            self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"],
                cwd=first, text=True), "")
            self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"],
                cwd=second, text=True), "")


def stage_source_snapshot(destination):
    """Build an isolated development-only Git snapshot from HEAD plus declared task inputs."""
    destination = pathlib.Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    archive = subprocess.check_output(["git", "archive", "HEAD"], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_tar:
        source_tar.extractall(destination)
    for relative in TASK_INPUTS:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(source.stat().st_mode & 0o777)
    subprocess.run(["git", "init", "--quiet"], cwd=destination, check=True)
    subprocess.run(["git", "config", "user.name", "Genewhip development snapshot"], cwd=destination, check=True)
    subprocess.run(["git", "config", "user.email", "development-snapshot@example.invalid"], cwd=destination, check=True)
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True)
    snapshot_env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_DATE="2000-01-01T00:00:00Z",
                        GIT_COMMITTER_DATE="2000-01-01T00:00:00Z")
    subprocess.run(["git", "commit", "--quiet", "-m", "development-only package input snapshot"],
                   cwd=destination, check=True, env=snapshot_env)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=destination, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=destination, text=True)
    if status:
        raise ValueError("development-snapshot-not-clean")
    return destination, revision


def pinned_sdl_archive(*, required=True):
    dependency = json.loads((ROOT / "packaging/dependencies/sdl3.json").read_text())
    expected = dependency.get("sha256")
    configured = os.environ.get("GENEWHIP_SDL3_ARCHIVE")
    candidates = ([pathlib.Path(configured)] if configured else [
        ROOT / "build/phase6/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/desktop/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/desktop3/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/desktop4/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/desktop4-prod/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/gameplay/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
        ROOT / "build/phase4-san/_deps/sdl3-subbuild/sdl3-populate-prefix/src/SDL3-3.4.18.tar.gz",
    ])
    for archive in candidates:
        if archive.is_file() and hashlib.sha256(archive.read_bytes()).hexdigest() == expected:
            return archive.resolve()
    if required:
        raise ValueError("pinned-sdl3-local-archive-unavailable-or-mismatched")
    return None


def execute_local_package(kind, public_evidence, output_dir):
    if kind not in ("sdk", "desktop"):
        raise ValueError("package-kind-invalid")
    main_root = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT,
                                                    text=True).strip()).resolve()
    authoritative = pathlib.Path(subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                                                        text=True).strip()).resolve()
    if main_root != authoritative or main_root != ROOT.resolve():
        raise ValueError("worktree-root-mismatch")
    evidence = pathlib.Path(public_evidence).resolve()
    output = pathlib.Path(output_dir).resolve()
    try:
        evidence.relative_to(ROOT.resolve())
        output.relative_to(ROOT.resolve())
    except ValueError:
        raise ValueError("package-path-outside-checkout")
    if not evidence.is_dir():
        raise ValueError("public-evidence-directory-missing")
    output.mkdir(parents=True, exist_ok=True)
    sdl_archive = pinned_sdl_archive() if kind == "desktop" else None
    with tempfile.TemporaryDirectory(prefix="gw-v02-package-stage-") as temp:
        source, revision = stage_source_snapshot(pathlib.Path(temp) / "source")
        builder = "scripts/package_sdk.py" if kind == "sdk" else "scripts/package_desktop.py"
        command = [sys.executable, str(source / builder), "--release-version", "0.2.0", "--source-sha", revision,
                   "--public-evidence", str(evidence), "--output-dir", str(output), "--development-only"]
        build_env = {name: os.environ[name] for name in (
            "PATH", "HOME", "TMPDIR", "DEVELOPER_DIR", "SDKROOT", "CC", "CXX",
            "CFLAGS", "CXXFLAGS", "AR", "MACOSX_DEPLOYMENT_TARGET") if name in os.environ}
        build_env.update({"GIT_CONFIG_NOSYSTEM": "1"})
        if sdl_archive is not None:
            build_env["GENEWHIP_SDL3_ARCHIVE"] = str(sdl_archive)
        result = subprocess.run(command, cwd=source, env=build_env, text=True,
                                capture_output=True, timeout=7200)
        if result.returncode:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise RuntimeError(f"{kind}-package-builder-failed ({result.returncode})")
        print(result.stdout, end="")
        return json.loads(result.stdout.strip().splitlines()[-1])


def main():
    if not any(arg in {"--sdk", "--desktop", "--stage-local", "--public-evidence", "--output-dir"}
               for arg in sys.argv[1:]):
        unittest.main(argv=[sys.argv[0], *sys.argv[1:]])
        return
    parser = argparse.ArgumentParser(description="Build and smoke an isolated local v0.2 package snapshot")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sdk", action="store_true")
    group.add_argument("--desktop", action="store_true")
    parser.add_argument("--stage-local", action="store_true", required=True)
    parser.add_argument("--public-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    execute_local_package("sdk" if args.sdk else "desktop", args.public_evidence, args.output_dir)


if __name__ == "__main__":
    main()
