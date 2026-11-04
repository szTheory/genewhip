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
    "scripts/evidence/v02_scope.py", "tools/evidence/core_benchmark.py",
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

    def test_performance_evidence_uses_selected_scope_and_rejects_scope_mutants(self):
        sdk_spec = importlib.util.spec_from_file_location(
            "gw_package_scope_selection", ROOT / "scripts/package_sdk.py")
        sdk = importlib.util.module_from_spec(sdk_spec)
        sdk_spec.loader.exec_module(sdk)
        benchmark = sdk._load_benchmark_module()
        fixture_spec = importlib.util.spec_from_file_location(
            "gw_package_scope_report_fixtures", ROOT / "tests/evidence/v02_qualification_contract.py")
        fixtures = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixtures)

        legacy_relative = pathlib.Path("evidence/v02-execution.json")
        authorized_relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        legacy_bytes = (ROOT / legacy_relative).read_bytes()
        authorized_bytes = (ROOT / authorized_relative).read_bytes()
        legacy_sha = hashlib.sha256(legacy_bytes).hexdigest()
        authorized_sha = hashlib.sha256(authorized_bytes).hexdigest()
        identity = {"source_sha": "a" * 40, "head_sha": "a" * 40,
                    "base_sha": "c" * 40, "run_id": "123456", "run_attempt": "2"}
        source_identity_sha = benchmark.source_identity()

        with tempfile.TemporaryDirectory(prefix="gw-package-scope-contract-") as directory:
            root = pathlib.Path(directory)
            legacy_path, authorized_path = root / legacy_relative, root / authorized_relative
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            authorized_path.parent.mkdir(parents=True, exist_ok=True)
            legacy_path.write_bytes(legacy_bytes)
            authorized_path.write_bytes(authorized_bytes)
            report_root = root / "build/v02/collected"
            report_root.mkdir(parents=True)
            performance_path = root / "build/v02/performance.json"
            performance_path.parent.mkdir(parents=True, exist_ok=True)

            def write_projection(scope_path, scope_sha):
                scope = json.loads(scope_path.read_text())
                reports = fixtures.synthetic_qualified_reports(benchmark, identity,
                    source_identity_sha, scope["scope_id"], scope_sha)
                raw_digests = {}
                for workload, report in reports.items():
                    report_path = report_root / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
                    raw_digests[workload] = hashlib.sha256(report_path.read_bytes()).hexdigest()
                projection = benchmark.build_public_performance_projection(reports, raw_digests,
                    identity=identity, source_identity_sha256=source_identity_sha,
                    scope_id=scope["scope_id"], scope_sha256=scope_sha)
                performance_path.write_text(json.dumps(projection, sort_keys=True, indent=2) + "\n")
                return projection

            scope_env = {
                "GITHUB_SHA": identity["head_sha"],
                "GITHUB_BASE_SHA": identity["base_sha"],
                "GITHUB_RUN_ID": identity["run_id"],
                "GITHUB_RUN_ATTEMPT": identity["run_attempt"],
            }
            with patch.object(sdk, "ROOT", root), patch.object(sdk, "_load_benchmark_module",
                    return_value=benchmark):
                for relative, scope_sha, scope_bytes in (
                        (authorized_relative, authorized_sha, authorized_bytes),
                        (legacy_relative, legacy_sha, legacy_bytes)):
                    selected_path = relative.as_posix() if relative == authorized_relative else ""
                    selector = {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": selected_path,
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": scope_sha if selected_path else ""}
                    with self.subTest(profile=relative.name), patch.dict(os.environ, selector):
                        scope_path = root / relative
                        projection = write_projection(scope_path, scope_sha)
                        self.assertEqual(projection["scope_sha256"], hashlib.sha256(scope_bytes).hexdigest())
                        digest = sdk._validate_performance_evidence(performance_path, identity["source_sha"])
                        self.assertEqual(digest, hashlib.sha256(performance_path.read_bytes()).hexdigest())

                with patch.dict(os.environ, {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_relative.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}):
                    write_projection(authorized_path, authorized_sha)
                    scope_module = sdk._load_scope_module()
                    original_read_scope = scope_module.read_scope

                    def read_then_replace(*args, **kwargs):
                        selected_path, selected_bytes = original_read_scope(*args, **kwargs)
                        selected_path.write_bytes(selected_bytes + b" ")
                        return selected_path, selected_bytes

                    with patch.object(sdk, "_load_scope_module", return_value=scope_module), \
                            patch.object(scope_module, "read_scope", side_effect=read_then_replace):
                        digest = sdk._validate_performance_evidence(performance_path, identity["source_sha"])
                    self.assertEqual(digest, hashlib.sha256(performance_path.read_bytes()).hexdigest())
                    self.assertNotEqual(hashlib.sha256(authorized_path.read_bytes()).hexdigest(), authorized_sha)
                    authorized_path.write_bytes(authorized_bytes)

                with patch.dict(os.environ, {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_relative.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": "0" * 64}):
                    write_projection(authorized_path, authorized_sha)
                    with self.assertRaisesRegex(ValueError,
                            "package-performance-scope-profile-invalid"):
                        sdk._validate_performance_evidence(performance_path, identity["source_sha"])

                with patch.dict(os.environ, {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": legacy_relative.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}):
                    with self.assertRaisesRegex(ValueError,
                            "package-performance-scope-profile-invalid"):
                        sdk._validate_performance_evidence(performance_path, identity["source_sha"])

                authorized_path.write_bytes(authorized_bytes + b" ")
                with patch.dict(os.environ, {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_relative.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}):
                    with self.assertRaisesRegex(ValueError,
                            "package-performance-scope-profile-invalid"):
                        sdk._validate_performance_evidence(performance_path, identity["source_sha"])

                authorized_path.write_bytes(authorized_bytes)
                with patch.dict(os.environ, {**scope_env,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_relative.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}):
                    projection = write_projection(authorized_path, authorized_sha)
                    projection["scope_sha256"] = "f" * 64
                    performance_path.write_text(json.dumps(projection, sort_keys=True, indent=2) + "\n")
                    with self.assertRaisesRegex(ValueError,
                            "public-performance-policy-rejected:.*public-performance-envelope"):
                        sdk._validate_performance_evidence(performance_path, identity["source_sha"])

    def test_staged_local_package_validation_keeps_authorized_scope_and_current_validator(self):
        authorized_relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        authorized_sha = hashlib.sha256((ROOT / authorized_relative).read_bytes()).hexdigest()
        selectors = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_relative.as_posix(),
            "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}
        with patch.dict(os.environ, selectors):
            child_env = package_child_environment()
        self.assertEqual({name: child_env[name] for name in selectors}, selectors)

        fixture_spec = importlib.util.spec_from_file_location(
            "gw_staged_package_report_fixtures", ROOT / "tests/evidence/v02_qualification_contract.py")
        fixtures = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixtures)
        revision = "d" * 40
        identity = {"source_sha": revision, "head_sha": revision, "base_sha": revision,
                    "run_id": "local", "run_attempt": "1"}

        with tempfile.TemporaryDirectory(prefix="gw-v02-staged-scope-contract-") as directory:
            source, unused_revision = stage_source_snapshot(pathlib.Path(directory) / "source", commit=False)
            self.assertIsNone(unused_revision)
            for relative in ("scripts/evidence/v02_scope.py", "tools/evidence/core_benchmark.py"):
                self.assertEqual((source / relative).read_bytes(), (ROOT / relative).read_bytes())

            sdk_spec = importlib.util.spec_from_file_location(
                "gw_staged_scope_package_sdk", source / "scripts/package_sdk.py")
            staged_sdk = importlib.util.module_from_spec(sdk_spec)
            sdk_spec.loader.exec_module(staged_sdk)
            staged_scope_module = staged_sdk._load_scope_module()
            self.assertEqual(pathlib.Path(staged_scope_module.__file__).resolve(),
                (source / "scripts/evidence/v02_scope.py").resolve())
            benchmark = staged_sdk._load_benchmark_module()
            self.assertEqual(benchmark.ROOT.resolve(), source.resolve())
            scope_path = source / authorized_relative
            scope = json.loads(scope_path.read_text())
            source_identity_sha = benchmark.source_identity()
            reports = fixtures.synthetic_qualified_reports(benchmark, identity,
                source_identity_sha, scope["scope_id"], authorized_sha)
            raw_digests = {}
            report_root = source / "build/v02/collected"
            for workload, report in reports.items():
                report_path = report_root / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
                raw_digests[workload] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            projection = benchmark.build_public_performance_projection(reports, raw_digests,
                identity=identity, source_identity_sha256=source_identity_sha,
                scope_id=scope["scope_id"], scope_sha256=authorized_sha)
            performance_path = source / "build/v02/performance.json"
            performance_path.parent.mkdir(parents=True, exist_ok=True)
            performance_path.write_text(json.dumps(projection, sort_keys=True, indent=2) + "\n")

            with patch.dict(os.environ, child_env, clear=True):
                digest = staged_sdk._validate_performance_evidence(performance_path, revision)
            self.assertEqual(digest, hashlib.sha256(performance_path.read_bytes()).hexdigest())


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


class DesktopBuildScratchContract(unittest.TestCase):
    def test_legacy_package_guest_checks_inherit_monitored_builder_group(self):
        package = self.package
        empty = io.BytesIO()
        with tarfile.open(fileobj=empty, mode="w"):
            pass
        class ReachedGuestCheck(Exception):
            pass
        for marker in ("", "1"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                observed = []
                def capture(command, **kwargs):
                    observed.append(command)
                    raise ReachedGuestCheck()
                with patch.dict(os.environ, {"GENEWHIP_CI_PACKAGE_OUTER_GROUP": marker}), \
                        patch.object(package.subprocess, "check_output", return_value=empty.getvalue()), \
                        patch.object(package, "configure_build"), \
                        patch.object(package, "sdl_route", return_value=([], "test")), \
                        patch.object(package.platform, "system", return_value="Darwin"), \
                        patch.object(package.platform, "machine", return_value="arm64"), \
                        patch.object(package.subprocess, "run", side_effect=capture):
                    with self.assertRaises(ReachedGuestCheck):
                        package.build_archive("a" * 40, pathlib.Path(directory), "test")
                self.assertEqual(len(observed), 1)
                self.assertIn("phase4_game.py", observed[0][1])
                self.assertEqual("--outer-process-group" in observed[0], marker == "1")

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "gw_desktop_build_scratch_contract", ROOT / "scripts/package_desktop.py")
        cls.package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.package)

    @staticmethod
    def _archive_bytes(name, *, extra_member=False):
        metadata = {"runtime_content_identity": "runtime", "public_evidence_digest": "public",
                    "performance_evidence_digest": "performance", "api_version": 4,
                    "input_log_version": 1}
        members = {"checksums.json": b"{}",
                   "metadata.json": json.dumps(metadata, sort_keys=True).encode()}
        if extra_member:
            members["repeat-only.txt"] = b"different repeat output"
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path, body in sorted(members.items()):
                    info = tarfile.TarInfo(name + "/" + path)
                    info.size, info.mtime, info.mode = len(body), 0, 0o644
                    tar.addfile(info, io.BytesIO(body))
        return output.getvalue()

    @staticmethod
    def _make_intermediates(scratch):
        for relative in ("source/.package-build/CMakeCache.txt", "stage/bin/app",
                         "public-closure/manifest.json", "performance.json"):
            path = pathlib.Path(scratch) / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("owned build input")

    def test_release_preserves_sealed_archive_and_removes_owned_intermediates(self):
        package = self.package
        with tempfile.TemporaryDirectory(prefix="gw-v02-build-cleanup-") as directory:
            root = pathlib.Path(directory)
            scratch = root / "owned-scratch"
            scratch.mkdir()
            archive = scratch / "desktop.tar.gz"
            archive.write_bytes(self._archive_bytes("package-root"))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self._make_intermediates(scratch)
            outside = root / "outside"
            outside.mkdir()
            external_payload = outside / "keep.txt"
            external_payload.write_text("must remain untouched")
            link = scratch / "owned-link"
            link.symlink_to(outside, target_is_directory=True)

            package._release_v02_build_scratch(scratch, archive, digest)

            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
            self.assertEqual(list(scratch.iterdir()), [archive])
            self.assertFalse(os.path.lexists(link))
            self.assertEqual(external_payload.read_text(), "must remain untouched")

    def test_release_rejects_unsealed_or_unowned_archive_before_deleting(self):
        package = self.package
        for failure in ("wrong-digest", "symlink-archive", "outside-archive"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(
                    prefix="gw-v02-build-cleanup-reject-") as directory:
                root = pathlib.Path(directory)
                scratch = root / "owned-scratch"
                scratch.mkdir()
                self._make_intermediates(scratch)
                owned_marker = scratch / "source/.package-build/CMakeCache.txt"
                archive_bytes = self._archive_bytes("package-root")
                if failure == "wrong-digest":
                    archive = scratch / "desktop.tar.gz"
                    archive.write_bytes(archive_bytes)
                    digest = "0" * 64
                else:
                    outside = root / "outside"
                    outside.mkdir()
                    archive = outside / "desktop.tar.gz"
                    archive.write_bytes(archive_bytes)
                    digest = hashlib.sha256(archive_bytes).hexdigest()
                    if failure == "symlink-archive":
                        link = scratch / "desktop.tar.gz"
                        link.symlink_to(archive)
                        archive = link

                with self.assertRaisesRegex(ValueError, "desktop-build-cleanup-archive-not-sealed"):
                    package._release_v02_build_scratch(scratch, archive, digest)

                self.assertEqual(owned_marker.read_text(), "owned build input")
                if failure == "wrong-digest":
                    self.assertEqual((scratch / "desktop.tar.gz").read_bytes(), archive_bytes)
                elif failure == "symlink-archive":
                    self.assertTrue((scratch / "desktop.tar.gz").is_symlink())
                    self.assertEqual(archive.resolve().read_bytes(), archive_bytes)
                else:
                    self.assertEqual(archive.read_bytes(), archive_bytes)

    def _run_mocked_package(self, root, *, repeat_mismatch=False):
        package = self.package
        revision = "a" * 40
        args = argparse.Namespace(development_only=True, source_sha=revision,
            output_dir=pathlib.Path(root) / "output", public_evidence=pathlib.Path(root) / "evidence")
        state = {"events": [], "builds": [], "smoke_calls": 0}

        def build_archive(_revision, scratch, name, _development_only, _public_evidence,
                          *, expected_performance_identity=None):
            self.assertIsNone(expected_performance_identity)
            index = len(state["builds"])
            self._make_intermediates(scratch)
            archive = pathlib.Path(scratch) / "desktop.tar.gz"
            archive.write_bytes(self._archive_bytes(name, extra_member=(repeat_mismatch and index == 1)))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            state["builds"].append((pathlib.Path(scratch), archive, digest))
            state["events"].append("build-" + str(index + 1))
            if index == 1:
                first_scratch, first_archive, first_digest = state["builds"][0]
                self.assertEqual(list(first_scratch.iterdir()), [first_archive])
                self.assertEqual(hashlib.sha256(first_archive.read_bytes()).hexdigest(), first_digest)
            return archive, digest

        def smoke(command, **_kwargs):
            state["smoke_calls"] += 1
            state["events"].append("smoke")
            self.assertEqual(state["events"][:-1], ["build-1", "build-2"])
            first_scratch, first_archive, first_digest = state["builds"][0]
            repeat_scratch = state["builds"][1][0]
            self.assertEqual(list(first_scratch.iterdir()), [first_archive])
            self.assertFalse(repeat_scratch.exists())
            self.assertEqual(hashlib.sha256(first_archive.read_bytes()).hexdigest(), first_digest)
            self.assertEqual(pathlib.Path(command[3]), first_archive)
            return subprocess.CompletedProcess(command, 0, json.dumps({"outcome": "pass"}) + "\n", "")

        patchers = (
            patch.object(package.platform, "system", return_value="Darwin"),
            patch.object(package.platform, "machine", return_value="arm64"),
            patch.object(package.subprocess, "check_output", return_value=""),
            patch.object(package, "run", return_value=revision),
            patch.object(package, "_build_v02_archive", side_effect=build_archive),
            patch.object(package.subprocess, "run", side_effect=smoke),
            patch("builtins.print"),
        )
        return args, state, patchers

    def test_v02_package_releases_first_build_before_repeat_and_smoke(self):
        with tempfile.TemporaryDirectory(prefix="gw-v02-package-order-") as directory:
            args, state, patchers = self._run_mocked_package(directory)
            with patchers[0], patchers[1], patchers[2], patchers[3], patchers[4], patchers[5], patchers[6]:
                self.package._v02_package(args)

            self.assertEqual(state["events"], ["build-1", "build-2", "smoke"])
            self.assertEqual(state["smoke_calls"], 1)
            first_digest = state["builds"][0][2]
            output_archive = args.output_dir / ("genewhip-0.2.0-playable-preview-macos-arm64-" +
                                               args.source_sha[:12] + ".tar.gz")
            self.assertEqual(hashlib.sha256(output_archive.read_bytes()).hexdigest(), first_digest)
            receipt = json.loads(output_archive.with_suffix(output_archive.suffix + ".qualification.json").read_text())
            self.assertEqual(receipt["smoke"]["outcome"], "pass")

    def test_v02_package_keeps_repeat_mismatch_rejection_before_smoke(self):
        with tempfile.TemporaryDirectory(prefix="gw-v02-package-repeat-mismatch-") as directory:
            args, state, patchers = self._run_mocked_package(directory, repeat_mismatch=True)
            with patchers[0], patchers[1], patchers[2], patchers[3], patchers[4], patchers[5], patchers[6]:
                with self.assertRaisesRegex(ValueError, "desktop-v02-archive-not-repeatable"):
                    self.package._v02_package(args)

            self.assertEqual(state["events"], ["build-1", "build-2"])
            self.assertEqual(state["smoke_calls"], 0)
            self.assertEqual(list(args.output_dir.iterdir()), [])


def stage_source_snapshot(destination, *, commit=True):
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
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True)
    if not commit:
        return destination, None
    subprocess.run(["git", "config", "user.name", "Genewhip development snapshot"], cwd=destination, check=True)
    subprocess.run(["git", "config", "user.email", "development-snapshot@example.invalid"], cwd=destination, check=True)
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


def package_child_environment():
    """Keep only required local tooling variables and the selected scope identity."""
    names = ("PATH", "HOME", "TMPDIR", "DEVELOPER_DIR", "SDKROOT", "CC", "CXX",
        "CFLAGS", "CXXFLAGS", "AR", "MACOSX_DEPLOYMENT_TARGET",
        "GENEWHIP_QUALIFICATION_SCOPE_PATH", "GENEWHIP_QUALIFICATION_SCOPE_SHA256")
    build_env = {name: os.environ[name] for name in names if name in os.environ}
    build_env["GIT_CONFIG_NOSYSTEM"] = "1"
    return build_env


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
        build_env = package_child_environment()
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
