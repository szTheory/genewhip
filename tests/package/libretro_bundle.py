#!/usr/bin/env python3
"""Contract tests for the bounded, source-bound Libretro bundle."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import json
import pathlib
import re
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import package_libretro
from scripts.ci import run_libretro_tracer_container, verify_attestation_inputs
from scripts.release import promote

SOURCE = "a" * 40
RUN_ID = "12345"
ATTEMPT = "2"


def _elf_fixture() -> bytes:
    """A structural ELF fixture for portable package-contract tests, not a release core."""
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (3).to_bytes(2, "little")
    data[18:20] = (62).to_bytes(2, "little")
    data[20:24] = (1).to_bytes(4, "little")
    data[32:40] = (64).to_bytes(8, "little")
    data[52:54] = (64).to_bytes(2, "little")
    data[54:56] = (56).to_bytes(2, "little")
    data[56:58] = (1).to_bytes(2, "little")
    data[64:68] = (1).to_bytes(4, "little")  # PT_LOAD
    data[68:72] = (5).to_bytes(4, "little")
    return bytes(data)


class LibretroBundleContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="libretro-bundle-contract-")
        self.root = pathlib.Path(self.temp.name)
        self.library = self.root / package_libretro.MODULE_NAME
        self.library.write_bytes(_elf_fixture())

    def tearDown(self):
        self.temp.cleanup()

    def build(self, version="0.3.0", name="release"):
        output = self.root / name
        def structural_module_check(path):
            if not package_libretro._elf_x86_64(path):
                raise ValueError("libretro-module-invalid")

        # These bundle contracts use a structural ELF fixture. The actual Linux
        # module is dynamically loaded by the Linux CI integration and tracer.
        with mock.patch.object(package_libretro, "_validate_module_contract",
                               side_effect=structural_module_check):
            package_libretro.build(self.library, output, SOURCE, version, RUN_ID, ATTEMPT)
        return output

    def test_truncated_elf_header_is_rejected_as_a_module(self):
        # Retained RED evidence: an identification header without a loadable
        # ELF program header must not be packaged as a Linux module.
        self.library.write_bytes(bytes.fromhex("7f454c460201") + bytes(14))
        with self.assertRaisesRegex(ValueError, "module"):
            package_libretro.build(self.library, self.root / "release", SOURCE,
                                   "0.3.0", RUN_ID, ATTEMPT)

    def test_realistic_bundle_roundtrips_and_repeats_byte_for_byte(self):
        first = self.build(name="first")
        second = self.build(name="second")
        inventory = package_libretro.validate_bundle(first, source_sha=SOURCE,
            version="0.3.0", run_id=RUN_ID, run_attempt=ATTEMPT)
        self.assertEqual((first / "inventory.json").read_bytes(), (second / "inventory.json").read_bytes())
        archive_name = "genewhip-0.3.0-linux-x86_64-libretro.tar.gz"
        self.assertEqual((first / archive_name).read_bytes(), (second / archive_name).read_bytes())
        self.assertEqual(list(inventory["assets"]), sorted(inventory["assets"]))
        with tarfile.open(first / archive_name, "r:gz") as archive:
            self.assertEqual([row.name for row in archive.getmembers()], sorted(package_libretro.MEMBERS))
            files = {row.name: archive.extractfile(row).read() for row in archive.getmembers()}
        self.assertEqual(files["LICENSE"], (ROOT / "LICENSE").read_bytes())
        header_license = files["LIBRETRO-HEADER-LICENSE.txt"].decode()
        self.assertIn("Libretro API header notice", header_license)
        self.assertNotIn(str(pathlib.Path.home()), header_license)

    def test_ci_only_release_keeps_embedded_module_version_and_bytes(self):
        original = self.build("0.3.0", "original")
        later = self.build("0.3.1", "later")
        old = package_libretro.validate_bundle(original, source_sha=SOURCE, version="0.3.0",
                                               run_id=RUN_ID, run_attempt=ATTEMPT)
        new = package_libretro.validate_bundle(later, source_sha=SOURCE, version="0.3.1",
                                               run_id=RUN_ID, run_attempt=ATTEMPT)
        self.assertEqual(new["module_version"], "0.3.0")
        self.assertEqual(old["module_version"], "0.3.0")
        self.assertEqual((original / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz").read_bytes(),
                         (later / "genewhip-0.3.1-linux-x86_64-libretro.tar.gz").read_bytes())

    def test_stale_or_unsupported_metadata_is_rejected(self):
        cases = (("version", "0.3.1"), ("supported_extensions", "bin|gen|iso"),
                 ("need_fullpath", "true"), ("supports_no_game", "true"),
                 ("invented_capability", "true"))
        source = (ROOT / "packaging/libretro/genewhip_libretro.info").read_text()
        for key, value in cases:
            with self.subTest(key=key):
                altered = source + f'{key} = "{value}"\n'
                info = self.root / "bad.info"
                info.write_text(altered)
                output = self.root / ("bad-" + key)
                with mock.patch.object(package_libretro, "INFO", info):
                    with self.assertRaises(ValueError):
                        package_libretro.build(self.library, output, SOURCE, "0.3.0", RUN_ID, ATTEMPT)

    def test_package_and_publisher_reject_source_run_attempt_and_bytes_mismatch(self):
        output = self.build()
        inventory = json.loads((output / "inventory.json").read_text())
        self.assertEqual(promote.validate_release_inventory(output, inventory)[1], [])
        self.assertEqual(promote.validate_v03_libretro_inventory(output, inventory, SOURCE), [])
        self.assertIn("inventory-source-mismatch",
                      promote.validate_v03_libretro_inventory(output, inventory, "b" * 40))
        for field, changed in (("run_id", "54321"), ("run_attempt", "3"),
                               ("version", "0.3.1"), ("module_version", "0.3.1")):
            mutant = copy.deepcopy(inventory)
            mutant[field] = changed
            with self.subTest(field=field):
                self.assertTrue(promote.validate_v03_libretro_inventory(output, mutant, SOURCE))
        archive = output / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"private-payload-marker\n")
        self.assertTrue(promote.validate_release_inventory(output, inventory)[1])

    def test_publisher_rejects_resealed_member_claims_that_disagree_with_archive(self):
        output = self.build()
        inventory_path = output / "inventory.json"
        inventory = json.loads(inventory_path.read_text())
        qualification_path = output / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz.qualification.json"
        qualification = json.loads(qualification_path.read_text())
        qualification["members"][0]["sha256"] = "0" * 64
        qualification_bytes = package_libretro._json(qualification)
        qualification_path.write_bytes(qualification_bytes)
        row = inventory["assets"][qualification_path.name]
        row.update(size=len(qualification_bytes), sha256=hashlib.sha256(qualification_bytes).hexdigest())
        inventory_bytes = package_libretro._json(inventory)
        inventory_path.write_bytes(inventory_bytes)
        sums = "".join(f"{entry['sha256']}  {filename}\n"
                       for filename, entry in sorted(inventory["assets"].items()))
        sums += f"{hashlib.sha256(inventory_bytes).hexdigest()}  inventory.json\n"
        (output / "SHA256SUMS").write_text(sums)
        self.assertEqual(promote.validate_release_inventory(output, inventory)[1], [])
        self.assertIn("inventory-package-receipt-invalid",
                      promote.validate_v03_libretro_inventory(output, inventory, SOURCE))

    def test_sidecars_and_truncated_archives_are_rejected(self):
        output = self.build()
        inventory = json.loads((output / "inventory.json").read_text())
        checksum = output / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz.sha256"
        original = checksum.read_bytes()
        checksum.write_bytes(original + b"tampered")
        self.assertTrue(promote.validate_release_inventory(output, inventory)[1])
        checksum.write_bytes(original)
        archive = output / "genewhip-0.3.0-linux-x86_64-libretro.tar.gz"
        original_archive = archive.read_bytes()
        with self.assertRaises(ValueError):
            package_libretro._open_archive(original_archive[:len(original_archive) // 2])
        archive.write_bytes(original_archive)

    def test_duplicate_and_special_members_are_rejected(self):
        raw = tempfile.NamedTemporaryFile(delete=False)
        raw.close()
        try:
            with tarfile.open(raw.name, "w:gz") as archive:
                for name in sorted(package_libretro.MEMBERS):
                    item = tarfile.TarInfo(name)
                    item.size = 1
                    archive.addfile(item, __import__("io").BytesIO(b"x"))
                item = tarfile.TarInfo("LICENSE")
                item.size = 1
                archive.addfile(item, __import__("io").BytesIO(b"x"))
            with self.assertRaises(ValueError):
                package_libretro._open_archive(pathlib.Path(raw.name).read_bytes())
        finally:
            pathlib.Path(raw.name).unlink(missing_ok=True)

    def test_expansion_limit_is_applied_before_archive_read(self):
        files = {name: b"x" for name in package_libretro.MEMBERS}
        archive = package_libretro._tar_bytes(files)
        with mock.patch.object(package_libretro, "MAX_EXPANDED", 100):
            with self.assertRaises(ValueError):
                package_libretro._open_archive(archive)

    def test_attestation_input_gate_binds_independent_run_identity(self):
        output = self.build()
        identity_dir = self.root / "identity"
        identity_dir.mkdir()
        expected = verify_attestation_inputs.identity("owner/repo", SOURCE, RUN_ID, ATTEMPT,
            "push", "refs/heads/main", "Required preview checks")
        (identity_dir / "_ci-identity.json").write_text(json.dumps(expected))
        self.assertEqual(verify_attestation_inputs.validate_inputs(output, expected, identity_dir), [])
        for field, value in (("run_id", "99999"), ("run_attempt", "1"), ("source_sha", "b" * 40)):
            mutant = dict(expected)
            mutant[field] = value
            with self.subTest(field=field):
                self.assertTrue(verify_attestation_inputs.validate_inputs(output, mutant, identity_dir))

    def test_v03_publisher_requires_successful_libretro_and_attestation_jobs(self):
        api = promote.GitHub("token", "owner/repo")
        base = [
            {"name": "required-ci", "status": "completed", "conclusion": "success"},
            {"name": "attestation", "status": "completed", "conclusion": "success"},
        ]
        with mock.patch.object(api, "get", return_value={"jobs": base}):
            with self.assertRaisesRegex(promote.PromotionError, "libretro-qualification-job-not-success"):
                api.verify_required_check(RUN_ID, int(ATTEMPT), "0.3.0")
        for conclusion in ("failure", "skipped"):
            jobs = base + [{"name": "libretro", "status": "completed", "conclusion": conclusion}]
            with mock.patch.object(api, "get", return_value={"jobs": jobs}):
                with self.subTest(conclusion=conclusion):
                    with self.assertRaisesRegex(promote.PromotionError, "libretro-qualification-job-not-success"):
                        api.verify_required_check(RUN_ID, int(ATTEMPT), "0.3.0")
        jobs = base + [{"name": "libretro", "status": "completed", "conclusion": "success"}]
        with mock.patch.object(api, "get", return_value={"jobs": jobs}):
            api.verify_required_check(RUN_ID, int(ATTEMPT), "0.3.0")

    def test_publisher_closure_recorder_never_publishes_an_incomplete_roster(self):
        output = self.build()
        inventory = json.loads((output / "inventory.json").read_text())
        package_libretro._recorded_publisher_closure(output, inventory, SOURCE)

    def test_self_test_reuses_supplied_module_without_cmake_and_runs_production_chain(self):
        library = self.root / "supplied core with spaces.so"
        library_bytes = _elf_fixture()
        library.write_bytes(library_bytes)
        real_build = package_libretro.build
        real_validate = package_libretro.validate_bundle
        real_closure = package_libretro._recorded_publisher_closure
        observed = {}

        def record_build(path, *args, **kwargs):
            observed["path"] = pathlib.Path(path)
            observed["bytes"] = pathlib.Path(path).read_bytes()
            return real_build(path, *args, **kwargs)

        with mock.patch.object(package_libretro.platform, "system", return_value="Linux"), \
                mock.patch.object(package_libretro.platform, "machine", return_value="x86_64"), \
                mock.patch.object(package_libretro.subprocess, "check_output", return_value=SOURCE), \
                mock.patch.object(package_libretro.subprocess, "run") as cmake, \
                mock.patch.object(package_libretro, "_validate_module_contract") as load_boundary, \
                mock.patch.object(package_libretro, "build", side_effect=record_build) as build, \
                mock.patch.object(package_libretro, "validate_bundle", wraps=real_validate) as validate, \
                mock.patch.object(package_libretro, "_recorded_publisher_closure", wraps=real_closure) as closure, \
                contextlib.redirect_stdout(__import__("io").StringIO()):
            package_libretro._self_test(library)

        self.assertEqual(observed["path"], library.resolve())
        self.assertEqual(observed["bytes"], library_bytes)
        cmake.assert_not_called()
        build.assert_called_once()
        load_boundary.assert_called_once_with(library.resolve())
        validate.assert_called_once()
        closure.assert_called_once()

    def test_self_test_without_library_keeps_temporary_configure_and_build_path(self):
        inventory = {"run_id": "1", "run_attempt": "1"}
        with mock.patch.object(package_libretro.platform, "system", return_value="Linux"), \
                mock.patch.object(package_libretro.platform, "machine", return_value="x86_64"), \
                mock.patch.object(package_libretro.subprocess, "check_output", return_value=SOURCE), \
                mock.patch.object(package_libretro.subprocess, "run") as cmake, \
                mock.patch.object(package_libretro, "build", return_value=inventory) as build, \
                mock.patch.object(package_libretro, "validate_bundle", return_value=inventory) as validate, \
                mock.patch.object(package_libretro, "_recorded_publisher_closure") as closure, \
                contextlib.redirect_stdout(__import__("io").StringIO()):
            package_libretro._self_test()

        self.assertEqual(cmake.call_count, 2)
        configure = cmake.call_args_list[0].args[0]
        build_command = cmake.call_args_list[1].args[0]
        self.assertEqual(configure[:3], ["cmake", "-S", str(package_libretro.ROOT)])
        self.assertEqual(build_command, ["cmake", "--build", configure[configure.index("-B") + 1],
                                         "--target", "genewhip_libretro", "--parallel", "2"])
        supplied = build.call_args.args[0]
        self.assertEqual(supplied.name, package_libretro.MODULE_NAME)
        self.assertEqual(supplied.parent.name, "build")
        self.assertEqual(validate.call_args.kwargs["source_sha"], SOURCE)
        validate.assert_called_once()
        closure.assert_called_once()

    def test_invalid_or_unloadable_supplied_module_rejects_without_cmake_fallback(self):
        wrong_arch = _elf_fixture()[:18] + (183).to_bytes(2, "little") + _elf_fixture()[20:]
        invalid_inputs = (b"not an ELF shared object", wrong_arch)
        with mock.patch.object(package_libretro.platform, "system", return_value="Linux"), \
                mock.patch.object(package_libretro.platform, "machine", return_value="x86_64"), \
                mock.patch.object(package_libretro.subprocess, "check_output", return_value=SOURCE), \
                mock.patch.object(package_libretro.subprocess, "run") as cmake:
            missing = self.root / "missing module.so"
            with self.assertRaises(OSError):
                package_libretro._self_test(missing)
            for index, content in enumerate(invalid_inputs):
                invalid = self.root / f"invalid module {index}.so"
                invalid.write_bytes(content)
                with self.subTest(index=index):
                    with self.assertRaisesRegex(ValueError, "module"):
                        package_libretro._self_test(invalid)
        cmake.assert_not_called()

        unloadable = self.root / "unloadable module.so"
        unloadable.write_bytes(_elf_fixture())
        with mock.patch.object(package_libretro.platform, "system", return_value="Linux"), \
                mock.patch.object(package_libretro.platform, "machine", return_value="x86_64"), \
                mock.patch.object(package_libretro.subprocess, "check_output", return_value=SOURCE), \
                mock.patch.object(package_libretro.ctypes, "CDLL", side_effect=OSError("bad shared object")), \
                mock.patch.object(package_libretro.subprocess, "run") as cmake:
            with self.assertRaisesRegex(ValueError, "module-invalid"):
                package_libretro._self_test(unloadable)
        cmake.assert_not_called()

    def test_host_guard_rejects_both_self_test_paths_before_build(self):
        supplied = self.root / "module.so"
        supplied.write_bytes(_elf_fixture())
        for library in (None, supplied):
            with self.subTest(supplied=library is not None), \
                    mock.patch.object(package_libretro.platform, "system", return_value="Darwin"), \
                    mock.patch.object(package_libretro.platform, "machine", return_value="arm64"), \
                    mock.patch.object(package_libretro.subprocess, "run") as cmake:
                with self.assertRaisesRegex(ValueError, "requires-linux-x86_64-host"):
                    package_libretro._self_test(library)
                cmake.assert_not_called()

    def test_self_test_cli_forwards_source_identity_to_combined_tracer_mode(self):
        library = self.root / "module.so"
        with mock.patch.object(package_libretro, "_self_test") as self_test, \
                contextlib.redirect_stdout(__import__("io").StringIO()):
            self.assertEqual(package_libretro.main([
                "--self-test", "--tracer", "--library", str(library), "--source-sha", SOURCE,
            ]), 0)
        self_test.assert_called_once_with(library, SOURCE)

    def test_tracer_documentation_matches_runner_resources_and_exact_pins(self):
        docs = (ROOT / "docs/libretro.md").read_text(encoding="utf-8")
        self.assertIn("python3 -I scripts/ci/run_libretro_tracer_container.py", docs)
        self.assertIn("2 CPUs", docs)
        self.assertIn("2 GiB memory", docs)
        self.assertIn("no extra swap", docs)
        self.assertIn("256 PIDs", docs)
        self.assertIn("executable 2 GiB `/tmp`", docs)
        self.assertRegex(docs, r"(?i)image build and tracer run each have separate deadlines of 900 seconds")
        self.assertRegex(docs, r"Docker engine prerequisites and each cleanup command have a 15-second deadline")
        self.assertEqual(re.search(r"(\d+) CPUs", docs).group(1), run_libretro_tracer_container.CPUS)
        self.assertEqual(re.search(r"(\d+) GiB memory", docs).group(1) + "g", run_libretro_tracer_container.MEMORY)
        self.assertEqual(re.search(r"(\d+) PIDs", docs).group(1), run_libretro_tracer_container.PIDS_LIMIT)
        tmpfs_gib = int(re.search(r"(\d+) GiB `/tmp`", docs).group(1))
        self.assertEqual(str(tmpfs_gib * 1024**3), run_libretro_tracer_container.TMPFS_BYTES)
        deadlines = re.search(r"each have separate deadlines of (\d+) seconds", docs, re.IGNORECASE).group(1)
        self.assertEqual(int(deadlines), run_libretro_tracer_container.BUILD_TIMEOUT_SECONDS)
        self.assertEqual(int(deadlines), run_libretro_tracer_container.TRACER_TIMEOUT_SECONDS)
        cleanup_seconds = re.search(r"each cleanup command have a (\d+)-second deadline", docs).group(1)
        self.assertEqual(int(cleanup_seconds), run_libretro_tracer_container.DOCKER_COMMAND_TIMEOUT_SECONDS)
        self.assertEqual(run_libretro_tracer_container.MEMORY, run_libretro_tracer_container.MEMORY_SWAP)
        self.assertIn(run_libretro_tracer_container.BASE_IMAGE, docs)
        self.assertIn(run_libretro_tracer_container.DEBIAN_SNAPSHOT, docs)
        self.assertIn(run_libretro_tracer_container.CMAKE_VERSION, docs)
        self.assertIn("python3 -I scripts/package_libretro.py --self-test --tracer --library build/libretro/genewhip_libretro.so", docs)

    def test_linux_ci_tracer_reuses_qualified_module_after_sanitizer_checks(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        lane = workflow.split("  libretro:\n", 1)[1].split("\n  product-smoke:", 1)[0]
        contracts_name = "- name: Run Libretro package and container-runner contracts"
        tracer_name = "- name: Run production package tracer against tested module"
        self.assertIn(contracts_name, lane)
        self.assertIn(tracer_name, lane)
        contracts_step = lane.index(contracts_name)
        tracer_step = lane.index(tracer_name)
        sanitizer = lane.index("- name: Run actual-module lifecycle and route tests with AddressSanitizer and UndefinedBehaviorSanitizer")
        package = lane.index("- name: Package tested Linux x86_64 core")
        self.assertLess(sanitizer, contracts_step)
        self.assertLess(contracts_step, tracer_step)
        self.assertLess(tracer_step, package)
        contracts = lane[contracts_step:tracer_step]
        self.assertIn("python3 -I tests/package/libretro_bundle.py", contracts)
        self.assertIn("python3 -I tests/package/libretro_tracer_container.py", contracts)
        tracer = lane[tracer_step:package]
        for argument in ("python3 -I scripts/package_libretro.py", "--self-test", "--tracer",
                         "--library build/libretro/genewhip_libretro.so"):
            self.assertIn(argument, tracer)
        for retained in ("Run aggregate and actual module contracts", "Run release actual-module and evidence tests",
                         "Validate source-bound Linux callback report", "Export immutable Linux core package",
                         "Bind Libretro package input to the exact run attempt"):
            self.assertIn(retained, lane)

    def test_unsafe_archive_rosters_are_rejected(self):
        good = {name: b"x" for name in package_libretro.MEMBERS}
        cases = (
            {**good, "private.txt": b"x"},
            {"../escape": b"x", **{name: value for name, value in good.items() if name != "LICENSE"}},
            {"/absolute": b"x", **{name: value for name, value in good.items() if name != "LICENSE"}},
            {"bad\\name": b"x", **{name: value for name, value in good.items() if name != "LICENSE"}},
        )
        for files in cases:
            with self.subTest(names=tuple(files)):
                with self.assertRaises(ValueError):
                    package_libretro._open_archive(package_libretro._tar_bytes(files))

        raw = tempfile.NamedTemporaryFile(delete=False)
        raw.close()
        try:
            with tarfile.open(raw.name, "w:gz") as archive:
                link = tarfile.TarInfo("LICENSE")
                link.type = tarfile.SYMTYPE
                link.linkname = "target"
                archive.addfile(link)
            with self.assertRaises(ValueError):
                package_libretro._open_archive(pathlib.Path(raw.name).read_bytes())
        finally:
            pathlib.Path(raw.name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
