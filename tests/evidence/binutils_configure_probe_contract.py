#!/usr/bin/env python3
"""Offline contracts for the pinned Binutils configure-probe source correction."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/evidence"))

import independent_game_toolchain as toolchain  # noqa: E402


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test module unavailable: " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PATCHER = load_module("genewhip_configure_probe", ROOT / "fixtures/independent-game/toolchain/configure_probe.py")
ROUTE_CONTRACT = load_module("genewhip_probe_scanner", ROOT / "tests/session/phase6_route_contract.py")
OLD = PATCHER.OLD_PROBE
NEW = PATCHER.NEW_PROBE


class ConfigureProbePatchContract(unittest.TestCase):
    def test_actual_replacement_text_changes_only_the_probe_and_scanner_accepts_control(self):
        source = b"if ln -s conf$$.file conf$$ 2>/dev/null; then\n" + OLD + b" 2>/dev/null\n"
        patched = PATCHER.replace_probe_bytes(source, 1)
        self.assertEqual(patched, source.replace(OLD, NEW))
        self.assertEqual(patched.count(OLD), 0)
        self.assertEqual(patched.count(NEW), 1)

        upstream_target = OLD.split(b" ")[2].decode("ascii").replace("$$", "123")
        patched_target = NEW.split(b" ")[2].decode("ascii").replace("$$", "123")
        with tempfile.TemporaryDirectory(prefix="gw-binutils-probe-scan-") as temporary:
            build = pathlib.Path(temporary).resolve()
            (build / "conf123.file").write_bytes(b"probe passed\n")
            probe_dir = build / "conf123.dir"
            probe_dir.mkdir()
            probe_link = probe_dir / "conf123.file"
            probe_link.symlink_to(upstream_target)
            diagnostics: list[dict[str, object]] = []
            self.assertIsNone(ROUTE_CONTRACT._safe_tree_bytes(
                build, diagnostics, allow_build_file_links=True))
            self.assertEqual(diagnostics[0]["kind"], "unsafe-file-symlink")
            self.assertEqual(diagnostics[0]["reason"], "target-symlink-rejected")

            probe_link.unlink()
            probe_link.symlink_to(patched_target)
            diagnostics = []
            measured = ROUTE_CONTRACT._safe_tree_bytes(
                build, diagnostics, allow_build_file_links=True)
            self.assertIsNotNone(measured)
            self.assertEqual(diagnostics, [])
            self.assertEqual(measured, (build / "conf123.file").stat().st_size
                             + probe_link.lstat().st_size)

    def test_replacement_and_source_identity_reject_changed_inputs(self):
        with self.assertRaisesRegex(ValueError, "occurrence count"):
            PATCHER.replace_probe_bytes(NEW, 1)
        with self.assertRaisesRegex(ValueError, "occurrence count"):
            PATCHER.replace_probe_bytes(OLD * 2, 1)
        with tempfile.TemporaryDirectory(prefix="gw-binutils-probe-identity-") as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(ValueError, "archive identity"):
                PATCHER.patch_tree(root, "0" * 64)
            with self.assertRaisesRegex(ValueError, "unpatched source tree"):
                PATCHER.patch_tree(root, PATCHER.ARCHIVE_SHA256)

    def test_allowlist_checks_exact_filelist_counts_and_original_hashes(self):
        content_a = b"prefix\n" + OLD + b"\n"
        content_b = b"prefix\n" + OLD + b"\n" + OLD + b"\n"
        expected = (
            ("a/configure", hashlib.sha256(content_a).hexdigest(), 1),
            ("b/configure", hashlib.sha256(content_b).hexdigest(), 2),
        )

        def make_root() -> pathlib.Path:
            temporary = tempfile.TemporaryDirectory(prefix="gw-probe-allowlist-")
            self.addCleanup(temporary.cleanup)
            root = pathlib.Path(temporary.name)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a/configure").write_bytes(content_a)
            (root / "b/configure").write_bytes(content_b)
            return root

        PATCHER.verify_probe_files(make_root(), expected)
        missing = make_root()
        (missing / "b/configure").unlink()
        with self.assertRaisesRegex(ValueError, "file list or occurrence counts"):
            PATCHER.verify_probe_files(missing, expected)

        extra = make_root()
        (extra / "unlisted").write_bytes(OLD)
        with self.assertRaisesRegex(ValueError, "file list or occurrence counts"):
            PATCHER.verify_probe_files(extra, expected)

        wrong_count = make_root()
        (wrong_count / "a/configure").write_bytes(content_a + OLD)
        with self.assertRaisesRegex(ValueError, "file list or occurrence counts"):
            PATCHER.verify_probe_files(wrong_count, expected)

        wrong_hash = make_root()
        (wrong_hash / "a/configure").write_bytes(b"changed\n" + OLD + b"\n")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            PATCHER.verify_probe_files(wrong_hash, expected)


class CurrentHostReceiptContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = toolchain.load_and_validate(toolchain.DEFAULT_LOCK)
        cls.patch = PATCHER.expected_patch_manifest()

    def receipt(self, binary: pathlib.Path, schema: str) -> dict:
        record = copy.deepcopy(self.lock["assembler"])
        record["signature"]["keyring_sha256"] = toolchain.CURRENT_KEYRING_SHA
        record["executable"]["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        basis = toolchain.CURRENT_RECEIPT_V1_BASIS
        if schema == toolchain.CURRENT_RECEIPT_V2:
            patch = copy.deepcopy(self.patch)
            record["source_patch"] = patch
            record["source_revision"] = (
                "binutils-2.47 official release archive; verified upstream source tree SHA-256 "
                + patch["original_source_tree_sha256"] + "; applied exact local source patch "
                + patch["id"] + "; patched source tree SHA-256 " + patch["patched_source_tree_sha256"]
            )
            record["inputs"] = [
                "official GNU Binutils 2.47 archive SHA-256 " + patch["archive_sha256"],
                "verified upstream source tree SHA-256 " + patch["original_source_tree_sha256"],
                "recorded local source patch " + patch["id"] + "; manifest SHA-256 " + patch["manifest_sha256"],
                "patched source tree SHA-256 " + patch["patched_source_tree_sha256"],
            ]
            record["disposition"] = (
                "verified upstream source; recorded local configure-probe patch applied; "
                "no Homebrew Binutils bottle used"
            )
            basis = toolchain.CURRENT_RECEIPT_V2_BASIS
        return {
            "schema": schema,
            "receipt_basis": basis,
            "historical_lock_sha256": hashlib.sha256(toolchain.DEFAULT_LOCK.read_bytes()).hexdigest(),
            "target": "m68k-elf",
            "record": record,
        }

    def test_production_validator_accepts_legacy_and_exact_v2_and_rejects_forgery(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-binutils-receipt-") as temporary:
            binary = pathlib.Path(temporary) / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            v1 = self.receipt(binary, toolchain.CURRENT_RECEIPT_V1)
            v2 = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)
            toolchain.validate_current_receipt(v1, "m68k-elf", binary)
            toolchain.validate_current_receipt(v2, "m68k-elf", binary)
            v1_with_dispatch = copy.deepcopy(v1)
            v1_with_dispatch["dispatch"] = "legacy receipt note"
            v1_with_dispatch["record"]["disposition"] += "; dispatch metadata retained"
            toolchain.validate_current_receipt(v1_with_dispatch, "m68k-elf", binary)
            identity = toolchain.current_receipt_log_identity(
                v2, json.dumps(v2, sort_keys=True, separators=(",", ":")).encode())
            self.assertEqual(identity["binutils"]["source_tree_sha256"],
                             self.patch["patched_source_tree_sha256"])
            self.assertEqual(identity["binutils"]["original_source_tree_sha256"],
                             self.patch["original_source_tree_sha256"])
            self.assertEqual(identity["binutils"]["source_patch"]["manifest_sha256"],
                             self.patch["manifest_sha256"])
            self.assertNotIn("/Users/", json.dumps(identity))
            self.assertNotIn("/home/", json.dumps(identity))

            cases = []

            def case(label, mutate, base=v2):
                altered = copy.deepcopy(base)
                mutate(altered)
                cases.append((label, altered))

            case("unknown schema", lambda d: d.__setitem__("schema", "genewhip-current-host-toolchain-v99"))
            case("malformed schema type", lambda d: d.__setitem__("schema", []))
            case("unknown root field", lambda d: d.__setitem__("unreviewed", True))
            case("missing patch", lambda d: d["record"].pop("source_patch"))
            case("patch list type", lambda d: d["record"].__setitem__("source_patch", []))
            case("patch map type", lambda d: d["record"].__setitem__("source_patch", {}))
            case("patch bool type", lambda d: d["record"].__setitem__("source_patch", True))
            case("patch null type", lambda d: d["record"].__setitem__("source_patch", None))
            case("patch unknown string", lambda d: d["record"].__setitem__("source_patch", "unknown"))
            case("extra patch field", lambda d: d["record"]["source_patch"].__setitem__("new_field", True))
            case("wrong archive", lambda d: d["record"]["source_patch"].__setitem__("archive_sha256", "0" * 64))
            case("wrong upstream tree", lambda d: d["record"]["source_patch"].__setitem__("original_source_tree_sha256", "0" * 64))
            case("wrong patched tree", lambda d: d["record"]["source_patch"].__setitem__("patched_source_tree_sha256", "0" * 64))
            case("wrong recipe", lambda d: d["record"]["source_patch"].__setitem__("recipe_sha256", "0" * 64))
            case("wrong helper", lambda d: d["record"]["source_patch"].__setitem__("helper_sha256", "0" * 64))
            case("wrong manifest", lambda d: d["record"]["source_patch"].__setitem__("manifest_sha256", "0" * 64))
            case("missing file identity", lambda d: d["record"]["source_patch"]["files"].pop())
            case("forged source file hash", lambda d: d["record"]["source_patch"]["files"][0].__setitem__("original_sha256", "0" * 64))
            case("forged patched file hash", lambda d: d["record"]["source_patch"]["files"][0].__setitem__("patched_sha256", "0" * 64))
            case("wrong file count", lambda d: d["record"]["source_patch"]["files"][0].__setitem__("replacement_count", 99))
            case("boolean file count", lambda d: d["record"]["source_patch"]["files"][0].__setitem__("replacement_count", True))
            case("wrong source revision", lambda d: d["record"].__setitem__("source_revision", "upstream unchanged"))
            case("legacy patch claim", lambda d: d["record"].__setitem__("source_patch", self.patch), v1)

            for label, malformed in (("array", []), ("map", {}), ("boolean", True), ("null", None)):
                case(label + " original file hash type",
                     lambda d, value=malformed: d["record"]["source_patch"]["files"][0].__setitem__("original_sha256", value))
                case(label + " patched file hash type",
                     lambda d, value=malformed: d["record"]["source_patch"]["files"][0].__setitem__("patched_sha256", value))

            for label, altered in cases:
                with self.subTest(label=label):
                    with self.assertRaises(ValueError, msg=label):
                        toolchain.validate_current_receipt(altered, "m68k-elf", binary)

    def test_receipt_writer_ignores_predictable_tmp_symlink_and_validator_accepts_bytes(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-receipt-writer-") as temporary:
            root = pathlib.Path(temporary)
            binary = root / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            payload = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)
            target = root / "current-receipt.json"
            sentinel = root / "sentinel.json"
            sentinel_bytes = b"leave this target unchanged\n"
            sentinel.write_bytes(sentinel_bytes)
            predictable = target.with_name(target.name + ".tmp")
            predictable.symlink_to(sentinel.name)

            expected = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
            written = toolchain.write_current_receipt(target, payload)
            self.assertEqual(written, expected)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(sentinel.read_bytes(), sentinel_bytes)
            self.assertTrue(predictable.is_symlink())
            self.assertEqual(predictable.readlink(), pathlib.Path(sentinel.name))
            toolchain.validate_current_receipt(json.loads(target.read_bytes()), "m68k-elf", binary)

    def test_receipt_writer_normal_overwrite_is_byte_identical(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-receipt-overwrite-") as temporary:
            root = pathlib.Path(temporary)
            binary = root / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            payload = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)
            target = root / "current-receipt.json"
            target.write_bytes(b"old regular receipt\n")

            expected = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
            self.assertEqual(toolchain.write_current_receipt(target, payload), expected)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(sorted(path.name for path in root.iterdir()),
                             ["current-receipt.json", "m68k-elf-as"])
            toolchain.validate_current_receipt(json.loads(target.read_bytes()), "m68k-elf", binary)

    def test_receipt_writer_write_and_replace_failures_preserve_target_and_cleanup_owned_temp(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-receipt-failure-") as temporary:
            root = pathlib.Path(temporary)
            binary = root / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            payload = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)
            target = root / "current-receipt.json"
            previous = b"prior receipt remains intact\n"

            for failure in ("write", "replace"):
                with self.subTest(failure=failure):
                    target.write_bytes(previous)
                    if failure == "write":
                        real_fdopen = toolchain.os.fdopen

                        class FailingWrite:
                            def __init__(self, descriptor, mode):
                                self.stream = real_fdopen(descriptor, mode)

                            def __enter__(self):
                                return self

                            def write(self, data):
                                raise OSError("injected receipt write failure")

                            def __exit__(self, exc_type, exc_value, traceback):
                                self.stream.close()

                        patcher = mock.patch.object(toolchain.os, "fdopen", FailingWrite)
                    else:
                        patcher = mock.patch.object(
                            toolchain.os, "replace", side_effect=OSError("injected receipt replace failure"))
                    with patcher, self.assertRaises(OSError):
                        toolchain.write_current_receipt(target, payload)
                    self.assertEqual(target.read_bytes(), previous)
                    self.assertEqual(sorted(path.name for path in root.iterdir()),
                                     ["current-receipt.json", "m68k-elf-as"])

    def test_receipt_writer_never_unlinks_foreign_replacement_during_failure_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-receipt-owned-cleanup-") as temporary:
            root = pathlib.Path(temporary)
            binary = root / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            payload = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)
            target = root / "current-receipt.json"
            previous = b"prior receipt remains intact\n"
            target.write_bytes(previous)
            sentinel = root / "sentinel.json"
            sentinel_bytes = b"foreign replacement target\n"
            sentinel.write_bytes(sentinel_bytes)
            def replace_after_foreign_substitution(source, destination, **kwargs):
                source_path = root / source
                source_path.unlink()
                source_path.symlink_to(sentinel.name)
                raise OSError("injected replacement race")

            with mock.patch.object(toolchain.os, "replace",
                                   side_effect=replace_after_foreign_substitution):
                with self.assertRaisesRegex(OSError, "replacement race"):
                    toolchain.write_current_receipt(target, payload)
            self.assertEqual(target.read_bytes(), previous)
            self.assertEqual(sentinel.read_bytes(), sentinel_bytes)
            foreign_temps = [path for path in root.iterdir()
                             if path.name.startswith(".current-receipt.json.")]
            self.assertEqual(len(foreign_temps), 1)
            self.assertTrue(foreign_temps[0].is_symlink())
            self.assertEqual(foreign_temps[0].readlink(), pathlib.Path(sentinel.name))

    def test_receipt_writer_fails_closed_when_parent_changes_at_temp_creation(self):
        with tempfile.TemporaryDirectory(prefix="gw-current-receipt-parent-swap-") as temporary:
            root = pathlib.Path(temporary).resolve()
            parent = root / "receipt-dir"
            parent.mkdir()
            target = parent / "current-receipt.json"
            previous = b"prior receipt remains intact\n"
            target.write_bytes(previous)

            replacement = root / "replacement-dir"
            replacement.mkdir()
            sentinel = replacement / "sentinel.json"
            sentinel_bytes = b"replacement directory remains untouched\n"
            sentinel.write_bytes(sentinel_bytes)
            displaced = root / "displaced-original-dir"

            binary = root / "m68k-elf-as"
            binary.write_bytes(b"synthetic assembler bytes")
            binary.chmod(0o755)
            payload = self.receipt(binary, toolchain.CURRENT_RECEIPT_V2)

            real_open = toolchain.os.open
            observed = {}

            def swap_parent_during_temp_open(path, flags, mode=0o777, *, dir_fd=None):
                if dir_fd is None and pathlib.Path(path) == parent:
                    descriptor = real_open(path, flags, mode)
                    observed["directory_fd"] = descriptor
                    return descriptor
                if ("directory_fd" in observed and dir_fd is not None
                        and dir_fd == observed["directory_fd"] and flags & os.O_CREAT
                        and "temporary_fd" not in observed):
                    parent.rename(displaced)
                    replacement.rename(parent)
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    observed["temporary_name"] = path
                    observed["temporary_fd"] = descriptor
                    return descriptor
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(toolchain.os, "open", side_effect=swap_parent_during_temp_open):
                with self.assertRaisesRegex(ValueError, "directory changed during write"):
                    toolchain.write_current_receipt(target, payload)

            self.assertIn("directory_fd", observed)
            self.assertIn("temporary_fd", observed)
            with self.assertRaises(OSError):
                os.fstat(observed["directory_fd"])
            with self.assertRaises(OSError):
                os.fstat(observed["temporary_fd"])

            self.assertEqual((displaced / target.name).read_bytes(), previous)
            self.assertEqual((parent / sentinel.name).read_bytes(), sentinel_bytes)
            self.assertEqual(sorted(path.name for path in parent.iterdir()), ["sentinel.json"])
            self.assertEqual(sorted(path.name for path in displaced.iterdir()), [target.name])
            self.assertEqual(list(root.rglob(".current-receipt.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
