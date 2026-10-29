"""Run only after independent source approval: python3 -I -B this-file.

Audit denial is an accidental-execution guard for trusted serial test code, not
a hostile-code sandbox. All result rows go to stdout for parent retention.
"""

# Preload the exact stdlib dependencies before installing denial. No writer or
# project module is imported here. The writer is compiled from one approved path.
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import sysconfig
import tempfile
import types
import unittest
import traceback
import tokenize
import linecache
import ast
import unicodedata


SOURCE = Path(__file__).resolve().with_name("d131_synthetic_writer.py")
PROJECT = SOURCE.parents[2]
STDLIB = Path(sysconfig.get_path("stdlib")).resolve()
ROOTS = []
VIOLATIONS = []
EXPECTED = False


class GuardDenied(RuntimeError):
    pass


def reject(event):
    VIOLATIONS.append({"event": event, "expected": EXPECTED})
    raise GuardDenied("forbidden operation: " + event)


def inside(path, root):
    return path == root or root in path.parents


def audit(event, args):
    if (event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec",
                          "os.spawn", "os.posix_spawn", "os.fork"))
            or event in ("os.system", "pty.spawn")):
        reject(event)
    if event == "import":
        name = args[0].split(".")[0]
        if name not in ALLOWED_IMPORTS:
            reject("import:" + name)
    if event == "open":
        raw, mode, flags = args
        if isinstance(raw, int):
            return  # fdopen on descriptors opened through this same guard
        path = Path(os.fsdecode(raw)).absolute().resolve()
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT
                                | os.O_TRUNC | os.O_APPEND))
        if any(inside(path, root) for root in ROOTS):
            return
        if not writing and path == SOURCE:
            return
        if not writing and inside(path, STDLIB) and not inside(path, PROJECT):
            return
        reject("open")
    if event in ("os.listdir", "os.scandir"):
        # Enumeration is a read, too. No fd-relative directory access is needed
        # by this flat harness; reject it rather than guessing its provenance.
        if isinstance(args[0], int):
            reject(event)
        path = Path(os.fsdecode(args[0])).absolute().resolve()
        if not (any(inside(path, root) for root in ROOTS)
                or (inside(path, STDLIB) and not inside(path, PROJECT))):
            reject(event)
    # Mutations other than open also remain inside registered disposable roots.
    mutations = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,),
                 "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (1,),
                 "shutil.rmtree": (0,)}
    for index in mutations.get(event, ()):
        path = Path(os.fsdecode(args[index])).absolute().resolve()
        if not any(inside(path, root) for root in ROOTS):
            reject(event)


ALLOWED_IMPORTS = {
    "hashlib", "json", "os", "pathlib", "re", "tempfile",
    "_io", "io", "sys", "builtins", "tokenize", "linecache", "ast",
    "unicodedata",
}
original_import = builtins.__import__


def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level or name.split(".")[0] not in ALLOWED_IMPORTS:
        reject("import:" + name.split(".")[0])
    return original_import(name, globals, locals, fromlist, level)


# Resolve the system temporary base before denial; never inspect the project.
TEMP_BASE = Path(tempfile.gettempdir()).resolve()
sys.addaudithook(audit)
builtins.__import__ = guarded_import


def expect_denied(action):
    global EXPECTED
    EXPECTED = True
    before = len(VIOLATIONS)
    try:
        action()
    except GuardDenied:
        if len(VIOLATIONS) != before + 1:
            raise AssertionError("denial did not produce exactly one audit row")
    else:
        raise AssertionError("guard probe unexpectedly permitted")
    finally:
        EXPECTED = False


# These probes must pass BEFORE the writer source is read or compiled.
expect_denied(lambda: sys.audit("subprocess.Popen", "denial-probe", (), None, None))
expect_denied(lambda: os.system("denial-probe-must-never-execute"))
expect_denied(lambda: sys.audit("socket.__new__", None, 0, 0, 0))
expect_denied(lambda: sys.audit("ctypes.dlopen", "denial-probe"))
expect_denied(lambda: __import__("phase6_accounting"))
expect_denied(lambda: __import__("subprocess"))
expect_denied(lambda: (PROJECT / "evidence/phase6-repairs.json").read_bytes())
expect_denied(lambda: os.listdir(PROJECT))
expect_denied(lambda: os.scandir(PROJECT / "evidence"))
BOOTSTRAP_DENIALS = len(VIOLATIONS)
writer = types.ModuleType("d131_synthetic_writer")
exec(compile(SOURCE.read_bytes(), "d131_synthetic_writer.py", "exec"), writer.__dict__)


class SyntheticContract(unittest.TestCase):
    def setUp(self):
        # The candidate is registered before mkdir, without permitting arbitrary
        # temp-root mutation. Cleanup uses the same registered root.
        self.root = TEMP_BASE / ("d131-" + os.urandom(12).hex())
        ROOTS.append(self.root)
        self.root.mkdir(mode=0o700)
        self.addCleanup(self.remove_root, self.root)

    @staticmethod
    def remove_root(root):
        # Flat synthetic roots only; absolute names keep audit checks unambiguous.
        for path in root.iterdir():
            path.unlink()
        root.rmdir()

    def fresh(self):
        return writer.Writer(self.root)

    def charge_count(self):
        return len(list(self.root.glob("*.charge.json")))

    def assert_intent_before_effects(self):
        if (self.root / "output.bin").exists() or self.charge_count():
            self.assertTrue((self.root / "txn-alpha.intent.json").is_file(),
                            "publication or charge requires persisted intent")

    def assert_complete(self):
        self.assert_intent_before_effects()
        self.assertEqual((self.root / "output.bin").read_bytes(), b"synthetic-v1")
        intent = json.loads((self.root / "txn-alpha.intent.json").read_bytes())
        self.assertEqual(intent, {"version": 1, "id": "alpha",
                                 "destination": "output.bin",
                                 "payload": b"synthetic-v1".hex()})
        charge = json.loads((self.root / "txn-alpha.charge.json").read_bytes())
        self.assertEqual(charge, {"id": "alpha", "units": 1,
                                 "intent_sha256": hashlib.sha256(
                                     (self.root / "txn-alpha.intent.json").read_bytes()
                                 ).hexdigest()})
        self.assertEqual(self.charge_count(), 1)

    def run_transaction(self, fail_at=None):
        return self.fresh().transact("alpha", "output.bin", b"synthetic-v1", fail_at)

    def test_absent_and_repeated_recovery(self):
        self.assertEqual(self.run_transaction(), "published-and-charged")
        self.assert_complete()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        for _ in range(3):
            self.run_transaction()
        self.assert_complete()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_identical_preserved(self):
        path = self.root / "output.bin"
        path.write_bytes(b"synthetic-v1")
        inode = path.stat().st_ino
        self.run_transaction()
        self.assertEqual(path.stat().st_ino, inode)
        self.assert_complete()

    def test_conflict_preserved_without_charge(self):
        (self.root / "output.bin").write_bytes(b"existing-other")
        for _ in range(2):
            with self.assertRaisesRegex(writer.Rejected, "conflict"):
                self.run_transaction()
        self.assertEqual((self.root / "output.bin").read_bytes(), b"existing-other")
        self.assertTrue((self.root / "txn-alpha.intent.json").is_file())
        self.assertEqual(self.charge_count(), 0)

    def test_interruption_restarts(self):
        # Explicit independent checkpoint oracle, not Writer.CHECKPOINTS.
        expected = {"after_intent": (False, 0), "before_publication": (False, 0),
                    "after_publication": (True, 0), "before_charge": (True, 0),
                    "after_charge": (True, 1)}
        for checkpoint, (published, charges) in expected.items():
            with self.subTest(checkpoint=checkpoint):
                # Each case gets a new registered flat disposable root.
                old_root = self.root
                self.root = TEMP_BASE / ("d131-" + os.urandom(12).hex())
                ROOTS.append(self.root)
                self.root.mkdir(mode=0o700)
                self.addCleanup(self.remove_root, self.root)
                with self.assertRaisesRegex(writer.Interrupted, checkpoint):
                    self.run_transaction(checkpoint)
                self.assertTrue((self.root / "txn-alpha.intent.json").is_file())
                self.assertEqual((self.root / "output.bin").exists(), published)
                self.assertEqual(self.charge_count(), charges)
                self.assert_intent_before_effects()
                # Interrupt recovery itself, while the first attempt's actual
                # persisted state is still present. Nothing is reset or removed.
                with self.assertRaisesRegex(writer.Interrupted, checkpoint):
                    self.run_transaction(checkpoint)
                self.assertTrue((self.root / "txn-alpha.intent.json").is_file())
                self.assertEqual((self.root / "output.bin").exists(), published)
                self.assertEqual(self.charge_count(), charges)
                self.assert_intent_before_effects()
                # No cleanup/reset of intent, stage, output or charge on restart.
                self.run_transaction()
                self.run_transaction()
                self.assert_complete()
                self.root = old_root

    def test_identity_cannot_change_semantics(self):
        self.run_transaction()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        for name, data in (("other.bin", b"synthetic-v1"),
                           ("output.bin", b"changed")):
            with self.assertRaises(writer.Rejected):
                self.fresh().transact("alpha", name, data)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_negative_oracle_wrong_output_despite_success(self):
        reported_success = self.run_transaction()
        (self.root / "output.bin").write_bytes(b"deliberately-wrong")
        self.assertEqual(reported_success, "published-and-charged")
        with self.assertRaises(AssertionError):
            self.assert_complete()

    def test_negative_oracle_duplicate_charge_after_reload(self):
        self.run_transaction()
        duplicate = (self.root / "txn-alpha.charge.json").read_bytes()
        (self.root / "txn-deliberate-duplicate.charge.json").write_bytes(duplicate)
        reloaded = self.fresh()
        self.assertIsNotNone(reloaded)
        with self.assertRaises(AssertionError):
            self.assert_complete()

    def test_negative_oracle_missing_intent(self):
        self.run_transaction()
        (self.root / "txn-alpha.intent.json").unlink()
        with self.assertRaisesRegex(AssertionError, "requires persisted intent"):
            self.assert_intent_before_effects()

    def test_recovery_rejects_new_conflict(self):
        with self.assertRaises(writer.Interrupted):
            self.run_transaction("after_intent")
        (self.root / "output.bin").write_bytes(b"protected-conflict")
        with self.assertRaises(writer.Rejected):
            self.run_transaction()
        self.assertEqual((self.root / "output.bin").read_bytes(), b"protected-conflict")
        self.assertEqual(self.charge_count(), 0)

    def test_symlink_and_escape_rejected(self):
        target = self.root / "target.bin"
        target.write_bytes(b"preserve")
        for name in ("output.bin", "txn-alpha.intent.json", "txn-alpha.stage",
                     "txn-alpha.charge.json"):
            with self.subTest(name=name):
                link = self.root / name
                link.symlink_to(target)
                with self.assertRaises(writer.Rejected):
                    self.run_transaction()
                self.assertTrue(link.is_symlink())
                self.assertEqual(target.read_bytes(), b"preserve")
                link.unlink()
        for name in ("../escape.bin", "/escape.bin", "sub/file.bin", "a/../x.bin"):
            with self.assertRaises(writer.Rejected):
                self.fresh().transact("alpha", name, b"data")
        dangling_target = self.root / "never-created.bin"
        dangling = self.root / "output.bin"
        dangling.symlink_to(dangling_target)
        with self.assertRaises(writer.Rejected):
            self.run_transaction()
        self.assertTrue(dangling.is_symlink())
        self.assertFalse(dangling_target.exists())
        dangling.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(writer.Rejected):
            writer.Writer(alias)
        with self.assertRaises(writer.Rejected):
            writer.Writer(self.root / "..")
        self.assertEqual(self.charge_count(), 0)


class SourceFreeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        # unittest's default formatter lazily reads source through linecache and
        # imports traceback helpers. Report complete frame locations and the
        # actual exception without reading any file or importing anything. This
        # also keeps guard errors from being masked by error-reporting failures.
        exception_type, exception, frame = err
        rows = ["Traceback (source-free):"]
        while frame is not None:
            code = frame.tb_frame.f_code
            rows.append("  " + Path(code.co_filename).name + ":"
                        + str(frame.tb_lineno) + " in " + code.co_name)
            frame = frame.tb_next
        rows.append(exception_type.__name__ + ": " + str(exception))
        return "\n".join(rows) + "\n"


if __name__ == "__main__":
    capture = io.StringIO()
    result = unittest.TextTestRunner(stream=capture, verbosity=2,
                                    resultclass=SourceFreeResult).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticContract))
    unexpected = [row for row in VIOLATIONS if not row["expected"]]
    report = capture.getvalue().replace(str(PROJECT), "<project>")
    report = report.replace(str(TEMP_BASE), "<temporary>")
    print(report, end="")
    print(json.dumps({"scope": "D131 synthetic only", "tests": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "bootstrap_denials_before_import": BOOTSTRAP_DENIALS,
                      "violations": VIOLATIONS,
                      "status": "pass" if result.wasSuccessful() and not unexpected else "halt"},
                     sort_keys=True))
    sys.exit(0 if result.wasSuccessful() and not unexpected else 1)
