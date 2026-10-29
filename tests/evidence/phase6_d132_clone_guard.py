"""D132 source-pinned, clone-only accidental-execution guard.

No project module is compiled until denial and explicit self-probes are active.
This is not a hostile-code sandbox. Parent retains stdout and disposable files.
"""
import argparse
import builtins
import contextlib
import datetime
import fcntl
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import typing
import __future__


SOURCE_NAMES = ("scripts/evidence/phase6_accounting.py",
                "tests/evidence/test_phase6_ledger_transaction.py",
                "tests/evidence/phase6_d132_clone_guard.py")
APPROVAL_NAME = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D132-APPROVAL.json"
SNAPSHOT_NAME = "build/phase6/d132-29/entry-ledger.json"
ALLOWED_IMPORTS = frozenset(("__future__", "datetime", "contextlib", "fcntl",
    "hashlib", "json", "math", "os", "pathlib", "re", "stat", "subprocess",
    "tempfile", "time", "typing", "io", "_io"))


class GuardDenied(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("tracer", "fault-matrix",
                        "oracle-negative-controls", "final-package"), required=True)
    parser.add_argument("--review-pin", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    # Only parent-controlled review/approval/snapshot data is read here. Source
    # bytes themselves are acquired after denial. Never read the live ledger.
    pin_path = Path(args.review_pin).resolve(strict=True)
    pin_bytes = pin_path.read_bytes()
    pin = json.loads(pin_bytes)
    require(pin.get("decision") == "accepted" and pin.get("reviewer_identity"),
            "independent-review-required")
    require(pin.get("bootstrap_before_compile") is True, "review-bootstrap-required")
    approved = pin.get("source_sha256", {})
    require(set(approved) == set(SOURCE_NAMES), "exact-source-roster-required")
    approval_bytes = (project / APPROVAL_NAME).read_bytes()
    require(digest(approval_bytes) == pin.get("approval_sha256"), "approval-pin")
    approval = json.loads(approval_bytes)
    require(approval.get("snapshot_path") == SNAPSHOT_NAME, "parent-snapshot-path")
    baseline = (project / SNAPSHOT_NAME).read_bytes()
    require(digest(baseline) == approval.get("snapshot_sha256") ==
            approval.get("ledger_sha256"), "clone-entry-byte-identity")
    expected = approval["ledger_objects_sha256"]
    require(len(expected) == 68 and len(json.loads(baseline)) == 68,
            "clone-original68-roster")
    retained = {}
    if args.case == "final-package":
        # Completed reviewer-owned evidence only; never consume our own future
        # result. Exact files are staged as data before filesystem denial.
        require(pin.get("stage") == "completed-final-result-review" and
                pin.get("result_review_completed") is True and
                pin.get("scope") == "D132 exact clone only", "completed-final-review-required")
        phase = Path(APPROVAL_NAME).parent
        entry_bytes = (project / phase / "06-D132-ENTRY.json").read_bytes()
        require(digest(entry_bytes) == pin.get("entry_sha256"), "final-entry-pin")
        entry = json.loads(entry_bytes)
        require(entry.get("approval_sha256") == digest(approval_bytes) and entry.get("admitted") is True,
                "final-entry-approval")
        require(pin.get("live_baseline_sha256") == digest(baseline) and
                pin.get("live_baseline_unchanged") is True and
                pin.get("parent_integrity_checked") is True, "parent-live-integrity-attestation")
        review_bytes = (project / phase / "06-29-SOURCE-REVIEW.json").read_bytes()
        require(digest(review_bytes) == pin.get("source_review_sha256"), "final-source-review-pin")
        source_review = json.loads(review_bytes)
        require(source_review.get("decision") == "accepted" and
                source_review.get("reviewer_identity") == pin["reviewer_identity"] and
                source_review.get("source_sha256") == approved and
                source_review.get("frozen_rosters") == pin.get("frozen_rosters") and
                source_review.get("approval_sha256") == digest(approval_bytes), "final-source-review-identity")
        bindings = pin.get("result_reports", {})
        require(set(bindings) == {"tracer", "fault-matrix", "oracle-negative-controls"}, "final-result-roster")
        for lane, binding in bindings.items():
            relative = Path(binding["path"])
            require(not relative.is_absolute() and ".." not in relative.parts and relative.parent == phase,
                    "exact-parent-retained-report-path")
            data = (project / relative).read_bytes()
            require(len(data) <= 2097152 and digest(data) == binding.get("sha256"), "final-raw-result-pin:" + lane)
            retained[lane] = json.loads(data)
    if args.output_root != "temporary":
        raise AssertionError("fresh-direct-temporary-sentinel-required")
    root = Path(tempfile.mkdtemp(prefix="genewhip-d132-", dir=tempfile.gettempdir())).resolve()
    root_stat = root.stat()
    require(root.parent == Path(tempfile.gettempdir()).resolve() and
            stat.S_ISDIR(root_stat.st_mode), "fresh-direct-temporary-root")
    events = []
    expected_probe = [False]
    fds = {}
    source_paths = {project / name for name in SOURCE_NAMES}
    helper_trace = []
    real_open = os.open
    real_close = os.close
    raw_lstat = os.lstat
    raw_readlink = os.readlink
    raw_fstat = os.fstat
    real_import = builtins.__import__

    def deny(event):
        events.append({"event": event, "expected": expected_probe[0]})
        raise GuardDenied("guard-denied:" + event)

    def inside(path):
        return path == root or root in path.parents

    def resolved(raw, strict=False):
        # Use captured primitives only: patched Path.resolve/os.lstat would
        # recursively re-enter classification. These reads only classify the
        # requested path; callers receive no outside-root metadata.
        pending = list(Path(os.path.abspath(os.fsdecode(raw))).parts[1:])
        current = Path(os.path.sep)
        links = 0
        while pending:
            part = pending.pop(0)
            if part == "..":
                current = current.parent
                continue
            candidate = current / part
            try:
                info = raw_lstat(candidate)
            except FileNotFoundError:
                if strict:
                    raise
                current = candidate
                continue
            if stat.S_ISLNK(info.st_mode):
                links += 1
                require(links <= 40, "path-symlink-loop")
                target = Path(raw_readlink(candidate))
                if target.is_absolute():
                    current = Path(os.path.sep)
                    pending = list(target.parts[1:]) + pending
                else:
                    pending = list(target.parts) + pending
            else:
                current = candidate
        return current

    def checked_fd(fd):
        if fd not in fds:
            deny("unknown-fd")
        try:
            info = raw_fstat(fd)
        except OSError:
            deny("closed-fd")
        if (info.st_dev, info.st_ino) != fds[fd]:
            deny("reused-fd")

    def checked_path(raw, writing=False):
        if isinstance(raw, int):
            checked_fd(raw)
            return
        path = resolved(raw)
        if inside(path) or (not writing and path in source_paths):
            return
        deny("outside-clone-write" if writing else "outside-clone-read")

    def audit(event, values):
        if event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec",
                "os.spawn", "os.posix_spawn", "os.fork")) or event in ("os.system", "pty.spawn"):
            deny(event)
        if event == "import" and values[0].split(".")[0] not in ALLOWED_IMPORTS:
            deny("import:" + values[0].split(".")[0])
        if event == "open":
            checked_path(values[0], bool(values[2] & (os.O_WRONLY | os.O_RDWR |
                         os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
        if event in ("os.listdir", "os.scandir"):
            checked_path(values[0])
        mutations = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,),
                     "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (1,),
                     "os.chmod": (0,), "os.truncate": (0,), "os.utime": (0,)}
        for index in mutations.get(event, ()):
            checked_path(values[index], True)

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            deny("dir-fd")
        checked_path(path, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                         os.O_TRUNC | os.O_APPEND)))
        fd = real_open(path, flags, mode)
        info = raw_fstat(fd)
        fds[fd] = (info.st_dev, info.st_ino)
        return fd

    def guarded_close(fd):
        checked_fd(fd)
        real_close(fd)
        del fds[fd]

    def fd_wrapper(function):
        def call(fd, *positional, **kwargs):
            checked_fd(fd)
            return function(fd, *positional, **kwargs)
        return call

    def path_wrapper(function, indices=(0,), writing=False):
        def call(*positional, **kwargs):
            if any(kwargs.get(key) is not None for key in
                   ("dir_fd", "src_dir_fd", "dst_dir_fd")):
                deny("dir-fd:" + function.__name__)
            for index in indices:
                checked_path(positional[index], writing)
            return function(*positional, **kwargs)
        return call

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in ALLOWED_IMPORTS:
            deny("import:" + name)
        return real_import(name, globals, locals, fromlist, level)

    sys.addaudithook(audit)
    builtins.__import__ = guarded_import
    os.open = guarded_open
    os.close = guarded_close
    # Prevent pathlib's own resolution from issuing intermediate metadata calls
    # through public wrappers; final canonical paths still require admission.
    def guarded_resolve(path, strict=False):
        checked_path(path)
        return resolved(path, strict)
    Path.resolve = guarded_resolve
    for name in ("read", "write", "fsync", "fstat", "fchmod", "ftruncate", "lseek", "fdopen", "fchown", "isatty"):
        setattr(os, name, fd_wrapper(getattr(os, name)))
    for name in ("stat", "lstat", "readlink", "access", "statvfs", "listdir", "scandir"):
        setattr(os, name, path_wrapper(getattr(os, name)))
    for name in ("unlink", "remove", "rmdir", "mkdir", "chmod", "chown", "truncate", "utime"):
        setattr(os, name, path_wrapper(getattr(os, name), writing=True))
    for name in ("rename", "replace", "link"):
        setattr(os, name, path_wrapper(getattr(os, name), (0, 1), True))
    os.symlink = path_wrapper(os.symlink, (1,), True)
    fcntl.flock = fd_wrapper(fcntl.flock)
    fcntl.lockf = fd_wrapper(fcntl.lockf)

    def unsupported(name):
        def call(*positional, **kwargs):
            deny("unsupported-primitive:" + name)
        return call
    # No clone operation needs descriptor duplication, raw ioctl/fcntl control,
    # cwd mutation, extended attributes or vectored/cross-descriptor transfers.
    for name in ("dup", "dup2", "chdir", "fchdir", "readv", "writev", "pread", "pwrite", "sendfile", "copy_file_range", "getxattr", "listxattr", "setxattr", "removexattr", "fwalk"):
        if hasattr(os, name):
            setattr(os, name, unsupported("os." + name))
    fcntl.fcntl = unsupported("fcntl.fcntl")
    fcntl.ioctl = unsupported("fcntl.ioctl")

    def probe(name, action):
        expected_probe[0] = True
        before = len(events)
        try:
            action()
        except GuardDenied:
            require(len(events) == before + 1, "probe-single-denial:" + name)
            events[-1]["probe_case_id"] = name
            events[-1]["probe_mode"] = "audit-event-only" if name.endswith("audit-only") else "actual-api-entry"
        else:
            raise AssertionError("probe-not-denied:" + name)
        finally:
            expected_probe[0] = False

    probe("outside-open", lambda: (project / "D132-must-not-open").read_bytes())
    probe("outside-enumeration", lambda: os.listdir(project))
    probe("unapproved-project-import", lambda: __import__("d128_seam"))
    probe("process-call-entry", lambda: os.system("D132-must-not-execute"))
    probe("unknown-fd", lambda: os.fdopen(987654, "r"))
    probe("dir-fd", lambda: os.open("absent", os.O_RDONLY, dir_fd=987654))
    probe("unknown-fd-stat", lambda: os.stat(0))
    probe("unknown-fd-flock", lambda: fcntl.flock(0, fcntl.LOCK_EX | fcntl.LOCK_NB))
    probe("outside-stat", lambda: os.stat(project / "D132-metadata-probe"))
    probe("outside-lstat", lambda: os.lstat(project / "D132-metadata-probe"))
    probe("outside-readlink", lambda: os.readlink(project / "D132-metadata-probe"))
    probe("outside-access", lambda: os.access(project / "D132-metadata-probe", os.R_OK))
    probe("socket-audit-only", lambda: sys.audit("socket.__new__", None, 0, 0, 0))
    probe("native-audit-only", lambda: sys.audit("ctypes.dlopen", "D132-probe"))
    bootstrap_denials = len(events)
    blobs = {name: (project / name).read_bytes() for name in SOURCE_NAMES}
    require(all(digest(blobs[name]) == approved[name] for name in SOURCE_NAMES),
            "reviewed-source-sha256")

    def load(name, source):
        module = types.ModuleType(name)
        module.__file__ = str(project / source)
        exec(compile(blobs[source], source, "exec"), module.__dict__)
        return module

    def trace(frame, event, arg):
        if event == "call" and frame.f_code.co_filename == SOURCE_NAMES[0] and frame.f_code.co_name in (
                "_locked", "_load", "_write", "_receipt_payload", "_publish_receipt_once"):
            helper_trace.append(frame.f_code.co_name)
        return trace

    def timeout(signum, frame):
        raise TimeoutError("internal55-second-deadline")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(55)
    rows = []
    try:
        dimensions = {}
        if args.case == "final-package":
            frozen = pin.get("frozen_rosters", {})
            require(all(isinstance(frozen.get(key), list) and len(frozen[key]) == count
                        for key, count in (("tracer", 3), ("checkpoints", 5),
                            ("repeated_recovery", 1), ("rejections", 38), ("oracle_controls", 3), ("denial_probes", 14))),
                    "final-frozen-roster-dimensions")
            wanted = {"tracer": frozen["tracer"], "fault-matrix": frozen["checkpoints"] + frozen["repeated_recovery"] + frozen["rejections"],
                      "oracle-negative-controls": frozen["oracle_controls"]}
            roster = []
            for lane in ("tracer", "fault-matrix", "oracle-negative-controls"):
                result = retained[lane]
                require(result.get("status") == "pass" and result.get("lane") == lane and
                        result.get("scope") == "D132 exact clone only" and result.get("pins") == approved and
                        result.get("snapshot_sha256") == digest(baseline), "final-retained-result-identity:" + lane)
                require(result.get("denominator") == len(wanted[lane]) == pin["result_reports"][lane].get("denominator") and
                        result.get("case_ids") == wanted[lane] and
                        [row["case_id"] for row in result.get("cases", [])] == wanted[lane] and
                        all(row.get("status") == "pass" for row in result["cases"]), "final-retained-case-roster:" + lane)
                require(result.get("bootstrap_denials") == 14 and result.get("unexpected_denial_count") == 0 and
                        len(result.get("denials", [])) == 14 and all(row.get("expected") is True for row in result["denials"]),
                        "final-retained-denials:" + lane)
                require([row.get("probe_case_id") for row in result["denials"]] == frozen["denial_probes"],
                        "final-retained-denial-roster:" + lane)
                require(set(("_locked", "_load", "_write", "_receipt_payload", "_publish_receipt_once")) <=
                        set(result.get("canonical_helper_trace", [])), "final-retained-helper-proof:" + lane)
                rows.extend(result["cases"])
                roster.extend(wanted[lane])
            dimensions = {"checkpoints": retained["fault-matrix"]["checkpoint_rows"],
                          "repeated_recovery": retained["fault-matrix"]["repeated_interrupted_recovery"],
                          "rejections": retained["fault-matrix"]["rejections"]}
        else:
            api = load("d132_canonical", SOURCE_NAMES[0])
            oracle = load("d132_oracle", SOURCE_NAMES[1])
            sys.setprofile(trace)
            fresh_api = lambda: load("d132_canonical_fresh", SOURCE_NAMES[0])
        if args.case == "tracer":
            rows = oracle.run_tracer(api, root, baseline, expected, fresh_api)
            roster = list(oracle.TRACER_CASES)
        elif args.case == "fault-matrix":
            dimensions = oracle.run_fault_matrix(root, baseline, expected, fresh_api)
            rows = dimensions["checkpoints"] + dimensions["repeated_recovery"] + dimensions["rejections"]
            roster = list(oracle.CHECKPOINTS) + ["repeated_interrupted_recovery"] + list(oracle.REJECTION_CASES)
        elif args.case == "oracle-negative-controls":
            rows = oracle.run_negative_controls(root, baseline, expected, fresh_api)
            roster = list(oracle.NEGATIVE_CASES)
        require([item["case_id"] for item in rows] == roster, "frozen-case-roster")
        if args.case != "final-package" and all(item["status"] == "pass" for item in rows):
            require(set(("_locked", "_load", "_write", "_receipt_payload", "_publish_receipt_once")) <= set(helper_trace),
                    "actual-canonical-helper-coverage")
    except Exception as exc:
        rows.append({"case_id": "bootstrap-or-lane", "status": "fail",
                     "exception": type(exc).__name__, "assertion": str(exc)})
    finally:
        sys.setprofile(None)
        signal.alarm(0)
    unexpected = [item for item in events if not item["expected"]]
    roster = locals().get("roster", [])
    dimensions = locals().get("dimensions", {})
    success = bool(roster) and len(rows) == len(roster) and all(item["status"] == "pass" for item in rows) and not unexpected
    report = {"scope": "D132 exact clone only", "lane": args.case,
              "case_ids": [item["case_id"] for item in rows], "denominator": len(roster),
              "cases": rows, "rejections": dimensions.get("rejections", []),
              "checkpoint_rows": dimensions.get("checkpoints", []),
              "repeated_interrupted_recovery": dimensions.get("repeated_recovery", []),
              "bootstrap_denials": bootstrap_denials,
              "denials": events, "unexpected_denial_count": len(unexpected),
              "pins": approved, "snapshot_sha256": digest(baseline),
              "review_pin_sha256": digest(pin_bytes),
              "canonical_helper_trace": helper_trace, "clone_basename": root.name,
              "retained_result_pins": pin.get("result_reports", {}) if args.case == "final-package" else {},
              "canonical_calls_this_run": len(helper_trace),
              "status": "pass" if success else "fail"}
    encoded = json.dumps(report, sort_keys=True).replace(str(project), "<project>").replace(str(root), "<clone>")
    (root / (args.case + ".json")).write_text(encoded + "\n")
    print(encoded)
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        # Source-free bootstrap error reporting must itself need no imports or
        # source reads under denial. OSError text may contain private paths.
        frames = []
        frame = exc.__traceback__
        while frame is not None:
            frames.append({"file": os.path.basename(frame.tb_frame.f_code.co_filename),
                           "line": frame.tb_lineno, "function": frame.tb_frame.f_code.co_name})
            frame = frame.tb_next
        print(json.dumps({"status": "fail", "stage": "bootstrap", "exception": type(exc).__name__,
                          "assertion": "bootstrap-os-error" if isinstance(exc, OSError) else str(exc),
                          "frames": frames}, sort_keys=True))
        exit_code = 1
    sys.exit(exit_code)
