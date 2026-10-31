"""Bounded first-party process capture and public evidence privacy checks."""
from __future__ import annotations

import os
import importlib.util
import json
import math
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import threading
from functools import lru_cache
from contextlib import contextmanager


@contextmanager
def receipt_file(root: Path, relative: Path, *, replace: bool = False):
    """Open an owned, new receipt through non-symlink directory descriptors."""
    if relative.is_absolute() or any(part in (".", "..") for part in relative.parts) or not relative.parts:
        raise ValueError("unsafe process receipt path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, flags)
    try:
        for part in relative.parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
            if os.fstat(directory).st_uid != os.getuid():
                raise ValueError("unowned process receipt directory")
        descriptor = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW |
                             (0 if replace else os.O_EXCL),
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("non-exclusive process output")
            if replace:
                stream.truncate(0)
            yield stream
    finally:
        os.close(directory)


@lru_cache(maxsize=1)
def process_boundary():
    """Reuse the existing host-admission and bounded group cleanup contract."""
    path = Path(__file__).resolve().parents[2] / "tests/session/phase6_route_contract.py"
    spec = importlib.util.spec_from_file_location("phase5_process_boundary", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProcessCaptureError(ValueError):
    def __init__(self, message, receipt):
        super().__init__(message)
        self.process_receipt = receipt


def public(value: object) -> None:
    """Reject private content without echoing the rejected value."""
    if isinstance(value, str):
        if re.search(r"(?:/Users/|/home/|/private/var/|[A-Za-z]:\\Users\\|-----BEGIN .*PRIVATE KEY|(?:api[_-]?key|(?:access[_-]?)?token|secret|password)\s*[:=]|authorization\s*:\s*bearer|\b(?:gh[pousr]_[A-Za-z0-9]+|sk-[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{16}))", value, re.I):
            raise ValueError("public evidence privacy rejection")
    elif isinstance(value, dict):
        for key, item in value.items():
            public(key)
            public(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            public(item)


def run(command: list[str], *, cwd, timeout: float = 30, cap: int = 1048576,
        runs: list | None = None, text: bool = True,
        process_receipt_stream=None, ownership_callback=None):
    """Capture at most cap combined bytes; kill the entire process group on failure."""
    boundary = process_boundary()
    boundary.require_host_process_context()
    if not math.isfinite(timeout) or timeout <= 0 or type(cap) is not int or cap < 0:
        raise ValueError("bounded process limits invalid")
    receipt = {"pid": None, "pgid": None, "status": "not-launched",
               "process_group_cleanup": "not-launched"}
    if runs is not None:
        runs.append(receipt)
    def persist_receipt():
        if process_receipt_stream is not None:
            process_receipt_stream.seek(0)
            json.dump({"processes": [receipt]}, process_receipt_stream, sort_keys=True, indent=2)
            process_receipt_stream.write("\n")
            process_receipt_stream.truncate()
            process_receipt_stream.flush()
            os.fsync(process_receipt_stream.fileno())

    if ownership_callback is not None and process_receipt_stream is None:
        raise ValueError("owned callback requires durable receipt sink")
    # A bad sink must fail before Popen or a signal-handler change.
    persist_receipt()
    process = None
    cleanup_status_budget = {
        "remaining": boundary._DARWIN_CLEANUP_MAX_STATUS_QUERIES,
        "attempted": 0,
        "last_reason": "cleanup-unclassified",
        "status_reason": "not-observed",
    }
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    cancelled = False
    installed = False
    prior_sigterm = None
    def defer_sigterm(_signum, _frame):
        nonlocal cancelled
        cancelled = True
    started = time.monotonic()
    deadline = started + timeout
    try:
        if threading.current_thread() is threading.main_thread():
            prior_sigterm = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGTERM, defer_sigterm)
            installed = True
        boundary.require_host_process_context()
        if cancelled:
            raise KeyboardInterrupt("parent requested bounded child cleanup before launch")
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        receipt.update(pid=process.pid, pgid=process.pid, status="started",
                       process_group_cleanup="pending")
        persist_receipt()
        if cancelled:
            raise KeyboardInterrupt("parent requested bounded child cleanup after creation")
        if ownership_callback is not None:
            ownership_callback(receipt)
        if cancelled:
            raise KeyboardInterrupt("parent requested bounded child cleanup after ownership")
        for name in output:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            if cancelled:
                raise KeyboardInterrupt("parent requested bounded child cleanup")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("bounded process timeout")
            for key, _ in selector.select(min(remaining, .1)):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    if sum(len(v) for v in output.values()) + len(block) > cap:
                        raise ValueError("bounded process output byte cap")
                    output[key.data].extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("bounded process timeout")
        try:
            # Poll in bounded slices so SIGTERM stays responsive after EOF.
            while process.poll() is None:
                if cancelled:
                    raise KeyboardInterrupt("parent requested bounded child cleanup")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("bounded process timeout")
                try:
                    process.wait(timeout=min(remaining, .1))
                except subprocess.TimeoutExpired:
                    continue
        except subprocess.TimeoutExpired:
            raise ValueError("bounded process timeout") from None
        result = subprocess.CompletedProcess(command, process.returncode,
                 *(bytes(output[name]).decode("utf-8", "replace") if text else bytes(output[name])
                   for name in ("stdout", "stderr")))
        receipt.update(status="completed", returncode=process.returncode)
        result.process_receipt = receipt
        return result
    except BaseException as error:
        receipt.update(status="failed", failure_type=type(error).__name__)
        if isinstance(error, ValueError):
            raise ProcessCaptureError(str(error), receipt) from error
        error.process_receipt = receipt
        raise
    finally:
        try:
            if process is not None:
                try:
                    if sys.platform == "darwin":
                        confirmed = boundary._terminate_process_group(
                            process, status_budget=cleanup_status_budget)
                    else:
                        confirmed = boundary._terminate_process_group(process)
                except OSError as error:
                    confirmed = False
                    receipt["cleanup_error"] = type(error).__name__
                    cleanup_status_budget["last_reason"] = (
                        "cleanup-permission-denied" if isinstance(error, PermissionError)
                        else "group-cleanup-os-error")
                    # Only the just-owned direct child can be cleaned here.
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired) as direct_error:
                        receipt["direct_child_cleanup_error"] = type(direct_error).__name__
                receipt["process_group_cleanup"] = "confirmed" if confirmed else "unconfirmed"
                if not confirmed:
                    receipt["status"] = "failed"
                    safe_reasons = boundary.SAFE_CLEANUP_REASONS
                    reason = cleanup_status_budget.get("last_reason")
                    status_observation = cleanup_status_budget.get("status_reason")
                    receipt["cleanup_reason"] = (
                        reason if reason in safe_reasons else "cleanup-unclassified")
                    receipt["cleanup_status_observation"] = (
                        status_observation if status_observation in safe_reasons else "cleanup-unclassified")
                    receipt["cleanup_observation_attempts"] = min(
                        boundary._DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                        max(0, int(cleanup_status_budget.get("attempted", 0))))
                    for key, allowed in (
                            ("observer_failure_stage", boundary.SAFE_DARWIN_OBSERVER_STAGES),
                            ("observer_return_category", boundary.SAFE_DARWIN_OBSERVER_RETURNS),
                            ("observer_error_category", boundary.SAFE_DARWIN_OBSERVER_ERRORS),
                            ("cleanup_signal_phase", boundary.SAFE_CLEANUP_SIGNAL_PHASES)):
                        value = cleanup_status_budget.get(key)
                        receipt[key] = value if value in allowed else "missing"
                    raise ProcessCaptureError("bounded process cleanup unconfirmed: non-qualifying", receipt)
        finally:
            selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
            if installed:
                signal.signal(signal.SIGTERM, prior_sigterm)
            receipt["wall_seconds"] = time.monotonic() - started
            try:
                persist_receipt()
            except BaseException as error:
                error.process_receipt = receipt
                raise
