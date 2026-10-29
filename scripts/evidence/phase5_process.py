"""Bounded first-party process capture and public evidence privacy checks."""
from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time


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


def run(command: list[str], *, cwd, timeout: float = 30, cap: int = 1048576):
    """Capture at most cap combined bytes; kill the entire process group on failure."""
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for name in output:
        selector.register(getattr(process, name), selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
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
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise ValueError("bounded process timeout") from None
        return subprocess.CompletedProcess(command, process.returncode,
                 output["stdout"].decode("utf-8", "replace"), output["stderr"].decode("utf-8", "replace"))
    finally:
        # Also terminate descendants that closed their inherited output pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
