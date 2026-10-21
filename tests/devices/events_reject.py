#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""gw_seam_runner --events must print REJECT: events and exit non-zero for malformed or
oversized schedules, and accept the same schedule when well formed (T-02-19)."""
import pathlib
import subprocess
import sys
import tempfile

GOOD = "112 0 c1\n112 1 38\n"
BAD = {
    "wrong-field-count": "112 0\n",
    "extra-field": "112 0 c1 x\n",
    "bad-port": "112 2 c1\n",
    "negative-tick": "-1 0 c1\n",
    "non-hex-mask": "112 0 zz\n",
    "mask-too-wide": "112 0 1ff\n",
    "hex-prefix": "112 0 0x1\n",
    "double-space": "112  0 c1\n",
    "blank-line": "112 0 c1\n\n",
    "no-final-newline": "112 0 c1",
    "oversized": "112 0 c1\n" * 65,
}


def run(runner, rom, text):
    with tempfile.TemporaryDirectory() as scratch:
        path = pathlib.Path(scratch) / "events.txt"
        path.write_text(text)
        return subprocess.run([runner, rom, "1000", "0", "4", "--events", str(path),
                               "--port-device", "pad3", "pad3"], capture_output=True, text=True, timeout=30)


def main():
    runner, rom = sys.argv[1:3]
    failures = []
    done = run(runner, rom, GOOD)
    if done.returncode != 0:
        failures.append("well-formed schedule rejected: " + done.stderr.strip())
    done = run(runner, rom, "112 0 c1\n" * 64)
    if done.returncode != 0:
        failures.append("exactly GW_EVENT_CAPACITY lines rejected: " + done.stderr.strip())
    for name, text in BAD.items():
        done = run(runner, rom, text)
        if done.returncode == 0 or "REJECT: events" not in done.stderr or done.stdout:
            failures.append("%s not rejected with REJECT: events" % name)
    for line in failures:
        print("FAIL: " + line)
    print("events reject: %s (%d malformed cases)" % ("FAIL" if failures else "PASS", len(BAD)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
