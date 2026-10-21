#!/usr/bin/env python3
"""Ensure identity and denominator errors fail for their intended reasons."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as temporary:
    copied = pathlib.Path(temporary) / "vectors"
    shutil.copytree(root, copied)
    selected = copied / "selected.json"
    original = selected.read_bytes()
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text())

    def rejected(reason):
        result = subprocess.run([sys.executable, str(copied / "run_vectors.py"),
                                 "--runner", sys.argv[1]], capture_output=True, text=True, timeout=10)
        if result.returncode != 2 or reason not in result.stderr:
            raise RuntimeError("wrong rejection: " + result.stdout + result.stderr)

    selected.write_bytes(original + b" ")
    rejected("SHA256 mismatch: selected.json")
    selected.write_bytes(original)
    entries = json.loads(original)
    selected.write_text(json.dumps(entries[:-1]))
    manifest["selected"]["sha256"] = hashlib.sha256(selected.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    rejected("denominator mismatch")
    selected.unlink()
    rejected("selected.json")
    # A sub-form total that disagrees with the source's record count is rejected.
    selected.write_bytes(original)
    manifest = json.loads((root / "manifest.json").read_text())
    first_form = next(iter(manifest["sources"][0]["sub_forms"]))
    manifest["sources"][0]["sub_forms"][first_form] += 1
    manifest_path.write_text(json.dumps(manifest))
    rejected("sub-form denominator mismatch")
print("cpu_vectors_integrity: PASS (corrupt, dropped, missing data and sub-form tampering rejected)")
