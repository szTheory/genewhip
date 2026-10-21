"""Regression controls for public-source privacy and fixture binary policy."""
from pathlib import Path
import importlib.util
import hashlib
import json
import shutil
import sys
import tempfile


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "public_hygiene", ROOT / "scripts/ci/public_hygiene.py")
hygiene = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hygiene)

with tempfile.TemporaryDirectory(prefix="gw-public-hygiene-") as temporary:
    root = Path(temporary)
    shutil.copy(ROOT / "LICENSE", root / "LICENSE")
    shutil.copytree(ROOT / "tests/vectors", root / "tests/vectors")
    shutil.copytree(ROOT / "fixtures/independent-game", root / "fixtures/independent-game")
    shutil.copy(ROOT / "fixtures/manifest.json", root / "fixtures/manifest.json")
    (root / "evidence").mkdir()
    shutil.copy(ROOT / "evidence/independent-game.json", root / "evidence/independent-game.json")

    candidate = "fixtures/independent-game/game.bin"
    assert hygiene.inspect(root, [candidate]) == [], (
        "the exact admitted versioned ROM with current rights/evidence identity must be public"
    )
    print("PASS: admitted versioned ROM with current evidence identity is public")

    untrusted = "fixtures/independent-game/unreviewed.bin"
    (root / untrusted).write_bytes(bytes(32))
    assert hygiene.inspect(root, [untrusted]) == [(untrusted, "private-fixture-or-config")], (
        "arbitrary binary files must remain rejected"
    )
    print("PASS: arbitrary binary remains rejected")

    manifest_path = root / "fixtures/manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    game = next(row for row in manifest["fixtures"]
                if row.get("id") == "genewhip-independent-game-v1")
    game["outcome"] = "unknown"
    manifest_path.write_text(json.dumps(manifest))
    assert hygiene.inspect(root, [candidate]) == [(candidate, "unverified-public-binary")], (
        "a tampered fixture outcome must not inherit the public-binary exception"
    )
    manifest_path.write_bytes(manifest_bytes)
    print("PASS: tampered manifest outcome loses public-binary exception")

    evidence_path = root / "evidence/independent-game.json"
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    evidence.pop("temporal_scope", None)
    evidence_path.write_text(json.dumps(evidence))
    manifest = json.loads(manifest_bytes)
    game = next(row for row in manifest["fixtures"]
                if row.get("id") == "genewhip-independent-game-v1")
    game["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    assert hygiene.inspect(root, [candidate]) == [(candidate, "unverified-public-binary")], (
        "missing historical scope must not inherit the public-binary exception, even with a refreshed digest"
    )
    evidence_path.write_bytes(evidence_bytes)
    manifest_path.write_bytes(manifest_bytes)
    print("PASS: missing historical scope loses public-binary exception with refreshed digest")

    rom = root / candidate
    content = bytearray(rom.read_bytes())
    content[-1] ^= 1
    rom.write_bytes(content)
    assert hygiene.inspect(root, [candidate]) == [(candidate, "unverified-public-binary")], (
        "changed candidate bytes must not inherit the public exception"
    )
    print("PASS: tampered ROM bytes are rejected")

    personal_path = "path.txt"
    private_path = "/" + "Users" + "/fixture/private/file\n"
    (root / personal_path).write_text(private_path)
    assert hygiene.inspect(root, [personal_path]) == [(personal_path, "personal-path")], (
        "personal-path privacy control must remain active"
    )
    print("PASS: personal-path privacy control remains active")

print("public hygiene regressions: 6/6 passed")
