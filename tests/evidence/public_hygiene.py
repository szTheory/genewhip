"""Regression controls for public-source privacy and fixture binary policy."""
from pathlib import Path
import importlib.util
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
from types import SimpleNamespace


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
    shutil.copytree(ROOT / "fixtures/phase5-a", root / "fixtures/phase5-a",
                    ignore=shutil.ignore_patterns("raw-build-*.bin"))
    shutil.copytree(ROOT / "fixtures/phase5-b", root / "fixtures/phase5-b",
                    ignore=shutil.ignore_patterns("raw-build-*.bin"))
    shutil.copy(ROOT / "fixtures/manifest.json", root / "fixtures/manifest.json")
    shutil.copytree(ROOT / "fixtures/independent-game-v2", root / "fixtures/independent-game-v2")
    shutil.copytree(ROOT / "evidence", root / "evidence")
    (root / "tools").mkdir()
    shutil.copytree(ROOT / "tools/evidence", root / "tools/evidence")
    for relative in (
        "tests/fixtures/game_successor_reference.py",
        "tests/evidence/game_successor_admission.py",
        "scripts/fixtures/source_provenance.py",
        "scripts/fixtures/public_admission.py",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, target)
    candidate = "fixtures/independent-game/game.bin"
    assert hygiene.inspect(root, [candidate]) == [], (
        "the exact admitted versioned ROM with current rights/evidence identity must be public"
    )
    print("PASS: admitted versioned ROM with current evidence identity is public")

    admitted_phase5 = ("fixtures/phase5-a/game.bin", "fixtures/phase5-b/game.bin")
    for relative in admitted_phase5:
        assert hygiene.inspect(ROOT, [relative]) == [], (
            "the canonical Phase 5 ROM must pass its local admission, source, notice, and rights chain"
        )
    admission_spec = importlib.util.spec_from_file_location(
        "gw_public_admission_test", ROOT / "scripts/fixtures/public_admission.py")
    admission_module = importlib.util.module_from_spec(admission_spec)
    admission_spec.loader.exec_module(admission_module)
    public_projection = ROOT / "evidence/phase5-public-admissions.json"
    if public_projection.is_file():
        public_records = json.loads(public_projection.read_text())["admissions"]
    else:
        public_records = []
        for suffix in ("a", "b"):
            private_record = json.loads((ROOT / f"evidence/phase5-admission-{suffix}.json").read_text())
            public_records.append(admission_module.project_private_record(private_record))
    for projected in public_records:
        assert admission_module.validate_projection(projected, ROOT.resolve(), projected["fixture_id"]) == "ok"
    projection_bytes = (json.dumps({"schema": "genewhip-phase5-public-admission-set-v1",
        "admissions": public_records}, sort_keys=True, indent=2) + "\n").encode()
    projection_path = root / "evidence/phase5-public-admissions.json"
    projection_path.write_bytes(projection_bytes)
    manifest = json.loads((root / "fixtures/manifest.json").read_text())
    for row in manifest["fixtures"]:
        if row.get("kind") == "phase5-independent-game-v1":
            row["admission"] = {"path": "evidence/phase5-public-admissions.json",
                                "sha256": hashlib.sha256(projection_bytes).hexdigest()}
    (root / "fixtures/manifest.json").write_text(json.dumps(manifest))
    assert hygiene.inspect(root, list(admitted_phase5)) == [], (
        "the public projection must independently qualify both canonical Phase 5 fixtures without .planning"
    )
    for relative in admitted_phase5:
        raw = relative.rsplit("/", 1)[0] + "/raw-build-1.bin"
        assert not (root / raw).exists(), "sanitized snapshots must omit raw Phase 5 build products"
        (root / raw).write_bytes(b"synthetic prohibited intermediate bytes")
        assert hygiene.inspect(root, [raw]) == [(raw, "private-fixture-or-config")], (
            "the production scanner must reject bytes at a prohibited raw-build path"
        )
        (root / raw).unlink()
    print("PASS: only the exact admitted Phase 5 ROMs are public; raw build products remain private")

    print("PASS: public Phase 5 rights projection validates in a checkout without .planning")

    successor = "fixtures/independent-game-v2/game.bin"
    manifest_path = root / "fixtures/manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    successor_row = next(row for row in manifest["fixtures"]
                         if row.get("id") == "genewhip-independent-game-v2")

    def fake_git_revision(*, tag_target=None, source_bytes=None):
        log_calls = 0
        def run(command, **_kwargs):
            nonlocal log_calls
            if (len(command) >= 5 and command[:2] == ["git", "-C"]
                    and Path(command[2]).resolve() == root.resolve()
                    and command[3:5] == ["log", "--follow"]):
                log_calls += 1
                # Model a squash-imported source: HEAD differs, but the evidence's
                # own historical source join still observes the admitted SHA.
                revision = "f" * 40 if log_calls == 1 else successor_row["revision"]
                return SimpleNamespace(stdout=revision + "\n")
            if (len(command) >= 5 and command[:2] == ["git", "-C"]
                    and Path(command[2]).resolve() == root.resolve()
                    and command[3] == "rev-parse"):
                return SimpleNamespace(stdout=(tag_target or successor_row["revision"]) + "\n")
            if (len(command) >= 5 and command[:2] == ["git", "-C"]
                    and Path(command[2]).resolve() == root.resolve()
                    and command[3] == "show"):
                return SimpleNamespace(stdout=(source_bytes if source_bytes is not None
                                               else (root / successor_row["source"]).read_bytes()))
            raise AssertionError(f"unexpected process in offline public-fixture validation: {command!r}")
        return run

    with patch("subprocess.run", side_effect=fake_git_revision()):
        observed = hygiene.inspect(root, [successor])
        assert observed == [], (
            f"the exact admitted v2 successor with its pinned source tag and complete production evidence must be public: {observed}"
        )
        print("PASS: admitted v2 ROM validates via its immutable source tag and current rights/build/reference identities")

        with patch("subprocess.run", side_effect=fake_git_revision(tag_target="e" * 40)):
            assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
                "a source tag that resolves to a different commit must not qualify the binary"
            )
        print("PASS: mismatched immutable source tag is rejected")

        def fake_missing_tag(command, **kwargs):
            if len(command) >= 5 and command[3] == "rev-parse":
                raise subprocess.CalledProcessError(1, command)
            return fake_git_revision()(command, **kwargs)
        with patch("subprocess.run", side_effect=fake_missing_tag):
            assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
                "a missing source tag must reject the binary without crashing the hygiene scan"
            )
        print("PASS: missing immutable source tag is rejected")

        with patch("subprocess.run", side_effect=fake_git_revision(
                source_bytes=b"different source revision")):
            assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
                "a tagged revision whose source bytes differ from the admitted source digest must be rejected"
            )
        print("PASS: mismatched tagged source bytes are rejected")

        # Each control passes through inspect(), which is also used by the actual
        # public-hygiene command. No path-prefix exception or fixture allowlist is used.
        rom_path = root / successor
        original_rom = rom_path.read_bytes()
        rom_path.write_bytes(original_rom[:-1] + bytes([original_rom[-1] ^ 1]))
        assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
            "tampered successor bytes must lose the public-binary exception"
        )
        rom_path.write_bytes(original_rom)
        print("PASS: tampered v2 ROM bytes are rejected")

        successor_row["outcome"] = "unknown"
        manifest_path.write_text(json.dumps(manifest))
        assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
            "a non-pass v2 admission must not receive the public-binary exception"
        )
        manifest_path.write_bytes(manifest_bytes)
        print("PASS: non-pass v2 admission is rejected")

        manifest = json.loads(manifest_bytes)
        successor_row = next(row for row in manifest["fixtures"]
                             if row.get("id") == "genewhip-independent-game-v2")
        evidence_path = root / "evidence/independent-game-v2.json"
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
        evidence["outcome_counts"]["unknown"] = 1
        evidence_path.write_text(json.dumps(evidence))
        successor_row["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        assert hygiene.inspect(root, [successor]) == [(successor, "unverified-public-binary")], (
            "refreshing the evidence digest must not hide an unknown v2 reference outcome"
        )
        evidence_path.write_bytes(evidence_bytes)
        manifest_path.write_bytes(manifest_bytes)
        print("PASS: digest-current evidence with an unknown result is rejected")

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

print("public hygiene regressions: 11/11 passed")
