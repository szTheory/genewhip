#!/usr/bin/env python3
"""Public fixture admission projection checks without private planning history."""
import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gw_public_admission_contract",
                                               ROOT / "scripts/fixtures/public_admission.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def main():
    public_file = ROOT / "evidence/phase5-public-admissions.json"
    if public_file.is_file():
        original = {item["fixture_id"]: item for item in json.loads(public_file.read_text())["admissions"]}
    else:
        original = {}
        for suffix in ("a", "b"):
            record = json.loads((ROOT / f"evidence/phase5-admission-{suffix}.json").read_text())
            projection = admission.project_private_record(record)
            original[projection["fixture_id"]] = projection
    for fixture_id, projection in original.items():
        assert admission.validate_projection(projection, ROOT.resolve(), projection["fixture_id"]) == "ok"
    # Exercise the production v2 adapter with this CMake tree's actual
    # generated diagnostic ROM; it cannot silently use build/ci/native.
    validator_spec = importlib.util.spec_from_file_location(
        "gw_selected_diagnostic_validator", ROOT / "tools/evidence/fixture_manifest.py")
    validator = importlib.util.module_from_spec(validator_spec)
    validator_spec.loader.exec_module(validator)
    provenance_spec = importlib.util.spec_from_file_location(
        "gw_selected_diagnostic_provenance", ROOT / "scripts/fixtures/source_provenance.py")
    provenance = importlib.util.module_from_spec(provenance_spec)
    provenance_spec.loader.exec_module(provenance)
    selected_diagnostic = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/ci/native/diagnostic.bin")
    provenance.require_admitted(validator, ROOT.resolve(), "fixtures/manifest.json",
        "genewhip-independent-game-v2", selected_diagnostic)
    mutations = {
        "wrong source": lambda row: row["identities"]["source_archive"].update(
            original["genewhip-phase5-b"]["identities"]["source_archive"]),
        "wrong ROM": lambda row: row["identities"]["canonical_rom"].update(
            {"path": "fixtures/phase5-b/game.bin", "sha256": original["genewhip-phase5-b"]["identities"]["canonical_rom"]["sha256"]}),
        "wrong notice": lambda row: row["identities"]["notices"][0].update(
            {"path": "LICENSE", "sha256": hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()}),
        "wrong role": lambda row: row.update({"role": "unreviewed-binary"}),
        "omitted admission fact": lambda row: row["identities"].pop("material_terms"),
        "zero source revision": lambda row: row.update({"source_revision": "0" * 40}),
        "fixture project swap": lambda row: row.update({"project": "baba20o/RECURSION94"}),
        "wrong frozen route": lambda row: row["route"].update({"frozen_route_sha256": "0" * 64}),
        "false private history claim": lambda row: row.update({
            "evidence_basis": "Omitted private history independently reopened."}),
        "notice coverage omission": lambda row: row["identities"]["notices"][0].update({"covers": []}),
        "material authority swap": lambda row: row["identities"]["material_terms"].update(
            {"sha256": original["genewhip-phase5-b"]["identities"]["material_terms"]["sha256"]}),
    }
    for label, mutate in mutations.items():
        row = copy.deepcopy(original["genewhip-phase5-a"])
        mutate(row)
        envelope = {"schema": "genewhip-phase5-public-admission-set-v1", "admissions": [row]}
        serialized = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        outer = hashlib.sha256(serialized).hexdigest()
        assert len(outer) == 64
        try:
            admission.validate_projection(envelope["admissions"][0], ROOT.resolve(), "genewhip-phase5-a")
        except (KeyError, OSError, TypeError, ValueError):
            continue
        raise AssertionError(f"public admission mutant accepted: {label}")
    # Recompute each descriptor binding and the enclosing public envelope after
    # replacing the actual descriptor bytes. The validator must reject the
    # independently unreviewed reference authority, not just stale hashes.
    for field in ("reference_executable", "reference_build"):
        with tempfile.TemporaryDirectory(prefix="gw-public-reference-authority-") as temp:
            candidate = Path(temp)
            projection = copy.deepcopy(original["genewhip-phase5-a"])
            paths = {binding["path"] for name, binding in projection["identities"].items()
                     if name != "notices"}
            paths.update(binding["path"] for binding in projection["identities"]["notices"])
            paths.update({"scripts/fixtures/source_provenance.py", "tools/evidence/phase5_records.py",
                          "tools/evidence/fixture_manifest.py"})
            for relative in paths:
                target = candidate / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            binding = projection["identities"][field]
            descriptor = candidate / binding["path"]
            descriptor.write_text(json.dumps({"unreviewed_reference_authority": True}))
            binding["sha256"] = hashlib.sha256(descriptor.read_bytes()).hexdigest()
            envelope = {"schema": "genewhip-phase5-public-admission-set-v1",
                        "admissions": [projection]}
            envelope_path = candidate / "evidence/phase5-public-admissions.json"
            envelope_path.parent.mkdir(parents=True, exist_ok=True)
            envelope_path.write_text(json.dumps(envelope, sort_keys=True))
            manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
            row = copy.deepcopy(next(item for item in manifest["fixtures"]
                if item.get("id") == "genewhip-phase5-a"))
            row["admission"] = {"path": "evidence/phase5-public-admissions.json",
                "sha256": hashlib.sha256(envelope_path.read_bytes()).hexdigest()}
            validator_spec = importlib.util.spec_from_file_location(
                "gw_public_descriptor_mutant_validator", candidate / "tools/evidence/fixture_manifest.py")
            validator = importlib.util.module_from_spec(validator_spec)
            validator_spec.loader.exec_module(validator)
            provenance_spec = importlib.util.spec_from_file_location(
                "gw_public_descriptor_mutant_provenance", candidate / "scripts/fixtures/source_provenance.py")
            provenance = importlib.util.module_from_spec(provenance_spec)
            provenance_spec.loader.exec_module(provenance)
            try:
                provenance._phase5_candidate_record(validator, row, candidate)
            except (KeyError, OSError, TypeError, ValueError):
                continue
            raise AssertionError(f"public admission accepted rehashed {field} authority mutant")
    # Exercise the production manifest consumer in a clean, .planning-free source tree.
    with tempfile.TemporaryDirectory(prefix="gw-public-admission-clean-") as temp:
        candidate = Path(temp)
        row = json.loads((ROOT / "fixtures/manifest.json").read_text())
        row = next(item for item in row["fixtures"] if item.get("id") == "genewhip-phase5-a")
        projection = copy.deepcopy(original["genewhip-phase5-a"])
        public_paths = {binding["path"] for name, binding in projection["identities"].items()
                        if name != "notices"}
        public_paths.update(binding["path"] for binding in projection["identities"]["notices"])
        public_paths.update({"scripts/fixtures/public_admission.py", "scripts/fixtures/source_provenance.py",
                             "tools/evidence/phase5_records.py", "tools/evidence/fixture_manifest.py"})
        for relative in public_paths:
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        assert not (candidate / ".planning").exists()
        envelope_path = candidate / "evidence/phase5-public-admissions.json"
        envelope_path.parent.mkdir(parents=True, exist_ok=True)
        envelope = {"schema": "genewhip-phase5-public-admission-set-v1", "admissions": [projection]}
        envelope_path.write_text(json.dumps(envelope, sort_keys=True))
        row["admission"] = {"path": "evidence/phase5-public-admissions.json",
                            "sha256": hashlib.sha256(envelope_path.read_bytes()).hexdigest()}
        validator_spec = importlib.util.spec_from_file_location(
            "gw_public_admission_fixture_manifest", candidate / "tools/evidence/fixture_manifest.py")
        validator = importlib.util.module_from_spec(validator_spec)
        validator_spec.loader.exec_module(validator)
        provenance_spec = importlib.util.spec_from_file_location(
            "gw_public_admission_source_provenance", candidate / "scripts/fixtures/source_provenance.py")
        provenance = importlib.util.module_from_spec(provenance_spec)
        provenance_spec.loader.exec_module(provenance)
        assert provenance._phase5_candidate_record(validator, row, candidate)["fixture_id"] == "genewhip-phase5-a"
        row_mutants = {
            "manifest project": {"project": "attacker/unreviewed"},
            "manifest source revision": {"revision": "0" * 40},
            "manifest license": {"license": "All rights reserved"},
            "manifest assets": {"assets": ["unreviewed"]},
            "manifest source path": {"source": "fixtures/phase5-b/source.tar"},
            "manifest source digest": {"source_sha256": "0" * 64},
            "manifest ROM path": {"rom": "fixtures/phase5-b/game.bin"},
            "manifest ROM digest": {"sha256": "0" * 64},
            "manifest notices": {"notices": ["LICENSE"]},
        }
        for label, changes in row_mutants.items():
            changed = dict(row)
            changed.update(changes)
            try:
                provenance._phase5_candidate_record(validator, changed, candidate)
            except (KeyError, OSError, TypeError, ValueError):
                continue
            raise AssertionError(f"public manifest mutant accepted: {label}")
        # Rebind a changed oracle and every outer digest; the frozen route must
        # still be recomputed from the five reopened public inputs.
        oracle_root = candidate / "oracle-mutant"
        for relative in public_paths:
            target = oracle_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        oracle_projection = copy.deepcopy(original["genewhip-phase5-a"])
        oracle_binding = oracle_projection["identities"]["oracle"]
        oracle_path = oracle_root / oracle_binding["path"]
        changed_oracle = json.loads(oracle_path.read_text())
        changed_oracle["tampered_public_claim"] = True
        oracle_path.write_text(json.dumps(changed_oracle, sort_keys=True))
        oracle_binding["sha256"] = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
        oracle_projection["route"]["oracle_sha256"] = oracle_binding["sha256"]
        oracle_envelope = {"schema": "genewhip-phase5-public-admission-set-v1",
                           "admissions": [oracle_projection]}
        oracle_envelope_path = oracle_root / "evidence/phase5-public-admissions.json"
        oracle_envelope_path.parent.mkdir(parents=True, exist_ok=True)
        oracle_envelope_path.write_text(json.dumps(oracle_envelope, sort_keys=True))
        oracle_row = dict(row)
        oracle_row["admission"] = {"path": "evidence/phase5-public-admissions.json",
            "sha256": hashlib.sha256(oracle_envelope_path.read_bytes()).hexdigest()}
        try:
            provenance._phase5_candidate_record(validator, oracle_row, oracle_root)
        except (KeyError, OSError, TypeError, ValueError):
            pass
        else:
            raise AssertionError("public admission accepted re-bound oracle bytes with stale frozen route")
    print("public admission: 2 valid projections; projection, rights, route and manifest mutants rejected in a clean checkout without .planning")


if __name__ == "__main__":
    main()
