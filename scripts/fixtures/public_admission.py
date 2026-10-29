"""Narrow public projection for Phase 5 fixture rights and byte identities.

This projection intentionally does not reproduce the private historical selection
and run ledger. It rechecks the admitted source, ROM, route inputs and notices.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = "genewhip-phase5-public-admission-v1"
ROSTER = {"genewhip-phase5-a": "tank-battle", "genewhip-phase5-b": "recursion94"}
REVIEWED = {
    "genewhip-phase5-a": {
        "project": "monteslu/retro-homebrew-games",
        "revision": "eb7dc3044f9d2f76047f3b3573971bf86575ca52",
        "source_archive": "0751013a99631e08b0309bfde06c8ff578abeda0113c3b208aaf81951a1e6753",
        "scenario_source_archive": "0751013a99631e08b0309bfde06c8ff578abeda0113c3b208aaf81951a1e6753",
        "content_inventory": "5608495469fda40769ef547cd44eda811924316b732dfed7550345e744e484a5",
        "material_terms": "4001838aed0967953916dbe4c1067cc8d3f72b48e3c70f92cde5aa9bc6407483",
        "canonical_rom": "ceb75f72a08565424e88ed0a38d0d682e2c7f7cbb6e98b920f442b108e09f723",
        "notices": "bda225ef2d04d904dbcc6d44a5bef719553ac432a37394546281fa81584ce29d",
        "reference_executable": "f07106d1eb6cd959df1e17f5c418e64923c5eeb29bc759c5229b93c98868a6a1",
        "reference_build": "464855118ecaddbb16224c545bcb65740cf0aee417400926e92f2d12d7f8ec18",
        "tool_lock": "6faae09cbe3a5ff5122ee7af21f111b64961b50de6ad506ae736fd3ef83988a6",
        "mame_executable": "07e811e49b38a5e2378ccf070fad5b6b48008dcfe5bcc746c6941dd8fe06b5bb",
        "mame_source": "0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84",
        "mame_patch": "323f00f433f730ea682a26aaf4c142430538072d7389dd6fe8292477d0b6ac73",
        "frozen_route": "6c1367575f81d452df8a352c7bab0e173949952ebb485c1e9bb24f916d5f7279",
        "notice_covers": ["local-fixtures/phase5/tank-battle/NOTICES.txt"],
    },
    "genewhip-phase5-b": {
        "project": "baba20o/RECURSION94",
        "revision": "ab73bc9c7d2bbc4fcd94b3e0e2b89756cb1dc0cd",
        "source_archive": "d6302d23168fb7e20e643c97eed0c694ef702b23cea0b26897e0bb8152e3ad1b",
        "scenario_source_archive": "9177d9c950e1be5acc43c4edcbd41de6e19d9d0df3c8a6f537324ab2fe06acf8",
        "content_inventory": "074be9d8508e86a9427fa48d9e1237f8228f256168c8158d3142fc37caebecfb",
        "material_terms": "13efe0139b75ee1c66898614547a3143d944f5dba0d07f17855efa01e87fbd49",
        "canonical_rom": "d334b18a46c4ffa6436b3e0bb95c0947cf6047ac96d5145cbf2d0f0ead5071ff",
        "notices": "13f44f15391b814c159d5b431e3057f2a43cfaaab2639a10d5a42866c4a3ee64",
        "reference_executable": "f07106d1eb6cd959df1e17f5c418e64923c5eeb29bc759c5229b93c98868a6a1",
        "reference_build": "38494c9cc46fa92e2d1e7c727d41265229dc20f2aa752c8ed6558bed3b0df48c",
        "tool_lock": "784cddd1d8c80cc61145a1dc2464ad3c69a3e5b1ed06592cc5aacfcbd13e6923",
        "mame_executable": "07e811e49b38a5e2378ccf070fad5b6b48008dcfe5bcc746c6941dd8fe06b5bb",
        "mame_source": "0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84",
        "mame_patch": "323f00f433f730ea682a26aaf4c142430538072d7389dd6fe8292477d0b6ac73",
        "frozen_route": "9927d37815aefe995b210f904d660d66f75fa53f5c11f00287db80d61a2fa362",
        "notice_covers": ["Genewhip LICENSE", "LICENSE",
                          "local-fixtures/phase5/recursion94/NOTICES.txt",
                          "phase5-inputs/Python-3.12.10.tgz#Python-3.12.10/LICENSE",
                          "phase5-inputs/sjasmplus-1.23.1-src.tar.xz#sjasmplus-1.23.1/LICENSE.md",
                          "phase5-inputs/vasm2_0f.tar.gz#vasm/doc/vasm.texi",
                          "phase5-inputs/zlib-1.3.1.tar.gz#zlib-1.3.1/LICENSE"],
    },
}
FILE_FIELDS = ("source_archive", "content_inventory", "material_terms", "canonical_rom",
               "notices", "scenario", "input_schedule", "input_program", "oracle",
               "reference_script", "reference_executable", "reference_build", "tool_lock")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bound(root: Path, binding: dict) -> bytes:
    if (not isinstance(binding, dict) or set(binding) != {"path", "sha256"}
            or not isinstance(binding["path"], str)
            or not re.fullmatch(r"[a-zA-Z0-9_./-]+", binding["path"])
            or binding["path"].startswith("/") or ".." in Path(binding["path"]).parts
            or not re.fullmatch(r"[0-9a-f]{64}", str(binding["sha256"]))):
        raise ValueError("public admission file binding is malformed")
    path = root / binding["path"]
    if any(part.is_symlink() for part in [path, *path.parents] if part != root.parent):
        raise ValueError("public admission file path contains symlink")
    resolved = path.resolve(strict=True)
    if root.resolve() not in resolved.parents or not resolved.is_file():
        raise ValueError("public admission file escapes repository")
    data = resolved.read_bytes()
    if hashlib.sha256(data).hexdigest() != binding["sha256"]:
        raise ValueError("public admission file digest mismatch")
    return data


def project_private_record(record: dict) -> dict:
    """Create an allowlisted projection after the unchanged private validator passes."""
    title = record.get("title_id")
    fixture_id = record.get("fixture_id")
    if ROSTER.get(fixture_id) != title or record.get("status") != "qualified" or record.get("outcome") != "pass":
        raise ValueError("private admission is not a qualified public fixture")
    ids = record["identities"]
    files = {name: ids[name] for name in FILE_FIELDS if name != "notices"}
    files["notices"] = [{"path": item["path"], "sha256": item["sha256"],
                          "covers": item["covers"]} for item in ids["notices"]]
    return {
        "schema": SCHEMA,
        "fixture_id": fixture_id,
        "title_id": title,
        "role": "independent-game-fixture",
        "project": record["project"],
        "source_revision": record["source_revision"],
        "license": record["license"],
        "assets": record["assets"],
        "status": "admitted",
        "outcome": "pass",
        "identities": files,
        "route": {"scenario_sha256": ids["scenario"]["sha256"],
                  "oracle_sha256": ids["oracle"]["sha256"],
                  "reference_script_sha256": ids["reference_script"]["sha256"],
                  "frozen_route_sha256": record["route_evidence"]["frozen_route_sha256"]},
        "evidence_basis": EVIDENCE_BASIS,
    }


def validate_projection(document: dict, root: Path, expected_id: str | None = None) -> str:
    """Validate the exact public roster and retained rights/provenance chain."""
    if not isinstance(document, dict) or set(document) != {
            "schema", "fixture_id", "title_id", "role", "project", "source_revision",
            "license", "assets", "status", "outcome", "identities", "route", "evidence_basis"}:
        raise ValueError("public admission projection has missing or unknown facts")
    fixture_id = document.get("fixture_id")
    title = ROSTER.get(fixture_id)
    authority = REVIEWED.get(fixture_id)
    if (document.get("schema") != SCHEMA or (expected_id and fixture_id != expected_id)
            or document.get("title_id") != title or document.get("role") != "independent-game-fixture"
            or document.get("status") != "admitted" or document.get("outcome") != "pass"
            or not isinstance(document.get("source_revision"), str)
            or document.get("source_revision") != authority["revision"]
            or document.get("project") != authority["project"]
            or document.get("license") != "See per-material terms; mixed components"
            or document.get("assets") != []):
        raise ValueError("public admission fixture role, source or rights facts mismatch")
    if document.get("evidence_basis") != EVIDENCE_BASIS:
        raise ValueError("public admission evidence basis overstates retained public evidence")
    ids = document.get("identities")
    if not isinstance(ids, dict) or set(ids) != set(FILE_FIELDS):
        raise ValueError("public admission identity facts are incomplete")
    slot = "a" if fixture_id.endswith("-a") else "b"
    if (not isinstance(ids.get("notices"), list) or len(ids["notices"]) != 1
            or ids["notices"][0].get("path") != f"fixtures/phase5-{slot}/NOTICES.md"):
        raise ValueError("public admission notice path is not canonical")
    loaded = {}
    for name in FILE_FIELDS:
        bindings = ids[name] if name == "notices" else [ids[name]]
        if name == "notices" and (not isinstance(bindings, list) or len(bindings) != 1):
            raise ValueError("public admission notice coverage is incomplete")
        loaded[name] = [_bound(root, {"path": binding.get("path"),
                                      "sha256": binding.get("sha256")})
                        for binding in bindings]
        if name == "notices" and (not isinstance(bindings[0].get("covers"), list)
                                   or not bindings[0]["covers"]):
            raise ValueError("public admission notice coverage is missing")
    for field in ("source_archive", "content_inventory", "material_terms", "canonical_rom",
                  "reference_executable", "reference_build", "tool_lock"):
        if ids[field].get("sha256") != authority[field]:
            raise ValueError("public admission retained authority digest mismatch")
    if (ids["notices"][0].get("sha256") != authority["notices"]
            or sorted(ids["notices"][0]["covers"]) != sorted(authority["notice_covers"])):
        raise ValueError("public admission retained notice coverage mismatch")
    inventory = json.loads(loaded["content_inventory"][0])
    terms = json.loads(loaded["material_terms"][0])
    scenario = json.loads(loaded["scenario"][0])
    schedule = json.loads(loaded["input_schedule"][0])
    program = json.loads(loaded["input_program"][0])
    oracle = json.loads(loaded["oracle"][0])
    executable_pin = json.loads(loaded["reference_executable"][0])
    reference_build = json.loads(loaded["reference_build"][0])
    expected_reference = {
        "schema": "genewhip-phase5-reference-executable-v1",
        "executable_sha256": authority["mame_executable"],
        "source_revision": "f34f02505e32c1993c6a782b6814232cbfc74e36",
        "source_archive_sha256": authority["mame_source"],
        "patch_sha256": authority["mame_patch"],
    }
    if executable_pin != expected_reference:
        raise ValueError("public admission reference executable authority mismatch")
    if (not isinstance(reference_build, dict)
            or reference_build.get("schema") != "genewhip-phase5-reference-build-v1"
            or reference_build.get("scenario_sha256") != ids["scenario"].get("sha256")
            or reference_build.get("tool_lock_sha256") != authority["tool_lock"]
            or reference_build.get("executable_sha256") != executable_pin["executable_sha256"]
            or reference_build.get("script_sha256") != ids["reference_script"].get("sha256")
            or reference_build.get("input_schedule_sha256") != ids["input_schedule"].get("sha256")
            or reference_build.get("input_program_sha256") != ids["input_program"].get("sha256")
            or reference_build.get("mame_source_revision") != executable_pin["source_revision"]
            or reference_build.get("mame_source_sha256") != executable_pin["source_archive_sha256"]
            or reference_build.get("mame_patch_sha256") != executable_pin["patch_sha256"]):
        raise ValueError("public admission reference build relation mismatch")
    if inventory.get("schema") != "genewhip-phase5-content-inventory-v1" or not inventory.get("files"):
        raise ValueError("public admission source inventory is invalid")
    if terms.get("schema") != "genewhip-phase5-material-terms-v1" or not terms.get("materials"):
        raise ValueError("public admission material rights terms are missing")
    if (not isinstance(terms["materials"], list) or not terms["materials"]
            or not all(isinstance(item, dict) and isinstance(item.get("license"), str)
                       and item["license"].strip() and item["license"].lower() != "unknown"
                       and isinstance(item.get("notice"), str)
                       and item["notice"] in ids["notices"][0]["covers"]
                       and isinstance(item.get("path"), str)
                       and re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
                       for item in terms["materials"])):
        raise ValueError("public admission material license is incomplete")
    # The archive reader rejects unsafe/duplicate members and inventories bytes without extraction.
    spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
    records_path = root / "tools/evidence/phase5_records.py"
    module_spec = spec.spec_from_file_location("gw_public_phase5_records", records_path)
    module = spec.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    actual = module._read_source_archive(root, ids["source_archive"])
    if inventory["files"] != [actual[key] for key in sorted(actual)]:
        raise ValueError("public admission archive differs from complete source inventory")
    notice_doc = loaded["notices"][0].decode("utf-8")
    if not notice_doc.strip() or not any(term in notice_doc for term in
            ("MIT License", "BSD", "PSF-2.0", "zlib License", "license terms")):
        raise ValueError("public admission notice does not describe retained rights")
    route = document.get("route")
    scenario_ids = scenario.get("identities")
    expected_input_sha = hashlib.sha256(json.dumps({
        "input_schedule": scenario.get("input_schedule"),
        "input_program": scenario.get("input_program")}, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()
    if (not isinstance(scenario_ids, dict)
            or scenario_ids.get("source_archive_sha256") != authority["scenario_source_archive"]
            or scenario_ids.get("source_revision") != authority["revision"]
            or scenario_ids.get("rom_sha256") != ids["canonical_rom"].get("sha256")
            or scenario_ids.get("mame_script_sha256") != ids["reference_script"].get("sha256")
            or scenario_ids.get("input_sha256") != expected_input_sha
            or scenario_ids.get("mame_build_sha256") != authority["mame_executable"]
            or scenario_ids.get("mame_source_revision") != executable_pin.get("source_revision")
            or scenario_ids.get("mame_source_sha256") != authority["mame_source"]
            or scenario_ids.get("mame_patch_sha256") != authority["mame_patch"]):
        raise ValueError("public admission scenario evidence identity mismatch")
    route_identity = {name: ids[name]["sha256"] for name in
                      ("scenario", "input_schedule", "input_program", "oracle", "reference_script")}
    frozen_route = hashlib.sha256(json.dumps(route_identity, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()
    if (not isinstance(route, dict) or set(route) != {"scenario_sha256", "oracle_sha256", "reference_script_sha256", "frozen_route_sha256"}
            or route.get("scenario_sha256") != ids["scenario"]["sha256"]
            or route.get("oracle_sha256") != ids["oracle"]["sha256"]
            or route.get("reference_script_sha256") != ids["reference_script"]["sha256"]
            or frozen_route != authority["frozen_route"]
            or route.get("frozen_route_sha256") != frozen_route
            or scenario.get("title_id") != title
            or scenario.get("input_schedule") != schedule or scenario.get("input_program") != program
            or scenario.get("identities", {}).get("rom_sha256") != ids["canonical_rom"]["sha256"]
            or scenario.get("identities", {}).get("mame_script_sha256") != ids["reference_script"]["sha256"]):
        raise ValueError("public admission route identities are inconsistent")
    rom_binding = ids["canonical_rom"]
    if (rom_binding.get("path") != f"fixtures/phase5-{'a' if fixture_id.endswith('-a') else 'b'}/game.bin"
            or hashlib.sha256(loaded["canonical_rom"][0]).hexdigest() != rom_binding.get("sha256")):
        raise ValueError("public admission canonical ROM identity mismatch")
    return "ok"


def validate_manifest_binding(row: dict, projection: dict) -> None:
    """Bind public projection claims back to the independently consumed manifest row."""
    fixture_id = row.get("id") if isinstance(row, dict) else None
    authority = REVIEWED.get(fixture_id)
    ids = projection.get("identities", {}) if isinstance(projection, dict) else {}
    expected_notices = [item.get("path") for item in ids.get("notices", [])]
    checks = (
        row.get("kind") == "phase5-independent-game-v1",
        projection.get("fixture_id") == fixture_id,
        row.get("project") == authority["project"] if authority else False,
        row.get("revision") == authority["revision"] if authority else False,
        row.get("license") == projection.get("license") == "See per-material terms; mixed components",
        row.get("assets") == projection.get("assets") == [],
        row.get("status") == "admitted" and row.get("outcome") == "pass",
        row.get("source") == ids.get("source_archive", {}).get("path"),
        row.get("source_sha256") == ids.get("source_archive", {}).get("sha256"),
        row.get("rom") == ids.get("canonical_rom", {}).get("path"),
        row.get("sha256") == ids.get("canonical_rom", {}).get("sha256"),
        row.get("notices") == expected_notices,
    )
    if not all(checks):
        raise ValueError("phase5 manifest does not match reviewed public admission")


EVIDENCE_BASIS = ("This public projection independently rechecks retained public byte, rights, route, and notice identities. "
                  "It does not reproduce omitted private selection or run history.")
