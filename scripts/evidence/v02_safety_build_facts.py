"""Portable safety-build fact projection and policy validation."""
from __future__ import annotations

import pathlib
import re

SCHEMA = "genewhip.v02-portable-build-facts.v1"
FIXED_SETTINGS = {
    "native": {
        "CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja",
        "CMAKE_C_FLAGS": "", "CMAKE_EXE_LINKER_FLAGS": "",
        "BUILD_TESTING": "ON", "GENEWHIP_BUILD_TOOLS": "ON",
        "GENEWHIP_BUILD_DESKTOP": "ON", "GENEWHIP_TEST_HOOKS": "ON",
    },
    "sanitize": {
        "CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja",
        "CMAKE_C_FLAGS": "-fsanitize=address,undefined -fno-omit-frame-pointer",
        "CMAKE_EXE_LINKER_FLAGS": "-fsanitize=address,undefined",
        "BUILD_TESTING": "ON", "GENEWHIP_BUILD_TOOLS": "ON",
        "GENEWHIP_BUILD_DESKTOP": "OFF", "GENEWHIP_TEST_HOOKS": "ON",
    },
    "hooks-off": {
        "CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja",
        "CMAKE_C_FLAGS": "", "CMAKE_EXE_LINKER_FLAGS": "",
        "BUILD_TESTING": "ON", "GENEWHIP_BUILD_TOOLS": "ON",
        "GENEWHIP_BUILD_DESKTOP": "OFF", "GENEWHIP_TEST_HOOKS": "OFF",
    },
}
COMPILER_IDS = {"AppleClang", "Clang"}
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?\Z")
SAFE_CACHE_KEYS = set(FIXED_SETTINGS["native"]) | {
    "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION"}


def project_cache(path: pathlib.Path) -> dict[str, str]:
    """Project only whitelisted, portable CMake facts from an observed cache."""
    values = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if line.startswith("//") or line.startswith("#") or ":" not in line or "=" not in line:
            continue
        key, typed_value = line.split(":", 1)
        _, value = typed_value.split("=", 1)
        if key in SAFE_CACHE_KEYS:
            values[key] = value
    return values


def validate_facts(variant: str, facts: dict, expected_sources: dict[str, str]) -> str | None:
    """Check portable configuration against trusted variant policy and source hashes."""
    if variant not in FIXED_SETTINGS or not isinstance(facts, dict):
        return "variant"
    if set(facts) != SAFE_CACHE_KEYS or any(not isinstance(value, str) for value in facts.values()):
        return "settings-roster"
    for key, value in FIXED_SETTINGS[variant].items():
        if facts.get(key) != value:
            return "configuration:" + key
    if facts.get("CMAKE_C_COMPILER_ID") not in COMPILER_IDS:
        return "compiler-id"
    if not VERSION.fullmatch(facts.get("CMAKE_C_COMPILER_VERSION", "")):
        return "compiler-version"
    if not isinstance(expected_sources, dict) or not expected_sources:
        return "source-roster"
    return None


def validate_projection(document: dict, variant: str, expected_sources: dict[str, str]) -> str | None:
    """Validate one transferred fact document, including every source identity."""
    if not isinstance(document, dict) or document.get("schema") != SCHEMA or document.get("variant") != variant:
        return "schema-or-variant"
    if document.get("raw_build_artifact_bytes_transferred") is not False:
        return "raw-bytes-policy"
    problem = validate_facts(variant, document.get("build_facts"), expected_sources)
    if problem:
        return problem
    observed = document.get("raw_build_artifact_identities")
    if not isinstance(observed, list):
        return "source-identities"
    actual = {}
    for row in observed:
        if (not isinstance(row, dict) or set(row) != {"source_path", "sha256", "size"} or
                not isinstance(row.get("source_path"), str) or
                not isinstance(row.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or
                type(row.get("size")) is not int or row["size"] < 0):
            return "source-identities"
        actual[row["source_path"]] = row["sha256"]
    if actual != expected_sources or len(observed) != len(expected_sources):
        return "source-identities"
    return None
