"""Portable safety-build fact projection and policy validation."""
from __future__ import annotations

import pathlib
import re
import hashlib
import os
import stat

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
MAX_COMPILER_METADATA_BYTES = 1024 * 1024

COMPILER_ID_LINE = re.compile(r'^set\(CMAKE_C_COMPILER_ID "([A-Za-z][A-Za-z0-9+_.-]{0,63})"\)$')
COMPILER_VERSION_LINE = re.compile(r'^set\(CMAKE_C_COMPILER_VERSION "([0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?)"\)$')
COMPILER_ID_ASSIGNMENT = re.compile(r'^set\(CMAKE_C_COMPILER_ID(?=\s|\))')
COMPILER_VERSION_ASSIGNMENT = re.compile(r'^set\(CMAKE_C_COMPILER_VERSION(?=\s|\))')
COMPILER_METADATA_REL = re.compile(r'^CMakeFiles/[0-9]+(?:\.[0-9]+){1,3}/CMakeCCompiler\.cmake$')


def project_cache(path: pathlib.Path) -> dict[str, str]:
    """Project the same ten safe CMake facts, including generated compiler facts."""
    facts, _compiler_input = project_cache_inputs(path)
    return facts


def _read_compiler_metadata(path: pathlib.Path) -> tuple[bytes, tuple[str, str]]:
    """Read one generated CMake compiler file as a bounded, no-follow snapshot."""
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink != 1 or
                before.st_size <= 0 or before.st_size > MAX_COMPILER_METADATA_BYTES):
            raise ValueError("compiler-metadata-invalid")
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                    opened.st_size != before.st_size or
                    (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise ValueError("compiler-metadata-invalid")
            data = stream.read(MAX_COMPILER_METADATA_BYTES + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
        if (len(data) != before.st_size or len(data) > MAX_COMPILER_METADATA_BYTES or
                (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns) !=
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) or
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
            raise ValueError("compiler-metadata-invalid")
        text = data.decode("utf-8", errors="strict")
    except ValueError:
        raise
    except (OSError, UnicodeError) as error:
        raise ValueError("compiler-metadata-invalid") from error
    ids, versions = [], []
    for line in text.splitlines():
        for assignment, pattern, values in (
                (COMPILER_ID_ASSIGNMENT, COMPILER_ID_LINE, ids),
                (COMPILER_VERSION_ASSIGNMENT, COMPILER_VERSION_LINE, versions)):
            if assignment.match(line.lstrip()):
                match = pattern.fullmatch(line)
                if not match:
                    raise ValueError("compiler-metadata-invalid")
                values.append(match.group(1))
    if len(ids) != 1 or len(versions) != 1:
        raise ValueError("compiler-metadata-invalid")
    return data, (ids[0], versions[0])


def _compiler_metadata_path(cache_path: pathlib.Path) -> pathlib.Path:
    """Find the one compiler metadata file owned by this CMake build tree."""
    build_root = cache_path.parent
    if build_root.is_symlink():
        raise ValueError("compiler-metadata-invalid")
    cmake_files = build_root / "CMakeFiles"
    if cmake_files.is_symlink() or not cmake_files.is_dir():
        raise ValueError("compiler-metadata-missing")
    candidates = sorted(cmake_files.glob("*/CMakeCCompiler.cmake"))
    if not candidates:
        raise ValueError("compiler-metadata-missing")
    if len(candidates) != 1:
        raise ValueError("compiler-metadata-ambiguous")
    path = candidates[0]
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("compiler-metadata-invalid")
    try:
        relative = path.relative_to(build_root).as_posix()
    except ValueError as error:
        raise ValueError("compiler-metadata-invalid") from error
    if not COMPILER_METADATA_REL.fullmatch(relative):
        raise ValueError("compiler-metadata-invalid")
    return path


def project_cache_inputs(path: pathlib.Path) -> tuple[dict[str, str], dict[str, object]]:
    """Project safe facts and bind compiler identity to the exact generated input bytes.

    CMake stores its detected compiler ID and version in CMakeFiles/*/CMakeCCompiler.cmake
    rather than CMakeCache.txt. Parse only those two generated assignments and retain the
    metadata file's path, digest and size as an input identity; never export its contents.
    """
    values = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if line.startswith("//") or line.startswith("#") or ":" not in line or "=" not in line:
            continue
        key, typed_value = line.split(":", 1)
        _, value = typed_value.split("=", 1)
        if key in SAFE_CACHE_KEYS:
            if key in values:
                raise ValueError("settings-roster")
            values[key] = value
    compiler_path = _compiler_metadata_path(path)
    compiler_bytes, (compiler_id, compiler_version) = _read_compiler_metadata(compiler_path)
    cached_id, cached_version = values.pop("CMAKE_C_COMPILER_ID", None), values.pop("CMAKE_C_COMPILER_VERSION", None)
    if (cached_id is not None or cached_version is not None) and (cached_id, cached_version) != (
            compiler_id, compiler_version):
        raise ValueError("compiler-metadata-cache-mismatch")
    values["CMAKE_C_COMPILER_ID"] = compiler_id
    values["CMAKE_C_COMPILER_VERSION"] = compiler_version
    compiler_input = {"path": compiler_path, "sha256": hashlib.sha256(compiler_bytes).hexdigest(),
        "size": len(compiler_bytes)}
    return values, compiler_input


def validate_configuration(variant: str, facts: dict) -> str | None:
    """Validate exactly the portable CMake facts before checking artifact identities."""
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
    return None


def validate_facts(variant: str, facts: dict, expected_sources: dict[str, str]) -> str | None:
    """Check portable configuration against trusted variant policy and source hashes."""
    problem = validate_configuration(variant, facts)
    if problem:
        return problem
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
