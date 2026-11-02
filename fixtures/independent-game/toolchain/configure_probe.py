#!/usr/bin/env python3
"""Apply the narrowly pinned Binutils configure probe compatibility fix."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


PATCH_SCHEMA = "genewhip-binutils-source-patch-v1"
PATCH_ID = "binutils-2.47-configure-parent-relative-probe"
ARCHIVE_SHA256 = "3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8"
ORIGINAL_TREE_SHA256 = "7b2b4f3a271745bacec91336a38689218dbbe7a01371dbfdfb11e0e933e47a09"
PATCHED_TREE_SHA256 = "49aebd642f4f7cb498ea4d3c5edc7ad908707ef6a01ad6c67207cbf48c57d304"
OLD_PROBE = b"ln -s conf$$.file conf$$.dir"
NEW_PROBE = b"ln -s ../conf$$.file conf$$.dir"

# Exact upstream file bytes and occurrence counts from the signed 2.47 archive.
# The allowlist is deliberately complete: any new matching file fails closed.
PATCH_FILES = (
    ("bfd/configure", "cebcff00017832ee5c164fbdd6d4ac48b75168e41152678f0b9f855d2afa892e", 2),
    ("binutils/configure", "2a48a17eee22dd3d15f342057480eba2b85e40654c1feae67b73937ffaea575f", 2),
    ("configure", "c91bd515aebdf8425189ae4a8037e38dc37555137c9a25f69b20f765237b7852", 2),
    ("etc/configure", "ba4153aa9e945f569aa5cce904460bed33724b7c4a67df9d53949d9350a3831b", 2),
    ("gas/configure", "6051dcdc44a0ef1fa65f978f532206f7eb89ad0607e2209b39d851723aba9bd2", 2),
    ("gprof/configure", "0b8e23be2a708ab3ba1d6bb661533b09ea7d90af2fd316ab8b0f2d8e46f5103f", 2),
    ("gprofng/configure", "fb496bb7c7568fa395d3db541bf695972cf26d4ecc0cdc642900f383acee97d3", 2),
    ("gprofng/libcollector/configure", "0b5a0d7d3d2930eaa5b179f63b3c1a05a4c14a819ecf83da9de5c3595ebcfc1d", 2),
    ("ld/configure", "a3304f2f0b3dbfe79ea4b6b418ae731d0d7df733cfe8e02d9d051fe278285ef4", 2),
    ("libctf/configure", "85a9f30999e7f8a1d3ec6308ef325f80c2b6d4318cb0b54ae04593f6a95555a6", 3),
    ("libiberty/configure", "989d185d699e5e48c9a0fdc2cbc0d963f30930f3fd38a9bfc564cd86790eb384", 2),
    ("libsframe/configure", "c7de4638114571cd107de82919a9db85a4427feea3804eaa71fd4630f26df520", 2),
    ("opcodes/configure", "63ae672fbec755c2a82ca2332d4f52b46db32999a93df0dc97c2db5172f1d5ac", 2),
    ("zlib/configure", "eac4271966c998e9e83c840c6132bb17007c81dadd43d1b88119fecd178f1fb3", 2),
)
PATCHED_FILE_SHA256 = {
    "bfd/configure": "3008bb2a13b84a32d4542687a4053efa133d4b53fadfe66beecf7dcc4eb80611",
    "binutils/configure": "d31e240d595af827127d38f213ee9d15f768594bfef71e6e96b0e8949c348e27",
    "configure": "df0292f08e09c4264154a946d9106993bc7cc16b814ee278ffcc9da24f99e278",
    "etc/configure": "67928a498784e25d07e7d10599516a4342a9871b460b94137185fdf65daee591",
    "gas/configure": "3a46ee4b8c8fc0c726b36f1063b65d50d9fbb965ddba7786442af707c5830367",
    "gprof/configure": "00bc09b62fb1784c7f55ed603f8f4c7ed1f250f153de54cce6c328b87b8fe646",
    "gprofng/configure": "525b4d51ab4291832b3356d8516202cf176622a373e7e7a382cba2bc42e4853f",
    "gprofng/libcollector/configure": "de60e475889a2910c97b4c5081e56aa1cc90504fddba2d9a1c70c85bc7e4f137",
    "ld/configure": "ea2fbea6d8560aeba80381113ff78eef7196694a29eb9decaaa0a0ec3fccb88f",
    "libctf/configure": "be8e643ead5709c8ce7f6f5cb99276b8b3607c83f36520973450723dbf845cf2",
    "libiberty/configure": "a19a40fd86f043cf89c7feb22dd1540cf0f118e2012702df8d0ab0e61901b5f4",
    "libsframe/configure": "a3875cc22a148755ba437370f076a06696bb26ee71104a9f2255838bf2b8a79f",
    "opcodes/configure": "b3178ee80c98bb4f958991c9ae3f35854e96029174f8a60458e6c6c6587ba9d5",
    "zlib/configure": "ae4089ca7fa4f42ca8b2893aa01b0e68e223ee497a488b9d7a23771046cd80f0",
}


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def tree_sha256(root: pathlib.Path) -> str:
    root = pathlib.Path(root)
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(content_sha))
    return digest.hexdigest()


def patch_recipe() -> dict[str, object]:
    return {
        "schema": PATCH_SCHEMA,
        "id": PATCH_ID,
        "archive_sha256": ARCHIVE_SHA256,
        "original_source_tree_sha256": ORIGINAL_TREE_SHA256,
        "replacement": {"from": OLD_PROBE.decode("ascii"), "to": NEW_PROBE.decode("ascii")},
        "files": [
            {"path": name, "original_sha256": digest, "replacement_count": count}
            for name, digest, count in PATCH_FILES
        ],
    }


def replace_probe_bytes(original: bytes, expected_count: int) -> bytes:
    """Transform only the pinned probe text after its containing file was verified."""
    if type(expected_count) is not int or expected_count < 1:
        raise ValueError("configure probe replacement count is invalid")
    if original.count(OLD_PROBE) != expected_count:
        raise ValueError("configure probe occurrence count differs from the pinned recipe")
    return original.replace(OLD_PROBE, NEW_PROBE)


def expected_patch_manifest() -> dict[str, object]:
    manifest: dict[str, object] = {
        "schema": PATCH_SCHEMA,
        "id": PATCH_ID,
        "archive_sha256": ARCHIVE_SHA256,
        "original_source_tree_sha256": ORIGINAL_TREE_SHA256,
        "patched_source_tree_sha256": PATCHED_TREE_SHA256,
        "recipe_sha256": canonical_sha256(patch_recipe()),
        "helper_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "files": [
            {"path": name, "original_sha256": original, "patched_sha256": PATCHED_FILE_SHA256[name],
             "replacement_count": count}
            for name, original, count in PATCH_FILES
        ],
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def verify_probe_files(root: pathlib.Path, expected_files: tuple[tuple[str, str, int], ...]) -> None:
    """Check one explicit file/hash/count manifest; production supplies the fixed upstream allowlist."""
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("upstream source root is not a real directory")
    expected = {name: (digest, count) for name, digest, count in expected_files}
    observed: dict[str, int] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        count = content.count(OLD_PROBE)
        if count:
            observed[relative] = count
    if observed != {name: row[1] for name, row in expected.items()}:
        raise ValueError("configure probe file list or occurrence counts differ from the signed release allowlist")
    for name, (expected_digest, _) in expected.items():
        path = root / pathlib.Path(name)
        if path.is_symlink() or not path.is_file():
            raise ValueError("allowlisted configure probe file is missing or not a regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            raise ValueError("allowlisted configure probe file bytes differ from the signed release")


def verify_upstream_probe_files(root: pathlib.Path) -> None:
    """Reject any unrecognized, missing, changed, or differently repeated upstream probe."""
    verify_probe_files(root, PATCH_FILES)


def patch_tree(root: pathlib.Path, archive_sha256: str) -> dict[str, object]:
    """Verify the complete signed extraction, patch the exact probe, and bind its tree."""
    root = pathlib.Path(root)
    if archive_sha256 != ARCHIVE_SHA256:
        raise ValueError("signed archive identity differs from the pinned configure probe patch")
    upstream_tree = tree_sha256(root)
    if upstream_tree != ORIGINAL_TREE_SHA256:
        raise ValueError("unpatched source tree does not match the pinned upstream extraction")
    verify_upstream_probe_files(root)

    patched_files = []
    for name, original_sha, expected_count in PATCH_FILES:
        path = root / pathlib.Path(name)
        original = path.read_bytes()
        if hashlib.sha256(original).hexdigest() != original_sha:
            raise ValueError("configure probe file changed before patch application")
        patched = replace_probe_bytes(original, expected_count)
        patched_sha = hashlib.sha256(patched).hexdigest()
        if patched_sha != PATCHED_FILE_SHA256[name]:
            raise ValueError("configure probe file differs from the pinned transformation")
        path.write_bytes(patched)
        patched_files.append({
            "path": name,
            "original_sha256": original_sha,
            "patched_sha256": patched_sha,
            "replacement_count": expected_count,
        })

    patched_tree = tree_sha256(root)
    if patched_tree != PATCHED_TREE_SHA256:
        raise ValueError("patched source tree differs from the pinned configure probe transformation")
    recipe = patch_recipe()
    manifest = expected_patch_manifest()
    if (manifest["archive_sha256"] != archive_sha256
            or manifest["original_source_tree_sha256"] != upstream_tree
            or manifest["patched_source_tree_sha256"] != patched_tree
            or manifest["recipe_sha256"] != canonical_sha256(recipe)
            or manifest["files"] != patched_files):
        raise ValueError("configure probe receipt differs from the pinned patch manifest")
    return manifest


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", type=pathlib.Path, metavar="SOURCE_ROOT", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        manifest = patch_tree(args.apply, args.archive_sha256)
        data = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
        if args.manifest.exists() or args.manifest.is_symlink():
            raise ValueError("patch manifest output already exists")
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(data, encoding="utf-8")
    except (OSError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
