#!/usr/bin/env python3
"""Keep LGPL reference-emulator material outside core, install, and SDK files."""
import io
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile


TOKENS = (b"ym3438", b"OPN2_", b"GNU LESSER GENERAL PUBLIC LICENSE", b"SPDX-License-Identifier: LGPL")


def content_violations(name, data, documentary=False):
    """Only identified package evidence documents may name the comparator.

    The allowance never covers code identifiers or LGPL licence text, even in
    these documents. Every other payload (including executables) rejects names
    and symbols, independent of its extension.
    """
    lowered = data.lower()
    tokens = tuple(token.lower() for token in TOKENS)
    found = ["LGPL material in %s token=%s" % (name, token.decode("ascii"))
             for token in tokens if token in lowered]
    # A lowercase English word in an attributed upstream comment is not a
    # comparator symbol. Preserve the original proper-name check, and also
    # reject lower/mixed-case implementation identifiers.
    if not documentary and (b"Nuked" in data or re.search(rb"\bnuked[_-][a-z0-9_]+", lowered)):
        found.append("LGPL material in %s token=Nuked" % name)
    return found


def evidence_document(name):
    parts = pathlib.PurePosixPath(name).parts
    return len(parts) >= 3 and parts[-3:-1] == ("share", "genewhip") and parts[-1] in (
        "README.md", "phase3-evidence.json")


def violations(paths, label, allow_evidence_docs=False):
    found = []
    for root in paths:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = sorted(p for p in root.rglob("*") if p.is_file())
        else:
            continue
        for path in candidates:
            name = path.name.lower()
            if any(token in name for token in ("ym3438", "opn2", "nuked")):
                found.append("LGPL material in %s: %s" % (label, path.name))
                continue
            try:
                data = path.read_bytes()
            except OSError as error:
                found.append("cannot scan %s: %s (%s)" % (label, path, error))
                continue
            found.extend(content_violations(label + ": " + path.name, data,
                                           documentary=allow_evidence_docs and evidence_document(path.as_posix())))
    return found


def negative_control():
    with tempfile.TemporaryDirectory(prefix="gw-lgpl-negative-") as temporary:
        injected = pathlib.Path(temporary) / "ym3438.c"
        injected.write_text("/* synthetic negative control */\n")
        matches = violations([pathlib.Path(temporary)], "negative-control")
        expected = "LGPL material in negative-control: ym3438.c"
        if expected not in matches:
            raise SystemExit("FAIL: negative control did not detect the named forbidden file")
        print("PASS: negative control rejected " + expected)
        # Exercise the actual archive scanner, including extensionless binaries
        # and documents with the same names outside the identified evidence path.
        allowed = {"pkg/share/genewhip/phase3-evidence.json": b'{"id":"ym_nuked_model_comparison","oracle_class":"Nuked-OPN2-model"}',
                   "pkg/share/genewhip/README.md": b"Compared with Nuked-OPN2; deviations reported."}

        def scan(extra):
            archive = pathlib.Path(temporary) / "control.tar"
            with tarfile.open(archive, "w") as tar:
                for name, data in {**allowed, **extra}.items():
                    info = tarfile.TarInfo(name); info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return archive_violations(archive)

        if scan({}):
            raise SystemExit("FAIL: documentary provenance rejected")
        for name, data in (
                ("pkg/src/chip.c", b"/* Nuked implementation */"),
                ("pkg/include/chip.h", b"OPN2_Reset"),
                ("pkg/lib/core.a", b"ym3438"),
                ("pkg/bin/runner", b"Nuked"),
                ("pkg/bin/lowercase-runner", b"nuked_clock"),
                ("pkg/share/genewhip/ym3438.c", b"synthetic"),
                ("pkg/share/genewhip/phase3-evidence.json", b"OPN2_Reset"),
                ("pkg/share/genewhip/README.md", b"GNU LESSER GENERAL PUBLIC LICENSE"),
                ("pkg/other/README.md", b"Nuked")):
            if not scan({name: data}):
                raise SystemExit("FAIL: archive negative control survived: " + name)
        print("PASS: archive metadata allowed; source/header/library/binary, filenames, code identifiers and LGPL text rejected")


def archive_violations(archive):
    failures = []
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = pathlib.PurePosixPath(member.name).name
            if any(token in name.lower() for token in ("ym3438", "opn2", "nuked")):
                failures.append("LGPL material in archive file name: " + member.name)
                continue
            stream = tar.extractfile(member)
            if stream is None:
                failures.append("cannot read archive member: " + member.name)
                continue
            data = stream.read()
            failures.extend(content_violations("archive member: " + member.name, data,
                                               documentary=evidence_document(member.name)))
    return failures


def main():
    if sys.argv[1:] and sys.argv[1] == "--negative-control":
        negative_control()
        return
    if len(sys.argv) < 3 or (len(sys.argv) - 3) % 2:
        raise SystemExit("usage: no_lgpl_in_install.py SOURCE_ROOT BUILD_DIR [--archive PATH ...]")
    source = pathlib.Path(sys.argv[1]).resolve()
    build = pathlib.Path(sys.argv[2]).resolve()
    archive_args = sys.argv[3:]
    archives = []
    while archive_args:
        flag, path, *archive_args = archive_args
        if flag != "--archive":
            raise SystemExit("FAIL: expected --archive PATH")
        archives.append(pathlib.Path(path).resolve())
    with tempfile.TemporaryDirectory(prefix="gw-lgpl-install-") as temporary:
        install = pathlib.Path(temporary) / "install"
        subprocess.run(["cmake", "--install", str(build), "--prefix", str(install)], check=True)
        listing = subprocess.run([sys.executable, "-I", str(source / "scripts/package_sdk.py"), "--list"],
                                 cwd=source, check=True, text=True, stdout=subprocess.PIPE)
        archive_names = [line.split("\t", 1)[1] for line in listing.stdout.splitlines()
                         if line.startswith("SDK_FILE\t")]
        if not archive_names:
            raise SystemExit("FAIL: SDK file-list mode returned no archive paths")
        checks = [(violations([source / "src", source / "include"], "source")),
                  (violations([install], "install", allow_evidence_docs=True))]
        for name in archive_names:
            lowered = name.lower()
            if any(token in lowered for token in ("ym3438", "opn2", "nuked")):
                checks.append(["LGPL material in SDK archive file list: " + name])
            upper = name.encode("utf-8").upper()
            if b"GNU LESSER GENERAL PUBLIC LICENSE" in upper or b"OPN2_" in upper or b"YM3438" in upper:
                checks.append(["LGPL material in SDK archive file list: " + name])
        for archive in archives:
            checks.append(archive_violations(archive))
        failures = [item for group in checks for item in group]
        if failures:
            for failure in failures:
                print(failure, file=sys.stderr)
            raise SystemExit(1)
        print("PASS: no LGPL implementation material in source, install, SDK file list, or requested archives; documentary comparator names preserved")


if __name__ == "__main__":
    main()
