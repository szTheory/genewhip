"""Check inventory/identity before executing only the exact extracted desktop archive bytes."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

LABEL = "audio-capable diagnostic desktop preview"
ENV = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
STATUS = re.compile(r"^fields=(\d+) paused_fields=(\d+) resets=(\d+)(?: .*)?$", re.M)


def check_files(root):
    expected = json.loads((root / "checksums.json").read_text())
    actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*") if p.is_file() and p.name != "checksums.json"}
    if expected != actual:
        raise ValueError("package-content-checksum")


def runner(prefix, *args):
    return subprocess.run([str(prefix / "bin/genewhip-desktop"), *map(str, args)], capture_output=True, text=True,
                          env=ENV, timeout=60)


def hash_lines(text):
    return [line for line in text.splitlines() if line.startswith("{")]


def main():
    archive, digest, revision = sys.argv[1:]
    if hashlib.sha256(pathlib.Path(archive).read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    with tempfile.TemporaryDirectory(prefix="gw-desktop-smoke-") as tmp:
        scratch = pathlib.Path(tmp)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not member.isfile():
                    raise ValueError("archive-member")
            tar.extractall(scratch)
        roots = list(scratch.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("archive-root")
        prefix = roots[0]
        check_files(prefix)
        metadata = json.loads((prefix / "metadata.json").read_text())
        if metadata["source_revision"] != revision or metadata["source_state"] != "clean":
            raise ValueError("package-revision")
        if metadata.get("api_version") != 4:
            raise ValueError("package-api-version")
        share = prefix / "share/genewhip"
        for name in ["README.md", "LICENSE", "SDL3-LICENSE.txt", "sdl3.json", "manifest.json", "raster-toy.bin",
                     "THIRD-PARTY-ymfm.txt", "raster-toy-NOTICES.md", "raster-toy-demo.log", "phase3-evidence.json", "video.md", "input.md",
                     "desktop.md"]:
            if not (share / name).is_file():
                raise ValueError("package-notice-or-evidence: " + name)
        source_notice = pathlib.Path(__file__).resolve().parents[2] / "packaging/notices/THIRD-PARTY-ymfm.txt"
        if (share / "THIRD-PARTY-ymfm.txt").read_bytes() != source_notice.read_bytes():
            raise ValueError("package-ymfm-notice-drift")
        if (metadata.get("label") != LABEL or "PSG/FM/DAC" not in (share / "README.md").read_text()
                or metadata.get("signing") != "unsigned, unnotarized" or metadata.get("architectures") != ["arm64"]):
            raise ValueError("desktop-label")
        evidence = json.loads((share / "phase3-evidence.json").read_text())
        if evidence["source_revision"] != revision or evidence["source_state"] != "clean":
            raise ValueError("package-evidence-revision")
        validator = pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase3_report.py"
        subprocess.run([sys.executable, str(validator), "--validate", str(share / "phase3-evidence.json"),
                        "--expected-revision", revision], check=True)
        # Named mutation must be detected before any client execution.
        license_path = share / "LICENSE"
        original = license_path.read_bytes()
        license_path.write_bytes(original + b"tampered")
        try:
            check_files(prefix)
        except ValueError as error:
            if str(error) != "package-content-checksum":
                raise
        else:
            raise ValueError("negative-control-not-detected")
        license_path.write_bytes(original)
        check_files(prefix)
        # Move the prefix again: nothing may depend on the extraction path.
        moved = scratch / "relocated"
        prefix.rename(moved)
        share = moved / "share/genewhip"
        rom, log = share / "raster-toy.bin", share / "raster-toy-demo.log"
        result = runner(moved, "--fields", 60, rom)
        if result.returncode != 0 or "fields=60" not in result.stdout:
            raise ValueError("desktop-run: " + result.stderr.strip())
        live = runner(moved, "--replay", log, "--print-field-hashes", "--fields", 240, rom)
        headless = subprocess.run([str(moved / "bin/gw_headless"), str(rom), "--fields", "240", "--replay", str(log)],
                                  capture_output=True, text=True, env=ENV, timeout=60)
        if live.returncode != 0 or headless.returncode != 0:
            raise ValueError("desktop-replay-drift: nonzero exit")
        lines = hash_lines(live.stdout)
        if len(lines) != 241 or lines != hash_lines(headless.stdout):
            raise ValueError("desktop-replay-drift")
        summary = next((line for line in live.stdout.splitlines() if line.startswith("fields=")), "")
        values = {key: int(value) for key, value in re.findall(r"([a-z_]+)=(\d+)", summary)}
        if ("audio=on" not in summary or values.get("produced_frames") != values.get("consumed_frames", -1)
                + values.get("queued_frames", -1) + values.get("dropped_frames", -1)
                or values.get("core_lost") != 0):
            raise ValueError("desktop-audio-counters: " + summary)
        # Load error: REJECT reason on stderr and a non-zero exit.
        missing = runner(moved, scratch / "absent.bin")
        if missing.returncode == 0 or not missing.stderr.startswith("REJECT: missing"):
            raise ValueError("desktop-load-error-not-rejected")
        script = scratch / "controls.script"
        script.write_text("10 pause\n30 resume\n40 reset\n60 quit\n")
        controls = runner(moved, "--host-script", script, rom)
        match = STATUS.search(controls.stdout)
        if (controls.returncode != 0 or not match or tuple(map(int, match.groups())) != (40, 20, 1)
                or "audio=on" not in controls.stdout):
            raise ValueError("desktop-host-controls: " + controls.stdout.strip())
        print("desktop package smoke: PASS; archive checksum, inventory, tamper rejection, relocated runner, "
              "A/B/C audio counters and headless replay equivalence")


if __name__ == "__main__":
    main()
