"""Real guest execution and designated evidence/fixture failure reasons."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

runner, validator, rom = map(Path, sys.argv[1:])
def run(args):
    return subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=10)
first = run([runner, rom]); second = run([runner, rom])
assert first.returncode == 0, first.stderr
assert second.returncode == 0 and first.stdout == second.stdout, "repeat evidence must be byte-identical"
report = json.loads(first.stdout)
assert report["expected"] == len(report["results"]) == 6
assert all(row["outcome"] == "pass" for row in report["results"])
assert report["results"][1]["observed"] == "d0-00001234-d1-89abcdef"
assert report["results"][2]["observed"] == "sr-00002704-pc-0000022a"
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "report.json"
    path.write_text(first.stdout)
    inspected = run([validator, path, "--inspect"])
    assert inspected.returncode == 0 and "pass=6" in inspected.stdout, inspected.stdout
    qualified = run([validator, path])
    if report["source_state"] == "clean":
        assert qualified.returncode == 0, qualified.stdout
    else:
        assert qualified.returncode == 1 and "dirty" in qualified.stdout, qualified.stdout
    def reject(text, reason):
        path.write_text(text)
        result = run([validator, path, "--inspect"])
        assert result.returncode == 1 and f"REJECT: {reason}" in result.stdout, (reason,result.stdout,result.stderr)
    for key, reason in (("source_revision","revision"),("configuration","configuration"),
                        ("fixture","fixture"),("input","input"),("profile","profile"),("oracle","oracle")):
        copy = dict(report); copy[key] = ("a" if report[key][0] != "a" else "b") + report[key][1:]
        reject(json.dumps(copy,separators=(",",":")),reason)
    copy = dict(report); copy["results"] = report["results"][:-1]
    reject(json.dumps(copy,separators=(",",":")),"denominator")
    reject(first.stdout + "false","malformed")
    reject("{" + '"schema_version":1,' * 5000,"oversize")
    missing = run([validator, Path(directory)/"missing.json"])
    assert missing.returncode == 1 and "REJECT: missing" in missing.stderr
    changed = bytearray(rom.read_bytes()); changed[0x203] ^= 1
    bad_rom = Path(directory)/"modified.bin"; bad_rom.write_bytes(changed)
    bad = run([runner,bad_rom])
    assert bad.returncode == 1 and "REJECT: fixture-content" in bad.stderr and not bad.stdout
print("PASS: headless guest oracle, deterministic reports, current identity, stale/missing/mismatch/denominator and ROM controls")
