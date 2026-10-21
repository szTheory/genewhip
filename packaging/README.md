# Local SDK/diagnostic preview

This is a native-host SDK/diagnostic preview, version 0.1.0 and C API 4. It
contains the tested diagnostic core and deterministic PSG/FM/DAC paths from
original Genewhip fixtures. FM is an attributed BSD-3-Clause ymfm port; its
comparison deviations and model limits are recorded in the Phase 3 evidence
and reset amendment. Exact VA3 FM reset wiring remains unknown. No game audio
compatibility or performance claim is made. Pong remains rejected and no
independently authored playable game is admitted. The package is unsigned and
unnotarized; checksum identity is not authentication.

The package carries the MIT notice, upstream SingleStepTests notice and
`THIRD-PARTY-ymfm.txt`. It contains no upstream vectors, decoder, LGPL reference
implementation or playable ROM. Only the original manifest-admitted diagnostic
bytes are bundled.

From a clean checkout with CMake 3.27+, a C17/C++11 compiler, Python 3.8+ and Git:

```sh
bash scripts/ci/required-gate.sh
cmake -DPROJECT_SOURCE_DIR="$PWD" -P tests/package/package_smoke.cmake
```

The package script builds in a fresh temporary directory, rejects dirty inputs
and revision changes during the build, validates clean diagnostic evidence,
then checks and exercises the exact archive in another temporary directory.
Only a passing archive and its SHA-256 sidecar are copied to `artifacts/`.
Archive names include version, OS, architecture and source revision.
`metadata.json` records the exact revision, build configuration identity,
toolchain and native OS. `checksums.json` inventories every payload file;
tar/gzip ownership and timestamps are normalized. Repeatability is scoped to
the same source and toolchain; this does not claim cross-toolchain or cross-host
byte reproducibility.

After checking the sidecar with `shasum -a 256 -c ARCHIVE.tar.gz.sha256`,
extract the archive and run `bin/gw_diagnostic_runner
share/genewhip/diagnostic.bin`. `bin/gw_validate_evidence
share/genewhip/diagnostic-evidence.json` checks the included six-case
diagnostic evidence. The SDK can be moved; set `CMAKE_PREFIX_PATH` to the
extracted root and link `Genewhip::core` using
`find_package(Genewhip 0.1.0 EXACT CONFIG REQUIRED)`.
`share/genewhip/consumer` is a runnable external C/C++ example. Test hooks are
off.

See `core.md` for CPU, bus, time and profile limits. Execution on other OS
versions or architectures remains unqualified until separately recorded;
runner image selection in CI is configuration, not proof of execution.

The local required gate covers native, ASan/UBSan, hooks-off and relocated
consumer tests plus public-source hygiene and four seeded failures. Apple ASan
does not provide LeakSanitizer; Darwin runs explicitly disable leak detection.
The scanner detects common credential/path patterns and rejects ROM/save file
extensions, not every possible secret encoding or renamed private asset.
Preserve upstream notices exactly. Do not include local logs, caches, private
ROMs or save files.

`bash scripts/ci/extended-gate.sh` separately fetches hash-pinned NOP/MOVEQ
vectors and runs a fixed 4,096-case sanitizer fuzz budget. Reports preserve all
5,000 selected-family records (including unsupported states) and disclose 125
unrun families with unknown record counts. Fuzz passes mean bounded
deterministic API behavior, not hardware accuracy. Required PR tests need no
network downloads.
