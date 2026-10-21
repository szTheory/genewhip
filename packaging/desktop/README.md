# Playable desktop preview

The local desktop package is built from a committed source snapshot and qualified against its exact archive bytes. Read its adjacent `.qualification.json` receipt for the filename, source revision, checksum, inventory identity, and measured scenario results. Old snapshots may remain for historical evidence; only the current receipt-backed identity should be recommended for adoption.

The package version is 0.1.0 and the core API is version 4. The corrected MIT game v2 is admitted for its bounded MAME reference contract and separately exercised by Genewhip over six frozen cases and a 720-field sustained scenario. This does not establish general game compatibility or hardware accuracy. The raster toy provides PSG/FM/DAC diagnostics, not commercial-game audio compatibility. FM comparator deviations and exact VA3 reset wiring remain documented unknowns.

The package was exercised on macOS 26.6.2 arm64. Its build deployment target was not explicitly set, so the tested OS does not establish a minimum supported macOS version. It is unsigned and unnotarized. The checksum identifies bytes, not publisher identity.

Download the complete 0.1.0 release inventory, then select the desktop archive by its inventory entry. The same commands are exercised against the published bytes during release verification:

```sh
gh release download v0.1.0 --repo szTheory/genewhip --dir "$ARTIFACT_DIR"
DESKTOP_ARCHIVE="$(python3 -c 'import json,os; d=json.load(open(os.path.join(os.environ["ARTIFACT_DIR"],"inventory.json"))); print(next(n for n in d["assets"] if "playable-preview" in n and n.endswith(".tar.gz")))')"
```

The local commands below verify, extract and run the exact downloaded archive.

<a id="desktop-local-verify-extract-run"></a>

```sh
cd "$ARTIFACT_DIR"
shasum -a 256 -c "$DESKTOP_ARCHIVE.sha256"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARTIFACT_DIR/$DESKTOP_ARCHIVE" -C "$EXTRACT_DIR"
PACKAGE_DIR="$EXTRACT_DIR/${DESKTOP_ARCHIVE%.tar.gz}"
"$PACKAGE_DIR/bin/genewhip-desktop" --fields 120 \
  "$PACKAGE_DIR/share/genewhip/independent-game-v2.bin"
```

Keyboard controls use arrows and Z/X/C for directions and A/B/C; Return maps to Start. A connected gamepad uses its D-pad, west/south/east face buttons, and Start. P pauses/resumes, R resets, M toggles mute, and Escape quits. Dragging a cartridge onto the window loads it; a failed drop prints a sanitized `REJECT:` reason and keeps the current session. With no usable audio device the runner continues video-only and reports that audio is unavailable. The runner does not claim physical scanout, achieved vsync, acoustic quality, or latency.

The extracted package includes the exact manifest, fixture source and notices, input logs, evidence reports, SDL3 and ymfm notices, metadata, and member inventory. Preserve upstream notices in any copy or redistribution. The bounded smoke also checks incompatible input-log version rejection, missing/truncated cartridge handling, drop/reload, exact inventory and notice identity.

For a fresh local archive from this checkout, use:

<a id="desktop-package-smoke"></a>

```sh
cmake -DPROJECT_SOURCE_DIR="$PWD" -P tests/package/desktop_package_smoke.cmake
```

The command needs a reviewed/pinned SDL3 archive or network access for its pinned source archive, plus CMake 3.27+, C17/C++11 compilers, Python 3.8+, and Git. It builds and qualifies new bytes under `artifacts/`; it does not mutate a published release. See [desktop runner details](../../docs/desktop.md) and [fixture evidence](../../fixtures/README.md).
