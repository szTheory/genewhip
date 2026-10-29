# Playable v0.2.0 desktop preview

The local v0.2.0 archive is development-only. It is not a published release; public-source, hosted promotion, and external download-adoption evidence remain pending. Published v0.1.0 assets are separate and immutable.

<a id="v02-play"></a>

## Play from an exact archive

Use the SDK/desktop archive names, SHA-256 values, and receipt from one current inventory. Before running any bundled verifier or executable from a downloaded archive, verify the trusted provenance and subject digest for that exact archive against its expected source, workflow, ref, run, attempt, and inventory. The verifier may come from the authenticated archive. Do not treat a self-hash, checksum sidecar, or source checkout download as trusted provenance. For a local development archive, use the trusted checkout's package consumer instead.

Prerequisites: macOS arm64, `shasum`, `tar`, and a current reviewed desktop archive plus its exact receipt/inventory. The v0.2 desktop package ran on macOS 26.6.2 arm64; its deployment target is not evidence for earlier OS support. It is unsigned and unnotarized. If Gatekeeper blocks an archive you have independently verified and trust, try opening the app once, then use **System Settings → Privacy & Security → Open Anyway** for that app and confirm. This creates an app-specific exception; never disable Gatekeeper globally. See [Apple's current steps](https://support.apple.com/en-us/102445).

For a local development snapshot, `CHECKOUT` names this trusted checkout and `ARTIFACT_DIR`, `DESKTOP_ARCHIVE`, and `EXTRACT_DIR` name the exact staged package inputs and a fresh scratch destination. The trusted checkout checks its receipt and archive digest before extraction or execution:

```sh
python3 -I "$CHECKOUT/tests/package/docs_commands.py" --verify-local \
  --local-artifacts "$ARTIFACT_DIR" --archive "$DESKTOP_ARCHIVE" --role desktop --version 0.2.0
cd "$ARTIFACT_DIR"
shasum -a 256 -c "$ARTIFACT_DIR/$DESKTOP_ARCHIVE.sha256"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARTIFACT_DIR/$DESKTOP_ARCHIVE" -C "$EXTRACT_DIR"
PACKAGE_DIR="$EXTRACT_DIR/${DESKTOP_ARCHIVE%.tar.gz}"
"$PACKAGE_DIR/bin/genewhip-desktop" --fields 120 \
  "$PACKAGE_DIR/share/genewhip/tank-battle.bin"
```

The published-download path remains pending. Before running any bundled tool there, verify signed provenance and the archive subject digest with the trusted publisher flow; a separate source download is not needed. The verifier may come from the authenticated archive only after those checks.

The published v0.1.0 desktop package is built from a committed source snapshot and qualified against its exact archive bytes. Read its adjacent `.qualification.json` receipt for the filename, source revision, checksum, inventory identity, and measured scenario results. Old snapshots may remain for historical evidence; only the current receipt-backed identity should be recommended for adoption.

Keyboard: arrows move; Z is A, X is B, C is C, and Return is Start. On a gamepad, use the D-pad, west face button for A, south for B, east for C, and Start. P or Space pauses/resumes, R requests a console reset, M toggles mute, and Escape exits. Dragging a ROM onto the window loads it; a rejected drop keeps the current session. If audio startup fails, video continues and `audio=off` is reported; that fallback does not qualify an audio route.

The package version is 0.1.0 and the core API is version 4. The corrected MIT game v2 is admitted for its bounded MAME reference contract and separately exercised by Genewhip over six frozen cases and a 720-field sustained scenario. This does not establish general game compatibility or hardware accuracy. The raster toy provides PSG/FM/DAC diagnostics, not commercial-game audio compatibility. FM comparator deviations and exact VA3 reset wiring remain documented unknowns.

The package was exercised on macOS 26.6.2 arm64. Its build deployment target was not explicitly set, so the tested OS does not establish a minimum supported macOS version. It is unsigned and unnotarized. The checksum identifies bytes, not publisher identity.

For the preserved published v0.1.0 desktop, download its complete release inventory and select the archive by its inventory entry:

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
