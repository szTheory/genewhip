# SDL-free v0.2.0 SDK archive

The current v0.2.0 SDK is a local development-only qualification artifact. Public-source qualification, hosted promotion, and download adoption remain pending; the published v0.1.0 archive remains available separately. Package version 0.2.0, public API version 4, and input-log format version 1 are distinct.

<a id="v02-build-core"></a>

## Build with the SDL-free SDK

The SDK archive has no SDL dependency. This command verifies and extracts the selected local development archive, then builds its external C/C++ consumer using only the relocated package bytes. Prerequisites: a trusted checkout, the exact SDK archive/receipt/sidecar, CMake 3.27 or newer, Ninja, and C17/C++11 compilers. No network or developer cache is used.

```sh
python3 -I "$CHECKOUT/tests/package/docs_commands.py" --verify-local \
  --local-artifacts "$ARTIFACT_DIR" --archive "$SDK_ARCHIVE" --role sdk --version 0.2.0
cd "$ARTIFACT_DIR"
shasum -a 256 -c "$ARTIFACT_DIR/$SDK_ARCHIVE.sha256"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARTIFACT_DIR/$SDK_ARCHIVE" -C "$EXTRACT_DIR"
SDK_DIR="$EXTRACT_DIR/${SDK_ARCHIVE%.tar.gz}"
cmake -S "$SDK_DIR/share/genewhip/consumer" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_PREFIX_PATH="$SDK_DIR" \
  -DGW_ROM="$SDK_DIR/share/genewhip/diagnostic.bin"
cmake --build "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error
```

The optional desktop runner is a separate path. It needs the reviewed pinned SDL3 3.4.18 archive (SHA-256 `9c75cf16330322c217dedd2e0609f1124f1b54b8633e763467b4684d0f4334a3`) or network access to fetch those exact bytes. Evidence tools additionally need Python 3.11 and the declared CMake tool targets. The core-only commands above do not use that toolchain or network. For a packaged SDK consumer, the archive's external C/C++ project is under `share/genewhip/consumer`; the embed guide builds it against the exact extracted install prefix.

The local SDK package is built from a clean development-only source snapshot and qualified against its exact archive bytes. Read its adjacent `.qualification.json` receipt for the filename, source revision, checksum, inventory identity, and measured consumer results. Old snapshots may remain for historical evidence; only the current receipt-backed identity should be recommended for adoption. This receipt is not signed provenance and does not authenticate a downloaded publisher.

It includes the original diagnostic and API 4 core, not the admitted game ROMs. API 4 is the public source/structure version; 0.2.0 is this local package version. Recompile consumers when the pre-1.0 API changes. Input-log format version 1 is independent of both. The package is native macOS arm64, unsigned and unnotarized. It was exercised on macOS 26.6.2; no older deployment target or other OS/architecture is claimed. Checksum identity does not authenticate a publisher.

The following is the preserved published v0.1.0 SDK path. Download that complete release inventory and select the SDK archive by its inventory entry:

```sh
gh release download v0.1.0 --repo szTheory/genewhip --dir "$ARTIFACT_DIR"
SDK_ARCHIVE="$(python3 -c 'import json,os; d=json.load(open(os.path.join(os.environ["ARTIFACT_DIR"],"inventory.json"))); print(next(n for n in d["assets"] if "sdk-diagnostic" in n and n.endswith(".tar.gz")))')"
```

The local commands below verify and extract the exact downloaded archive.

<a id="sdk-local-verify-extract"></a>

```sh
cd "$ARTIFACT_DIR"
shasum -a 256 -c "$SDK_ARCHIVE.sha256"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARTIFACT_DIR/$SDK_ARCHIVE" -C "$EXTRACT_DIR"
```

The archive itself contains the checked `metadata.json` and complete `checksums.json`. The offline CMake consumer uses `Genewhip::core` and the public C++ header; the smoke relocates the install prefix, runs the diagnostic, and rejects API incompatibility. For a fresh local archive from the checkout, run:

<a id="sdk-package-smoke"></a>

```sh
cmake -DPROJECT_SOURCE_DIR="$PWD" -P tests/package/package_smoke.cmake
```

That build writes a new exact package under `artifacts/`; it requires a clean source identity, CMake 3.27+, C17/C++11 compilers, Python 3.8+, and Git. It does not claim two-clean-build byte reproducibility. The checked-in example and API contract are in [`tests/consumer`](../tests/consumer) and [`docs/core.md`](../docs/core.md).

The original project MIT notice and upstream ymfm/SingleStepTests notices are retained in the package. Do not strip or replace those notices. No upstream vector corpus, decoder, LGPL implementation, private ROM/save data, or local logs are included.
