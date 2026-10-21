# SDL-free API 4 SDK archive

The local SDK package is built from a committed source snapshot and qualified against its exact archive bytes. Read its adjacent `.qualification.json` receipt for the filename, source revision, checksum, inventory identity, and measured consumer results. Old snapshots may remain for historical evidence; only the current receipt-backed identity should be recommended for adoption.

It includes the original diagnostic and API 4 core, not the playable game ROM. API 4 is the public source/structure version; 0.1.0 is the package version. Recompile consumers when the pre-1.0 API changes. Input-log format version 1 is independent of both. The package is native macOS arm64, unsigned and unnotarized. It was exercised on macOS 26.6.2; no older deployment target or other OS/architecture is claimed. Checksum identity does not authenticate a publisher.

Download the complete 0.1.0 release inventory, then select the SDK archive by its inventory entry. The same commands are exercised against the published bytes during release verification:

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
