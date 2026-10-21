# Genewhip audio-capable diagnostic desktop preview

This unsigned, unnotarized archive is a macOS arm64 diagnostic preview, version
0.1.0 and C API 4. It runs the original Genewhip raster toy and its scripted
PSG, FM and DAC inputs. The core has deterministic PCM and the runner exposes
host audio counters. This is not a game-compatible release: no game audio
compatibility or performance claim is made. macOS arm64 is the only exercised
platform.

FM is the attributed BSD-3-Clause ymfm port. The Phase 3 report records known
model comparison deviations: 54,925 of 54,991 FM samples and 87 of 239 DAC
samples differ from an alternate reference model; 22 FM and 34 DAC status
readings also differ. These comparisons do not establish hardware truth. Exact
VA3 FM reset wiring remains uncertain; the adopted reset behavior is a model
choice. The report keeps unsupported, skipped and unknown evidence outcomes
visible.

## Contents

| Path | What |
|---|---|
| `bin/genewhip-desktop` | SDL3 3.4.18 static runner with audio enabled |
| `bin/gw_headless` | SDL-free replay client |
| `share/genewhip/raster-toy.bin` | Original 32 KiB Genewhip diagnostic cartridge |
| `share/genewhip/raster-toy-demo.log` | Scripted A/B/C PSG/FM/DAC input schedule |
| `share/genewhip/phase3-evidence.json` | Versioned Phase 3 evidence for this source revision |
| `share/genewhip/LICENSE`, `SDL3-LICENSE.txt`, `THIRD-PARTY-ymfm.txt`, `raster-toy-NOTICES.md` | MIT, SDL3 zlib, ymfm BSD-3-Clause and fixture provenance/notices |
| `metadata.json`, `checksums.json` | Source revision, toolchain, archive label and per-file SHA-256 inventory |

## Verify and run

Check the supplied `.sha256` sidecar, extract the archive, then run:

```sh
bin/genewhip-desktop share/genewhip/raster-toy.bin
```

Press A, B and C to trigger the toy's PSG, FM and DAC voices. M toggles mute,
P or Space pauses/resumes, and R resets. The process exit line reports audio
and buffering counters. The exact archive smoke replays the bundled log for
240 fields under SDL dummy drivers, verifies `audio=on`, checks
`produced_frames = consumed_frames + queued_frames + dropped_frames` and
`core_lost=0`, and compares every field hash with `gw_headless` replaying the
same log. It also validates the archive checksum and inventory, detects a
named tamper, and repeats execution after relocating the extracted directory.

The archive is unsigned and unnotarized. A checksum identifies bytes but does
not authenticate their origin. No signed, notarized, multi-architecture or
published release is claimed.

## Human-only observations for phase closeout

Automation establishes deterministic activity and counter integrity. It cannot
establish these two physical-output observations:

1. On a physical macOS audio device, assess the subjective quality of the toy's
   PSG, FM and DAC sounds.
2. Listen for any audible pop or click during at least 60 seconds of A/B/C
   presses, including mute, pause/resume and reset transitions.

These are perceptual checks requiring a listener and physical output. Structural
underrun accounting is already automated. They do not establish game audio
compatibility.
