# Independent game fixture notices

`src/game.s` is solely authored for Genewhip under the repository MIT license
(`../../LICENSE`). The game logic, vectors, generated tile patterns, ROM bytes
and gameplay sound sequence are original. No third-party game source, sound,
graphics, font or other bundled assets are included. The successor is separately
versioned from v1; v1 source, ROM, scenario and historical evidence are retained.
No bundled assets are present.

The ROM was built with the signed-source, source-built GNU Binutils 2.47
M68K assembler identified by `toolchain.lock`. The assembler and its source are
not bundled. Upstream GNU licensing notices and tool provenance are enumerated
in that lock. The generated ROM contains no SRAM claim and targets the declared
VA3 NTSC-U, linear-cartridge, three-button profile.

**Status: admitted.** The retained record in
[`evidence/independent-game-v2.json`](../../evidence/independent-game-v2.json)
binds the source and 16 KiB ROM hashes above, six passing reference cases, and
six passing production-consumer cases. Its SHA-256 is
`50365004d85f95cf15e2dc10bb7887d2f77231c23996b3c996986687e0c08d95`.
The current manifest and read-only admission verifier preserve those identities.
The separate v1 fixture and its admission history are unchanged.

This admission supports the bounded source-defined route only. It does not
establish whole-game compatibility or hardware behavior outside the recorded
profile and cases.
