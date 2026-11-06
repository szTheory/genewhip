# Steam Deck setup: RetroArch Flatpak and ES-DE

This guide describes how to use the downloaded Linux x86_64 core with RetroArch installed from Discover as a Flatpak, directly or through an ES-DE custom system. It does not claim that either launch path has been observed on a physical Deck. ES-DE custom-system resolution and Flatpak filesystem visibility depend on the installed app versions and settings and must be checked on the target device.

## Verify the downloaded release

Download the Linux x86_64 archive and `SHA256SUMS` from the same versioned Genewhip prerelease. Before extracting or running anything, compare the archive bytes with the published checksum:

```sh
sha256sum --check SHA256SUMS
```

A matching checksum establishes byte consistency between the archive and checksum file, but it does not establish artifact origin or who produced either file. Verify the archive's GitHub build attestation separately, substituting the versioned archive filename:

```sh
gh attestation verify genewhip-linux-x86_64.tar.gz \
  --repo szTheory/genewhip \
  --signer-workflow szTheory/genewhip/.github/workflows/ci.yml \\
  --source-digest <full-source-commit-sha> \\
  --format=json
```

Replace the source SHA placeholder with the full source commit listed for that release. Review the JSON result: it must identify the expected Genewhip repository, `.github/workflows/ci.yml`, that source revision, the successful source run and attempt, and the archive subject digest described on the release page. Stop if any value differs. This verifies provenance separately from checksum byte consistency. The project does not require `gh release verify` or `gh release verify-asset`; use only commands supported by your installed GitHub CLI.

Extract the verified archive. It contains `genewhip_libretro.so` and the matching `genewhip_libretro.info`. Keep the pair from the same archive.

## Install in RetroArch

1. In Steam Deck Desktop Mode, install RetroArch from Discover. Record the RetroArch and Flatpak versions if you are collecting an observation.
2. Open RetroArch and use **Settings → Directory → Cores** and **Settings → Directory → Core Info** to see the configured writable directories. These configured values are authoritative; Flatpak locations differ from native installations and can vary by configuration.
3. Copy `genewhip_libretro.so` to the configured Cores directory and `genewhip_libretro.info` to Core Info. Restart RetroArch.
4. To launch from the interface, choose **Load Core → Genewhip**, then **Load Content** and select a user-owned `.bin` or `.gen` file.

For a direct command-line launch, replace the placeholders with the paths reported by RetroArch and a content path visible to its Flatpak sandbox. Quote each path as one shell argument:

```sh
flatpak run org.libretro.RetroArch -L "<configured-core-dir>/genewhip_libretro.so" "<accessible-content-dir>/<user-owned-game>.bin"
```

Keep the game in a directory RetroArch can already access when possible. If it cannot see the selected game, grant access only to that directory, read-only, and remove that same override when finished. Use the actual absolute directory as one argument; do not grant the whole home directory or host filesystem, and do not modify SteamOS's read-only system image:

```sh
flatpak override --user --filesystem="/path/to/selected/games:ro" org.libretro.RetroArch
flatpak override --user --nofilesystem="/path/to/selected/games" org.libretro.RetroArch
```

The second command removes only the matching user override. Inspect the path carefully before applying it. Paths with spaces should remain one quoted argument.

## Add an ES-DE custom system

The complete custom entry is [packaging/libretro/es_systems.xml](../packaging/libretro/es_systems.xml). Copy its `<system>` element into `~/ES-DE/custom_systems/es_systems.xml`, creating the directory if needed. Do not edit ES-DE's bundled system file. This adds a uniquely named Genewhip system and accepts only `.bin` and `.gen`, matching the core metadata.

The launch command uses ES-DE's documented `%EMULATOR_RETROARCH%`, `%CORE_RETROARCH%`, and `%ROM%` variables. In ES-DE's emulator settings, choose the RetroArch Flatpak installation and the `genewhip_libretro` core for this system. Confirm that its selected emulator resolves to the Flatpak app, not a separately installed native RetroArch. The XML variable contract and syntax follow ES-DE's current Linux system definitions; the actual Flatpak executable and core find-rule resolution must be checked with the installed ES-DE version on the Deck.

Ensure the game directory is visible to both ES-DE and RetroArch. If the RetroArch Flatpak cannot read it, use only the selected-directory read-only override above. Do not add a broad permission for ES-DE or RetroArch. Restart ES-DE, refresh the game list, and launch the custom Genewhip entry. A static XML check cannot prove that a particular ES-DE build resolves the Flatpak path.

## Physical observation checklist

The project has no lawful game copy to distribute. The selected route is a personally supplied lawful no-SRAM copy of **RECURSION94**; the Phase 8 authored fixture is not a substitute. If that copy is missing, unavailable, not the selected route, or cannot be lawfully used, stop: record the route as unavailable/unknown and resolve the route decision before claiming the physical acceptance requirement. Keep the game bytes, checksums/fingerprints, save data, personal account details, and local paths private.

Use the Deck evidence record template with the exact downloaded release archive and core digests, repository/source/workflow/run/attempt identity, route-map identity, device and SteamOS versions, RetroArch Flatpak and ES-DE versions, and relevant display/controller/audio conditions. Record direct RetroArch and ES-DE launch outcomes separately. For each path, record controls, visible progress, continuous audio, clean close, and relaunch as `pass`, `fail`, or `unknown`; add concise observations without private paths or content.

For the RECURSION94 route, follow the accepted source input mapping: press Start to enter the run, then use the defined Right action to advance through the route. Look for the bounded source-defined **40-field start-move marker checkpoint** documented in the route map; do not require frame-exact manual presses or infer that a manual observation reproduces the automated route. Observe continuous output, close the core cleanly, and relaunch it once through each launch path. Record unknown when the game or observation cannot establish a result. A schema validator checks the record's shape and identity fields only; it cannot establish that a human observed the device or that an outcome is true.

There has been no physical observation of the Deck and no app installation while preparing this guide. Static documentation, XML, and evidence-contract checks do not establish device behavior, the availability of a lawful game copy, or DECK-01 acceptance.

## Upstream setup references

- [RetroArch core installation](https://docs.libretro.com/guides/download-cores/) and [directory configuration](https://docs.libretro.com/guides/change-directories/)
- [RetroArch command-line guide](https://docs.libretro.com/guides/cli-intro/)
- [ES-DE installation and custom systems](https://gitlab.com/es-de/emulationstation-de/-/blob/master/INSTALL.md) and [Linux system definitions](https://gitlab.com/es-de/emulationstation-de/-/blob/master/resources/systems/linux/es_systems.xml)
- [Flatpak sandbox permissions](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
