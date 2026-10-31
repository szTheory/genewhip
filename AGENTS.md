# Genewhip agent guide

Start with `.planning/STATE.md`, then the current phase in `.planning/ROADMAP.md`. The accepted scope is `.planning/PROJECT.md` and `.planning/REQUIREMENTS.md`. Read [.planning/context/OPERATING.md](.planning/context/OPERATING.md) for persistent workflow/delivery rules and [.planning/research/README.md](.planning/research/README.md) for focused research retrieval.

**Stop after every phase and milestone.** Both auto-advance flags stay false. Routine decisions, automated verification and ordinary green-check PR merge/release are authorized within the active phase. These do not authorize starting the next phase. Use the tiered Claude model profile in `.planning/config.json`. Verification is automation-first with a zero-human-UAT goal: plan every check as an automated test or CI lane and hand off only named human-only items (see OPERATING.md § Automation-first verification).

**Current maturity:** Phase 1 is verified with a tested C17 diagnostic core, an exercised local macOS arm64 SDK archive, and one independently authored fixture admitted for its bounded MAME route/runtime scenario. Genewhip-core game compatibility, broader compatibility, performance, hosted CI, and a published release remain unproven. Preserve upstream notices and source provenance; avoid personal paths, secrets and private ROM/save data in public artifacts. Local tooling secrets use ignored `.env.local`; CI uses GitHub secrets. The core requires neither.

<!-- GSD:project-start source:PROJECT.md -->

## Project

**Genewhip**

Genewhip is a portable Sega Genesis / Mega Drive emulator written in C. It is a reusable core for emulator frontends, including eventual Playstead integration, with a small desktop runner so people can play and evaluate it independently on macOS. Its development prioritizes documented hardware behavior, deterministic execution, efficient operation, readable code, and repeatable evidence of correctness.

**Core Value:** Run Genesis / Mega Drive software faithfully and efficiently through a small, dependable C interface that frontend developers can trust.

### Constraints

- **Phase boundaries:** Stop after every phase. Never automatically start the next phase or milestone. Automation within an explicitly started phase is encouraged; phase stops are review/model-switch opportunities, not mandatory manual UAT.
- **Language:** C for the core. Select a conservative portable standard and document integer, endian, alignment, memory, and threading assumptions.
- **Timing:** Emulated time must be independent of host clocks, display refresh, threads, and filesystem behavior.
- **Evidence:** Compatibility and performance claims require identified fixtures, versions, inputs, settings, denominators, and reproducible results. Unknown and skipped outcomes must remain visible.
- **Delivery:** Prefer short PRs, green main, reproducible release artifacts and automatic merge/release when required checks pass. New repository publication and remote infrastructure belong to an implementation phase.
- **Privacy:** Public files must omit personal names, emails, absolute home paths, secrets, private dumps, and unrelated project data. Describe local source provenance with project name, relative path, and revision only.
- **Secrets:** Local tooling may use ignored `.env.local`; CI credentials use GitHub secrets. The emulator core requires no credentials and never reads environment configuration implicitly.
- **Verification:** Automate unit, seam, integration, packaging, and smoke evidence whenever useful. Reserve human checks for physical-device or subjective observations that automation cannot establish.
- **Simplicity:** One coherent hardware model first; measurable improvements justify optional fast paths. Avoid redundant abstraction layers, speculative frameworks, and low-value gates.
- **Models:** GSD runs on the Codex runtime with the `adaptive` profile; tiers map opus/sonnet/haiku to `gpt-6.1-sol`/`gpt-6-luna`/`gpt-6-luna` via `model_profile_overrides.codex` in `.planning/config.json`. Change models there, not per session.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md; condensed at initialization -->

## Technology stack

- Original C17 core, explicit integer/endian rules, no compiler extensions in the portable path.
- CMake 3.24+ for core-only builds; evidence tools require 3.27+ with single-config Make or Ninja. Offline core build/install without SDL; CTest for verification.
- Separate SDL3 desktop runner; pin reviewed dependencies during implementation.
- Small C tests, sanitizer lanes and bounded fuzz/property checks at meaningful seams.
- MIT for original work; exact component/fixture license and source records before admission.
- Toolchain, OS and architecture support require actual build/execution evidence.

See [.planning/research/STACK.md](.planning/research/STACK.md); source recommendations remain distinct from tested support.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Use plain C modules with explicit ownership, bounded work and cohesive hardware concepts. Avoid hidden mutable globals, undefined arithmetic, raw-struct serialization and speculative frameworks. Behavior changes update tests, public contracts, examples and limitations together. Detailed code conventions are established in Phase 1.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

The instance-owned CPU subset, ROM/RAM bus and integer master-tick model are implemented; current contracts and limitations are in [docs/core.md](docs/core.md). Future device work follows [.planning/research/ARCHITECTURE.md](.planning/research/ARCHITECTURE.md), refined by [the accepted synthesis](.planning/research/SUMMARY.md). Deterministic chip-to-PCM conversion may live in a core output module; device drift correction and display pacing belong to the host. Inventory future-affecting state as each device is added.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `$gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `$gsd-debug` for investigation and bug fixing
- `$gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `$gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
