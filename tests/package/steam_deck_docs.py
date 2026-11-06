#!/usr/bin/env python3
"""Portable contracts for the Steam Deck setup instructions and ES-DE XML."""

from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/steam-deck.md"
XML = ROOT / "packaging/libretro/es_systems.xml"


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    doc = DOC.read_text(encoding="utf-8")
    libretro_doc = (ROOT / "docs/libretro.md").read_text(encoding="utf-8")
    tree = ET.parse(XML)
    system = tree.getroot().find("system")
    check(system is not None, "custom system is missing")
    check(system.findtext("name") == "genewhip", "system name must be unique and stable")
    check(system.findtext("extension") == ".bin .BIN .gen .GEN", "extensions must match the core info")
    command = system.findtext("command") or ""
    check(command == "%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/genewhip_libretro.so %ROM%",
          "command must use supported ES-DE variables and the configured core lookup")
    check("%ROMPATH%" in (system.findtext("path") or ""), "system path must use ES-DE's ROMPATH variable")
    check("steam-deck.md" in libretro_doc, "libretro documentation must link to Steam Deck setup")
    for phrase in ("Settings → Directory → Cores", "Settings → Directory → Core Info",
                   "sha256sum --check", "gh attestation verify", "byte consistency",
                   "origin", "custom_systems", "flatpak run org.libretro.RetroArch -L",
                   "--filesystem=", "--nofilesystem=", "RECURSION94", "no-SRAM",
                   "controls", "progress", "audio", "unknown", "no physical observation"):
        check(phrase.lower() in doc.lower(), f"missing required setup/privacy/evidence text: {phrase}")
    check(not re.search(r"(?:/Users/|/home/[A-Za-z0-9_-]+/|/Users/[A-Za-z0-9_-]+/)", doc),
          "documentation must not contain personal absolute paths")
    check("--filesystem=host" not in doc and "--filesystem=home" not in doc,
          "documentation must not recommend broad filesystem access")

    # Ensure direct-launch arguments survive shell tokenization with paths that
    # include whitespace, metacharacters, and Unicode, without launching apps.
    core = "/configured cores/Genewhip & β/genewhip_libretro.so"
    content = "/accessible games/Zoë (test) & demo.bin"
    command_line = "flatpak run org.libretro.RetroArch -L " + shlex.quote(core) + " " + shlex.quote(content)
    args = shlex.split(command_line)
    check(args == ["flatpak", "run", "org.libretro.RetroArch", "-L", core, content],
          "quoted direct-launch arguments must preserve unusual path characters")
    print("Steam Deck docs and ES-DE XML contracts passed")


if __name__ == "__main__":
    main()
