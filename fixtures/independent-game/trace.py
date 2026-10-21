#!/usr/bin/env python3
"""Bounded parser for the exact patched MAME Genesis bus trace."""
from __future__ import annotations

import hashlib
import re

TRACE = re.compile(r"^(?:\[:[^\]]*\]\s*)?GWTRACE,(\d+),(AS_PROGRAM|AS_CPU_SPACE),([RW]),([0-9A-F]{6}),16,([0-9A-F]{4}),([0-9A-F]{4}),([0-9A-F]{6})$")


def parse(raw: bytes, max_bytes: int, max_rows: int) -> list[dict]:
    if len(raw) > max_bytes:
        raise ValueError(f"trace exceeds byte bound: {len(raw)} > {max_bytes}")
    text = raw.decode("utf-8", errors="strict")
    rows = []
    for line in text.splitlines():
        if "GWTRACE," not in line:
            continue
        if len(rows) >= max_rows:
            raise ValueError(f"trace exceeds row bound: {max_rows}")
        match = TRACE.fullmatch(line)
        if not match:
            raise ValueError(f"malformed trace record at row {len(rows) + 1}")
        sequence, space, operation, address, value, mask, pc = match.groups()
        rows.append({"sequence": int(sequence), "space": space, "operation": operation,
                     "address": int(address, 16), "width_bits": 16,
                     "value": int(value, 16), "mem_mask": int(mask, 16),
                     "pc": int(pc, 16)})
    if not rows:
        raise ValueError("trace contains no GWTRACE bus records")
    sequences = [row["sequence"] for row in rows]
    if sequences != list(range(sequences[0], sequences[0] + len(sequences))):
        raise ValueError("trace sequence is unordered, duplicated, or contains a gap")
    return rows


def trace_summary(raw: bytes, rows: list[dict]) -> dict:
    counts = {}
    for row in rows:
        key = f"{row['space']}:{row['operation']}"
        counts[key] = counts.get(key, 0) + 1
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "rows": len(rows), "first_sequence": rows[0]["sequence"],
            "last_sequence": rows[-1]["sequence"], "counts": counts,
            "address_min": min(row["address"] for row in rows),
            "address_max": max(row["address"] for row in rows)}
