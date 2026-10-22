#!/usr/bin/env python3
"""Focused malformed-state checks for the pinned Z80 vector adapter."""
import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("run_z80_vectors", ROOT / "run_z80_vectors.py")
vectors = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vectors)


class StateValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((ROOT / "selected.json").read_text())[0]["test"]["initial"]

    def test_pinned_record_and_width_boundaries_are_accepted(self):
        vectors.validate_state(self.record, "pinned initial")
        boundary = copy.deepcopy(self.record)
        for key, width in vectors.STATE_WIDTHS.items():
            boundary[key] = (1 << width) - 1
        boundary.update(ei=1, iff1=1, iff2=1, im=2, p=1)
        vectors.pack_state(boundary)

    def test_out_of_range_registers_are_rejected(self):
        for key, invalid in (("a", 256), ("pc", 65536), ("r", 256)):
            with self.subTest(key=key):
                state = copy.deepcopy(self.record)
                state[key] = invalid
                with self.assertRaisesRegex(ValueError, key):
                    vectors.pack_state(state)

    def test_bool_and_invalid_control_domains_are_rejected(self):
        for key, invalid in (("a", True), ("p", 2), ("ei", -1),
                             ("iff1", 2), ("im", 3)):
            with self.subTest(key=key):
                state = copy.deepcopy(self.record)
                state[key] = invalid
                with self.assertRaisesRegex(ValueError, key):
                    vectors.pack_state(state)

    def test_missing_and_extra_fields_are_rejected(self):
        for mutate, expected in ((lambda state: state.pop("a"), "missing a"),
                                 (lambda state: state.update(extra=0), "unexpected extra")):
            state = copy.deepcopy(self.record)
            mutate(state)
            with self.assertRaisesRegex(ValueError, expected):
                vectors.pack_state(state)


if __name__ == "__main__":
    unittest.main()
