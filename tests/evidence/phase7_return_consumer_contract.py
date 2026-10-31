#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only return consumer checks. No live selector or production authority."""
from __future__ import annotations
import argparse
import contextlib
import ctypes
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
NATIVE_DENIALS = []

def deny_native(event, _args):
    if event in ("ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle"):
        NATIVE_DENIALS.append(event)
        raise PermissionError("sticky-native-denial")

sys.addaudithook(deny_native)

def native_self_test():
    try:
        ctypes.CDLL("/__gw_no_native_library__")
    except PermissionError as error:
        if str(error) != "sticky-native-denial":
            raise
    else:
        raise AssertionError("native-denial-not-reached")

native_self_test()

def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# The frozen helper installs and self-tests sticky denial before its production imports.
fixture_module = load("tests/evidence/phase7_wrapper16_contract.py", "consumer_fixtures")
denial = fixture_module.denial
coordinator = fixture_module.coordinator
PHASE = fixture_module.PHASE

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def document(fields):
    return "---\n" + "".join(f"{key}: {value}\n" for key, value in fields.items()) + "---\n"

class FixtureClock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 10, 30, 18, 2, tzinfo=datetime.timezone.utc)
        return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

class ReturnConsumers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-return-consumer-")
        self.addCleanup(self.temp.cleanup)
        self.root, self.packet_path, self.packet, self.campaign_path = fixture_module.fixture(Path(self.temp.name))
        self.patch = mock.patch.object(coordinator, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.env = mock.patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.clock = mock.patch.object(coordinator.datetime, "datetime", FixtureClock)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.packet_sha = sha(self.packet_path)
        self.campaign = json.loads(self.campaign_path.read_bytes())
        # A synthetic current admission campaign: no historical rebinding in production.
        self.campaign["admission_sha256"] = self.packet_sha
        self.campaign.pop("record_sha256")
        self.campaign["record_sha256"] = hashlib.sha256(json.dumps(self.campaign,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.campaign_path.write_text(json.dumps(self.campaign))
        self.campaign_sha = sha(self.campaign_path)
        self.live_path = self.root / "build/v02/recovery15/live.json"
        self.live = dict(status="pass", attempt_number=4, campaign_sha256=self.campaign_sha,
            packet_sha256=self.packet_sha, historical_identity_liveness="UNKNOWN",
            **{"historical_T-07-07": "OPEN/high", "requirements_qualified": []})
        self.live_path.write_text(json.dumps(self.live))
        self.common = dict(campaign_sha256=self.campaign_sha, packet_sha256=self.packet_sha,
            protocol_sha256=self.packet["protocol_sha256"], live_sha256=sha(self.live_path),
            source_pins_sha256=hashlib.sha256(json.dumps(self.packet["sources"],
                sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.security = dict(status="accepted", reviewer_role="gsd-security-auditor",
            reviewer_model="gpt-6.1-sol", author_role="gsd-executor",
            **{"source-review": "actual-live-and-return-readiness",
               "unresolved current high/critical": "0", "critical": "0", "high": "0",
               "historical identity/liveness": "UNKNOWN", "residual T-07-07": "nonblocking",
               "prospective diagnostic source eligibility": "accepted", "T-07-07": "OPEN/high"},
            **self.common)
        self.review = dict(status="accepted", reviewer_role="gsd-code-reviewer",
            reviewer_model="gpt-6-luna", author_role="gsd-executor",
            independent_security_role="gsd-security-auditor", security_model="gpt-6.1-sol",
            **{"source-review": "actual-live-and-return-readiness",
               "unresolved high/critical": "0", "critical": "0", "high": "0"}, **self.common)
        self.return_fields = dict(status="accepted", **self.common)
        self.write_reports()

    def path(self, suffix):
        return self.root / PHASE / ("07-16-" + suffix + ".md")

    def write_reports(self):
        self.path("SECURITY").write_text(document(self.security) + "Independent security disposition: ACCEPTED\n")
        self.review["security_sha256"] = sha(self.path("SECURITY"))
        self.path("RETURN-REVIEW").write_text(document(self.review) + "Independent review: ACCEPTED\n")
        self.return_fields.update(review_sha256=sha(self.path("RETURN-REVIEW")),
            security_sha256=sha(self.path("SECURITY")))
        self.path("RETURN").write_text(document(self.return_fields))

    def validate(self):
        coordinator._validate_campaign_return16(self.campaign, self.campaign_sha, self.packet, self.packet_sha)

    def argv(self, selection="16", mode="runtime"):
        args = ["--mode", mode, "--out", "build/v02/campaign15/result.json",
            "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
            "--preflight", "build/v02/campaign15/preflight.json",
            "--campaign", str(self.campaign_path), "--campaign-sha256", self.campaign_sha]
        if selection is not None:
            args += ["--recovery-selection", selection]
        return args

    def test_positive_canonical_return(self):
        self.validate()

    def test_body_acceptance_cannot_override_blocked_return(self):
        text = self.path("RETURN").read_text()
        self.path("RETURN").write_text(text.replace("status: accepted", "status: blocked") +
            "```\nstatus: accepted\n```\n")
        with self.assertRaisesRegex(ValueError, "return16-gate-rejected"):
            self.validate()

    def test_actual_blocked_reports_remain_rejected(self):
        for suffix in ("RETURN", "RETURN-REVIEW", "SECURITY"):
            self.path(suffix).write_bytes((ROOT / PHASE / ("07-16-" + suffix + ".md")).read_bytes())
        before = {p: sha(p) for p in self.root.rglob("*") if p.is_file()}
        with self.assertRaisesRegex(ValueError, "return16-gate-rejected"):
            self.validate()
        self.assertEqual(before, {p: sha(p) for p in self.root.rglob("*") if p.is_file()})

    def test_all_cli_consumers_reject_blocked16_before_effects(self):
        self.return_fields["status"] = "blocked"
        self.write_reports()
        before = {p: sha(p) for p in self.root.rglob("*") if p.is_file()}
        for mode in ("runtime", "package", "validate", "semantic-mutants", "stage-public", "retry-source", "hosted", "close"):
            with self.subTest(mode=mode), contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(coordinator.main(self.argv(mode=mode)), 1)
                self.assertIn("return16-gate-rejected", output.getvalue())
        self.assertEqual(before, {p: sha(p) for p in self.root.rglob("*") if p.is_file()})

    def test_live_scalar_and_duplicate_keys_reject(self):
        for text in ("[]", "null", "0", '{"status":"failed",' + json.dumps(self.live)[1:]):
            self.live_path.write_text(text)
            for fields in (self.return_fields, self.review, self.security):
                fields["live_sha256"] = sha(self.live_path)
            self.write_reports()
            with self.subTest(text=text[:35]), self.assertRaises(ValueError):
                self.validate()

    def test_canonical_final_security_cannot_bypass_source_admission(self):
        for key in ("prospective diagnostic source eligibility", "unresolved current high/critical",
                "packet_sha256", "protocol_sha256", "source_pins_sha256", "reviewer_role",
                "reviewer_model", "historical identity/liveness", "T-07-07"):
            original = self.security[key]
            self.security[key] = "wrong"
            self.write_reports()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "current16-admission-invalid"):
                coordinator._validate_current_admission16(self.packet, self.packet_sha)
            self.security[key] = original
        self.write_reports()
        coordinator._validate_current_admission16(self.packet, self.packet_sha)

    def test_actual_cli_selects16_through_actual_projection(self):
        for mode in ("runtime", "stage-public", "retry-source", "hosted"):
            with self.subTest(mode=mode), mock.patch.object(coordinator, "_validate_campaign_return16",
                    wraps=coordinator._validate_campaign_return16) as gate, contextlib.redirect_stderr(io.StringIO()) as output:
                # The return gate must accept before the real next validation rejects
                # our deliberately absent build/preflight. No validator is replaced.
                args = self.argv(mode=mode) + ["--publication-copy", "build/v02/campaign15/copy"]
                self.assertEqual(coordinator.main(args), 1)
                self.assertIn("No such file or directory", output.getvalue())
                self.assertEqual(gate.call_count, 1 if mode == "runtime" else 2)

    def test_unknown_selector_rejects_before_effects(self):
        with mock.patch.object(coordinator, "run_runtime") as external, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                coordinator.main(self.argv("18"))
            external.assert_not_called()

    def test17_requires_continuation_before_effects(self):
        with mock.patch.object(coordinator, "run_runtime") as external, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(coordinator.main(self.argv("17")), 1)
            external.assert_not_called()

    def test_default15_retained_and_blocked16_has_no_mutations(self):
        with mock.patch.object(coordinator, "run_runtime") as external, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(coordinator.main(self.argv(None)), 1)
            self.return_fields["status"] = "blocked"
            self.write_reports()
            before = {p.relative_to(self.root): sha(p) for p in self.root.rglob("*") if p.is_file()}
            self.assertEqual(coordinator.main(self.argv()), 1)
            self.assertEqual(before, {p.relative_to(self.root): sha(p) for p in self.root.rglob("*") if p.is_file()})
            external.assert_not_called()

    def test_semantic_mutants_reject_even_with_recomputed_outer_hashes(self):
        for report in ("return", "review", "security"):
            fields = getattr(self, report + ("_fields" if report == "return" else ""))
            for key in list(fields):
                original = fields[key]
                fields[key] = "wrong"
                suffix = {"return": "RETURN", "review": "RETURN-REVIEW", "security": "SECURITY"}[report]
                self.path(suffix).write_text(document(fields))
                if report == "security":
                    self.review["security_sha256"] = sha(self.path("SECURITY"))
                    self.path("RETURN-REVIEW").write_text(document(self.review))
                if report != "return":
                    self.return_fields.update(review_sha256=sha(self.path("RETURN-REVIEW")),
                        security_sha256=sha(self.path("SECURITY")))
                    self.path("RETURN").write_text(document(self.return_fields))
                with self.subTest(report=report, key=key), self.assertRaises(ValueError):
                    self.validate()
                fields[key] = original
                self.write_reports()
            self.write_reports()

    def test_malformed_duplicate_scalar_fenced_metadata_rejects(self):
        for suffix in ("RETURN", "RETURN-REVIEW", "SECURITY"):
            original = self.path(suffix).read_text()
            for mutant in (original.replace("---\n", "---\nstatus: accepted\n", 1),
                    original.replace("---\n", "---\nstatus: blocked\n", 1),
                    original.replace("---\n", "---\nunknown: accepted\n", 1),
                    original.replace("status: accepted\n", ""),
                    "```\n" + original + "```\n", original.removeprefix("---\n"),
                    original.replace("status: accepted", "status: 'accepted'"),
                    original.replace("status: accepted", "status: [accepted]"),
                    original.replace("status: accepted", " status: accepted")):
                self.path(suffix).write_text(mutant)
                with self.subTest(report=suffix, mutant=mutant[:70]), self.assertRaises(ValueError):
                    self.validate()
            self.path(suffix).write_text(original)

    def test_attempt_and_count_boundary_neighbors_reject(self):
        for attempt in (3, 5, 4.0, True, "4"):
            self.live["attempt_number"] = attempt
            self.live_path.write_text(json.dumps(self.live))
            for fields in (self.return_fields, self.review, self.security):
                fields["live_sha256"] = sha(self.live_path)
            self.write_reports()
            with self.subTest(attempt=attempt), self.assertRaises(ValueError):
                self.validate()
        self.live["attempt_number"] = 4
        self.live_path.write_text(json.dumps(self.live))
        for fields in (self.return_fields, self.review, self.security):
            fields["live_sha256"] = sha(self.live_path)
        for fields in (self.review, self.security):
            for count in ("-1", "1", "00"):
                fields["high"] = count
                self.write_reports()
                with self.subTest(count=count), self.assertRaises(ValueError):
                    self.validate()
            fields["high"] = "0"

    def test_live_mutants_reject_after_digest_rebinding(self):
        for key in self.live:
            original = self.live[key]
            self.live[key] = "wrong"
            self.live_path.write_text(json.dumps(self.live))
            self.common["live_sha256"] = sha(self.live_path)
            for fields in (self.return_fields, self.review, self.security):
                fields["live_sha256"] = self.common["live_sha256"]
            self.write_reports()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate()
            self.live[key] = original

    def test_journal_helpers_propagate16_before_external_work(self):
        journal = self.root / "build/v02/campaign15/hosted-delivery-journal.json"
        for function in (coordinator.retry_sanitized_source, coordinator.publish_sanitized_source):
            with mock.patch.object(coordinator, "_valid_packet_for_delivery",
                    wraps=coordinator._valid_packet_for_delivery) as external:
                with self.assertRaises(FileNotFoundError):
                    function(self.root / "packet", self.root / "copy", journal,
                        campaign_path=self.campaign_path, campaign_sha256=self.campaign_sha,
                        recovery_selection="16")
                external.assert_called_once()
                self.return_fields["status"] = "blocked"
                self.write_reports()
                external.reset_mock()
                with self.assertRaisesRegex(ValueError, "return16-gate-rejected"):
                    function(self.root / "packet", self.root / "copy", journal,
                        campaign_path=self.campaign_path, campaign_sha256=self.campaign_sha,
                        recovery_selection="16")
                external.assert_not_called()
                self.return_fields["status"] = "accepted"
                self.write_reports()

    def test_unknown_api_selection_and_noncampaign16_reject(self):
        for selection, journal in (("17", self.root / "build/v02/campaign15/hosted-delivery-journal.json"),
                ("16", self.root / "build/v02/hosted-delivery-journal.json")):
            with self.subTest(selection=selection), mock.patch.object(coordinator, "_valid_packet_for_delivery",
                    wraps=coordinator._valid_packet_for_delivery) as external:
                with self.assertRaises(ValueError):
                    coordinator.retry_sanitized_source(self.root / "packet", self.root / "copy", journal,
                        campaign_path=self.campaign_path, campaign_sha256=self.campaign_sha,
                        recovery_selection=selection)
                external.assert_not_called()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--return-check", action="store_true", required=True)
    parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReturnConsumers))
    denial.self_test("after-mock-restoration")
    native_self_test()
    receipt = denial.receipt()
    receipt["native_self_test_denials"] = len(NATIVE_DENIALS)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if result.wasSuccessful() and receipt["unexpected_denials"] == 0 and len(NATIVE_DENIALS) == 2 else 1

if __name__ == "__main__":
    raise SystemExit(main())
