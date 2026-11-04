#!/usr/bin/env python3
"""Pure contracts for the externally anchored, portable runtime identity seam."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ROUTE_PATH = ROOT / "scripts/evidence/phase6_routes.py"


def load_routes(name):
    spec = importlib.util.spec_from_file_location(name, ROUTE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PortableRuntimeIdentityContract(unittest.TestCase):
    def setUp(self):
        self.routes = load_routes("gw_portable_runtime_contract_primary")
        self.routes_alias = load_routes("gw_portable_runtime_contract_alias")
        self.candidate = {
            "schema": "genewhip-phase6-candidate-v1",
            "source_files": {"src/core.c": "1" * 64},
            "client_identities": {"public-core": {
                "path": "build/v02/runtime-build/tools/session/gw_headless",
                "sha256": "2" * 64}},
            "build_identity": {"cmake_cache_sha256": "3" * 64},
        }
        candidate_sha = self.routes.canonical_digest(self.candidate)
        self.subject = {
            "source_sha256": "4" * 64,
            "git_head": "5" * 40,
            "base_sha": "6" * 40,
            "run_id": "41735435251",
            "run_attempt": "1",
            "candidate_sha256": candidate_sha,
        }
        self.scope_sha256 = "7" * 64
        self.identity = {
            "schema": "genewhip-v02-runtime-identity-v1",
            **self.subject,
            "scope_sha256": self.scope_sha256,
            "build_identity": {
                "cmake_cache_sha256": "3" * 64,
                "configuration_sha256": "8" * 64,
                "headless_sha256": "2" * 64,
                "desktop_sha256": "9" * 64,
            },
        }
        self.raw = (json.dumps(self.identity, sort_keys=True, indent=2) + "\n").encode()
        self.expected_sha256 = hashlib.sha256(self.raw).hexdigest()
        self.context = self.routes.trusted_runtime_identity_from_bytes(self.raw,
            expected_sha256=self.expected_sha256, expected_subject=self.subject,
            expected_scope_sha256=self.scope_sha256)

    def test_context_rebinds_across_independently_loaded_route_modules(self):
        self.assertEqual(self.routes_alias._trusted_runtime_identity(self.context), self.identity)
        self.assertEqual(self.routes._validate_trusted_candidate(self.candidate, self.context), self.identity)
        self.routes._validate_trusted_candidate_digest(self.candidate, self.identity)

    def test_external_hash_subject_scope_and_identity_shape_are_mandatory(self):
        with self.assertRaisesRegex(self.routes.Invalid, "runtime-identity-context-invalid"):
            self.routes.trusted_runtime_identity_from_bytes(self.raw,
                expected_sha256="0" * 64, expected_subject=self.subject,
                expected_scope_sha256=self.scope_sha256)
        wrong_subject = dict(self.subject, git_head="a" * 40)
        with self.assertRaisesRegex(self.routes.Invalid, "runtime-identity-context-invalid"):
            self.routes.trusted_runtime_identity_from_bytes(self.raw,
                expected_sha256=self.expected_sha256, expected_subject=wrong_subject,
                expected_scope_sha256=self.scope_sha256)
        with self.assertRaisesRegex(self.routes.Invalid, "runtime-identity-context-invalid"):
            self.routes.trusted_runtime_identity_from_bytes(self.raw,
                expected_sha256=self.expected_sha256, expected_subject=self.subject,
                expected_scope_sha256="a" * 64)
        extra_subject = dict(self.subject, arbitrary_sha256="b" * 64)
        with self.assertRaisesRegex(self.routes.Invalid, "runtime-identity-context-invalid"):
            self.routes.trusted_runtime_identity_from_bytes(self.raw,
                expected_sha256=self.expected_sha256, expected_subject=extra_subject,
                expected_scope_sha256=self.scope_sha256)
        for changed in (
                {**self.identity, "unexpected": True},
                {**self.identity, "build_identity": {**self.identity["build_identity"],
                    "headless_sha256": "invalid"}},
                {**self.identity, "scope_sha256": "a" * 64}):
            raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    self.routes.Invalid, "runtime-identity-context-invalid"):
                self.routes.trusted_runtime_identity_from_bytes(raw,
                    expected_sha256=hashlib.sha256(raw).hexdigest(), expected_subject=self.subject,
                    expected_scope_sha256=self.scope_sha256)
        for wrong_context in (None, {"sha256": self.expected_sha256}, list(self.context),
                              ("wrong-version",) + self.context[1:]):
            with self.subTest(wrong_context=type(wrong_context).__name__), self.assertRaisesRegex(
                    self.routes.Invalid, "runtime-identity-context-invalid"):
                self.routes._trusted_runtime_identity(wrong_context)

    def test_candidate_client_cache_and_recomputed_candidate_mutants_stay_rejected(self):
        changed_client = json.loads(json.dumps(self.candidate))
        changed_client["client_identities"]["public-core"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(self.routes.Invalid, "product-stale-client"):
            self.routes._validate_trusted_candidate(changed_client, self.context)
        changed_path = json.loads(json.dumps(self.candidate))
        changed_path["client_identities"]["public-core"]["path"] = "build/v02/runtime-build/elsewhere"
        with self.assertRaisesRegex(self.routes.Invalid, "product-stale-client"):
            self.routes._validate_trusted_candidate(changed_path, self.context)
        changed_cache = json.loads(json.dumps(self.candidate))
        changed_cache["build_identity"]["cmake_cache_sha256"] = "a" * 64
        with self.assertRaisesRegex(self.routes.Invalid, "product-stale-build"):
            self.routes._validate_trusted_candidate(changed_cache, self.context)

        # Even when an altered candidate and its report link are rehashed
        # consistently, the immutable external identity still names the
        # original candidate bytes.
        changed_source = json.loads(json.dumps(self.candidate))
        changed_source["source_files"]["src/core.c"] = "a" * 64
        report = {"candidate_sha256": self.routes.canonical_digest(changed_source)}
        self.assertEqual(report["candidate_sha256"], self.routes.canonical_digest(changed_source))
        with self.assertRaisesRegex(self.routes.Invalid, "product-candidate"):
            self.routes._validate_trusted_candidate_digest(changed_source, self.identity)

    def test_default_validator_path_still_requires_private_binary_bytes(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-identity-strict-", dir=ROOT) as temp:
            temporary = pathlib.Path(temp)
            missing_client = temporary / "missing-gw-headless"
            relative_client = missing_client.relative_to(ROOT).as_posix()
            candidate = {
                "source_files": {},
                "client_identities": {"public-core": {
                    "path": relative_client, "sha256": "a" * 64}},
                "build_identity": {"cmake_cache_sha256": "b" * 64},
            }
            candidate_bytes = (json.dumps(candidate, sort_keys=True) + "\n").encode()
            candidate_path = temporary / "candidate.json"
            candidate_path.write_bytes(candidate_bytes)
            report = {
                "schema": "genewhip-phase6-product-report-v1",
                "candidate_sha256": self.routes.canonical_digest(candidate),
                "candidate_manifest": {"path": candidate_path.relative_to(ROOT).as_posix(),
                    "sha256": hashlib.sha256(candidate_bytes).hexdigest()},
            }
            with self.assertRaisesRegex(self.routes.Invalid, "product-stale-client"):
                self.routes.validate_product_report(report, candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
