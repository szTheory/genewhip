"""Independent, source-free D137 oracle. No project code is imported here."""
from decimal import Decimal, Inexact, InvalidOperation, Overflow, Rounded, localcontext

EXPECTED_SEMANTIC_ROSTERS = {
    "T": ("fixed_fullposted_reserved_current_readers", "absent_publication_all_six_consumers", "identical_repeat", "fresh_module_missing_output_recovery"),
    "M01-M58": tuple("identical_preexisting_receipt conflicting_preexisting_receipt changed_record changed_destination missing_intent corrupt_journal_schema corrupt_intent intent_digest_mismatch receipt_digest_mismatch ledger_symlink_live ledger_symlink_dangling receipt_symlink_live receipt_symlink_dangling directory_symlink_live directory_symlink_dangling root_symlink_live root_symlink_dangling lock_symlink_live lock_symlink_dangling absolute_escape traversal_escape nested_destination publication_collision_identical publication_collision_conflict lock_timeout changed_original_object missing_original_object changed_baseline_map duplicate_purpose_across_ids stale_baseline_pin stale_source_pin stale_approval_pin stale_review_pin stale_boot missing_own_observation missing_terminal_observation wrong_allocation wrong_posted_base wrong_total wrong_reserve wrong_cap hidden_unknown_tail unrecognized_settlement_policy numeric_bool numeric_nan numeric_infinity numeric_negative numeric_overflow purpose_below_threshold purpose_equal_threshold purpose_above_threshold global_below_threshold global_equal_threshold global_above_threshold known_excess funded_forecast_not_double_counted pending_liabilities_not_double_counted mixed_coordinator_flags".split()),
    "M59-M64": ("before_intent", "after_intent", "before_publication", "after_publication", "after_verification", "repeated_interrupted_recovery"),
    "M65-M92": tuple("selected_original_absent selected_original_digest_mismatch terminal_bytes_hash_mismatch terminal_outer_total_conflict terminal_wrong_purpose terminal_wrong_owner terminal_wrong_status duplicate_outer_key duplicate_terminal_key duplicate_authority_key duplicate_receipt_key component_subtotal_substitution cumulative_snapshot_sum arbitrary_latest_object incidental_member_order lossless_decimal_token numeric_binary_float precision_128_digits precision_129_digits exponent_boundary exponent_overflow decimal_text_256 decimal_text_257 exact_threshold_one_unit_below_equal_above authorized_append_then_current_view unexpected_append_transition orphan_receipt_retains_all_nine old_d133_liability_never_recycled".split()),
    "U01-U12": tuple("wrong_total double_counted_purpose hidden_unknown_tail false_receipt_success stale_source_identity forged_authority_identity component_as_fullposted cumulative_snapshots_summed terminal_identity_forged old_d133_reservation_dropped pending_capacity_freed obsolete_entry_sha_after_valid_append".split()),
}
EXPECTED_CASE_ROSTER = tuple((f"T{i:02d}", name) for i, name in enumerate(EXPECTED_SEMANTIC_ROSTERS["T"], 1)) + tuple((f"M{i:02d}", name) for i, name in enumerate(EXPECTED_SEMANTIC_ROSTERS["M01-M58"] + EXPECTED_SEMANTIC_ROSTERS["M59-M64"] + EXPECTED_SEMANTIC_ROSTERS["M65-M92"], 1)) + tuple((f"U{i:02d}", name) for i, name in enumerate(EXPECTED_SEMANTIC_ROSTERS["U01-U12"], 1))
EXPECTED_CASE_IDS = tuple(case_id for case_id, _ in EXPECTED_CASE_ROSTER)
EXPECTED_HISTORICAL_17 = {
    "D129-S": "1800", "D130-old-A": "5400", "D131-probe": "1200",
    "D132-engineering": "4200", "D132-documentary-control": "1800",
    "D133-documentary-control": "2400", "D133-settlement30-current-readers": "9000",
    "D134-documentary-control": "4800", "D134-settlement31-current-readers": "12000",
    "D135-documentary-control": "7200", "D135-inventory-control": "16200",
    "D136-postsource-po1-control": "6000", "D136-q4p-completed-fact-packet": "1800",
    "D136-qv9-completed-acquisition": "900", "D136-documentary-discuss-plan-delivery": "9000",
    "D136-inherited-tail-policy": "12000", "D136-settlement38-reviewed-current-readers": "26400",
}
EXPECTED_ALLOCATIONS = {
    # Historical 17 are preserved individually in the source-free expectation record.
    "historical_total": "122100", "d137_documentary": "9000", "d137_engineering": "33600",
    "all19_total": "164700", "ceiling": "219600", "purpose_cap": "33600",
    "forecast": "31200", "terminal_reserve": "2400", "F120_inside_terminal": "120",
    "posted_full": "45802.60140849992", "protected_process": "1794.135",
    "policy_exposure": "212296.73640849992", "policy_margin_before_new_excess": "7303.26359150008",
    "selected_D128_fullposted": "45802.60140849992", "D128_component_not_fullposted": "41434.624091166996",
}
EXPECTED_ALLOCATIONS.update(EXPECTED_HISTORICAL_17)
EXPECTED_READER_OUTPUTS = {
    "R01": {"route": "coordinator accounting preflight", "required": ("reserved-current", "fullposted=45802.60140849992", "allocations=164700")},
    "R02": {"route": "CLI remaining", "required": ("remaining=33600",)},
    "R03": {"route": "CLI global", "required": ("exposure=212296.73640849992", "ceiling=219600")},
    "R04": {"route": "CLI read-current", "required": ("fullposted=45802.60140849992",)},
    "R05": {"route": "CLI recompute-receipt", "required": ("receipt recomputation",)},
    "R06": {"route": "canonical under-lock transaction", "required": ("before-intent view", "post-store current view")},
}

def _decimal(text):
    if not isinstance(text, str) or len(text) > 256:
        raise ValueError("decimal text bound")
    with localcontext() as ctx:
        ctx.prec = 512
        for signal in (Inexact, Rounded, InvalidOperation, Overflow):
            ctx.traps[signal] = True
        value = Decimal(text)
        if not value.is_finite() or abs(value) > Decimal("1e12"):
            raise ValueError("decimal magnitude/nonfinite")
        tup = value.as_tuple()
        if len(tup.digits) > 128 or abs(tup.exponent) > 128:
            raise ValueError("decimal precision/exponent")
        return value

def check_report(report):
    """Raise AssertionError on any roster/order/route/numeric mismatch; return True otherwise."""
    ids = list(EXPECTED_CASE_IDS)
    assert report.get("case_ids") == ids, "case_ids must equal the exact ordered 108-case roster"
    cases = report.get("cases")
    assert isinstance(cases, list) and [c.get("case_id") for c in cases] == ids, "cases[].case_id roster/order mismatch"
    assert len(cases) == 108
    byid = {c["case_id"]: c for c in cases}
    allocations = report.get("allocations")
    assert isinstance(allocations, dict), "allocation map is required"
    required_allocations = set(EXPECTED_HISTORICAL_17) | {"D137-documentary-discuss-plan-check-commit-delivery", "D137-settlement43-trusted-setup-current-readers"}
    assert required_allocations <= set(allocations), "one or more of the 19 separately keyed allocations is missing"
    assert allocations["D137-documentary-discuss-plan-check-commit-delivery"] == "9000"
    assert allocations["D137-settlement43-trusted-setup-current-readers"] == "33600"
    for key, val in EXPECTED_ALLOCATIONS.items():
        if key in allocations:
            assert _decimal(allocations[key]) == _decimal(val), f"allocation mismatch: {key}"
    routes = report.get("readers")
    assert isinstance(routes, dict) and set(routes) == set(EXPECTED_READER_OUTPUTS), "six explicit actual reader routes required"
    for route, expected in EXPECTED_READER_OUTPUTS.items():
        actual = routes[route]
        stdout = actual.get("stdout", "")
        assert isinstance(stdout, str) and stdout, f"{route} missing captured stdout"
        for token in expected["required"]:
            assert token in stdout, f"{route} missing semantic stdout evidence: {token}"
        assert actual.get("exit_code") == 0, f"{route} failed"
    assert byid["T01"].get("fullposted") == EXPECTED_ALLOCATIONS["selected_D128_fullposted"]
    assert byid["M64"].get("same_intent_recoveries") == 2
    assert byid["M65"].get("fullposted") == EXPECTED_ALLOCATIONS["selected_D128_fullposted"]
    return True

class TestIndependentOracle:
    def test_roster_is_108(self):
        assert len(EXPECTED_CASE_ROSTER) == 108 and len(EXPECTED_CASE_IDS) == 108 and len(set(EXPECTED_CASE_IDS)) == 108
        assert sum(map(len, EXPECTED_SEMANTIC_ROSTERS.values())) == 108

    def test_numeric_boundaries_are_discriminating(self):
        assert _decimal("1e-12") == Decimal("1e-12")
        for bad in ("1e-129", "1e129", "1" * 129, "1" * 257, "1.1e12"):
            try: _decimal(bad)
            except (ValueError, InvalidOperation): pass
            else: raise AssertionError(f"must reject {bad[:32]}")

