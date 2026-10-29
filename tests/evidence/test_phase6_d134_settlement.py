"""Independent D134 semantic oracle contract and bootstrap RED.

This file is source-free at bootstrap. It intentionally does not import or
execute project modules. Full positive/matrix lanes are added only after the
reviewed injection interface and independent source review are admitted.
"""

TRACER_CASES = (
    "fixed_fullposted_reserved_current_readers",
    "absent_publication_all_six_consumers",
    "identical_repeat",
    "fresh_module_missing_output_recovery",
)

HISTORICAL_REJECTIONS = (
    "identical_preexisting_receipt", "conflicting_preexisting_receipt",
    "changed_record", "changed_destination", "missing_intent",
    "corrupt_journal_schema", "corrupt_intent", "intent_digest_mismatch",
    "receipt_digest_mismatch", "ledger_symlink_live", "ledger_symlink_dangling",
    "receipt_symlink_live", "receipt_symlink_dangling", "directory_symlink_live",
    "directory_symlink_dangling", "root_symlink_live", "root_symlink_dangling",
    "lock_symlink_live", "lock_symlink_dangling", "absolute_escape",
    "traversal_escape", "nested_destination", "publication_collision_identical",
    "publication_collision_conflict", "lock_timeout", "changed_original_object",
    "missing_original_object", "changed_baseline_map", "duplicate_purpose_across_ids",
    "stale_baseline_pin", "stale_source_pin", "stale_approval_pin",
    "stale_review_pin", "stale_boot", "missing_own_observation",
    "missing_terminal_observation", "wrong_allocation", "wrong_posted_base",
    "wrong_total", "wrong_reserve", "wrong_cap", "hidden_unknown_tail",
    "unrecognized_settlement_policy", "numeric_bool", "numeric_nan",
    "numeric_infinity", "numeric_negative", "numeric_overflow",
    "purpose_below_threshold", "purpose_equal_threshold", "purpose_above_threshold",
    "global_below_threshold", "global_equal_threshold", "global_above_threshold",
    "known_excess", "funded_forecast_not_double_counted",
    "pending_liabilities_not_double_counted", "mixed_coordinator_flags",
)

CHECKPOINT_CASES = (
    "before_intent", "after_intent", "before_publication",
    "after_publication", "after_verification", "repeated_interrupted_recovery",
)

FIXED_BASE_CASES = (
    "selected_original_absent", "selected_original_digest_mismatch",
    "terminal_bytes_hash_mismatch", "terminal_outer_total_conflict",
    "terminal_wrong_purpose", "terminal_wrong_owner", "terminal_wrong_status",
    "duplicate_outer_key", "duplicate_terminal_key", "duplicate_authority_key",
    "duplicate_receipt_key", "component_subtotal_substitution",
    "cumulative_snapshot_sum", "arbitrary_latest_object", "incidental_member_order",
    "lossless_decimal_token", "numeric_binary_float", "precision_128_digits",
    "precision_129_digits", "exponent_boundary", "exponent_overflow",
    "decimal_text_256", "decimal_text_257", "exact_threshold_one_unit_below_equal_above",
    "authorized_append_then_current_view", "unexpected_append_transition",
    "orphan_receipt_retains_all_nine", "old_d133_liability_never_recycled",
)

MATRIX_CASES = HISTORICAL_REJECTIONS + CHECKPOINT_CASES + FIXED_BASE_CASES

MUTATION_CASES = (
    "wrong_total", "double_counted_purpose", "hidden_unknown_tail",
    "false_receipt_success", "stale_source_identity", "forged_authority_identity",
    "component_as_fullposted", "cumulative_snapshots_summed", "terminal_identity_forged",
    "old_d133_reservation_dropped", "pending_capacity_freed",
    "obsolete_entry_sha_after_valid_append",
)

# The original 32 names are retained verbatim from the approved D133 denial
# oracle; the eight additional D134 predicates follow them.
DENIAL_PROBES = (
    "outside-open", "outside-enumeration", "unapproved-project-import",
    "process-call-entry", "unknown-fd", "dir-fd", "unknown-fd-stat",
    "unknown-fd-flock", "outside-stat", "outside-lstat", "outside-readlink",
    "outside-access", "socket-audit-only", "native-audit-only",
    "live-without-authority", "clone-live-root-confusion", "arbitrary-project-write",
    "extra-receipt", "extra-id", "unsafe-temp", "unsafe-lock", "forbidden-caller",
    "live-direct-ledger-open", "live-direct-receipt-open", "live-replace-receipt",
    "live-rename-escape", "live-unlink-ledger", "live-chmod-ledger",
    "live-nonexclusive-temp", "live-follow-temp", "live-alternate-lock",
    "live-wrong-receipt-link", "clone_has_no_live_mode",
    "d133_approval_cannot_authorize31", "outside_root_lock", "alternate31_receipt",
    "extra31_intent", "unreviewed_live_source", "stale_transition_binding",
    "unpinned_metadata_descriptor",
)

ROSTERS = {
    "tracer": TRACER_CASES,
    "matrix": MATRIX_CASES,
    "mutations": MUTATION_CASES,
    "semantic": TRACER_CASES + MATRIX_CASES + MUTATION_CASES,
    "denial_probes": DENIAL_PROBES,
}

assert len(TRACER_CASES) == 4
assert len(HISTORICAL_REJECTIONS) == 58
assert len(MATRIX_CASES) == 92
assert len(MUTATION_CASES) == 12
assert len(ROSTERS["semantic"]) == 108
assert len(DENIAL_PROBES) == 40


def require_d134_surface(namespace):
    """Mirror the guard's frozen missing-feature checks without legacy use."""
    if "make_d134_settlement_record" not in namespace:
        raise AssertionError("missing-d134-constructor")
    if "d134_current_view" not in namespace:
        raise AssertionError("missing-d134-current-view")


def run_tracer(namespace, context, workspace):
    """Bootstrap gate. RED is valid only at the intended absent D134 API."""
    # The guard installs this source-free predicate before project compilation.
    # Calling it here first prevents import/build failures from masquerading as
    # evidence of a missing semantic feature.
    context["require_d134_surface"](namespace)
    require_d134_surface(namespace)
    raise AssertionError("d134-tracer-oracle-not-yet-admitted")
