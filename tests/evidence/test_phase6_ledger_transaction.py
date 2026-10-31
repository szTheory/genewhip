"""D132 semantic caller. Loaded only by the independently reviewed clone guard.

Assertions inspect persisted bytes independently of producer return labels.
"""
import hashlib
import json
import fcntl
import os
import time


TRACER_CASES = ("absent_publication", "identical_repeat", "missing_output_recovery")
CHECKPOINTS = ("before_intent", "after_intent", "before_publication",
               "after_publication", "after_verification")
NEGATIVE_CASES = ("wrong_receipt_reported_success", "duplicate_transaction_on_reload",
                  "missing_intent_despite_publication")
REJECTION_CASES = (
    "identical_preexisting_receipt", "conflicting_preexisting_receipt",
    "changed_record", "changed_destination", "missing_intent",
    "corrupt_journal_schema", "corrupt_intent", "intent_digest_mismatch",
    "receipt_digest_mismatch", "ledger_symlink_live", "ledger_symlink_dangling",
    "receipt_symlink_live", "receipt_symlink_dangling", "directory_symlink_live",
    "directory_symlink_dangling", "root_symlink_live", "root_symlink_dangling",
    "absolute_escape", "traversal_escape", "nested_destination", "alias_root",
    "id_empty", "id_41", "id_non_ascii", "id_wrong_type", "id_40_valid",
    "record_nonfinite", "record_wrong_type", "record_wrong_kind",
    "record_nonstring_key", "record_oversize", "record_65536_valid",
    "lock_timeout", "changed_original_object", "missing_original_object",
    "changed_baseline_map", "publication_collision_identical",
    "publication_collision_conflict")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def expected_receipt_bytes(transaction_id, receipt_name, record, expected):
    semantic = {"schema": "ledger-transaction-intent-v1", "transaction_id": transaction_id,
                "receipt_path": receipt_name, "record": record, "expected_objects": expected}
    payload = {"schema": "ledger-transaction-receipt-v1", "transaction_id": transaction_id,
               "receipt_path": receipt_name, "record": record,
               "intent_sha256": hashlib.sha256(canonical(semantic)).hexdigest()}
    return (json.dumps(payload, indent=2, sort_keys=False, allow_nan=False) + "\n").encode("utf-8")


def require(condition, name):
    if not condition:
        raise AssertionError(name)


def original_objects(value, expected):
    require(set(value) == set(expected) | {"ledger_transactions_v1"},
            "original-object-roster")
    for key, digest in expected.items():
        require(hashlib.sha256(canonical(value[key])).hexdigest() == digest,
                "original-object-unchanged:" + key)


def persisted_oracle(ledger, receipt, expected, transaction_id, record):
    value = json.loads(ledger.read_bytes())
    journal = value.get("ledger_transactions_v1")
    require(isinstance(journal, dict), "intent-present")
    original_objects(value, expected)
    require(journal.get("schema") == "ledger-transactions-v1", "journal-schema")
    rows = journal.get("transactions")
    require(isinstance(rows, dict) and set(rows) == {transaction_id},
            "exactly-one-transaction")
    intent = rows[transaction_id]
    require(isinstance(intent, dict) and intent.get("record") == record,
            "intent-record")
    require(intent.get("expected_objects") == expected, "intent-baseline")
    require(receipt.is_file(), "receipt-present")
    require(receipt.read_bytes().decode("utf-8") == intent.get("receipt_bytes"),
            "receipt-exact-intent-bytes")
    payload = json.loads(receipt.read_bytes())
    require(payload.get("transaction_id") == transaction_id and
            payload.get("record") == record, "receipt-semantics")
    semantic = {"schema": "ledger-transaction-intent-v1", "transaction_id": transaction_id,
                "receipt_path": receipt.name, "record": record, "expected_objects": expected}
    intent_bytes = canonical(semantic)
    require(intent.get("intent_bytes") == intent_bytes.decode("utf-8") and
            intent.get("intent_sha256") == hashlib.sha256(intent_bytes).hexdigest(),
            "independent-intent-digest")
    wanted_payload = {"schema": "ledger-transaction-receipt-v1", "transaction_id": transaction_id,
                      "receipt_path": receipt.name, "record": record,
                      "intent_sha256": hashlib.sha256(intent_bytes).hexdigest()}
    wanted_bytes = (json.dumps(wanted_payload, indent=2, sort_keys=False,
                              allow_nan=False) + "\n").encode("utf-8")
    require(receipt.read_bytes() == wanted_bytes, "independent-receipt-bytes")
    require(hashlib.sha256(receipt.read_bytes()).hexdigest() ==
            intent.get("receipt_sha256"), "receipt-digest")
    return value


def run_tracer(api, root, baseline, expected, fresh_api):
    ledger = root / "ledger.json"
    ledger.write_bytes(baseline)
    receipt = root / "receipt.json"
    record = {"kind": "engineering-metadata", "note": "D132 clone-only tracer"}
    common = dict(project_root=root, transaction_id="d132-tracer",
                  receipt_path=receipt, expected_objects=expected,
                  lock_root=root / "locks")
    rows = []
    for case in TRACER_CASES:
        try:
            require(callable(getattr(api, "commit_ledger_transaction", None)),
                    "target-api-present:commit_ledger_transaction")
            require(callable(getattr(api, "recover_ledger_transaction", None)),
                    "target-api-present:recover_ledger_transaction")
            if case == "absent_publication":
                api.commit_ledger_transaction(ledger, record=record, **common)
            elif case == "identical_repeat":
                before = ledger.read_bytes(), receipt.read_bytes(), receipt.stat().st_ino
                api = fresh_api()
                api.commit_ledger_transaction(ledger, record=record, **common)
                require(before == (ledger.read_bytes(), receipt.read_bytes(),
                                   receipt.stat().st_ino), "identical-repeat-no-effects")
            else:
                before = ledger.read_bytes(), receipt.read_bytes()
                receipt.unlink()
                api = fresh_api()
                api.recover_ledger_transaction(ledger, **common)
                api.recover_ledger_transaction(ledger, **common)
                require(before == (ledger.read_bytes(), receipt.read_bytes()),
                        "recovery-exact-no-duplicate")
            persisted_oracle(ledger, receipt, expected, "d132-tracer", record)
            rows.append({"case_id": case, "status": "pass"})
        except Exception as exc:
            rows.append({"case_id": case, "status": "fail",
                         "assertion": str(exc), "exception": type(exc).__name__})
    return rows


class InjectedBoundary(RuntimeError):
    pass


def scenario(root, name, baseline, expected):
    directory = root / name
    directory.mkdir()
    ledger = directory / "ledger.json"
    ledger.write_bytes(baseline)
    receipt = directory / "receipt.json"
    record = {"kind": "engineering-metadata", "note": "D132 retained matrix"}
    common = dict(project_root=directory, transaction_id="d132-matrix",
                  receipt_path=receipt, expected_objects=expected,
                  lock_root=directory / "locks")
    return directory, ledger, receipt, record, common


def invoke(fresh_api, ledger, common, record=None, checkpoint=None, recover=False):
    api = fresh_api()
    if recover:
        return api.recover_ledger_transaction(ledger, checkpoint=checkpoint, **common)
    return api.commit_ledger_transaction(ledger, record=record, checkpoint=checkpoint, **common)


def interrupted(action, target):
    def checkpoint(name):
        if name == target:
            raise InjectedBoundary(target)
    try:
        action(checkpoint)
    except InjectedBoundary as exc:
        require(str(exc) == target, "injected-boundary-identity")
    else:
        raise AssertionError("injected-boundary-not-reached:" + target)


def partial_state(ledger, receipt, expected, target):
    value = json.loads(ledger.read_bytes())
    has_intent = "ledger_transactions_v1" in value
    require(has_intent == (target != "before_intent"), "checkpoint-intent-order:" + target)
    if has_intent:
        original_objects(value, expected)
        require(set(value["ledger_transactions_v1"]["transactions"]) == {"d132-matrix"},
                "checkpoint-exactly-one-intent")
        row = value["ledger_transactions_v1"]["transactions"]["d132-matrix"]
        wanted = expected_receipt_bytes("d132-matrix", receipt.name,
            {"kind": "engineering-metadata", "note": "D132 retained matrix"}, expected)
        require(row.get("receipt_bytes") == wanted.decode("utf-8") and
                row.get("receipt_sha256") == hashlib.sha256(wanted).hexdigest(),
                "checkpoint-intact-independent-intent")
    else:
        require(set(value) == set(expected), "before-intent-original-roster")
        require(all(hashlib.sha256(canonical(value[key])).hexdigest() == digest
                    for key, digest in expected.items()), "before-intent-original68")
    published = target in ("after_publication", "after_verification")
    require(receipt.exists() == published, "checkpoint-publication-order:" + target)
    if published:
        require(receipt.read_bytes().decode("utf-8") ==
                value["ledger_transactions_v1"]["transactions"]["d132-matrix"]["receipt_bytes"],
                "checkpoint-exact-publication")
    return {"intent_present": has_intent, "receipt_present": published,
            "ledger_sha256": hashlib.sha256(ledger.read_bytes()).hexdigest()}


def expect_rejection(action, reason, api):
    try:
        action()
    except api.AccountingError as exc:
        require(str(exc) == reason, "rejection-reason:" + reason + ":actual=" + str(exc))
        return str(exc)
    raise AssertionError("rejection-not-raised:" + reason)


def run_fault_matrix(root, baseline, expected, fresh_api):
    checkpoints = []
    for target in CHECKPOINTS:
        try:
            directory, ledger, receipt, record, common = scenario(root, target, baseline, expected)
            observations = []
            for repeat in range(2):
                interrupted(lambda hook: invoke(fresh_api, ledger, common, record, hook), target)
                observations.append(partial_state(ledger, receipt, expected, target))
            if target == "before_intent":
                missing_api = fresh_api()
                expect_rejection(lambda: missing_api.recover_ledger_transaction(ledger, **common),
                                 "transaction-intent-missing", missing_api)
                invoke(fresh_api, ledger, common, record)
            for repeat in range(2):
                invoke(fresh_api, ledger, common, recover=True)
                persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
            checkpoints.append({"case_id": target, "status": "pass", "interruptions": observations,
                                "fresh_recoveries": 2})
        except Exception as exc:
            checkpoints.append(failure(target, exc))
    recovery_rows = []
    try:
        directory, ledger, receipt, record, common = scenario(root, "interrupted-recovery", baseline, expected)
        interrupted(lambda hook: invoke(fresh_api, ledger, common, record, hook), "after_intent")
        observations = []
        for repeat in range(2):
            interrupted(lambda hook: invoke(fresh_api, ledger, common, checkpoint=hook, recover=True),
                        "before_publication")
            observations.append(partial_state(ledger, receipt, expected, "before_publication"))
        for repeat in range(2):
            invoke(fresh_api, ledger, common, recover=True)
            persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
        recovery_rows.append({"case_id": "repeated_interrupted_recovery", "status": "pass",
                              "interruptions": observations, "fresh_recoveries": 2})
    except Exception as exc:
        recovery_rows.append(failure("repeated_interrupted_recovery", exc))
    rejections = []
    for case in REJECTION_CASES:
        try:
            evidence = rejection_case(case, root, baseline, expected, fresh_api)
            rejections.append(dict(case_id=case, status="pass", **evidence))
        except Exception as exc:
            rejections.append(failure(case, exc))
    return {"checkpoints": checkpoints, "repeated_recovery": recovery_rows,
            "rejections": rejections}


def failure(case, exc):
    return {"case_id": case, "status": "fail", "assertion": str(exc),
            "exception": type(exc).__name__}


def rejection_case(case, root, baseline, expected, fresh_api):
    directory, ledger, receipt, record, common = scenario(root, case, baseline, expected)
    api = fresh_api()
    reason = None
    call = lambda: api.commit_ledger_transaction(ledger, record=record, **common)
    mutated_input = False
    symlink_evidence = None
    if case in ("changed_record", "changed_destination", "corrupt_journal_schema",
                "corrupt_intent", "intent_digest_mismatch", "receipt_digest_mismatch",
                ):
        invoke(fresh_api, ledger, common, record)
    if case == "identical_preexisting_receipt":
        receipt.write_bytes(expected_receipt_bytes("d132-matrix", receipt.name, record, expected))
        before = receipt.read_bytes(), receipt.stat().st_ino
        call()
        require(before == (receipt.read_bytes(), receipt.stat().st_ino),
                "preexisting-identical-preserved")
        persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
        return {"expectation": "identical-inode-bytes-preserved"}
    if case == "conflicting_preexisting_receipt":
        receipt.write_bytes(b"conflicting evidence\n")
        reason = "transaction-receipt-conflict"
    elif case == "changed_record":
        record["note"] = "changed"
        reason = "transaction-identity-conflict"
    elif case == "changed_destination":
        common["receipt_path"] = directory / "different.json"
        reason = "transaction-identity-conflict"
    elif case == "missing_intent":
        receipt.write_bytes(b"published without intent\n")
        call = lambda: api.recover_ledger_transaction(ledger, **common)
        reason = "transaction-intent-missing"
    elif case in ("corrupt_journal_schema", "corrupt_intent", "intent_digest_mismatch", "receipt_digest_mismatch"):
        value = json.loads(ledger.read_bytes())
        journal = value["ledger_transactions_v1"]
        row = journal["transactions"]["d132-matrix"]
        if case == "corrupt_journal_schema":
            journal["schema"] = "unsupported"
            reason = "transaction-journal-invalid"
        elif case == "corrupt_intent":
            journal["transactions"]["d132-matrix"] = None
            reason = "transaction-intent-invalid"
        else:
            row["intent_sha256" if case == "intent_digest_mismatch" else "receipt_sha256"] = "0" * 64
            reason = "transaction-intent-digest-mismatch"
        ledger.write_bytes(canonical(value))
        call = lambda: api.recover_ledger_transaction(ledger, **common)
    elif "symlink" in case:
        live = case.endswith("_live")
        target = directory / "symlink-target"
        if live:
            if case.startswith(("directory_", "root_")):
                target.mkdir()
                (target / "ledger.json").write_bytes(baseline)
            else:
                target.write_bytes(baseline if case.startswith("ledger_") else b"target must survive")
        if case.startswith("ledger_"):
            ledger.unlink()
            ledger.symlink_to(target)
            reason = "transaction-path-symlink"
        elif case.startswith("receipt_"):
            receipt.symlink_to(target)
            reason = "transaction-path-symlink"
        elif case.startswith("directory_"):
            alias = directory / "journal-directory"
            alias.symlink_to(target, target_is_directory=True)
            ledger = alias / "ledger.json"
            reason = "transaction-path-symlink"
        else:
            alias = directory / "root-alias"
            alias.symlink_to(target, target_is_directory=True)
            common["project_root"] = alias
            reason = "transaction-root-alias-or-symlink"
        link = ledger if case.startswith("ledger_") else receipt if case.startswith("receipt_") else alias
        target_bytes = ((target / "ledger.json").read_bytes() if target.is_dir() else
                        target.read_bytes() if target.is_file() else None)
        symlink_evidence = (link, os.readlink(link), target, target_bytes)
    elif case == "absolute_escape":
        common["receipt_path"] = root / "outside-case.json"
        reason = "transaction-path-escape"
    elif case == "traversal_escape":
        common["receipt_path"] = "../outside-case.json"
        reason = "transaction-path-escape"
    elif case == "nested_destination":
        common["receipt_path"] = "nested/receipt.json"
        reason = "transaction-flat-destination-required"
    elif case == "alias_root":
        common["project_root"] = str(directory) + "/../" + directory.name
        reason = "transaction-root-alias-or-symlink"
    elif case.startswith("id_"):
        common["transaction_id"] = {"id_empty": "", "id_41": "a" * 41,
            "id_non_ascii": "\u00e9", "id_wrong_type": 1, "id_40_valid": "a" * 40}[case]
        reason = None if case == "id_40_valid" else "transaction-id-invalid"
    elif case.startswith("record_"):
        if case == "record_nonfinite":
            record["bad"] = float("nan")
        elif case == "record_wrong_type":
            record = []
        elif case == "record_wrong_kind":
            record["kind"] = "financial-settlement"
        elif case == "record_nonstring_key":
            record[1] = "bad"
        else:
            record = {"kind": "engineering-metadata", "note": ""}
            record["note"] = "x" * (65536 - len(canonical(record)) + (case == "record_oversize"))
        reason = (None if case == "record_65536_valid" else
                  "transaction-record-too-large" if case == "record_oversize" else "transaction-record-invalid")
    elif case in ("changed_original_object", "missing_original_object"):
        value = json.loads(ledger.read_bytes())
        if case == "changed_original_object":
            value["phase"] = "intentionally-corrupted-test-input"
            reason = "transaction-original-object-changed"
        else:
            del value["phase"]
            reason = "transaction-original-roster-changed"
        ledger.write_bytes(canonical(value))
        mutated_input = True
    elif case == "changed_baseline_map":
        common["expected_objects"] = dict(expected, phase="0" * 64)
        reason = "transaction-original-object-changed"
    elif case == "lock_timeout":
        lock_directory = common["lock_root"]
        lock_directory.mkdir()
        name = hashlib.sha256(str(ledger).encode()).hexdigest()
        fd = os.open(lock_directory / ("genewhip-phase6-accounting-" + name + ".lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            start = time.monotonic()
            before = ledger.read_bytes()
            expect_rejection(call, "transaction-lock-timeout", api)
            elapsed = time.monotonic() - start
            require(1.9 <= elapsed < 3, "lock-timeout-bounded")
            require(before == ledger.read_bytes() and not receipt.exists(), "lock-timeout-no-effects")
            return {"expectation": "transaction-lock-timeout", "elapsed_seconds": elapsed}
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    elif case.startswith("publication_collision_"):
        # The real canonical publisher is unchanged. Inject only at its actual
        # os.link boundary, create a competing path, then delegate the real link
        # so the filesystem raises FileExistsError under the held lock.
        actual_link = os.link
        collision = []
        def collide(source, destination, **kwargs):
            if destination == receipt and not collision:
                collision.append(True)
                value = json.loads(ledger.read_bytes())
                data = value["ledger_transactions_v1"]["transactions"]["d132-matrix"]["receipt_bytes"].encode()
                receipt.write_bytes(data if case.endswith("identical") else b"collision must survive")
                collision.append((receipt.read_bytes(), receipt.stat().st_ino))
            return actual_link(source, destination, **kwargs)
        os.link = collide
        try:
            if case.endswith("identical"):
                call()
                persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
            else:
                expect_rejection(call, "transaction-receipt-conflict", api)
            require(len(collision) == 2 and collision[1] == (receipt.read_bytes(), receipt.stat().st_ino),
                    "publication-collision-preserved")
            original_objects(json.loads(ledger.read_bytes()), expected)
            return {"expectation": "real-FileExistsError-revalidation", "collision_injected": True}
        finally:
            os.link = actual_link
    before_ledger = ledger.read_bytes() if ledger.is_file() else None
    before_receipt = (receipt.read_bytes(), receipt.stat().st_ino) if receipt.is_file() else None
    link_before = os.readlink(receipt) if receipt.is_symlink() else None
    if reason is None:
        call()
        persisted_oracle(ledger, receipt, expected, common["transaction_id"], record)
        return {"expectation": "valid-boundary-accepted"}
    observed = expect_rejection(call, reason, api)
    # A conflicting destination can retain honest intent, but cannot overwrite
    # the publication. All other rejections must leave the input ledger exact.
    if case != "conflicting_preexisting_receipt":
        require(before_ledger == (ledger.read_bytes() if ledger.is_file() else None),
                "rejection-ledger-bytes-preserved")
    if before_receipt is not None:
        require(before_receipt == (receipt.read_bytes(), receipt.stat().st_ino),
                "rejection-receipt-preserved")
    if link_before is not None:
        require(receipt.is_symlink() and os.readlink(receipt) == link_before, "rejection-link-preserved")
    if symlink_evidence is not None:
        link, link_text, target, target_bytes = symlink_evidence
        require(link.is_symlink() and os.readlink(link) == link_text, "all-symlink-kinds-preserved")
        after_target = ((target / "ledger.json").read_bytes() if target.is_dir() else
                        target.read_bytes() if target.is_file() else None)
        require(target_bytes == after_target, "symlink-target-bytes-or-absence-preserved")
    # Intentional corrupt-input tests compare entry bytes rather than asserting
    # that their deliberately changed input already matched the original map.
    if not mutated_input and not ("symlink" in case and not ledger.is_file()):
        value = json.loads(ledger.read_bytes())
        for key, digest in expected.items():
            require(hashlib.sha256(canonical(value[key])).hexdigest() == digest,
                    "rejection-original68-preserved")
    return {"expectation": observed, "intentional_original_input_corruption": mutated_input}


def run_negative_controls(root, baseline, expected, fresh_api):
    rows = []
    expected_assertions = {"wrong_receipt_reported_success": "receipt-exact-intent-bytes",
        "duplicate_transaction_on_reload": "exactly-one-transaction",
        "missing_intent_despite_publication": "intent-present"}
    for case in NEGATIVE_CASES:
        try:
            directory, ledger, receipt, record, common = scenario(root, case, baseline, expected)
            producer_result = invoke(fresh_api, ledger, common, record)
            persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
            value = json.loads(ledger.read_bytes())
            if case == "wrong_receipt_reported_success":
                receipt.write_bytes(b"wrong bytes despite reported success")
            elif case == "duplicate_transaction_on_reload":
                value["ledger_transactions_v1"]["transactions"]["duplicate"] = dict(
                    value["ledger_transactions_v1"]["transactions"]["d132-matrix"])
                ledger.write_bytes(canonical(value))
            else:
                del value["ledger_transactions_v1"]
                ledger.write_bytes(canonical(value))
            try:
                persisted_oracle(ledger, receipt, expected, "d132-matrix", record)
            except AssertionError as exc:
                require(str(exc) == expected_assertions[case], "negative-control-wrong-assertion")
                rows.append({"case_id": case, "status": "pass", "detected_assertion": str(exc),
                             "producer_reported_status": producer_result.get("status")})
            else:
                raise AssertionError("negative-control-undetected")
        except Exception as exc:
            rows.append(failure(case, exc))
    return rows
