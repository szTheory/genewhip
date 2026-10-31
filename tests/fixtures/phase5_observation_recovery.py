"""D-117's bounded diagnostic and fresh RECURSION qualification, Tank inherited."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import time

REPORT = Path("evidence/phase5-reference-d117.json")


def validate_script(template):
    if (re.search(r":(?:write_|set_state|set_register)|registers\[", template)
            or "GW_PHASE_TAP = assert(space:install_write_tap" not in template):
        raise ValueError("observation-unsafe-script")
    callback = template.split('function(offset, data, mask)', 1)[-1].split('"phase tap unavailable"', 1)[0]
    if re.search(r"\breturn\s+(?!nil\b)[^\s;]", callback):
        raise ValueError("observation-tap-must-return-nil")


def verify_freeze(ref, ledger, eligibility):
    if ref.DECISION == "D-118":
        return verify_delivery_freeze(ref,ledger,eligibility)
    root = ref.ROOT
    plan = ref.read_json(root / ref.CORRECTION_AUTH)
    frozen = ref.read_json(root / ref.CORRECTION_FREEZE)
    scope = plan.get("scope", {})
    if (plan.get("decision") != "D-117" or plan.get("status") != "authorized-within-resumed-phase"
            or scope.get("diagnostic_processes") != 1 or scope.get("fresh_qualification_processes") != 6
            or scope.get("native_process_ceiling") != 7 or scope.get("active_fields") != 3600
            or scope.get("total_fields_ceiling") != 7200
            or any(scope.get(k) is not False for k in ("new_rom_builds", "new_titles", "guest_memory_or_register_mutation",
                    "change_gameplay_predicates", "post_diagnostic_source_expectation_tuning", "repeat_tank", "phase6"))
            or frozen.get("plan_sha256") != ref.sha(root / ref.CORRECTION_AUTH)
            or frozen.get("producer_sha256") != ref.sha(Path(ref.__file__))
            or frozen.get("recovery_producer_sha256") != ref.sha(Path(__file__))
            or frozen.get("decision") != "D-117" or frozen.get("status") != "source-frozen"):
        raise ValueError("observation-plan-or-producer-freeze")
    for anchor in (plan["prior_d116_report"], plan["prior_d116_attempt"]):
        if ref.sha(root / anchor["path"]) != anchor["sha256"]:
            raise ValueError("observation-d116-history-changed")
    old = plan["old_recursion_package"]
    for name, digest in old["files"].items():
        if ref.sha(root / old["path"] / name) != digest:
            raise ValueError("observation-old-package-changed")
    rows = ref.read_json(ledger)["candidates"]
    eligible = {r["title_id"]:r for r in ref.read_json(eligibility)["candidates"]}
    for row in rows:
        if row["counters"] != plan["preserved_counters"][row["id"]]:
            raise ValueError("observation-counter-change")
    for title in ref.TITLES:
        entry = frozen["routes"][title]
        if entry["package"] != f"local-fixtures/phase5/{title}/route-v3":
            raise ValueError("observation-package-identity")
        for name,digest in entry["files"].items():
            if ref.sha(root / entry["package"] / name) != digest:
                raise ValueError("observation-frozen-file-changed")
        scenario = ref.read_json(root / entry["package"] / "scenario.json")
        oracle = ref.read_json(root / entry["package"] / "oracle.json")
        if ref.freeze_route(scenario,oracle) != entry["frozen"] or eligible[title]["reference_route"]["frozen"] != entry["frozen"]:
            raise ValueError("observation-frozen-route-binding")
    recur = frozen["routes"]["recursion94"]
    if recur["files"]["oracle.json"] != plan["oracle_sha256"]:
        raise ValueError("observation-oracle-changed")
    original = ref.read_json(root / old["path"] / "scenario.json")["identities"]
    current = ref.read_json(root / recur["package"] / "scenario.json")["identities"]
    for key in ("rom_sha256","rom_path","source_revision","source_archive_sha256","build_sha256",
                "build_receipt_sha256","mame_build_sha256"):
        if original.get(key) != current.get(key):
            raise ValueError("observation-source-rom-build-tool-change")
    validate_script((root / recur["package"] / "mame.lua").read_text())
    history = next(r for r in rows if r["id"]=="recursion94")["identity_history"]
    events=[e for e in history if e.get("details",{}).get("decision")=="D-117"]
    if (len(events)!=1 or events[0]["event"]!="identity_observed"
            or events[0]["details"].get("measurement_exception_charge")!=1
            or events[0]["details"].get("plan_sha256")!=frozen["plan_sha256"]
            or events[0]["details"].get("frozen")!=recur["frozen"]):
        raise ValueError("observation-exception-journal")
    prior=ref.read_json(root / plan["prior_d116_report"]["path"])
    inherited=next(r for r in prior["routes"] if r["title_id"]=="tank-battle")
    old_freeze=ref.read_json(root / "evidence/phase5-reference-recovery-freeze.json")
    if inherited.get("status")!="pass" or frozen["routes"]["tank-battle"]!=old_freeze["routes"]["tank-battle"]:
        raise ValueError("observation-inherited-tank-identity")
    return frozen


def primary_check(ref,scenario,oracle,case):
    if max(row["signals"].get("active_ticks",0) for row in case["rows"]) != 3600:
        raise ValueError("observation-diagnostic-active-field-budget")
    primary={**scenario,"cases":scenario["cases"][:1]}
    ref.check_predicates(primary,oracle,{case["case"]:case["rows"]})


def semantic_equal(left,right):
    return left["rows"]==right["rows"] and left.get("inputs")==right.get("inputs")


def _consume(ref,ledger,eligibility):
    frozen=verify_freeze(ref,ledger,eligibility)
    ref._require_committed([Path(ref.__file__),Path(__file__),ledger,eligibility,
                           ref.ROOT/ref.CORRECTION_AUTH,ref.ROOT/ref.CORRECTION_FREEZE])
    delivery=ref.DECISION=="D-118"
    attempt={"schema":"genewhip-phase5-observation-attempt-v1","decision":ref.DECISION,"status":"started",
             "started_at_unix":time.time(),"plan_sha256":frozen["plan_sha256"],
             "freeze_sha256":ref.sha(ref.ROOT/ref.CORRECTION_FREEZE),"native_process_ceiling":6 if delivery else 7,"processes":[]}
    if delivery:
        attempt.update(prior_processes=1,combined_native_process_ceiling=7)
    try:
        with (ref.ROOT/ref.CORRECTION_ATTEMPT).open("x") as stream:
            stream.write(json.dumps(attempt,indent=2)+"\n");stream.flush();os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("observation-cycle-already-consumed") from exc
    return attempt


def qualify(ref,ledger,eligibility,output,title_id):
    ledger,eligibility,output=ledger.resolve(),eligibility.resolve(),output.resolve()
    delivery=ref.DECISION=="D-118"
    report_path=Path("evidence/phase5-reference-d118.json") if delivery else REPORT
    if title_id is not None or output!=(ref.ROOT/report_path).resolve():
        raise ValueError("observation-requires-bounded-aggregate-output")
    ref._author_check(ledger,eligibility)
    if delivery:
        verify_inherited_tank(ref)
    attempt=_consume(ref,ledger,eligibility)
    plan=ref.read_json(ref.ROOT/ref.CORRECTION_AUTH)
    inherited_anchor=(ref.read_json(ref.ROOT/plan["prior_plan"]["path"])["prior_d116_report"] if delivery else plan["prior_d116_report"])
    inherited=copy.deepcopy(next(r for r in ref.read_json(ref.ROOT/inherited_anchor["path"])["routes"] if r["title_id"]=="tank-battle"))
    inherited["provenance"]={"decision":"D-116",**inherited_anchor,
                             "producer_sha256":ref.read_json(ref.ROOT/"evidence/phase5-reference-recovery-freeze.json")["producer_sha256"]}
    result={"schema":"genewhip-phase5-reference-v1","decision":ref.DECISION,"status":"blocked","errors":[],
            "routes":[inherited],"candidate_genewhip_baseline":"not-run",
            "freeze_sha256":attempt["freeze_sha256"],"plan_sha256":attempt["plan_sha256"],
            "authority":"Pinned MAME differential evidence; source remains intended-behavior authority"}
    if delivery:
        result["prior_failed_diagnostic"]={"report":plan["prior_d117_report"],"attempt":plan["prior_d117_attempt"],
            "raw_capture":plan["diagnostic_receipt"],"causal_delivery_offset":{"old_assert_tick":696,"corrected_assert_tick":695,"intended_consumed_ticks":[697,720]},
            "status":"failed immutable old identity; corrected identity requires six fresh cases, no voting or diagnostic agreement"}
    scenario,oracle,frozen=next(r for r in ref._routes() if r[0]["title_id"]=="recursion94")
    package=ref._route_package("recursion94");template=(package/"mame.lua").read_text();rom=ref.ROOT/scenario["identities"]["rom_path"]
    runs=[]
    def capture(case,stage,repetition):
        if len(attempt["processes"])>=attempt["native_process_ceiling"]:raise ValueError("observation-process-ceiling")
        attempt["processes"].append({"ordinal":len(attempt["processes"])+1,"stage":stage,"repetition":repetition,"case":case["id"],"status":"started"})
        ref.write_json(ref.ROOT/ref.CORRECTION_ATTEMPT,attempt)
        value=ref._run_case(scenario,case,rom,ref._lua_script(scenario,case,template))
        attempt["processes"][-1].update(status="capture-complete",raw_capture=value["raw_capture"])
        ref.write_json(ref.ROOT/ref.CORRECTION_ATTEMPT,attempt)
        return value
    try:
        if not delivery:
            result["diagnostic"]=capture(scenario["cases"][0],"diagnostic",0)
            primary_check(ref,scenario,oracle,result["diagnostic"])
            result["diagnostic"]["source_predicates"]="pass"
        for repetition in (1,2):
            run={"repetition":repetition,"cases":[]};runs.append(run)
            for case in scenario["cases"]:
                captured=capture(case,"qualification",repetition);run["cases"].append(captured)
                if case==scenario["cases"][0]:
                    primary_check(ref,scenario,oracle,captured)
                    if not delivery and not semantic_equal(result["diagnostic"],captured):
                        raise ValueError("observation-diagnostic-primary-disagreement")
            ref.check_predicates(scenario,oracle,{c["case"]:c["rows"] for c in run["cases"]})
            run["status"]="pass"
        for left,right in zip(runs[0]["cases"],runs[1]["cases"]):
            if not semantic_equal(left,right):raise ValueError("observation-fresh-runs-disagree")
        if runs[-1]["cases"][0].get("audio_file",{}).get("peak",0)<=0:
            raise ValueError("observation-nonsilent-audio")
        current=ref.read_json(ledger);candidate=next(r for r in current["candidates"] if r["id"]=="recursion94")
        result["routes"].append({"title_id":"recursion94","status":"pass","frozen":frozen,"runs":runs,
            "lineage_id":candidate["lineage_id"],"source_revision":candidate["source_revision"],
            "provenance":{"decision":ref.DECISION,"producer_sha256":ref.sha(Path(ref.__file__)),
                          "recovery_producer_sha256":ref.sha(Path(__file__)),"freeze_sha256":attempt["freeze_sha256"]}})
        result.update(status="pass",selected_pair=list(ref.TITLES))
        current["selected_pair"]=list(ref.TITLES);ref.write_json(ledger,current)
    except (OSError,ValueError,RuntimeError,TimeoutError) as exc:
        result["errors"].append({"title_id":"recursion94","reason":str(exc),"status":"fail"})
        result["routes"].append({"title_id":"recursion94","status":"fail","reason":str(exc),"frozen":frozen,
                                "runs":runs,**getattr(exc,"observations",{})})
    finally:
        ref.write_json(output,result)
        attempt.update(status="pass" if result["status"]=="pass" else "failed",completed_at_unix=time.time(),
                       result=report_path.as_posix(),result_sha256=ref.sha(output))
        ref.write_json(ref.ROOT/ref.CORRECTION_ATTEMPT,attempt)
    return 0 if result["status"]=="pass" else 2


def verify_pair_bindings(ref,path):
    if ref.DECISION == "D-118":
        return verify_delivery_pair(ref,path)
    result=ref.read_json(path);attempt=ref.read_json(ref.ROOT/ref.CORRECTION_ATTEMPT)
    plan=ref.read_json(ref.ROOT/ref.CORRECTION_AUTH);freeze=ref.read_json(ref.ROOT/ref.CORRECTION_FREEZE)
    if (result.get("decision")!="D-117" or attempt.get("status")!="pass" or len(attempt.get("processes",[]))!=7
            or attempt.get("result_sha256")!=ref.sha(path) or result.get("freeze_sha256")!=ref.sha(ref.ROOT/ref.CORRECTION_FREEZE)
            or attempt.get("freeze_sha256")!=result["freeze_sha256"] or result.get("plan_sha256")!=ref.sha(ref.ROOT/ref.CORRECTION_AUTH)):
        raise ValueError("observation-pair-cycle-binding")
    original=next(r for r in ref.read_json(ref.ROOT/plan["prior_d116_report"]["path"])["routes"] if r["title_id"]=="tank-battle")
    inherited=next(r for r in result["routes"] if r["title_id"]=="tank-battle")
    if {k:v for k,v in inherited.items() if k!="provenance"}!=original:
        raise ValueError("observation-inherited-tank-changed")
    recur=next(r for r in result["routes"] if r["title_id"]=="recursion94")
    scenario=ref.read_json(ref._route_package("recursion94")/"scenario.json");oracle=ref.read_json(ref._route_package("recursion94")/"oracle.json")
    diagnostic=result["diagnostic"];primary_check(ref,scenario,oracle,diagnostic)
    cases=[diagnostic]+[c for route in result["routes"] for run in route.get("runs",[]) for c in run["cases"]]
    seen=set()
    for case in cases:
        raw=case["raw_capture"];receipt_path=ref.ROOT/raw["receipt"]
        if raw["run_id"] in seen or ref.sha(receipt_path)!=raw["receipt_sha256"]:
            raise ValueError("observation-reused-or-changed-capture")
        seen.add(raw["run_id"]);receipt=ref.read_json(receipt_path)
        for name,identity in receipt["files"].items():
            item=receipt_path.parent/name
            if item.stat().st_size!=identity["bytes"] or ref.sha(item)!=identity["sha256"]:
                raise ValueError("observation-raw-file-identity")
        expected=(inherited["provenance"]["producer_sha256"] if receipt["request"]["title_id"]=="tank-battle" else freeze["producer_sha256"])
        if receipt["request"]["producer_sha256"]!=expected or ref.sha(receipt_path.parent/"producer.py")!=expected:
            raise ValueError("observation-per-route-producer")
        if receipt["request"]["title_id"]=="recursion94" and ref.sha(receipt_path.parent/"observation-producer.py")!=freeze["recovery_producer_sha256"]:
            raise ValueError("observation-per-route-recovery-producer")
    diagnostic_receipt=ref.read_json(ref.ROOT/diagnostic["raw_capture"]["receipt"])
    request=diagnostic_receipt["request"];case=scenario["cases"][0]
    script=ref._lua_script(scenario,case,(ref._route_package("recursion94")/"mame.lua").read_text())
    if (request.get("rom_sha256")!=scenario["identities"]["rom_sha256"] or request.get("mame_sha256")!=ref.sha(ref.MAME)
            or request.get("script_sha256")!=hashlib.sha256(script.encode()).hexdigest()
            or diagnostic_receipt.get("capture_status")!="complete"):
        raise ValueError("observation-diagnostic-identity")
    diagnostic_path=(ref.ROOT/diagnostic["raw_capture"]["receipt"]).parent
    if (ref.parse_capture((diagnostic_path/"capture.csv").read_bytes(),scenario)!=diagnostic["rows"]
            or ref._parse_inputs((diagnostic_path/"stdout").read_bytes(),scenario,"full-route")!=diagnostic["inputs"]):
        raise ValueError("observation-diagnostic-raw-trace")
    for run in recur["runs"]:
        if not semantic_equal(diagnostic,run["cases"][0]):
            raise ValueError("observation-diagnostic-primary-disagreement")


def verify_delivery_freeze(ref,ledger,eligibility):
    root=ref.ROOT;plan=ref.read_json(root/ref.CORRECTION_AUTH);frozen=ref.read_json(root/ref.CORRECTION_FREEZE)
    scope=plan.get("scope",{})
    if (plan.get("decision")!="D-118" or plan.get("status")!="authorized-within-resumed-phase"
            or scope.get("additional_diagnostic_processes")!=0 or scope.get("fresh_qualification_processes")!=6
            or scope.get("prior_processes")!=1 or scope.get("combined_native_process_ceiling")!=7
            or scope.get("active_fields")!=3600 or scope.get("total_fields_ceiling")!=7200
            or any(scope.get(k) is not False for k in ("repeat_tank","new_rom_builds","new_titles","change_gameplay_predicates",
                                                       "guest_memory_or_register_mutation","further_retry","phase6"))
            or frozen.get("plan_sha256")!=ref.sha(root/ref.CORRECTION_AUTH)
            or frozen.get("producer_sha256")!=ref.sha(Path(ref.__file__))
            or frozen.get("recovery_producer_sha256")!=ref.sha(Path(__file__))
            or frozen.get("decision")!="D-118" or frozen.get("status")!="source-frozen"):
        raise ValueError("delivery-plan-or-producer-freeze")
    for name in ("prior_plan","prior_d117_attempt","prior_d117_report"):
        anchor=plan[name]
        if ref.sha(root/anchor["path"])!=anchor["sha256"]:raise ValueError("delivery-prior-history-changed")
    diagnostic=plan["diagnostic_receipt"]
    if ref.sha(root/diagnostic["receipt"])!=diagnostic["receipt_sha256"]:
        raise ValueError("delivery-diagnostic-receipt")
    old_attempt=ref.read_json(root/plan["prior_d117_attempt"]["path"])
    if old_attempt.get("status")!="failed" or len(old_attempt.get("processes",[]))!=1:
        raise ValueError("delivery-six-slots-not-available")
    original_plan=ref.read_json(root/plan["prior_plan"]["path"])
    for key in ("prior_d116_report","prior_d116_attempt"):
        anchor=original_plan[key]
        if ref.sha(root/anchor["path"])!=anchor["sha256"]:raise ValueError("delivery-d116-history-changed")
    old=plan["old_package"]
    for name,digest in old["files"].items():
        if ref.sha(root/old["path"]/name)!=digest:raise ValueError("delivery-old-package-changed")
    current=ref.read_json(ledger);eligible={r["title_id"]:r for r in ref.read_json(eligibility)["candidates"]}
    for row in current["candidates"]:
        if row["counters"]!=plan["preserved_counters"][row["id"]]:raise ValueError("delivery-counter-change")
    for title in ref.TITLES:
        entry=frozen["routes"][title]
        expected=f"local-fixtures/phase5/{title}/"+("route-v3" if title=="tank-battle" else "route-v4")
        if entry["package"]!=expected:raise ValueError("delivery-package-identity")
        for name,digest in entry["files"].items():
            if ref.sha(root/entry["package"]/name)!=digest:raise ValueError("delivery-frozen-file-changed")
        scenario=ref.read_json(root/entry["package"]/"scenario.json");oracle=ref.read_json(root/entry["package"]/"oracle.json")
        if ref.freeze_route(scenario,oracle)!=entry["frozen"] or eligible[title]["reference_route"]["frozen"]!=entry["frozen"]:
            raise ValueError("delivery-frozen-route-binding")
    entry=frozen["routes"]["recursion94"]
    if entry["files"]["oracle.json"]!=plan["oracle_sha256"] or entry["files"]["mame.lua"]!=old["files"]["mame.lua"]:
        raise ValueError("delivery-observer-or-oracle-changed")
    before=ref.read_json(root/old["path"]/"scenario.json");after=ref.read_json(root/entry["package"]/"scenario.json")
    normalized=copy.deepcopy(after);targets=[e for e in normalized["input_program"]["events"] if e["control"]=="P1 B" and e["asserted"]]
    if len(targets)!=1 or targets[0]["tick"]!=695:raise ValueError("delivery-offset-not-exact")
    targets[0]["tick"]=696;normalized["identities"]["input_sha256"]=before["identities"]["input_sha256"]
    if normalized!=before:raise ValueError("delivery-more-than-one-input-change")
    if frozen["routes"]["tank-battle"]!=ref.read_json(root/"evidence/phase5-reference-recovery-freeze.json")["routes"]["tank-battle"]:
        raise ValueError("delivery-inherited-tank-changed")
    history=next(r for r in current["candidates"] if r["id"]=="recursion94")["identity_history"]
    events=[e for e in history if e.get("details",{}).get("decision")=="D-118"]
    if (len(events)!=1 or events[0]["event"]!="identity_observed" or events[0]["details"].get("input_delivery_exception_charge")!=1
            or events[0]["details"].get("plan_sha256")!=frozen["plan_sha256"]
            or events[0]["details"].get("frozen")!=entry["frozen"]):
        raise ValueError("delivery-exception-journal")
    return frozen


def _raw_integrity(ref,case,producer,recovery_producer=None):
    raw=case["raw_capture"];path=ref.ROOT/raw["receipt"]
    if not path.resolve().is_relative_to((ref.LOCAL/"reference-captures").resolve()) or ref.sha(path)!=raw["receipt_sha256"]:
        raise ValueError("delivery-raw-receipt")
    receipt=ref.read_json(path)
    if receipt.get("capture_status")!="complete" or receipt["run_id"]!=raw["run_id"]:
        raise ValueError("delivery-capture-status")
    for name,identity in receipt["files"].items():
        item=(path.parent/name).resolve()
        if not item.is_relative_to(path.parent.resolve()) or item.stat().st_size!=identity["bytes"] or ref.sha(item)!=identity["sha256"]:
            raise ValueError("delivery-raw-file-identity")
    if receipt["request"].get("producer_sha256")!=producer or ref.sha(path.parent/"producer.py")!=producer:
        raise ValueError("delivery-per-route-producer")
    if recovery_producer and ref.sha(path.parent/"observation-producer.py")!=recovery_producer:
        raise ValueError("delivery-per-route-recovery-producer")
    return raw["run_id"]


def verify_inherited_tank(ref):
    plan=ref.read_json(ref.ROOT/ref.CORRECTION_AUTH)
    prior=ref.read_json(ref.ROOT/plan["prior_plan"]["path"])
    path=ref.ROOT/prior["prior_d116_report"]["path"]
    # This private single-title audit executes the same two-run/causal/raw checks
    # as pair verification. It cannot produce an aggregate pair claim.
    ref._verify_pair(path,inherited_title="tank-battle")
    tank=next(r for r in ref.read_json(path)["routes"] if r["title_id"]=="tank-battle")
    producer=ref.read_json(ref.ROOT/"evidence/phase5-reference-recovery-freeze.json")["producer_sha256"]
    for run in tank["runs"]:
        for case in run["cases"]:_raw_integrity(ref,case,producer)


def verify_delivery_pair(ref,path):
    result=ref.read_json(path);attempt=ref.read_json(ref.ROOT/ref.CORRECTION_ATTEMPT)
    plan=ref.read_json(ref.ROOT/ref.CORRECTION_AUTH);freeze=ref.read_json(ref.ROOT/ref.CORRECTION_FREEZE)
    processes=attempt.get("processes",[])
    expected=[(rep,case) for rep in (1,2) for case in ("full-route","withhold-first-plate","withhold-final-b")]
    if (result.get("decision")!="D-118" or attempt.get("decision")!="D-118" or attempt.get("status")!="pass"
            or attempt.get("prior_processes")!=1 or attempt.get("combined_native_process_ceiling")!=7
            or [(p.get("repetition"),p.get("case")) for p in processes]!=expected
            or any(p.get("stage")!="qualification" or p.get("status")!="capture-complete" for p in processes)
            or attempt.get("result_sha256")!=ref.sha(path) or result.get("freeze_sha256")!=ref.sha(ref.ROOT/ref.CORRECTION_FREEZE)
            or attempt.get("freeze_sha256")!=result["freeze_sha256"] or result.get("plan_sha256")!=ref.sha(ref.ROOT/ref.CORRECTION_AUTH)):
        raise ValueError("delivery-pair-cycle-binding")
    prior=ref.read_json(ref.ROOT/plan["prior_plan"]["path"])
    original=next(r for r in ref.read_json(ref.ROOT/prior["prior_d116_report"]["path"])["routes"] if r["title_id"]=="tank-battle")
    inherited=next(r for r in result["routes"] if r["title_id"]=="tank-battle")
    if {k:v for k,v in inherited.items() if k!="provenance"}!=original:raise ValueError("delivery-inherited-tank-forgery")
    negative=result.get("prior_failed_diagnostic",{})
    if (negative.get("report")!=plan["prior_d117_report"] or negative.get("attempt")!=plan["prior_d117_attempt"]
            or negative.get("raw_capture")!=plan["diagnostic_receipt"]
            or negative.get("causal_delivery_offset")!={"old_assert_tick":696,"corrected_assert_tick":695,"intended_consumed_ticks":[697,720]}):
        raise ValueError("delivery-negative-diagnostic-binding")
    tank_producer=ref.read_json(ref.ROOT/"evidence/phase5-reference-recovery-freeze.json")["producer_sha256"]
    seen={plan["diagnostic_receipt"]["run_id"]}
    recur=next(r for r in result["routes"] if r["title_id"]=="recursion94")
    fresh=[c for run in recur["runs"] for c in run["cases"]]
    if [p.get("raw_capture") for p in processes]!=[c["raw_capture"] for c in fresh]:raise ValueError("delivery-process-receipt-roster")
    for route in result["routes"]:
        for run in route["runs"]:
            for case in run["cases"]:
                is_tank=route["title_id"]=="tank-battle"
                identity=_raw_integrity(ref,case,tank_producer if is_tank else freeze["producer_sha256"],
                                        None if is_tank else freeze["recovery_producer_sha256"])
                if identity in seen:raise ValueError("delivery-capture-reuse")
                seen.add(identity)
