"""Saved source identities and observed sampling composition scope only."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot check source identities")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def identity(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

def packages(path):
    return {(p["name"], p["version"], p["source"], p["checksum"])
            for p in tomllib.loads(path.read_text(encoding="utf-8"))["package"] if "source" in p}

def observations(records):
    assert len(records) == 22
    def selected(kind):
        return [r for r in records if r["kind"] == kind]
    early = selected("incomplete")
    assert early == [{"kind":"incomplete", "result":"Err(Sample(Incomplete))", "generation":[0,0,0]}]
    shapes = selected("shape_refusal")
    assert [r["row"] for r in shapes] == [0,1]
    assert shapes[0]["before"] == shapes[0]["after"] == [0,0,0]
    assert shapes[1]["before"] == shapes[1]["after"] == [1,1,1]
    assert all(r["unchanged"] and r["result"] == "Err(RowShape)" for r in shapes)
    checkpoints = selected("sample_checkpoint")
    assert [r["row"] for r in checkpoints] == [0,5,6,11,12,81,82,275,276,277,8191]
    assert [(r["count"],r["cursor"],r["active"]) for r in checkpoints] == [
        (0,8,0),(0,8,0),(0,8,0),(0,8,0),(0,8,1),(59,77,1),
        (60,78,0),(60,78,0),(60,78,0),(60,78,0),(60,78,0)]
    assert all(r["independent_terminal"] == (r["row"] in [82,276,8191]) for r in checkpoints)
    corrupt = selected("comparator_corruption")
    assert [(r["row"],r["column"]) for r in corrupt] == [(6,26611),(12,27528),(82,43167),(276,27248),(8191,27540)]
    assert all(r["detected"] for r in corrupt)
    assert selected("complete") == [{"kind":"complete", "result":"Ok(())"}]
    exhausted = selected("exhaustion")
    assert len(exhausted) == 1
    assert exhausted[0]["result"] == "Err(Exhausted)" and exhausted[0]["unchanged"]
    assert exhausted[0]["before"] == exhausted[0]["after"] == [70,70,1]
    summary = selected("sample_summary")
    assert len(summary) == 1
    s=summary[0]
    for name,value in {"rows":8192,"original_prefix_rows":277,"original_fill_calls":1,
        "sampler_comparisons":8192*1186,"outside_comparisons":8192*21118,
        "protected_prefix_comparisons":8192*26611,"xof_byte_comparisons":8192*272,
        "checkpoints":11,"terminal_checks":3,"terminal_coefficients":768,"events":70,"takes":60,"rejects":10,
        "first_terminal_row":82,"comparator_controls":5,"restored_controls":5,"shape_refusals":2,
        "incomplete_refusals":1,"completion_checks":1,"exhaustion_refusals":1,
        "candidate_generation":[70,70,1],"reference_hash_generations":0,"prefix_released":True,
        "rejected_byte_indices":[9,14,16,17,18,23,40,46,57,64]}.items():
        assert s[name] == value, name
    aliases=s["observed_alias_rows"]
    assert len(aliases)<=60 and all(type(x) is int and 12<=x<=81 for x in aliases)
    assert aliases==sorted(set(aliases))
    return s

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check-results",action="store_true")
    parser.add_argument("--registry-root",type=Path)
    args=parser.parse_args()
    p=json.loads((HERE/"provenance.json").read_bytes())
    for group,base in [("repository_files",ROOT),("execution_source_files",HERE),("experiment_files",HERE)]:
        for name,pin in p[group].items(): assert identity(base/name)==pin,name
    if args.registry_root:
        for name,pin in p["registry_source_files"].items(): assert identity(args.registry_root/name)==pin,name
    assert len(packages(HERE/"Cargo.lock"))==89
    assert packages(HERE/"Cargo.lock") <= packages(ROOT/"Cargo.lock")
    features=json.loads((HERE/"fixtures-features.json").read_bytes())
    baseline=json.loads((HERE.parent/"proof-preflight/fixtures/features.json").read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys()
    assert all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith("rayon/") or "parallel" in v for k,v in features.items())
    assert p["local_features"]["kova-signature-sample-source"]==["default","sample-controls"]
    assert not p["native_execution_enabled"]
    assert (HERE/"LICENSE").read_bytes()==(ROOT/"LICENSE").read_bytes()
    a=json.loads((HERE/"adaptation.json").read_bytes())
    assert a["build_prefix_unchanged"] and a["private_children_added"]==5 and not a["old_opaque_conversion"]
    assert (HERE/"src/build.rs").read_text().startswith((ROOT/a["build_origin"]).read_text())
    assert a["sampler_owned_range"]==[26611,27796] and a["activity_owned_column"]==43167
    assert not a["complete_row_source_implemented"] and a["tail_is_provisional"]
    f=json.loads((HERE/"fixtures-sample.json").read_bytes())
    ref=json.loads((HERE.parent/"signature-ownership/reference-fixture.json").read_bytes())
    record=ref["signature_records"][2]
    assert record["id"]=="B0" and record["key_id"]=="B" and record["transaction_id"]=="T0"
    stage=record["fixed_target_stages"]
    assert f["challenge_signed"]==stage["challenge_signed"]
    assert f["challenge_cursor"]==stage["capacity"]["challenge_cursor"]
    assert f["challenge_received_hex"]==stage["challenge_received_hex"]
    assert f["same_index_alias"]["reached"] is None
    assert f["same_index_alias"]["status"]=="not_recorded_in_retained_sampler_schema"
    assert not f["same_index_alias"]["absence_or_presence_claim"]
    assert all(value==0 for value in f["performed_computations"].values())
    records=[json.loads(line) for line in (HERE/"fixtures-observations.jsonl").read_text().splitlines()]
    summary=observations(records)
    v=json.loads((HERE/"validation.json").read_bytes())
    assert v["provenance"]==identity(HERE/"provenance.json")
    assert v["integration_tests_passed"]==1 and v["observation_records"]==22
    assert v["summary"]==summary
    assert v["trace_generator_calls"]==70 and v["source_inferred_internal_round_traces"]==140
    for field in ["new_scalar_hash_computations","complete_signature_traces","air_evaluations","backend_proofs","pcs_calls"]:
        assert v[field]==0
    for field in ["complete_row_source_implemented","private_payment_verified","full_security_profile_validated"]:
        assert v[field] is False
    g=v["guard"]
    assert g["process_limit_bytes"]==g["aggregate_limit_bytes"]==536870912
    assert g["minimum_available_bytes"]==2147483648 and g["timeout_seconds"]==120
    assert g["readback_flags"]==8960 and g["test_counts_verified"] and g["hard_limit_installed"]
    assert g["available_before_bytes"]>=g["minimum_available_bytes"]
    assert 0<g["peak_process_private_commit_bytes"]<=g["process_limit_bytes"]
    assert 0<g["peak_job_commit_bytes"]<=g["aggregate_limit_bytes"]
    assert g["exit_code"]==0
    assert not any(g[k] for k in ["timed_out","output_limit_exceeded","working_guard_terminated"])
    if args.check_results:
        assert (HERE/"results/observations.jsonl").read_bytes()==(HERE/"fixtures-observations.jsonl").read_bytes()
        r=json.loads((HERE/"results/signature-sample-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned sampling source identities and recorded composition scope match")

if __name__=="__main__": main()
