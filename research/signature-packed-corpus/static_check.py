"""Frozen corpus identities and independently derived record expectations."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate corpus evidence")
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CASES=[
    ("A1","A","A1","T1","N_A","accept"),
    ("B0","B","B0","T0","N_B","accept"),
    ("B1","B","B1","T1","N_B","accept"),
    ("A0_empty_context","A","A0_empty_context","T0","N_A","context"),
    ("A0_wrong_context41","A","A0_wrong_context41","T0","N_A","context"),
    ("A0_same_owner_alternate_note","A","A0","T0","N_A_alt","accept"),
    ("A0_wrong_owner_note","A","A0","T0","N_B","owner"),
    ("A0_wrong_verification_key","B","A0","T0","N_B","range"),
    ("A1_wrong_expected_transaction","A","A1","T0","N_A","range"),
]


def read(path):
    cap=9*1024*1024 if path.name=="reference-fixture.json" else 524288
    with path.open("rb") as file:
        raw=file.read(cap+1)
    assert len(raw)<=cap,path
    return raw.replace(b"\r\n",b"\n")


def identity(path):
    raw=read(path)
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def packages(path):
    return {tuple(p.get(k,"") for k in ("name","version","source","checksum"))
            for p in tomllib.loads(read(path).decode())["package"] if "source" in p}


def check_records(corpus_path,observations_path):
    summary=json.loads(read(corpus_path))
    assert summary==dict(case_ids=[c[0] for c in CASES],constructed_traces=9,evaluations=9,accepted=4,rejected=5,
                         maximum_live_traces=1,live_traces_after=0,independent_byte_comparisons=43,
                         independent_bytes=2464,rows_inferred_from_checker=54483,symbolic_collections=0,
                         borrowed_frame_checks=0,backend_proofs=0)
    records=[json.loads(line) for line in read(observations_path).splitlines()]
    assert len(records)==27
    inferred_rows=0
    for i,(case,key,sig,tx,note,expected) in enumerate(CASES):
        constructed,compared,evaluated=records[3*i:3*i+3]
        assert constructed==dict(phase="constructed",id=case,construction=i+1,height=8192,width=43176,
                                 raw_field_bytes=1414791168,live_traces=1)
        golden=expected!="range"
        assert compared==dict(phase="independent_bytes",id=case,comparisons=4+int(golden),bytes=224+64*int(golden),
                              owner_reference="N_"+key,mu_reference=key+tx[1],final_golden=golden,
                              canonical_transaction_match=True,authorization_values_match=True)
        assert evaluated["phase"]=="evaluated" and evaluated["id"]==case and evaluated["evaluation"]==i+1
        assert evaluated["reported_trace_height"]==8192 and evaluated["constraints_per_row"]==69242
        assert evaluated["accepted"]==evaluated["all_rows_checked"]==(expected=="accept")
        assert evaluated["same_failure_row"]
        if expected=="accept":
            assert evaluated["failures"]==0 and evaluated["first_indices"]==[]
            assert evaluated["first_row"] is evaluated["first_index"] is evaluated["last_index"] is None
            assert evaluated["all_owner_range"] and evaluated["all_final_range"]
            assert evaluated["rows_inferred_from_checker"]==8192
        else:
            owner=expected=="owner"
            row=234 if owner else 5369
            low,high=(25052,25116) if owner else (23836,23900)
            assert evaluated["first_row"]==row and evaluated["rows_inferred_from_checker"]==row+1
            assert 1<=evaluated["failures"]<=64
            assert low<=evaluated["first_index"]<=evaluated["last_index"]<high
            assert evaluated["first_indices"][0]==evaluated["first_index"]
            assert len(evaluated["first_indices"])==min(8,evaluated["failures"])
            assert evaluated["first_indices"]==sorted(set(evaluated["first_indices"]))
            assert all(low<=index<high for index in evaluated["first_indices"])
            assert evaluated["all_owner_range"]==owner and evaluated["all_final_range"]==(not owner)
            if expected!="range":
                assert evaluated["failures"]==64
                assert evaluated["first_index"]==low and evaluated["last_index"]==high-1
                assert evaluated["first_indices"]==list(range(low,low+8))
        inferred_rows+=evaluated["rows_inferred_from_checker"]
    assert inferred_rows==54483


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check-results",action="store_true")
    parser.add_argument("--registry-root",type=Path)
    args=parser.parse_args()
    p=json.loads(read(HERE/"provenance.json"))
    for name,pin in p["repository_files"].items():assert identity(ROOT/name)==pin,name
    for name,pin in p["experiment_files"].items():assert identity(HERE/name)==pin,name
    if args.registry_root is not None:
        for name,pin in p["registry_source_files"].items():assert identity(args.registry_root/name)==pin,name
    assert read(HERE/"LICENSE")==read(ROOT/"LICENSE")
    selected=packages(HERE/"Cargo.lock")
    assert len(selected)==80 and selected<=packages(ROOT/"Cargo.lock")
    features=json.loads(read(HERE/"fixtures-features.json"))
    assert features==json.loads(read(ROOT/"research/signature-packed/fixtures-features.json"))
    assert set(features)=={name+"/"+version for name,version,_,_ in selected}
    assert not any(k.startswith(("rayon/","rayon-core/")) or "parallel" in v for k,v in features.items())
    manifest=tomllib.loads(read(HERE/"Cargo.toml").decode())
    dep=manifest["dev-dependencies"]["kova-signature-packed"]
    assert not dep["default-features"] and dep["features"]==["native-execution"]
    assert not manifest["package"]["autobins"] and not manifest["package"]["autotests"]
    assert manifest["test"]==[dict(name="corpus",path="tests/corpus.rs")]
    check_records(HERE/"fixtures-corpus.json",HERE/"fixtures-observations.jsonl")
    v=json.loads(read(HERE/"validation.json"))
    assert v["provenance"]==identity(HERE/"provenance.json")
    assert v["native_traces"]==9 and v["maximum_live_traces"]==1
    assert v["accepted"]==4 and v["rejected"]==5 and v["symbolic_collections"]==v["backend_proofs"]==0
    assert not v["full_payment_implemented"] and not v["production_security_claim"]
    g=v["guard"]
    assert g["accepted"] and g["exit_code"]==0 and g["actual_passed"]==g["expected_tests"]==1
    assert g["actual_failed"]==g["actual_ignored"]==0 and g["test_counts_verified"]
    assert g["hard_limit_installed"] and g["installed_job_flags"]==8960
    assert not g["timed_out"] and not g["working_guard_terminated"] and not g["output_limit_exceeded"]
    assert g["installed_process_commit_limit_bytes"]==g["installed_job_commit_limit_bytes"]==2147483648
    assert g["minimum_available_bytes"]==5368709120<=g["available_before_bytes"]
    assert g["timeout_seconds"]==1200
    assert 0<g["peak_private_commit_bytes"]<=g["installed_process_commit_limit_bytes"]
    assert 0<g["peak_job_commit_bytes"]<=g["installed_job_commit_limit_bytes"]
    if args.check_results:
        check_records(HERE/"results/corpus.json",HERE/"results/observations.jsonl")
        for name in ["corpus.json","observations.jsonl"]:
            assert read(HERE/"results"/name)==read(HERE/("fixtures-"+name))
    print("Nine-tuple corpus identities and independent causal predictions match")


if __name__=="__main__":main()
