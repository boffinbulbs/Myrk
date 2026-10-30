"""Pinned padding evidence and fixed source expectations without AIR evaluation."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate padding evidence")
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
HEIGHT=8192
PORTS=[3,7,10,11,12,25,31,32,33,34,35,36,43,49,53,55,56,57,58,62,71,74,76,77,78,79,80,81,82,89,99,103,124]
CASES=[("signature_offset1",13130,46,1), ("signature_offset2",13130,46,2),
       ("note_offset1",13270,0,1), ("note_offset2",13270,0,2)]


def read(path):
    cap=9*1024*1024 if path.name=="reference-fixture.json" else 524288
    with path.open("rb") as file:raw=file.read(cap+1)
    assert len(raw)<=cap,path
    return raw.replace(b"\r\n",b"\n")


def identity(path):
    raw=read(path)
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def packages(path):
    return {tuple(p.get(k,"") for k in ("name","version","source","checksum"))
            for p in tomllib.loads(read(path).decode())["package"] if "source" in p}


def expected_index(port,offset):
    assert port in PORTS and offset in (1,2)
    return 6127+port+2*sum(p<port for p in PORTS)+offset


def expected_histograms():
    # Only the changing early signature intervals need a point count. The late
    # interval is constant except for the one final comparison row.
    def words(start,end):return set(range(start//3,(end+2)//3)) if start<end else set()
    signature=[0]*125
    for row in range(448):
        key=set()
        if row==0:key|=words(0,32)
        if row<256:key|=words(32+10*row,42+10*row)
        if 12<=row<228:
            b=row//6-2
            key|=words(72*b,72*b+72)
        if 234<=row<354:
            b=row//6-39
            key|=words(136*b,min(136*b+136,2592))
        sig=words(4619,4627)|words(64+10*row,74+10*row)
        if row<75:sig|=words(4544+row,4545+row)
        if row<6:sig|=words(0,64)
        port=len(key)+len(sig)-1
        assert port in PORTS
        signature[port]+=1
    signature[3]+=HEIGHT-448-1
    signature[25]+=1
    c=json.loads(read(ROOT/"research/source-certificate/fixtures-certificate.json"))
    assert c["format"]=="kova.source-certificate.v1" and c["rows"]==HEIGHT
    assert len(c["metric_names"])==8 and c["metric_names"][2]=="unique_words"
    note=[0]*125
    next_row=0
    for start,end,metrics in c["metric_runs"]:
        assert start==next_row and start<end<=HEIGHT and len(metrics)==8
        assert 1<=metrics[2]<=125
        port=metrics[2]-1
        assert port in PORTS
        note[port]+=end-start
        next_row=end
    assert next_row==HEIGHT and sum(signature)==sum(note)==HEIGHT
    return signature,note


def positive(name):
    return dict(phase="positive",name=name,accepted=True,reported_trace_height=HEIGHT,
                constraints_per_row=69242,all_rows_checked=True,failures=0,first_failures=[])


def check_records(summary_path,observations_path):
    s=json.loads(read(summary_path))
    assert s==dict(fixture="B0",constructed_traces=1,maximum_live_traces=1,positive_full_scans=5,
                   negative_all_frame_passes=4,negative_frame_evaluations=32768,total_frame_evaluations=73728,
                   controls=4,independent_byte_comparisons=5,independent_bytes=288,rank_projection_passes=1,
                   actual_tail_ports_compared=16384,symbolic_collections=0,backend_proofs=0)
    records=[json.loads(line) for line in read(observations_path).splitlines()]
    assert len(records)==16
    assert records[0]==dict(phase="tail_ranks",projection_passes=1,rows=HEIGHT,actual_tail_ports_compared=16384)
    assert records[1]==dict(phase="constructed",height=HEIGHT,width=43176,raw_field_bytes=1414791168)
    assert records[2]==dict(phase="independent_bytes",comparisons=5,bytes=288,
                            canonical_transaction_match=True,authorization_values_match=True)
    assert records[3]==positive("baseline")
    sig,note=expected_histograms()
    for i,(name,column,old,offset) in enumerate(CASES):
        altered,negative,restored=records[4+3*i:7+3*i]
        is_sig=name.startswith("signature")
        first,last=(43,3) if is_sig else (89,49)
        assert altered==dict(phase="altered",name=name,rows=HEIGHT,changed_cells=16384,
                             held_column=column,old_word=old,new_word=old+(1<<(8*offset)))
        assert negative==dict(phase="negative",name=name,rows_evaluated=HEIGHT,failures=HEIGHT,
                              unexpected_rows=0,complete=True,first_row=0,last_row=HEIGHT-1,
                              first_index=expected_index(first,offset),last_index=expected_index(last,offset),
                              port_histogram=sig if is_sig else note)
        assert restored==positive(name)


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
    m=tomllib.loads(read(HERE/"Cargo.toml").decode())
    dep=m["dev-dependencies"]["kova-signature-packed"]
    assert not dep["default-features"] and dep["features"]==["native-execution"]
    assert not m["package"]["autotests"] and not m["package"]["autobins"]
    assert m["test"]==[dict(name="padding",path="tests/padding.rs")]
    check_records(HERE/"fixtures-padding.json",HERE/"fixtures-observations.jsonl")
    v=json.loads(read(HERE/"validation.json"))
    assert v["provenance"]==identity(HERE/"provenance.json")
    assert v["native_traces"]==1 and v["maximum_live_traces"]==1
    assert v["positive_full_scans"]==5 and v["negative_all_frame_passes"]==4
    assert v["total_frame_evaluations"]==73728 and v["symbolic_collections"]==v["backend_proofs"]==0
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
        check_records(HERE/"results/padding.json",HERE/"results/observations.jsonl")
        for name in ["padding.json","observations.jsonl"]:
            assert read(HERE/"results"/name)==read(HERE/("fixtures-"+name))
    print("Padding source identities and independent all-frame expectations match")


if __name__=="__main__":main()
