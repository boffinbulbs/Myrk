"""Saved source identities and observed forward composition scope only."""
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
    assert len(records)==175
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)','generation':[0,0,0]}]
    seq=selected('reference_sequence')
    assert [r['requested'] for r in seq]==[1,32]
    assert all(r['result']=='Err(Sequence)' and r['prepared']==0 and r['unchanged'] for r in seq)
    shape=selected('shape_refusal')
    assert [r['row'] for r in shape]==[0,1]
    assert shape[0]['before']==shape[0]['after']==[0,0,0]
    assert shape[1]['before']==shape[1]['after']==[1,1,1]
    assert all(r['result']=='Err(RowShape)' and r['unchanged'] for r in shape)
    stages=selected('stage_checkpoint')
    assert len(stages)==144
    assert {(r['transform'],r['stage'],r['row']) for r in stages}=={(t,s,450+192*t+32+16*s) for t in range(16) for s in range(9)}
    assert all(r['coefficients']==256 for r in stages)
    outputs=selected('output_checkpoint')
    banks=[0,1,2,3,4,5,6,7,0,1,2,3,4,5,8,6]
    assert [(r['transform'],r['row'],r['bank']) for r in outputs]==[(t,642+192*t,banks[t]) for t in range(16)]
    assert all(r['coefficients']==256 for r in outputs)
    corrupt=selected('comparator_corruption')
    assert [(r['row'],r['column']) for r in corrupt]==[(0,30448),(450,32412),(482,30540),(610,30101),(642,27796),(8191,30099)]
    assert all(r['detected'] for r in corrupt)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())'}]
    exhausted=selected('exhaustion')
    assert len(exhausted)==1 and exhausted[0]['result']=='Err(Exhausted)' and exhausted[0]['unchanged']
    assert exhausted[0]['before']==exhausted[0]['after']==[70,70,1]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','prepared':8192,'unchanged':True}]
    summaries=selected('forward_summary')
    assert len(summaries)==1
    summary=summaries[0]
    expected={'rows':8192,'reference_rows':8192,'reference_windows':256,'forward_comparisons':40960000,
        'protected_source_comparisons':227713024,'initial_protected_comparisons':217997312,'outside_comparisons':132038656,
        'source_values':4096,'stage_checkpoints':144,'stage_coefficients':36864,'output_checkpoints':16,'output_coefficients':4096,
        'comparator_controls':6,'restored_controls':6,'shape_refusals':2,'sequence_refusals':2,'incomplete_refusals':1,
        'exhaustion_refusals':1,'reference_exhaustion_refusals':1,'candidate_generation':[70,70,1],'reference_hash_generations':0}
    assert summary=={'kind':'forward_summary',**expected}
    return summary

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--check-results',action='store_true')
    parser.add_argument('--registry-root',type=Path)
    args=parser.parse_args()
    p=json.loads((HERE/'provenance.json').read_bytes())
    for group,base in [('repository_files',ROOT),('execution_source_files',HERE),('experiment_files',HERE)]:
        for n,pin in p[group].items():assert identity(base/n)==pin,n
    if args.registry_root:
        for n,pin in p['registry_source_files'].items():assert identity(args.registry_root/n)==pin,n
    assert len(packages(HERE/'Cargo.lock'))==89
    assert packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    features=json.loads((HERE/'fixtures-features.json').read_bytes())
    baseline=json.loads((HERE.parent/'proof-preflight/fixtures/features.json').read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys()
    assert all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert p['local_features']['kova-signature-forward-source']==['default','forward-controls']
    assert not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==7 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['forward_owned_range']==[27796,32796] and a['reference_window_rows']==32
    assert not a['reference_unchanged_full_writer'] and not a['complete_row_source_implemented']
    assert a['tail_before_inverse_overlay']
    f=json.loads((HERE/'fixtures-forward.json').read_bytes())
    ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    record=ref['signature_records'][2]
    assert (record['id'],record['key_id'],record['transaction_id'])==('B0','B','T0')
    stages=record['fixed_target_stages']
    kinds=[f'z{i}' for i in range(7)]+['challenge']+[f't1_row{i}' for i in range(8)]
    indices=[0,1,2,3,4,5,6,7,8,10,12,14,16,18,20,22]
    assert f['selection_order']==kinds and f['original_interleaved_indices']==indices
    assert f['unscaled_t1']==stages['t1']
    assert f['forwards']==[{'logical_transform':t,**stages['transforms'][idx]} for t,idx in enumerate(indices)]
    assert all(x['kind']==kind and x['mode']==1 for x,kind in zip(f['forwards'],kinds))
    assert all(value==0 for value in f['performed_computations'].values())
    records=[json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()]
    summary=observations(records)
    v=json.loads((HERE/'validation.json').read_bytes())
    assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==175 and v['summary']==summary
    assert v['trace_generator_calls']==70 and v['source_inferred_internal_round_traces']==140
    assert v['source_inferred_forward_computations']=={'candidate':16,'adapted_reference':16,'total':32}
    for field in ['new_independent_reference_transforms','new_scalar_hash_computations','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:
        assert v[field]==0
    for field in ['complete_row_source_implemented','private_payment_verified','full_security_profile_validated']:
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
        r=json.loads((HERE/"results/signature-forward-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned forward source identities and recorded composition scope match")

if __name__=="__main__": main()
