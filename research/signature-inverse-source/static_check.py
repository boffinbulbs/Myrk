"""Saved source identities and observed inverse composition scope only."""
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

def observations(records,fixture,shared):
    assert len(records)==123
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)'}]
    seq=selected('reference_sequence');assert [x['requested'] for x in seq]==[1,3522]
    assert all(x['unchanged'] and x['result']=='Err(Sequence)' for x in seq)
    shape=selected('shape_refusal');assert [x['row'] for x in shape]==[0,3522,8191]
    for x in shape:
        assert x['before']==x['after'] and x['unchanged'] and x['result']=='Err(RowShape)'
        at=x['row'];assert x['before'][2]==[at,at,False]
        assert x['before'][:2]==([[0,0,0],[0,0,0]] if at==0 else [[70,70,1],[336,336,1]])
    assert selected('seed')==[{'kind':'seed','row':3522,'coefficients':256,'source':'actual held forward scratch compared to saved T1_7'}]
    assert selected('state_checkpoint')==[{'kind':'state_checkpoint','row':3522+224*i+32+16*r,'inverse':i,'state':r,'coefficients':256} for i in range(8) for r in range(11)]
    assert selected('inverse_complete')==[{'kind':'inverse_complete','row':3522+224*i+223,'inverse':i,'output_coefficients':256} for i in range(8)]
    assert selected('held_tail')==[{'kind':'held_tail','row':at,'coefficients':256} for at in [5314,8191]]
    b=selected('boundary');assert [x['row'] for x in b]==[3521,3522,3523,3554,3586,3746,5314,8191]
    assert all(x['owned']==(x['row']>=3522) and 0<=x['scratch0']<8380417 and 0<=x['scratch255']<8380417 for x in b)
    seed=shared['forward_outputs']['t1hat'][7]
    for x in b:
        if x['row'] in [3521,3522]:assert [x['scratch0'],x['scratch255']]==[seed[0],seed[255]]
        if x['row']==3523:assert [x['scratch0'],x['scratch255']]==[fixture['inverses'][0]['states'][0][0],seed[255]]
        if x['row']==3554:assert [x['scratch0'],x['scratch255']]==[fixture['inverses'][0]['states'][0][0],fixture['inverses'][0]['states'][0][255]]
        if x['row']==3586:assert [x['scratch0'],x['scratch255']]==[fixture['inverses'][0]['states'][2][0],fixture['inverses'][0]['states'][2][255]]
        if x['row']==3746:assert [x['scratch0'],x['scratch255']]==[fixture['inverses'][0]['states'][10][0],fixture['inverses'][0]['states'][10][255]]
        if x['row']>=5314:assert [x['scratch0'],x['scratch255']]==[fixture['inverses'][7]['states'][10][0],fixture['inverses'][7]['states'][10][255]]
    corrupt=selected('comparator_control')
    assert [(x['row'],x['column']) for x in corrupt]==[(3522,30355),(3522,32435),(3698,30228),(3714,32780),(3747,30355),(8191,30355)]
    assert all(x['detected'] and x['restored'] for x in corrupt)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())','position':[8192,8192,False]}]
    assert selected('exhaustion')==[{'kind':'exhaustion','result':'Err(Exhausted)','unchanged':True}]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','unchanged':True}]
    summary=selected('inverse_summary');assert len(summary)==1;summary=summary[0]
    expected={'rows':8192,'reference_rows':8192,'owned_comparisons':12590320,'preserved_comparisons':341107472,
      'prefix_preserved':[293511168,318788736,227713024,217997312],'seed_events':1,'state_checkpoints':88,'state_coefficients':22528,
      'partial_initializer_coefficients':65536,'initializer_values':2048,'output_values':2048,'normalized_values':2048,'inverse_completions':8,
      'held_tail_coefficients':512,'point_overlap_rows':64,'comparator_controls':6,'restored_controls':6,
      'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'trace_generator_calls':406,'reference_hash_generations':0,'standalone_transform_oracle_calls':0}
    assert set(summary)==set(expected)|{'kind','carries','borrows'} and summary['kind']=='inverse_summary'
    assert all(summary[k]==v for k,v in expected.items())
    assert 0<summary['carries']<=8192 and 0<summary['borrows']<=8192
    return summary

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-results',action='store_true');parser.add_argument('--registry-root',type=Path);args=parser.parse_args()
    p=json.loads((HERE/'provenance.json').read_bytes())
    for group,base in [('repository_files',ROOT),('execution_source_files',HERE),('experiment_files',HERE)]:
        for n,pin in p[group].items():assert identity(base/n)==pin,n
    if args.registry_root:
        for n,pin in p['registry_source_files'].items():assert identity(args.registry_root/n)==pin,n
    assert len(packages(HERE/'Cargo.lock'))==89 and packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    features=json.loads((HERE/'fixtures-features.json').read_bytes());baseline=json.loads((HERE.parent/'proof-preflight/fixtures/features.json').read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys() and all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert p['local_features']['kova-signature-inverse-source']==['default','inverse-controls'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==13 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['owned_ranges']==[[30100,32796]] and a['owned_from_row']==3522 and not a['reference_unchanged_full_writer'] and a['reference_window_rows']==1
    assert a['seed_events']==1 and a['inverse_transforms']==8 and a['forward_output_banks_preserved']==9 and a['held_tail_start']==5314 and a['partial_initializer_preserved']
    assert a['source_inferred_candidate_inverse_bodies']==a['source_inferred_adapted_reference_inverse_bodies']==8
    assert not a['capacity_preflight_executed'] and not a['complete_row_source_implemented'] and not a['final_hash_implemented']
    f=json.loads((HERE/'fixtures-inverse.json').read_bytes());ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    record=ref['signature_records'][2];assert (record['id'],record['key_id'],record['transaction_id'])==('B0','B','T0');stage=record['fixed_target_stages']
    assert f['selection']=={'key_id':'B','signature_id':'B0','transaction_id':'T0','note_id':'N_B'}
    assert f['relative_prestate_checkpoint_rows']==[32+16*r for r in range(11)] and len(f['inverses'])==8
    shared=f['shared_accumulator_fixture'];assert identity(ROOT/shared['path'])=={'bytes':shared['bytes'],'sha256':shared['sha256']}
    shared=json.loads((ROOT/shared['path']).read_bytes())
    assert shared['forward_outputs']['t1hat'][7]==stage['rows'][7]['t1hat']
    for i,t in enumerate(f['inverses']):
        old=stage['transforms'][9+2*i]
        assert (t['logical_inverse'],t['kind'],t['mode'],t['original_transform_index'])==(i,'inverse_row'+str(i),2,9+2*i)
        assert old['kind']==t['kind'] and old['mode']==2 and t['states']==old['stages'] and len(t['states'])==11
        assert t['input_state_index']==0 and t['output_state_index']==10
        assert t['states'][0]==old['input']==stage['rows'][i]['inverse_input']==shared['point_rows'][i]['inverse_input']
        assert t['states'][10]==old['output']==stage['rows'][i]['inverse_output']
        assert t['states'][9][128:]==t['states'][8][128:] and t['states'][10][:128]==t['states'][9][:128]
    assert all(x==0 for x in f['performed_computations'].values())
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()],f,shared)
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==123 and v['summary']==summary
    assert v['trace_generator_calls']==406 and v['source_inferred_internal_round_traces']==812
    assert v['source_inferred_forward_bodies']==16 and v['source_inferred_inverse_bodies']=={'candidate':8,'adapted_reference':8}
    assert v['source_inferred_candidate_caches_during_matrix']==2
    for n in ['new_independent_references','capacity_preflight_calls','standalone_transform_oracle_calls','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:assert v[n]==0
    assert v['inverse_source_construction_implemented']
    for n in ['complete_row_source_implemented','private_payment_verified','full_security_profile_validated','hints_implemented','final_hash_implemented','upstream_capacity_fault_reexecuted']:assert v[n] is False
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
        r=json.loads((HERE/"results/signature-inverse-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned inverse source identities and recorded composition scope match")

if __name__=="__main__": main()
