"""Saved source identities and observed hint composition scope only."""
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

def observations(records,fixture):
    assert len(records)==46
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)'}]
    seq=selected('reference_sequence');assert [x['requested'] for x in seq]==[1,3714]
    assert all(x['unchanged'] and x['result']=='Err(Sequence)' for x in seq)
    shape=selected('shape_refusal');assert [x['row'] for x in shape]==[0,3714,8191]
    for x in shape:
        assert x['before']==x['after'] and x['unchanged'] and x['result']=='Err(RowShape)'
        at=x['row'];assert x['before'][2]==[at,at,False]
        assert x['before'][:2]==([[0,0,0],[0,0,0]] if at==0 else [[70,70,1],[336,336,1]])
    assert selected('hint_row_complete')==[{'kind':'hint_row_complete','row':3522+224*i+223,'hint_row':i,'coefficients':256,'next_visible':3522+224*(i+1)} for i in range(8)]
    assert selected('packed_row_visible')==[{'kind':'packed_row_visible','row':3522+224*(i+1),'hint_row':i,'bytes':128} for i in range(8)]
    assert selected('terminal_packed')==[{'kind':'terminal_packed','row':8191,'bytes':1024}]
    boundaries=selected('boundary');assert [x['row'] for x in boundaries]==[0,75,3713,3714,3715,3745,3746,5313,5314,5316,5370,8191]
    packed=[bytes.fromhex(row['packed_w1_hex']) for row in fixture['rows']]
    for x in boundaries:
        for index in [0,3,1020,1023]:
            i,j=divmod(index,128);producer=3522+224*i+192+j//4
            assert x['w1_'+str(index)]==(packed[i][j] if x['row']>producer else 0)
    controls=selected('comparator_control')
    assert [(x['row'],x['column']) for x in controls]==[(0,41166),(3714,41248),(3714,41243),(3714,41244),(3715,42143),(5313,43166),(8191,43166)]
    assert all(x['detected'] and x['restored'] for x in controls)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())','position':[8192,8192,False]}]
    assert selected('exhaustion')==[{'kind':'exhaustion','result':'Err(Exhausted)','unchanged':True}]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','unchanged':True}]
    summary=selected('hint_summary');assert len(summary)==1;summary=summary[0]
    expected={'rows':8192,'reference_rows':8192,'owned_comparisons':16580608,'preserved_comparisons':337117184,
      'prefix_preserved':[341107472,293511168,318788736,227713024,217997312],'active_gadgets':2048,'dormant_gadgets':63488,
      'active_saved_fields':20480,'packed_byte_comparisons':8388608,'hint_row_completions':8,'packed_visible_rows':8,'terminal_packed_bytes':1024,
      'comparator_controls':7,'restored_controls':7,'initial_generation':[70,70,1],'matrix_generation':[336,336,1],
      'trace_generator_calls':406,'reference_hash_generations':0,'standalone_transform_oracle_calls':0}
    assert set(summary)==set(expected)|{'kind','active_branches'} and summary['kind']=='hint_summary'
    assert all(summary[k]==v for k,v in expected.items())
    # Branch consistency uses retained signed/flag literals, not decomposition.
    rows=fixture['rows'];lows=[x for r in rows for x in r['hint_step_columns']['low']];hs=[x for r in rows for x in r['hints']]
    branches={'positive':sum(x>0 for x in lows),'nonpositive':sum(x<=0 for x in lows),'ties':lows.count(0),'hint_zero':hs.count(0),'hint_one':hs.count(1)}
    for name in ['edge','borrow','overflow']:branches[name]=sum(x for r in rows for x in r['hint_step_columns'][name])
    assert summary['active_branches']==branches
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
    assert p['local_features']['kova-signature-hint-source']==['default','hint-controls'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==15 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['owned_ranges']==[[41143,43167]] and a['owned_all_rows'] and not a['reference_unchanged_full_writer'] and a['reference_window_rows']==1
    assert a['packed_prestate'] and a['first_packed_visible_row']==3715 and a['full_packed_visible_row']==5314
    assert a['active_gadgets_per_side']==2048 and a['dormant_gadgets_per_side']==63488 and a['source_inferred_hint_encodings_per_side']==65536
    assert not a['capacity_preflight_executed'] and not a['complete_row_source_implemented'] and not a['final_hash_implemented']
    f=json.loads((HERE/'fixtures-hint.json').read_bytes());ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    record=ref['signature_records'][2];assert (record['id'],record['key_id'],record['transaction_id'])==('B0','B','T0');stage=record['fixed_target_stages']
    assert f['selection']=={'key_id':'B','signature_id':'B0','transaction_id':'T0','note_id':'N_B'}
    shared=f['shared_inverse_fixture'];assert identity(ROOT/shared['path'])=={'bytes':shared['bytes'],'sha256':shared['sha256']}
    inv=json.loads((ROOT/shared['path']).read_bytes())
    fields=['high','low','positive','output','n','u','edge','sign_slack','borrow','overflow']
    assert f['hint_step_fields']==fields and len(f['rows'])==8
    for i,row in enumerate(f['rows']):
        old=stage['rows'][i]
        assert row['row']==i and row['hints']==old['hints'] and row['packed_w1_hex']==old['packed_w1_hex']
        assert row['inverse_output_pointer']=='/inverses/'+str(i)+'/states/10' and inv['inverses'][i]['states'][10]==old['inverse_output']
        assert row['hint_step_columns']=={k:[v[k] for v in old['hint_steps']] for k in fields}
        assert row['hint_step_columns']['output']==old['w1_coefficients']
    assert f['packed_w1_hex']==stage['packed_w1_hex']==''.join(r['packed_w1_hex'] for r in f['rows'])
    assert all(x==0 for x in f['performed_computations'].values())
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()],f)
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==46 and v['summary']==summary
    assert v['trace_generator_calls']==406 and v['source_inferred_internal_round_traces']==812
    assert v['source_inferred_forward_bodies']==16 and v['source_inferred_inverse_bodies']=={'candidate':8,'reference':0}
    assert v['source_inferred_hint_encodings_per_side']==65536 and v['source_inferred_candidate_caches_during_matrix']==2
    for n in ['new_independent_references','capacity_preflight_calls','standalone_transform_oracle_calls','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:assert v[n]==0
    assert v['hint_source_construction_implemented']
    for n in ['complete_row_source_implemented','private_payment_verified','full_security_profile_validated','final_hash_implemented','upstream_capacity_fault_reexecuted']:assert v[n] is False
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
        r=json.loads((HERE/"results/signature-hint-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned hint source identities and recorded composition scope match")

if __name__=="__main__": main()
