"""Saved source identities and observed accumulator composition scope only."""
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
    assert len(records)==157
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)'}]
    seq=selected('reference_sequence');assert [x['requested'] for x in seq]==[1,6]
    assert all(x['unchanged'] and x['result']=='Err(Sequence)' for x in seq)
    shape=selected('shape_refusal');assert [x['row'] for x in shape]==[0,1]
    for at,x in enumerate(shape):
        assert x['before']==x['after']==[[at,at,at],[0,0,0],[at,at,False]]
        assert x['unchanged'] and x['result']=='Err(RowShape)'
    streams=selected('stream_complete');assert len(streams)==56
    for s,x in enumerate(streams):
        c=fixture['matrix_columns'][s]
        assert x=={'kind':'stream_complete','row':689+48*s,'stream':s,'accepted':256,'cursor':c['cursor']['bytes_consumed'],'rejected_indices':c['cursor']['rejected_candidate_indices']}
    cols=selected('column_after');assert cols==[{'kind':'column_after','row':690+48*s,'stream':s,'coefficients':256} for s in range(56)]
    points=selected('point_after');assert points==[{'kind':'point_after','row':3362+32*i,'point_row':i,'coefficients':256} for i in range(8)]
    assert selected('terminal_accumulator')==[{'kind':'terminal_accumulator','row':8191,'coefficients':2048}]
    boundaries=selected('microstate_boundary');assert [x['row'] for x in boundaries]==[0,647,648,689,690,3329,3330,3521,3522,3554,3586,8191]
    assert all(0<=x['count0']<=x['count8']<=256 and 0<=x['cursor0']<=x['cursor8']<=1008 and 0<=x['active_slots']<=8 for x in boundaries)
    final_cursor=fixture['matrix_columns'][-1]['cursor']['bytes_consumed']
    for x in boundaries:
        if x['row']>=3329:assert (x['count0'],x['count8'],x['cursor0'],x['cursor8'],x['active_slots'])==(256,256,final_cursor,final_cursor,0)
    corrupt=selected('comparator_corruption')
    assert [(x['row'],x['column']) for x in corrupt]==[(0,36747),(648,33804),(649,36117),(689,43168),(690,36591),(3330,39079),(3522,39095),(8191,34060)]
    assert all(x['detected'] for x in corrupt)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())'}]
    ex=selected('exhaustion');assert len(ex)==1 and ex[0]['unchanged'] and ex[0]['result']=='Err(Exhausted)'
    assert ex[0]['before']==ex[0]['after']==[[70,70,1],[336,336,1],[8192,8192,False]]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','prepared':8192,'unchanged':True}]
    main=selected('accumulator_summary');assert len(main)==1;main=main[0]
    expected={'rows':8192,'reference_rows':8192,'owned_comparisons':60186624,'preserved_comparisons':293511168,
        'prefix_preserved':[318788736,227713024,217997312],'accepted':14336,'rejected':sum(len(c['cursor']['rejected_candidate_indices']) for c in fixture['matrix_columns']),
        'completion_slots':56,'point_values':2048,'point_borrows':1007,'matrix_carries':6190,'first_rejection':[967,7],'first_borrow':[3330,0],
        'stream_completions':56,'column_checkpoints':56,'point_checkpoints':8,'terminal_coefficients':2048,'comparator_controls':8,'restored_controls':8,
        'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'reference_hash_generations':0}
    # Borrow/carry/first-event values are recorded outcomes, not rerun arithmetic.
    assert main=={'kind':'accumulator_summary',**expected}
    assert len(selected('fault_begin'))==1
    assert selected('fault_capacity')==[{'kind':'fault_capacity','row':689,'accepted':0,'cursor':1008,'position':[689,690,True],'initial_generation':[70,70,1],'matrix_generation':[6,6,1]}]
    refused=selected('fault_refusal');assert [x['operation'] for x in refused]==['normal','fault']
    for x in refused:
        assert x['result']=='Err(Failed)' and x['unchanged'] and x['before']==x['after']==[[70,70,1],[6,6,1],[689,690,True]]
    assert selected('fault_finish')==[{'kind':'fault_finish','result':'Err(Failed)','kernel_emit':'Err(TerminalFailure)','kernel_finish':'Err(TerminalFailure)','unchanged':True}]
    fault={'kind':'fault_summary','successful_rows':689,'upstream_rows':690,'failure_row':689,'class_accepted':0,'class_cursor':1008,'position':[689,690,True],'initial_generation':[70,70,1],'matrix_generation':[6,6,1]}
    assert selected('fault_summary')==[fault]
    combined={'kind':'combined_summary','main':main,'fault':fault,'trace_generator_calls':482}
    assert selected('combined_summary')==[combined]
    return combined

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
    assert p['local_features']['kova-signature-accumulator-source']==['accumulator-controls','default'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==11 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['owned_ranges']==[[33804,41143],[43168,43176]] and not a['reference_unchanged_full_writer'] and a['reference_window_rows']==1
    assert a['nonfinal_count_resets']==55 and a['final_count_held'] and a['candidate_caches_during_matrix']==2
    assert not a['capacity_preflight_executed'] and not a['complete_row_source_implemented'] and not a['inverse_implemented'] and not a['final_hash_implemented']
    f=json.loads((HERE/'fixtures-accumulator.json').read_bytes());ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    record=ref['signature_records'][2];assert (record['id'],record['key_id'],record['transaction_id'])==('B0','B','T0');stage=record['fixed_target_stages']
    assert f['selection']=={'key_id':'B','signature_id':'B0','transaction_id':'T0','note_id':'N_B'}
    assert f['forward_outputs']=={'zhat':stage['zhat'],'chat':stage['chat'],'t1hat':[r['t1hat'] for r in stage['rows']]}
    for s,c in enumerate(f['matrix_columns']):
        i,j=s%8,s//8;old=ref['key_matrices']['B'][7*i+j];column=stage['rows'][i]['columns'][j]
        assert c=={'chronological_index':s,'row':i,'column':j,'original_row_major_index':7*i+j,'coefficients':old['coefficients'],'cursor':old['cursor'],'historical_supported_six_blocks':old['supported_six_blocks'],'products':column['products'],'after':column['after']}
        assert column['prior']==([0]*256 if j==0 else stage['rows'][i]['columns'][j-1]['after'])
    assert len(f['matrix_columns'])==56
    assert f['point_rows']==[{'row':r['row'],'challenge_products':r['challenge_products'],'inverse_input':r['inverse_input']} for r in stage['rows']]
    assert all(x==0 for x in f['performed_computations'].values())
    shared=f['shared_matrix_fixture'];assert identity(ROOT/shared['path'])=={'bytes':shared['bytes'],'sha256':shared['sha256']}
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()],f)
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==157 and v['summary']==summary
    assert v['trace_generator_calls']==482 and v['source_inferred_internal_round_traces']==964
    assert v['source_inferred_forward_work']=={'main_complete':16,'fault_complete':1,'fault_partial':1,'reference':0}
    assert v['source_inferred_candidate_caches_during_matrix']==2
    for n in ['new_independent_references','capacity_preflight_calls','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:assert v[n]==0
    assert v['matrix_sampler_implemented']
    for n in ['complete_row_source_implemented','inverse_implemented','private_payment_verified','full_security_profile_validated','genuine_shortage_seed_tested']:assert v[n] is False
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
        r=json.loads((HERE/"results/signature-accumulator-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned accumulator source identities and recorded composition scope match")

if __name__=="__main__": main()
