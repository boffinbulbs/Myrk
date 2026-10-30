"""Saved source identities and observed final composition scope only."""
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
    assert len(records)==47
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)'}]
    seq=selected('reference_sequence');assert [x['requested'] for x in seq]==[0,5322]
    assert all(x['unchanged'] and x['result']=='Err(Sequence)' for x in seq)
    shape=selected('shape_refusal');assert [x['row'] for x in shape]==[0,5316,8191]
    for x in shape:
        assert x['before']==x['after'] and x['unchanged'] and x['result']=='Err(RowShape)'
        at=x['row'];assert x['before'][3]==[at,at,False]
        assert x['before'][:2]==([[0,0,0],[0,0,0]] if at==0 else [[70,70,1],[336,336,1]])
        assert x['before'][2]==([9,9,1] if at==8191 else [0,0,0])
    assert selected('dummy_capture')==[{'kind':'dummy_capture','row':414+i,'phase':i,'fields':13220} for i in range(2)]
    assert selected('block_start')==[{'kind':'block_start','row':5316+6*i,'block':i,'rate':136,'source_bytes':1088,'preimage_limbs':100,'final_generation':[i+1,i+1,1],'reference_generation':[i+1,i+1,1]} for i in range(9)]
    assert selected('block_terminal')==[{'kind':'block_terminal','row':5321+6*i,'block':i,'reference_rows':6,'fields':79320} for i in range(9)]
    assert selected('terminal_diagnostic')==[{'kind':'terminal_diagnostic','row':5369,'saved_bytes':64,'same_owner_raw_bytes':64,'packed_port_equality_executed':False}]
    assert selected('dummy_restoration')==[{'kind':'dummy_restoration','row':at,'source_row':src,'fields':13220,'matches':True} for at,src in [(5370,414),(8191,415)]]
    boundaries=selected('boundary');assert [x['row'] for x in boundaries]==[5315,5316,5321,5322,5364,5369,5370,8191]
    mu=bytes.fromhex(fixture['mu_hex']);terminal=bytes.fromhex(fixture['challenge_expected_hex'])
    for x in boundaries:
        at=x['row'];assert x['owned']==(5316<=at<5370) and x['output167']==0
        assert 0<=x['message0']<256 and 0<=x['output0']<256
        if not x['owned']:assert x['message0']==x['output0']==0
        if at==5316:assert x['message0']==mu[0]
        if at in [5364,5369]:assert x['message0']==31
        if at==5369:assert x['output0']==terminal[0]
    controls=selected('comparator_control')
    assert [(x['row'],x['column']) for x in controls]==[(5316,0),(5316,16271),(5322,17359),(5322,18703),(5364,10531),(5369,18119)]
    assert all(x['detected'] and x['restored'] for x in controls)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())','position':[8192,8192,False]}]
    assert selected('exhaustion')==[{'kind':'exhaustion','result':'Err(Exhausted)','unchanged':True}]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','unchanged':True}]
    expected={'kind':'final_summary','rows':8192,'reference_windows':9,'reference_final_rows':54,'owned_comparisons':713880,'preserved_comparisons':352983912,
      'prefix_preserved':[337117184,341107472,293511168,318788736,227713024,217997312],
      'source_byte_comparisons':9792,'message_byte_comparisons':9072,'output_tail_bytes':1728,'preimage_join_limbs':900,'continuation_capacity_limbs':256,
      'final_blocks':9,'terminal_saved_bytes':64,'terminal_same_owner_raw_bytes':64,'dummy_restored_fields':26440,'comparator_controls':6,'restored_controls':6,
      'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'final_generation':[9,9,1],'reference_generation':[9,9,1],
      'candidate_trace_generator_calls':415,'reference_trace_generator_calls':9,'trace_generator_calls':424,
      'standalone_transform_oracle_calls':0,'new_independent_final_hash_references':0,'final_intermediate_goldens_available':False,'packed_port_equality_executed':False}
    assert selected('final_summary')==[expected]
    return expected

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
    assert p['local_features']['kova-signature-final-source']==['default','final-controls'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==17 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['owned_ranges']==[[0,10532],[16271,18959]] and a['owned_row_range']==[5316,5370] and not a['reference_unchanged_full_writer'] and a['reference_window_rows']==6
    assert a['full_sponge_state_bytes']==200 and a['rate_bytes']==136 and a['final_blocks']==9 and a['final_message_bytes']==1088
    assert a['dummy_capture_rows']==[414,415] and a['dummy_restoration_rows']==[5370,8191]
    assert a['candidate_logical_caches_during_final']==2 and a['maximum_logical_caches_with_reference_during_final']==3
    assert a['terminal_raw_comparison_is_diagnostic'] and not a['packed_port_equality_implemented'] and not a['final_intermediate_goldens_available']
    assert not a['capacity_preflight_executed'] and not a['complete_row_source_implemented']
    f=json.loads((HERE/'fixtures-final.json').read_bytes());ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    record=ref['signature_records'][2];assert (record['id'],record['key_id'],record['transaction_id'])==('B0','B','T0');stage=record['fixed_target_stages']
    assert f['selection']=={'key_id':'B','signature_id':'B0','transaction_id':'T0','note_id':'N_B'}
    for key in ['mu_hex','mu_preimage_hex','challenge_expected_hex','challenge_received_hex']:assert f[key]==stage[key]
    assert f['saved_challenge_equality_bytes']==stage['challenge_equality_bytes']==[True]*64
    for key in ['shared_sources_fixture','shared_packed_fixture','shared_initial_fixture','original_stage']:
        item=f[key]
        # Selection records raw identities. Published source checks normalize LF.
        assert f['provenance']['source_files'][item['path']]=={'bytes':item['bytes'],'sha256':item['sha256']}
        assert identity(ROOT/item['path'])==p['repository_files'][item['path']]
    shared=json.loads((ROOT/f['shared_packed_fixture']['path']).read_bytes())
    initial=json.loads((ROOT/f['shared_initial_fixture']['path']).read_bytes())
    raw=json.loads((ROOT/f['shared_sources_fixture']['path']).read_bytes())
    assert shared['packed_w1_hex']==stage['packed_w1_hex'] and initial['expected']['mu_hex']==f['mu_hex']
    assert bytes.fromhex(raw['signature_hex'])[:64]==bytes.fromhex(f['challenge_received_hex'])
    assert f['tr_hex']==initial['expected']['tr_hex'] and f['transaction']==raw['transaction']==initial['transaction']
    context=bytes.fromhex(ref['parameters']['context_hex']);a196=bytes.fromhex(f['transaction']['A196_hex'])
    assert bytes.fromhex(f['mu_preimage_hex'])==bytes.fromhex(f['tr_hex'])+bytes([0,41])+context+a196
    assert f['final_input']['unpadded_bytes']==1088 and f['final_input']['rate_bytes']==136 and f['final_input']['blocks_with_padding']==9
    assert f['final_input']['padding_metadata']=={'suffix':31,'suffix_offset':1088,'last_rate_bit_byte':128,'last_offset':1223}
    assert not f['final_intermediate_goldens_available'] and all(x==0 for x in f['new_computations'].values())
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()],f)
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==47 and v['summary']==summary
    assert v['candidate_trace_generator_calls']==415 and v['reference_trace_generator_calls']==9 and v['trace_generator_calls']==424
    assert v['source_inferred_internal_round_traces']==848 and v['source_inferred_forward_bodies']==16 and v['source_inferred_inverse_bodies']==8 and v['source_inferred_hint_encodings']==65536
    assert v['source_inferred_maximum_logical_caches_during_final_with_reference']==3
    for n in ['new_independent_references','capacity_preflight_calls','standalone_transform_oracle_calls','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:assert v[n]==0
    assert v['final_sponge_source_construction_implemented'] and v['terminal_raw_comparison_is_diagnostic']
    for n in ['complete_row_source_implemented','private_payment_verified','full_security_profile_validated','packed_port_equality_executed','final_intermediate_goldens_available','upstream_capacity_fault_reexecuted','signature_acceptor_implemented']:assert v[n] is False
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
        r=json.loads((HERE/"results/signature-final-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned final source identities and recorded composition scope match")

if __name__=="__main__": main()
