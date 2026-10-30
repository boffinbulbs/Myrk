"""Saved source and actual finite frame observations, without native replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib
if not __debug__:raise RuntimeError('Optimized checks refused')
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BASELINES=[0,63,74,233,255,413,447,5315,5368,5369,8190,8191]
CASES={0:[('current_clock',87,[0,1,5,576,6127,6128,6129,6130])],63:[('high_carry',2,[194,197])],5315:[('held_next',1,[580])],5369:[('selected_byte',1,[6158])],8190:[('compensated_non_boolean',2,[6103,6104]),('unused_port',1,[6315]),('local_virtual_tail',1,[6131])]}
def identity(path):
    b=path.read_bytes().replace(b'\r\n',b'\n');return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def packages(path):return {(p['name'],p['version'],p['source'],p['checksum']) for p in tomllib.loads(path.read_text(encoding='utf-8'))['package'] if 'source' in p}
def observations(records):
    assert len(records)==29
    assert records[0]=={'kind':'source_start','height':8192,'width':43176,'public_values':196,'preprocessed_columns':0,'periodic_columns':0,'boundary_io':0}
    expected=[]
    for row in BASELINES:
        expected.append((row,'baseline','genuine',0,[]))
        for case,count,indices in CASES.get(row,[]):
            expected.extend([(row,'negative',case,count,indices),(row,'restored',case,0,[])])
    assert len(expected)==26
    for r,(row,phase,case,count,indices) in zip(records[1:27],expected):
        assert r=={'kind':'frame_evaluation','row':row,'next_row':(row+1)%8192,'phase':phase,'case':case,'first':row==0,'last':row==8191,'transition':row!=8191,'failure_count':count,'first_indices':indices,'failure_rows_match':True,'clock_called':True,'packed_called':True}
    assert records[27]=={'kind':'source_complete','position':[8192,8192,False],'result':'Ok(())'}
    s={'kind':'frame_summary','source_rows':8192,'baseline_pairs':12,'negative_evaluations':7,'restored_evaluations':7,'positive_evaluations':19,'combined_frame_evaluations':26,'clock_evaluations':26,'packed_evaluations':26,'source_inferred_failure_bound_per_evaluation':6502,'clean_constraint_count_measured':False,'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'final_generation':[9,9,1],'candidate_trace_generator_calls':415,'reference_trace_generator_calls':0,'preserved_comparisons':306683904,'prefix_preserved':[352983912,337117184,341107472,293511168,318788736,227713024,217997312],'complete_streamed_row_walks':1,'complete_wide_trace_allocations':0,'whole_air_evaluations':0,'packed_port_air_signature_equality_executed':False,'backend_proofs':0,'old_controls_reexecuted':False}
    assert records[-1]==s
    return s
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-results',action='store_true');parser.add_argument('--registry-root',type=Path);args=parser.parse_args()
    p=json.loads((HERE/'provenance.json').read_bytes())
    for group,base in [('repository_files',ROOT),('execution_source_files',HERE),('experiment_files',HERE)]:
        for name,pin in p[group].items():assert identity(base/name)==pin,name
    if args.registry_root:
        for name,pin in p['registry_source_files'].items():assert identity(args.registry_root/name)==pin,name
    assert packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock') and len(packages(HERE/'Cargo.lock'))==89
    features=json.loads((HERE/'fixtures-features.json').read_bytes());baseline=json.loads((HERE.parent/'proof-preflight/fixtures/features.json').read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys() and all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert p['local_features']['kova-signature-frame-native']==['frame-controls'] and not p['native_execution_enabled']
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==18 and not a['old_port_reference_or_controls_included']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert not a['old_opaque_conversion'] and a['source_unchanged'] and a['actual_callees_unchanged'] and a['clock_then_packed_unconditional']
    assert (a['frame_width'],a['height'],a['public_values'],a['row_buffers'])==(43176,8192,196,3) and a['baseline_rows']==BASELINES
    assert a['source_inferred_failure_bound_per_evaluation']==6502 and not a['clean_constraint_count_measured'] and a['failure_output_prefix']==8
    assert not a['default_full_constructor_enabled'] and not a['signature_acceptor_implemented'] and not a['packed_port_air_signature_equality_executed']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    s=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()])
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json') and v['summary']==s
    assert v['integration_tests_passed']==1 and v['observation_records']==29
    for name,value in {'candidate_trace_generator_calls':415,'reference_trace_generator_calls':0,'source_inferred_internal_round_traces':830,'source_inferred_forward_bodies':16,'source_inferred_inverse_bodies':8,'source_inferred_hint_encodings':65536,'source_inferred_maximum_logical_caches_during_final':2,'complete_streamed_row_walks':1,'clock_evaluations':26,'packed_evaluations':26,'positive_evaluations':19,'negative_evaluations':7,'restored_evaluations':7}.items():assert v[name]==value
    for name in ['complete_wide_trace_allocations','whole_air_evaluations','backend_proofs','pcs_calls','new_independent_references','capacity_preflight_calls']:assert v[name]==0
    for name in ['default_full_constructor_enabled','packed_port_air_signature_equality_executed','signature_acceptor_implemented','private_payment_verified','full_security_profile_validated','old_controls_reexecuted','clean_constraint_count_measured']:assert v[name] is False
    g=v['guard'];assert g['process_limit_bytes']==g['aggregate_limit_bytes']==536870912
    assert g['minimum_available_bytes']==2147483648 and g['timeout_seconds']==120 and g['readback_flags']==8960
    assert g['available_before_bytes']>=g['minimum_available_bytes'] and g['test_counts_verified'] and g['hard_limit_installed'] and g['exit_code']==0
    assert 0<g['peak_process_private_commit_bytes']<=g['process_limit_bytes'] and 0<g['peak_job_commit_bytes']<=g['aggregate_limit_bytes']
    assert not any(g[k] for k in ['timed_out','output_limit_exceeded','working_guard_terminated'])
    if args.check_results:
        assert (HERE/'results/observations.jsonl').read_bytes()==(HERE/'fixtures-observations.jsonl').read_bytes()
        r=json.loads((HERE/'results/signature-frame-native-v1-memory-result.json').read_text(encoding='utf-8-sig'))
        assert r['accepted'] and r['expected_tests']==1 and r['launched'] and [r[k] for k in ['actual_passed','actual_failed','actual_ignored']]==[1,0,0]
        mapping={'process_limit_bytes':'installed_process_commit_limit_bytes','aggregate_limit_bytes':'installed_job_commit_limit_bytes','minimum_available_bytes':'minimum_available_bytes','available_before_bytes':'available_before_bytes','timeout_seconds':'timeout_seconds','readback_flags':'installed_job_flags','peak_job_commit_bytes':'peak_job_commit_bytes','peak_process_private_commit_bytes':'peak_private_commit_bytes','test_counts_verified':'test_counts_verified','exit_code':'exit_code','hard_limit_installed':'hard_limit_installed','timed_out':'timed_out','output_limit_exceeded':'output_limit_exceeded','working_guard_terminated':'working_guard_terminated'}
        assert all(g[k]==r[raw] for k,raw in mapping.items()) and not (HERE/'results/signature-frame-native-v1.stderr.txt').read_bytes()
    print('Genuine frame source identities and saved actual constraint outcomes match')
if __name__=='__main__':main()
