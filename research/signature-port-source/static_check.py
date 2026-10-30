"""Source identities and saved construction scope, without native replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib
if not __debug__:
    raise RuntimeError("Optimized Python cannot check source identities")
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
PROBES=[0,1,63,64,74,75,233,234,235,255,256,413,414,447,448,5315,5316,5368,5369,5370,8191]
def identity(path):
    data=path.read_bytes().replace(b"\r\n",b"\n")
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def packages(path):
    return {(p['name'],p['version'],p['source'],p['checksum']) for p in tomllib.loads(path.read_text(encoding='utf-8'))['package'] if 'source' in p}
def observations(records):
    assert len(records)==38
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)'}]
    seq=selected('reference_sequence');assert [x['requested'] for x in seq]==[1,64]
    assert all(x['unchanged'] and x['result']=='Err(Sequence)' for x in seq)
    shape=selected('shape_refusal');assert [x['row'] for x in shape]==[0,5369,8191]
    for x in shape:
        assert x['before']==x['after'] and x['unchanged'] and x['result']=='Err(RowShape)'
        at=x['row'];assert x['before'][3]==[at,at,False]
        assert x['before'][:2]==([[0,0,0],[0,0,0]] if at==0 else [[70,70,1],[336,336,1]])
        assert x['before'][2]==({0:[0,0,0],5369:[9,9,1],8191:[9,9,1]}[at])
    probes=selected('probe');assert [x['row'] for x in probes]==PROBES
    assert all(x['shared_helper_fields']==5739 and 0<x['used_ports']<=125 and x['selected_source_reads']>=40 for x in probes)
    assert selected('terminal_port_diagnostic')==[{'kind':'terminal_port_diagnostic','row':5369,'bytes':64,'packed_port_air_equality_executed':False}]
    controls=selected('comparator_control')
    assert [(x['row'],x['column']) for x in controls]==[(0,10532),(64,10597),(234,13178),(447,13351),(5369,13775),(8191,16247)]
    assert all(x['detected'] and x['restored'] for x in controls)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())','position':[8192,8192,False]}]
    assert selected('exhaustion')==[{'kind':'exhaustion','result':'Err(Exhausted)','unchanged':True}]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','unchanged':True}]
    summary=selected('port_summary');assert len(summary)==1 and records[-1]==summary[0]
    s=summary[0]
    expected={'kind':'port_summary','rows':8192,'reference_rows':21,'clock_checks':1572864,'held_word_checks':20865024,'port_bit_checks':24576000,'owned_comparisons':47013888,'preserved_comparisons':306683904,
              'prefix_preserved':[352983912,337117184,341107472,293511168,318788736,227713024,217997312],
              'shared_helper_comparisons':120519,'virtual_zero_bytes':84,'comparator_controls':6,
              'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'final_generation':[9,9,1],
              'candidate_trace_generator_calls':415,'reference_trace_generator_calls':0,'complete_streamed_row_walks':1,'complete_wide_trace_allocations':0,'whole_air_evaluations':0,'clock_air_evaluations':0,'packed_air_evaluations':0,'packed_port_air_equality_executed':False,'backend_proofs':0}
    assert set(s)==set(expected)|{'selected_source_reads','used_port_visits'}
    assert all(s[k]==v for k,v in expected.items())
    assert s['selected_source_reads']==sum(x['selected_source_reads'] for x in probes)
    assert sum(x['used_ports'] for x in probes)<=s['used_port_visits']<=8192*125
    return s
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-results',action='store_true');parser.add_argument('--registry-root',type=Path);args=parser.parse_args()
    p=json.loads((HERE/'provenance.json').read_bytes())
    for group,base in [('repository_files',ROOT),('execution_source_files',HERE),('experiment_files',HERE)]:
        for name,pin in p[group].items():assert identity(base/name)==pin,name
    if args.registry_root:
        for name,pin in p['registry_source_files'].items():assert identity(args.registry_root/name)==pin,name
    assert len(packages(HERE/'Cargo.lock'))==89 and packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    features=json.loads((HERE/'fixtures-features.json').read_bytes());baseline=json.loads((HERE.parent/'proof-preflight/fixtures/features.json').read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys() and all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert p['local_features']['kova-signature-port-source']==['port-controls'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==19 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['owned_ranges']==[[10532,16271]] and a['owned_row_range']==[0,8192]
    assert (a['clock_fields'],a['held_words'],a['ports'],a['bits_per_port'])==(192,2547,125,24)
    assert a['reference_rows']==PROBES and a['reference_buffer_fields']==16271
    assert a['reference_uses_unchanged_row_helper'] and not a['reference_unchanged_full_writer']
    assert a['streamed_row_source_implemented'] and not a['default_full_constructor_enabled']
    assert a['terminal_port_comparison_is_diagnostic'] and not a['packed_port_air_equality_executed'] and not a['signature_acceptor_implemented']
    assert a['maximum_route_epochs']==451 and a['maximum_epoch_words']==125 and not a['payload_bounds_are_allocation_measurements']
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()])
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['summary']==summary and v['integration_tests_passed']==1 and v['observation_records']==38
    for name,value in {'candidate_trace_generator_calls':415,'reference_trace_generator_calls':0,'source_inferred_internal_round_traces':830,'source_inferred_forward_bodies':16,'source_inferred_inverse_bodies':8,'source_inferred_hint_encodings':65536,'source_inferred_maximum_logical_caches_during_final':2,'complete_streamed_row_walks':1}.items():assert v[name]==value
    for name in ['new_independent_references','capacity_preflight_calls','standalone_transform_oracle_calls','complete_wide_trace_allocations','whole_air_evaluations','clock_air_evaluations','packed_air_evaluations','backend_proofs','pcs_calls']:assert v[name]==0
    assert v['streamed_row_source_implemented'] and v['terminal_port_comparison_is_diagnostic']
    for name in ['default_full_constructor_enabled','private_payment_verified','full_security_profile_validated','packed_port_air_equality_executed','signature_acceptor_implemented','old_route_or_padding_corpus_reexecuted']:assert v[name] is False
    g=v['guard'];assert g['process_limit_bytes']==g['aggregate_limit_bytes']==536870912
    assert g['minimum_available_bytes']==2147483648 and g['timeout_seconds']==120 and g['readback_flags']==8960
    assert g['available_before_bytes']>=g['minimum_available_bytes'] and g['test_counts_verified'] and g['hard_limit_installed'] and g['exit_code']==0
    assert 0<g['peak_process_private_commit_bytes']<=g['process_limit_bytes'] and 0<g['peak_job_commit_bytes']<=g['aggregate_limit_bytes']
    assert not any(g[k] for k in ['timed_out','output_limit_exceeded','working_guard_terminated'])
    if args.check_results:
        assert (HERE/'results/observations.jsonl').read_bytes()==(HERE/'fixtures-observations.jsonl').read_bytes()
        r=json.loads((HERE/'results/signature-port-source-v1-memory-result.json').read_text(encoding='utf-8-sig'))
        assert r['accepted'] and r['expected_tests']==1 and r['launched'] and [r[k] for k in ['actual_passed','actual_failed','actual_ignored']]==[1,0,0]
        mapping={'process_limit_bytes':'installed_process_commit_limit_bytes','aggregate_limit_bytes':'installed_job_commit_limit_bytes','minimum_available_bytes':'minimum_available_bytes','available_before_bytes':'available_before_bytes','timeout_seconds':'timeout_seconds','readback_flags':'installed_job_flags','peak_job_commit_bytes':'peak_job_commit_bytes','peak_process_private_commit_bytes':'peak_private_commit_bytes','test_counts_verified':'test_counts_verified','exit_code':'exit_code','hard_limit_installed':'hard_limit_installed','timed_out':'timed_out','output_limit_exceeded':'output_limit_exceeded','working_guard_terminated':'working_guard_terminated'}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
        assert not (HERE/'results/signature-port-source-v1.stderr.txt').read_bytes()
    print('Owned clock and packed source identities and recorded construction scope match')
if __name__=='__main__':main()
