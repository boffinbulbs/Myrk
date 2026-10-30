"""Saved source identities and observed matrix composition scope only."""
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
    assert len(records)==692
    def selected(kind):return [r for r in records if r['kind']==kind]
    assert selected('incomplete')==[{'kind':'incomplete','result':'Err(Incomplete)','initial_generation':[0,0,0],'matrix_generation':[0,0,0]}]
    sequence=selected('reference_sequence')
    assert [r['requested'] for r in sequence]==[1,6]
    assert all(r['result']=='Err(Sequence)' and r['prepared']==0 and r['unchanged'] for r in sequence)
    shape=selected('shape_refusal');assert [r['row'] for r in shape]==[0,1]
    assert shape[0]['initial_before']==shape[0]['initial_after']==[0,0,0]
    assert shape[1]['initial_before']==shape[1]['initial_after']==[1,1,1]
    assert all(r['matrix_before']==r['matrix_after']==[0,0,0] and r['result']=='Err(RowShape)' and r['unchanged'] for r in shape)
    squeeze=selected('squeeze_checkpoint');assert len(squeeze)==336
    assert [(r['stream'],r['block'],r['row']) for r in squeeze]==[(s,b,642+48*s+6*b+5) for s in range(56) for b in range(6)]
    assert all(r['bytes']==168 for r in squeeze)
    banks=selected('bank_checkpoint');assert len(banks)==340
    expected=[]
    for at in [0,641]:expected.append({'kind':'bank_checkpoint','row':at,'stream':None,'local':None,'ready_bytes':0,'bytes':1008})
    for s in range(56):
        for local in [0,5,6,35,36,47]:expected.append({'kind':'bank_checkpoint','row':642+48*s+local,'stream':s,'local':local,'ready_bytes':168*min(local//6,6),'bytes':1008})
    for at in [3330,8191]:expected.append({'kind':'bank_checkpoint','row':at,'stream':None,'local':None,'ready_bytes':0,'bytes':1008})
    assert banks==expected
    corrupt=selected('comparator_corruption')
    assert [(r['row'],r['column']) for r in corrupt]==[(0,32796),(642,16271),(647,17615),(648,32796),(653,10531),(3330,32796),(8191,33803)]
    assert all(r['detected'] for r in corrupt)
    assert selected('complete')==[{'kind':'complete','result':'Ok(())'}]
    exhausted=selected('exhaustion');assert len(exhausted)==1
    e=exhausted[0];assert e['result']=='Err(Exhausted)' and e['unchanged']
    assert e['initial_before']==e['initial_after']==[70,70,1] and e['matrix_before']==e['matrix_after']==[336,336,1]
    assert selected('reference_exhaustion')==[{'kind':'reference_exhaustion','result':'Err(Exhausted)','prepared':8192,'before':[336,336,1],'after':[336,336,1],'unchanged':True}]
    summary=selected('matrix_summary');assert len(summary)==1
    expected={'rows':8192,'reference_rows':8192,'reference_windows':1366,'last_reference_rows':2,'hash_rows':2016,
        'hash_comparisons':26651520,'xof_comparisons':8257536,'preserved_comparisons':318788736,
        'forward_preserved_comparisons':227713024,'initial_preserved_comparisons':217997312,
        'rho_bytes':10752,'squeeze_checkpoints':336,'squeeze_bytes':56448,'bank_checkpoints':340,
        'comparator_controls':7,'restored_controls':7,'shape_refusals':2,'sequence_refusals':2,'incomplete_refusals':1,'exhaustion_refusals':1,'reference_exhaustion_refusals':1,
        'initial_generation':[70,70,1],'matrix_generation':[336,336,1],'reference_generation':[336,336,1]}
    assert summary[0]=={'kind':'matrix_summary',**expected}
    return summary[0]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-results',action='store_true');parser.add_argument('--registry-root',type=Path);args=parser.parse_args()
    p=json.loads((HERE/'provenance.json').read_bytes())
    for group,base in [('repository_files',ROOT),('execution_source_files',HERE),('experiment_files',HERE)]:
        for n,pin in p[group].items():assert identity(base/n)==pin,n
    if args.registry_root:
        for n,pin in p['registry_source_files'].items():assert identity(args.registry_root/n)==pin,n
    assert len(packages(HERE/'Cargo.lock'))==89 and packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    features=json.loads((HERE/'fixtures-features.json').read_bytes());baseline=json.loads((HERE.parent/'proof-preflight/fixtures/features.json').read_bytes())
    assert len(features)==89 and features.keys()<=baseline.keys()
    assert all(set(v)<=set(baseline[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert p['local_features']['kova-signature-matrix-source']==['default','matrix-controls'] and not p['native_execution_enabled']
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    a=json.loads((HERE/'adaptation.json').read_bytes())
    assert a['build_prefix_unchanged'] and a['private_children_added']==9 and not a['old_opaque_conversion']
    assert (HERE/'src/build.rs').read_text().startswith((ROOT/a['build_origin']).read_text())
    assert a['hash_owned_ranges']==[[0,10532],[16271,18959]] and a['bank_owned_range']==[32796,33804]
    assert not a['reference_unchanged_full_writer'] and a['reference_window_rows']==6
    assert a['candidate_caches_during_matrix']==2 and not a['candidate_unified_hash_cache']
    assert a['reference_cache_dropped_before_return'] and not a['capacity_preflight_executed']
    assert not a['complete_row_source_implemented'] and not a['matrix_sampler_implemented'] and not a['final_hash_implemented']
    f=json.loads((HERE/'fixtures-matrix.json').read_bytes());ref=json.loads((HERE.parent/'signature-ownership/reference-fixture.json').read_bytes())
    raw=json.loads((HERE.parent/'signature-ownership/raw-fixture.json').read_bytes())
    assert f['selection']=={'key_id':'B','signature_id':'B0','transaction_id':'T0','note_id':'N_B'}
    key=next(r['public_key_hex'] for r in raw['keys'] if r['id']=='B')
    assert f['key_hex']==key and f['rho_hex']==key[:64]
    assert f['signature_hex']==next(r['signature_hex'] for r in raw['signatures'] if r['id']=='B0')
    assert f['note_hex']==ref['notes']['N_B']['opening_hex']
    assert f['transaction']==next(t for t in ref['transactions'] if t['id']=='T0')
    assert f['stream_count']==56 and len(f['streams'])==56 and f['saved_stream_bytes_total']==56448
    for s,stream in enumerate(f['streams']):
        i,j=s%8,s//8;idx=7*i+j;old=ref['key_matrices']['B'][idx]
        assert stream['chronological_index']==s and stream['row']==i and stream['column']==j and stream['original_row_major_index']==idx
        assert old['row']==i and old['column']==j and stream['six_block_stream_hex']==old['six_block_stream_hex']
        assert len(bytes.fromhex(stream['six_block_stream_hex']))==1008
        assert stream['chunks168_hex']==[old['six_block_stream_hex'][336*b:336*(b+1)] for b in range(6)]
        assert stream['historical_sampler_metadata']['cursor']==old['cursor'] and stream['historical_sampler_metadata']['supported_six_blocks']==old['supported_six_blocks']
    assert all(x==0 for x in f['performed_computations'].values())
    summary=observations([json.loads(line) for line in (HERE/'fixtures-observations.jsonl').read_text().splitlines()])
    v=json.loads((HERE/'validation.json').read_bytes());assert v['provenance']==identity(HERE/'provenance.json')
    assert v['integration_tests_passed']==1 and v['observation_records']==692 and v['summary']==summary
    assert v['trace_generator_calls']==742 and v['source_inferred_internal_round_traces']==1484
    assert v['source_inferred_forward_computations']=={'candidate':16,'adapted_reference':0,'total':16}
    assert v['source_inferred_candidate_caches_during_matrix']==2
    for n in ['new_independent_hash_references','capacity_preflight_calls','complete_signature_traces','air_evaluations','backend_proofs','pcs_calls']:assert v[n]==0
    for n in ['complete_row_source_implemented','matrix_sampler_implemented','private_payment_verified','full_security_profile_validated']:assert v[n] is False
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
        r=json.loads((HERE/"results/signature-matrix-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert r["accepted"] and r["expected_tests"]==1 and r["launched"]
        assert [r[k] for k in ["actual_passed","actual_failed","actual_ignored"]]==[1,0,0]
        mapping={"process_limit_bytes":"installed_process_commit_limit_bytes","aggregate_limit_bytes":"installed_job_commit_limit_bytes",
            "minimum_available_bytes":"minimum_available_bytes","available_before_bytes":"available_before_bytes",
            "timeout_seconds":"timeout_seconds","readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(g[k]==r[raw] for k,raw in mapping.items())
    print("Owned matrix source identities and recorded composition scope match")

if __name__=="__main__": main()
