"""Streamed overlay source and saved native evidence. No witness replay."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def identity(path):
    with path.open('rb') as stream:
        raw=stream.read(16_777_217)
    if len(raw)>16_777_216:
        raise ValueError('fixed source read bound exceeded')
    raw=raw.replace(b'\r\n',b'\n')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def check():
    manifest=json.loads((HERE/'provenance.json').read_bytes())
    for key,base in [('source_files',HERE),('repository_files',ROOT)]:
        for name,pin in manifest[key].items():
            assert identity(base/name)==pin,name
    packages=lambda p:{(v['name'],v['version'],v['source'],v['checksum'])
        for v in tomllib.loads(p.read_text())['package'] if 'source' in v}
    assert packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    features=json.loads((HERE/'fixtures-features.json').read_bytes())
    assert features==json.loads((ROOT/'research/signature-overlay/fixtures-features.json').read_bytes())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    assert (HERE/'LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes()
    record=json.loads((HERE/'validation.json').read_bytes())
    assert record['source_manifest_sha256']==identity(HERE/'provenance.json')['sha256']
    for name,pin in record['artifacts'].items():
        assert identity(HERE/name)==pin,name
    guard=record['guard']
    assert guard['accepted'] and guard['exit_code']==0 and guard['test_counts_verified'] and guard['hard_limit_installed']
    assert (guard['expected_tests'],guard['actual_passed'],guard['actual_failed'],guard['actual_ignored'])==(1,1,0,0)
    assert guard['installed_process_commit_limit_bytes']==guard['installed_job_commit_limit_bytes']==536870912
    assert guard['available_before_bytes']>=guard['minimum_available_bytes']==2147483648
    assert guard['timeout_seconds']==120 and guard['installed_job_flags']==8960
    assert not any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded'])
    measurement=json.loads((HERE/'results/measurement.json').read_bytes())
    summary=measurement['summary']
    assert (summary['height'],summary['width'],summary['public_values'])==(8192,42178,196)
    assert (summary['source_walks'],summary['baseline_frames'],summary['negative_frames'],summary['restored_frames'],summary['complete_air_calls'])==(1,8192,12,12,8216)
    assert summary['reference_comparisons']==[4096,2048,20480,1024]
    assert summary['mode_rows']==[3328,256,4608]
    assert summary['trace_generator_calls']==415 and measurement['journal_records']==42
    for key in ['whole_trace_allocations','symbolic_collections','backend_proofs','new_reference_generations']:
        assert summary[key]==0
    controls={c['case']:c for c in measurement['controls']}
    assert len(controls)==12
    for control in controls.values():
        assert control['failures']>0 and control['restored_failures']==0 and control['expected_seen']
    for case,index in [('idle_bank',585),('same_note_owner',27433),('hint_suffix',2273),('final_signature',26217),('transaction_context',27339)]:
        assert controls[case]['first_indices']==[index]
    assert controls['product_result_bit']['first_indices']==[47076,47077,53758,53759]
    assert controls['inverse_result_bit']['first_indices']==[47076,47077,53759]
    assert controls['hint_input_bit']['first_indices']==[68612,68615,69559]
    print('Streamed overlay source and recorded native evidence verified. No source, AIR or reference replay.')


if __name__=='__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
