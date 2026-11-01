"""Source and saved native evidence checks. No arithmetic or AIR replay."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    with path.open('rb') as stream:
        raw = stream.read(16_777_217)
    if len(raw) > 16_777_216:
        raise ValueError('fixed source read cap exceeded')
    raw = raw.replace(b'\r\n', b'\n')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def check():
    manifest = json.loads((HERE/'provenance.json').read_bytes())
    for key,base in [('source_files',HERE),('repository_files',ROOT)]:
        for name,pin in manifest[key].items():
            assert identity(base/name) == pin, name
    packages = lambda p:{(v['name'],v['version'],v['source'],v['checksum'])
        for v in tomllib.loads(p.read_text())['package'] if 'source' in v}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    features = json.loads((HERE/'fixtures-features.json').read_bytes())
    basis = json.loads((ROOT/'research/proof-preflight/fixtures/features.json').read_bytes())
    assert features.keys() <= basis.keys()
    assert all(set(v) <= set(basis[k]) for k,v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k,v in features.items())
    record = json.loads((HERE/'validation.json').read_bytes())
    assert record['source_manifest_sha256'] == identity(HERE/'provenance.json')['sha256']
    for name,pin in record['artifacts'].items():
        assert identity(HERE/name) == pin, name
    guard = record['guard']
    assert guard['accepted'] and guard['exit_code'] == 0 and guard['test_counts_verified']
    assert (guard['expected_tests'],guard['actual_passed'],guard['actual_failed'],guard['actual_ignored']) == (1,1,0,0)
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert not any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded'])
    meter = json.loads((HERE/'results/measurement.json').read_bytes())
    assert (meter['height'],meter['width'],meter['public_values'],meter['constraints_per_row'],meter['degree']) == (8192,1930,16,5889,3)
    assert (meter['symbolic_collections'],meter['constructed_traces'],meter['maximum_live_traces'],meter['full_positive_scans']) == (1,1,1,1)
    assert meter['native_trace_field_bytes'] == 63242240
    assert meter['mode_rows'] == [3328,256,4608]
    assert meter['negative_borrowed_frames'] == meter['restored_positive_frames'] == 32
    assert meter['backend_proofs'] == 0 and not meter['full_signature_layout_integrated']
    assert len(meter['controls']) == 16
    for control in meter['controls']:
        assert any(control['failure_counts']) and control['restored_positive_frames'] == 2
    controls = {c['case']:c for c in meter['controls']}
    assert 582 in controls['product_mode_suppression']['first_indices'][1]
    assert 584 in controls['simultaneous_modes']['first_indices'][1]
    assert controls['hint_suffix_stale_value']['first_indices'][1] == [2305]
    assert controls['idle_stale_value']['first_indices'][1] == [617]
    assert 579 in controls['last_clock_indicator']['first_indices'][1]
    print('Overlay source and saved native evidence verified. No AIR, trace or reference producer replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
