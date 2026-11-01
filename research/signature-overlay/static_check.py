"""Complete overlay source and saved symbolic checks. No AIR replay."""
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
        raise ValueError('fixed source bound exceeded')
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
    basis = json.loads((ROOT/'research/signature-packed/fixtures-features.json').read_bytes())
    assert features == basis
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
    result = json.loads((HERE/'results/symbolic.json').read_bytes())
    assert (result['height'],result['columns'],result['public_values'],result['constraints'],result['degree']) == (8192,42178,196,71623,4)
    assert result['degree_histogram'] == [72,3295,46690,20884,682,0,0,0]
    assert result['degrees_outside_histogram'] == 0
    assert result['symbolic_collections'] == 1 and result['native_traces'] == result['backend_proofs'] == 0
    assert not result['full_signature_witness_checked']
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Complete overlay source and saved symbolic result verified. No AIR or native trace replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
