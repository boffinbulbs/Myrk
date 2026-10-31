"""Source and saved live failure validation without proving or fault replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def identity(path):
    raw = path.read_bytes().replace(b'\r\n',b'\n')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def check(results):
    source = json.loads((HERE/'provenance.json').read_bytes())
    for key,base in [('source_files',HERE),('repository_files',ROOT)]:
        for name,pin in source[key].items(): assert identity(base/name) == pin, name
    packages = lambda path: {(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(path.read_text())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    features = json.loads((HERE/'fixtures-features.json').read_bytes())
    basis = json.loads((ROOT/'research/proof-preflight/fixtures/features.json').read_bytes())
    assert features.keys() <= basis.keys()
    assert all(set(value) <= set(basis[name]) for name,value in features.items())
    assert not any(name.startswith('rayon/') or 'parallel' in value for name,value in features.items())
    if results:
        validation = json.loads((HERE/'validation.json').read_bytes())
        assert validation['source_manifest_sha256'] == identity(HERE/'provenance.json')['sha256']
        for name,pin in validation['artifacts'].items(): assert identity(HERE/name) == pin, name
        guard = validation['guard']
        assert guard['accepted'] and guard['exit_code'] == 0 and guard['test_counts_verified']
        assert (guard['expected_tests'],guard['actual_passed'],guard['actual_failed'],guard['actual_ignored']) == (1,1,0,0)
        assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
        assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
        assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
        assert not any(guard[name] for name in ['timed_out','working_guard_terminated','output_limit_exceeded'])
        meter = json.loads((HERE/'results/measurement.json').read_bytes())
        assert meter['completed_proofs'] == meter['verifier_calls'] == 0
        assert [c['case'] for c in meter['cases']] == ['truncated_quotient','auxiliary_collision']
        for auxiliary,case in enumerate(meter['cases']):
            assert case['closed_actual_lease_aliases'] == 2
            assert case['sentinel_preserved_and_removed'] is bool(auxiliary)
            assert case['reentry_refused_without_protocol_effects']
            assert case['reserved_files'] == 13 and case['reserved_field_bytes'] == 1_325_056
            assert case['expected_first_cause'] == ['Access(Length)','Io(AlreadyExists)'][auxiliary]
            assert case['failure_boundary'] == ['typed return','actual unwind'][auxiliary]
            c = case['observations']
            assert c['input_commits'] == 1+auxiliary and c['get_matrices'] == c['mmcs_clones'] == 1
            assert len(case['actual_commit_roots']) == 1+auxiliary
            assert all(c[k] == 0 for k in ['extension_commits','scalar_opens','input_openings',
                'extension_openings','input_multi_opens','extension_multi_opens','verify_calls'])
            assert c['dft'] == {'coset_dft_batch':0,'coset_idft_batch':8*auxiliary,
                'coset_lde_batch':2+auxiliary,'coset_lde_batch_with_blocks':0,
                'coset_lde_batch_with_transform':0,'dft_batch':8*auxiliary,'idft_batch':0,'lde_batch':0}
            assert c['mask']['bytes'] == [107188,124664][auxiliary]
            assert c['salt']['bytes'] == [279800,2517396][auxiliary]
            assert c['initial_salt_bytes'] == 32
    print('Source and saved live failure evidence verified. No fault, prover or verifier replay.')

if __name__ == '__main__':
    if not __debug__: raise RuntimeError('Optimized validation refused')
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-results',action='store_true')
    check(parser.parse_args().check_results)
