"""Check source and saved proof evidence without replaying a prover."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def identity(path):
    raw = path.read_bytes().replace(b'\r\n', b'\n')
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}

def check(results):
    source = json.loads((HERE/'provenance.json').read_bytes())
    for key, base in [('source_files',HERE), ('repository_files',ROOT)]:
        for name, pin in source[key].items():
            assert identity(base/name) == pin, name
    packages = lambda path: {(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(path.read_text())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    assert source['features_retained_basis_subset'] and source['registry_tuples_root_lock_subset']
    features = json.loads((HERE/'fixtures-features.json').read_bytes())
    basis = json.loads((ROOT/'research/proof-preflight/fixtures/features.json').read_bytes())
    assert features.keys() <= basis.keys()
    assert all(set(value) <= set(basis[name]) for name,value in features.items())
    assert not any(name.startswith('rayon/') or 'parallel' in value for name,value in features.items())
    if results:
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
        assert not any(guard[key] for key in ['timed_out','working_guard_terminated','output_limit_exceeded'])
        assert record['prior_attempt']['exit_code'] == 101
        assert not record['prior_attempt']['accepted'] and not record['prior_attempt']['security_or_resource_change']
        meter = json.loads((HERE/'results/measurement.json').read_bytes())
        assert meter['whole_stark_proofs'] == meter['retained_verifier_accepts'] == 1
        assert set(meter['retained_verifier_rejects']) == {
            'initial_public_value','final_public_value','trace_commitment','quotient_commitment',
            'auxiliary_commitment','trace_opened_value','quotient_opened_value',
            'auxiliary_opened_value','degree_bits','transcript_context'}
        assert len(meter['retained_verifier_rejects']) == 10
        assert meter['encoded_proof_bytes'] == record['proof_identity']['bytes'] <= 2*1024*1024
        assert meter['reserved_files'] == 13 and meter['reserved_field_bytes'] == 1_325_056
        assert meter['proof_produced_after_construction'] and meter['reentry_refused_without_protocol_effects']
        prover = meter['prover_observations']
        assert (prover['input_commits'],prover['extension_commits'],prover['input_multi_opens'],prover['extension_multi_opens']) == (3,9,3,9)
        assert prover['scalar_opens'] == prover['verify_calls'] == 0
        assert prover['dft'] == {'dft_batch':8, 'coset_dft_batch':0, 'idft_batch':0,
            'coset_idft_batch':8, 'lde_batch':0, 'coset_lde_batch':3,
            'coset_lde_batch_with_transform':0, 'coset_lde_batch_with_blocks':0}
        assert meter['correct_verifier_observations']['verify_calls'] == 12
        assert meter['verifier_observations_after_mutations']['verify_calls'] <= 120
        for key in ['correct_verifier_observations','verifier_observations_after_mutations','other_context_verifier_observations']:
            observed = meter[key]
            assert observed['input_commits'] == observed['extension_commits'] == 0
            assert observed['input_openings'] == observed['extension_openings'] == observed['scalar_opens'] == 0
            assert not any(observed['dft'].values()) and observed['mask']['bytes'] == 0
            assert observed['salt']['bytes'] == observed['initial_salt_bytes'] == 32
        assert len(meter['commit_roots']) == 12
    print('Source and saved small proof evidence verified. No prover or verifier replay.')

if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-results', action='store_true')
    check(parser.parse_args().check_results)
