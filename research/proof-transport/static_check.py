"""Validate retained decoder evidence without executing it or parsing its proof."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def data(path, raw=False):
    with path.open('rb') as stream:
        value = stream.read(2_097_153)
    if len(value) > 2_097_152:
        raise ValueError('evidence read bound exceeded')
    return value if raw else value.replace(b'\r\n', b'\n')


def identity(path, raw=False):
    value = data(path, raw)
    return dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())


def check():
    provenance = json.loads(data(HERE / 'provenance.json'))
    for name, pin in provenance['source_files'].items():
        assert identity(HERE / name, name == 'fixtures/proof.json') == pin, name
    for name, pin in provenance['imported_source_files'].items():
        assert identity(ROOT / name) == pin, name
    assert provenance['prior_proof_fixture'] == identity(HERE/'fixtures/proof.json', True)['sha256']
    packages = lambda path: {(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(data(path).decode())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    prior = json.loads(data(ROOT/'research/fallible-main/fixtures-features.json'))
    assert provenance['metadata_nodes'] == 64 and len(provenance['registry_packages']) == 62
    for package in provenance['registry_packages']:
        assert set(package['features']) <= set(prior[package['name']+'/'+package['version']])
        assert 'parallel' not in package['features'] and package['license']
    validation = json.loads(data(HERE/'validation.json'))
    assert validation['provenance'] == identity(HERE/'provenance.json')
    assert validation['native'] == identity(HERE/'results/native.json')
    for name, guard in validation['guards'].items():
        assert guard['accepted'] and guard['exit_code'] == 0 and guard['hard_limit_installed']
        assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
        assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
        assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
        assert 0 < guard['peak_job_commit_bytes'] <= 536870912
        assert not any(guard[k] for k in ('timed_out','working_guard_terminated','output_limit_exceeded'))
        if name == 'proof-transport-v1':
            assert (guard['expected_tests'],guard['actual_passed'],guard['actual_failed'],guard['actual_ignored']) == (1,1,0,0)
            assert guard['test_counts_verified']
        else:
            assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    native = json.loads(data(HERE/'results/native.json'))
    assert native['fixture_bytes'] == 596650
    assert native['canonical_original_decodes'] == dict(admissions=4,typed_decodes=4,decoded_shapes=4,canonical_encodings=4)
    assert native['altered_commitment_decodes_without_verification'] == dict(admissions=1,typed_decodes=1,decoded_shapes=1,canonical_encodings=1)
    assert [native[k] for k in ('resource_refusals_before_decode','encoding_shape_canonical_refusals','canonical_writer_controls')] == [14,14,4]
    assert [native[k] for k in ('proofs_produced','verifier_calls','pcs_instances','full_signature_calls','network_reads')] == [0,0,0,0,0]
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Saved bounded decoder evidence and exact source identities verified. No diagnostic replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
