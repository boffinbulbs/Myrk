"""Check saved source identities and native evidence without replaying inputs."""
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
        raise ValueError('fixed source read bound exceeded')
    raw = raw.replace(b'\r\n', b'\n')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def check():
    manifest = json.loads((HERE / 'provenance.json').read_bytes())
    for key, base in [('source_files', HERE), ('repository_files', ROOT)]:
        for name, pin in manifest[key].items():
            assert identity(base / name) == pin, name
    packages = lambda p: {(v['name'], v['version'], v['source'], v['checksum'])
        for v in tomllib.loads(p.read_text())['package'] if 'source' in v}
    assert packages(HERE / 'Cargo.lock') <= packages(ROOT / 'Cargo.lock')
    features = json.loads((HERE / 'fixtures-features.json').read_bytes())
    basis = json.loads((ROOT / 'research/source-consumption/fixtures-features.json').read_bytes())
    assert all(k in basis and set(v) <= set(basis[k]) for k, v in features.items())
    assert not any(k.startswith('rayon/') or 'parallel' in v for k, v in features.items())
    assert len(features) == manifest['registry_packages'] == 54
    assert manifest['metadata_nodes'] == 57
    assert (HERE / 'LICENSE').read_bytes() == (ROOT / 'LICENSE').read_bytes()
    record = json.loads((HERE / 'validation.json').read_bytes())
    assert record['source_manifest_sha256'] == identity(HERE / 'provenance.json')['sha256']
    for name, pin in record['artifacts'].items():
        assert identity(HERE / name) == pin, name
    guard = record['guard']
    assert guard['accepted'] and guard['exit_code'] == 0 and guard['test_counts_verified'] and guard['hard_limit_installed']
    assert (guard['expected_tests'], guard['actual_passed'], guard['actual_failed'], guard['actual_ignored']) == (1, 1, 0, 0)
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert not any(guard[k] for k in ['timed_out', 'working_guard_terminated', 'output_limit_exceeded'])
    native = json.loads((HERE / 'results/native.json').read_bytes())
    assert native['source_shape'] == [4, 3] and native['source_bytes'] == 48
    assert native['primary_cases'] == 15 and native['failed_owner_reentries'] == 5
    assert (native['reference_field_comparisons'], native['reference_byte_comparisons']) == (24, 96)
    assert native['maximum_store_reservation'] == 48 and native['maximum_store_files'] == 1
    assert native['complete_proofs'] == native['full_signature_calls'] == 0
    cases = native['cases']
    assert len(cases) == 15
    success = [c for c in cases if c['kind'] == 'success']
    assert {c['legacy'] for c in success} == {False, True} and len(success) == 2
    assert all(c['counters'] == [1, 13] and c['bytes'] == 48 and c['fields'] == 12 for c in success)
    faults = [c for c in cases if c['kind'] == 'source_error']
    assert [(c['error'], c['counters']) for c in faults] == [('Length', [1, 7]), ('NonCanonicalField', [1, 6]), ('Bounds', [1, 13])]
    assert all(c['reentry'] == [0, 0] for c in faults)
    metadata = [c for c in cases if c['kind'] == 'metadata_refusal']
    assert len(metadata) == 8
    assert {(c['legacy'], tuple(c['shape'])) for c in metadata} == {(legacy, shape) for legacy in [False, True] for shape in [(0, 3), (3, 3), (8192, 3), (8192, 42178)]}
    assert all(c['counters'] == [0, 0] for c in metadata)
    collisions = [c for c in cases if c['kind'] == 'output_collision']
    assert len(collisions) == 2 and {c['legacy'] for c in collisions} == {False, True}
    assert all(c['counters'] == c['reentry'] == [0, 0] for c in collisions)
    print('Deferred raw source identities and saved native evidence verified. No input, AIR or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
