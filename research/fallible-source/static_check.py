"""Validate source identities and recorded Context failures without replay."""
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
    assert len(features) == manifest['registry_packages'] == 62
    assert manifest['metadata_nodes'] == 66
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
    assert native['source_shape'] == [256, 2] and native['source_bytes'] == 2048
    assert native['source_cases'] == native['failed_owner_reentries'] == 3
    assert native['complete_proofs'] == native['full_signature_calls'] == native['old_proof_replays'] == 0
    cases = native['cases']
    assert [(c['error'], c['counters']) for c in cases] == [('Length', [1, 1]), ('NonCanonicalField', [1, 256]), ('Bounds', [1, 513])]
    for case in cases:
        assert case['reentry'] == [0, 0]
        assert case['outer_phase'] == case['source_phase'] == case['extension_phase'] == 'Failed'
        assert case['raw_entry'] == 'Removed' and case['planned_entries'] == 12
        assert case['reserved_files'] == 13 and case['reserved_bytes'] == 1325056
        assert case['anchor_unchanged'] and case['fingerprints_unchanged']
        counts = case['before']
        assert counts == case['after']
        for key in ['input_commits', 'extension_commits', 'scalar_opens', 'input_openings', 'extension_openings', 'input_multi_opens', 'extension_multi_opens', 'verify_calls', 'get_matrices']:
            assert counts[key] == 0
        assert counts['mmcs_clones'] == 1 and counts['initial_salt_bytes'] == 32
        assert counts['salt']['bytes'] == 32 and counts['mask']['bytes'] == 0
        assert all(v == 0 for v in counts['dft'].values())
    print('Actual fallible owner source and saved Context failures verified. No raw source or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
