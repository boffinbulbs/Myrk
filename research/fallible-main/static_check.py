"""Verify saved actual main observations and source identities without replay."""
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
    if path.suffix != '.bin':
        raw = raw.replace(b'\r\n', b'\n')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def check():
    manifest = json.loads((HERE / 'provenance.json').read_bytes())
    assert manifest['normalization'] == 'CRLF to LF for text, binary unchanged'
    for key, base in [('source_files', HERE), ('repository_files', ROOT)]:
        for name, pin in manifest[key].items():
            assert identity(base / name) == pin, name
    packages = lambda p: {(v['name'], v['version'], v['source'], v['checksum'])
        for v in tomllib.loads(p.read_text())['package'] if 'source' in v}
    assert packages(HERE / 'Cargo.lock') <= packages(ROOT / 'Cargo.lock')
    features = json.loads((HERE / 'fixtures-features.json').read_bytes())
    assert features == json.loads((ROOT / 'research/fallible-source/fixtures-features.json').read_bytes())
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
    assert native['main_commits'] == 1 and native['source_shape'] == [256, 2]
    assert native['source_bytes'] == 2048 and native['source_counters'] == [1, 513]
    assert (native['leaf_rows'], native['leaf_width'], native['captured_leaf_bytes']) == (4096, 22, 360448)
    assert native['returned_main_fields'] == 24576 and native['committed_salt_preimage_fields'] == 65536
    expected_root = json.loads((ROOT / 'research/source-commitment/fixtures/root.json').read_bytes())['root']
    assert native['actual_root']['cap'] == expected_root
    prefix = json.loads((ROOT / 'research/source-consumption/results/measurement.json').read_bytes())
    assert native['delivered_rng_fingerprints'] == prefix['cases'][0]['delivered_rng_fingerprints']
    assert native['unused_private_opening_before_after'] == [True, True]
    assert (native['main_phase_before'], native['phase_after'], native['closure_cause']) == ('MainCommitted', 'Failed', 'Unwind')
    assert native['reserved_files'] == 13 and native['reserved_bytes'] == 1325056
    assert native['retained_main_field_bytes'] == 112640 and native['cheap_lease_refusals'] == 4
    assert native['reentry_counters'] == [0, 0] and native['anchor_unchanged']
    assert native['complete_proofs'] == native['old_proof_replays'] == native['full_signature_calls'] == 0
    counts = native['counts']
    assert (counts['input_commits'], counts['extension_commits'], counts['get_matrices']) == (1, 0, 1)
    assert (counts['mmcs_clones'], counts['initial_salt_bytes'], counts['mask']['bytes'], counts['salt']['bytes']) == (1, 32, 10948, 279800)
    assert counts['dft']['coset_lde_batch'] == 2
    assert all(v == 0 for k, v in counts['dft'].items() if k != 'coset_lde_batch')
    assert all(counts[k] == 0 for k in ['scalar_opens', 'input_openings', 'extension_openings', 'input_multi_opens', 'extension_multi_opens', 'verify_calls'])
    print('Actual main commitment source and saved observations verified. No source, reference or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
