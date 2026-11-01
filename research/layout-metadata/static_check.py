"""Saved fixed AIR metadata evidence. No AIR, witness or proof execution."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def data(path):
    with path.open('rb') as stream:
        raw = stream.read(16_777_217)
    if len(raw) > 16_777_216:
        raise ValueError('source record bound exceeded')
    return raw.replace(b'\r\n', b'\n')


def identity(path):
    raw = data(path)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def check():
    provenance = json.loads(data(HERE/'provenance.json'))
    for section, base in (('source_files', HERE), ('repository_files', ROOT)):
        for name, pin in provenance[section].items():
            assert identity(base/name) == pin, name
    packages = lambda path: {(p['name'], p['version'], p['source'], p['checksum'])
        for p in tomllib.loads(data(path).decode())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    basis = json.loads(data(ROOT/'research/signature-overlay/fixtures-features.json'))
    assert provenance['metadata_nodes'] == 85
    assert len(provenance['registry_packages']) == 80
    for package in provenance['registry_packages']:
        key = package['name']+'/'+package['version']
        assert set(package['features']) <= set(basis[key])
        assert 'parallel' not in package['features'] and package['license']
    assert provenance['imported_overlay_features'] == []
    record = json.loads(data(HERE/'validation.json'))
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native'] == identity(HERE/'results/metadata.json')
    guard = record['native_guard']
    assert guard['accepted'] and guard['hard_limit_installed'] and guard['exit_code'] == 0
    assert guard['test_counts_verified']
    assert (guard['expected_tests'], guard['actual_passed'], guard['actual_failed'], guard['actual_ignored']) == (1, 1, 0, 0)
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_private_commit_bytes'] <= 536870912
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[k] for k in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    native = json.loads(data(HERE/'results/metadata.json'))
    prior = json.loads(data(ROOT/'research/signature-overlay/results/symbolic.json'))
    assert (native['height'], native['columns'], native['public_values']) == (8192, 42178, 196)
    assert native['assertions'] == prior['constraints'] == 71623
    assert native['degree_histogram'] == prior['degree_histogram'] == [72, 3295, 46690, 20884, 682, 0, 0, 0]
    assert native['attached_metadata_charges'] == 3975662 <= 20000000
    assert native['independent_controls'] == 24 and native['actual_air_evaluations'] == 1
    assert native['requested_variable_bytes'] == 84552 * native['expression_bytes']
    assert native['expression_bytes'] == 40 and native['variable_capacity'] >= 84552
    assert native['assertion_capacity'] >= 80000
    assert [native[k] for k in ('symbolic_graph_collections', 'witness_frames', 'proofs')] == [0, 0, 0]
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Saved complete AIR metadata identities verified. No AIR or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
