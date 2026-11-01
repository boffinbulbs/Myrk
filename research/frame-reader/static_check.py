"""Verify saved reader evidence and source pins without native or proof replay."""
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
        raise ValueError('fixed evidence bound exceeded')
    return value if raw else value.replace(b'\r\n', b'\n')


def identity(path, raw=False):
    value = data(path, raw)
    return dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())


def check():
    provenance = json.loads(data(HERE/'provenance.json'))
    for name, pin in provenance['source_files'].items():
        assert identity(HERE/name) == pin, name
    for name, pin in provenance['imported_source_files'].items():
        assert identity(ROOT/name, name.endswith('/fixtures/proof.json')) == pin, name
    packages = lambda path: {(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(data(path).decode())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    prior = json.loads(data(ROOT/'research/proof-transport/provenance.json'))
    features = {p['name']+'/'+p['version']: set(p['features']) for p in prior['registry_packages']}
    assert provenance['metadata_nodes'] == 64 and len(provenance['registry_packages']) == 62
    for package in provenance['registry_packages']:
        assert set(package['features']) <= features[package['name']+'/'+package['version']]
        assert 'parallel' not in package['features'] and package['license']
    record = json.loads(data(HERE/'validation.json'))
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native'] == identity(HERE/'results/native.json')
    for name, guard in record['guards'].items():
        assert guard['accepted'] and guard['exit_code'] == 0 and guard['hard_limit_installed']
        assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
        assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
        assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
        assert 0 < guard['peak_job_commit_bytes'] <= 536870912
        assert not any(guard[k] for k in ('timed_out','working_guard_terminated','output_limit_exceeded'))
        if name == 'frame-reader-v1':
            assert (guard['expected_tests'],guard['actual_passed'],guard['actual_failed'],guard['actual_ignored']) == (1,1,0,0)
            assert guard['test_counts_verified']
        else:
            assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    native = json.loads(data(HERE/'results/native.json'))
    assert native['fixture_bytes'] == 596650
    for name in ('owned_file_positive','fragmented_positive'):
        result = native[name]
        assert result['spent'] and result['bytes_read'] == 596658 and result['wire_credit_spent'] == 596659
        assert result['payload_reservations'] == 1 and result['requested_payload_bytes'] == 596650
        assert result['payload_capacity'] >= 596650
        assert result['decode'] == dict(admissions=1,typed_decodes=1,decoded_shapes=1,canonical_encodings=1)
    assert native['owned_file_positive']['read_calls'] == 3
    assert native['fragmented_positive']['read_calls'] == 85239
    rows = native['failure_snapshots']
    assert len(rows) == 14 and all(len(r) == 11 and r[0] == 1 and r[10] == 0 for r in rows)
    for index in (0,1,2,3,4,9,11):
        assert rows[index][4] == rows[index][7] == 0
    for index in (5,6,10):
        assert rows[index][4] == 1 and rows[index][7] == 0
    for index in (7,8,12,13):
        assert rows[index][4] == rows[index][7] == rows[index][8] == 1
    assert rows[12][5] == 2097152 and rows[12][2] == 2097160
    assert rows[13][5] == 0
    assert [native[k] for k in ('failed_reentries','successful_reentries','owned_reader_drops','real_os_read_errors','preserved_synthetic_io_causes')] == [14,2,32,1,2]
    assert native['scratch_removed']
    assert [native[k] for k in ('proofs_produced','verifier_calls','pcs_instances','network_reads')] == [0,0,0,0]
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Saved finite reader evidence and exact identities verified. No native or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
