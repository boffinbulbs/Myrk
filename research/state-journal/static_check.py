"""Inspect journal source and saved evidence without native or child execution."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def contents(path):
    with path.open('rb') as source:
        data = source.read(1048577)
    assert len(data) <= 1048576, str(path)
    return data


def identity(path, raw=False):
    data = contents(path)
    if not raw:
        data = data.replace(b'\r\n', b'\n')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def check_guard(guard):
    assert guard['launched'] and guard['hard_limit_installed']
    assert guard['installed_process_commit_limit_bytes'] == 536870912
    assert guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert not any(guard[key] for key in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    assert 0 < guard['peak_private_commit_bytes'] <= 536870912
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912


def check():
    provenance = json.loads(contents(HERE/'provenance.json'))
    assert provenance['metadata_nodes'] == 1 and provenance['registry_packages'] == []
    assert provenance['features'] == ['default', 'diagnostics']
    for name, pin in provenance['source_files'].items():
        assert identity(HERE/name) == pin, name
    for name, pin in provenance['repository_files'].items():
        assert identity(ROOT/name) == pin, name
    assert contents(HERE/'LICENSE') == contents(ROOT/'LICENSE')
    assert contents(HERE/'run_guarded_windows.ps1') == contents(ROOT/'research/trace-domain/run_guarded_windows.ps1')
    record = json.loads(contents(HERE/'validation.json'))
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native_attempts'] == 3
    attempts = record['native']
    assert len(attempts) == 3
    for attempt in attempts:
        check_guard(attempt['guard'])
    assert [attempt['guard']['accepted'] for attempt in attempts] == [False, False, True]
    assert [attempt['guard']['exit_code'] for attempt in attempts] == [101, 101, 0]
    assert [attempt['source_counted_completed_primary_prefix'] for attempt in attempts] == [0, 16, 0]
    assert [attempt['child_processes'] for attempt in attempts] == [0, 0, 22]
    assert attempts[2]['guard']['test_counts_verified']
    assert attempts[2]['guard']['actual_passed'] == 1
    assert attempts[2]['guard']['actual_failed'] == attempts[2]['guard']['actual_ignored'] == 0
    assert record['native_freeze']['files'] == 1139 and record['native_freeze']['post_run_verified']
    assert record['prefix_body_unchanged']
    source = contents(HERE/'tests/admission.rs').replace(b'\r\n', b'\n')
    prefix = source.split(b'    let mut groups = 0;\n', 1)[1].split(b'    assert_eq!(groups, 16);', 1)[0]
    assert dict(bytes=len(prefix), sha256=hashlib.sha256(prefix).hexdigest()) == record['prefix_body_identity']
    assert record['result'] == identity(HERE/'results/native-v3.json', raw=True)
    result = json.loads(contents(HERE/'results/native-v3.json'))
    assert result['format'] == 'kova.state-journal.native.v3'
    assert (result['new_primary_groups'], result['owned_terminations'], result['fresh_reader_processes']) == (1, 5, 11)
    assert (result['fresh_postrestart_writers'], result['preserved_orphans'], result['total_child_processes']) == (5, 3, 22)
    assert result['maximum_payload_bytes'] == 64
    assert result['power_failure_tests'] == result['cryptographic_proof_calls'] == 0
    assert all(item['accepted'] and item['exit_code'] == 0 for item in record['preparations'])
    assert len(record['preparations']) == 11
    print('Journal source and saved recovery evidence verified. No native replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
