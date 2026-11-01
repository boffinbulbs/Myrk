"""Inspect fixed header source and saved evidence without cryptographic execution."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent


def identity(path, raw=False):
    with path.open('rb') as source:
        data = source.read(1048577)
    assert len(data) <= 1048576, str(path)
    if not raw:
        data = data.replace(b'\r\n', b'\n')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def check():
    provenance = json.loads((HERE/'provenance.json').read_text(encoding='utf8'))
    for name, entry in provenance['source_files'].items():
        assert identity(HERE/name, entry['raw']) == entry['identity'], name
    lock = tomllib.loads((HERE/'Cargo.lock').read_text(encoding='utf8'))
    packages = {(item['name'], item['version']): item['checksum']
                for item in lock['package'] if 'source' in item}
    expected = {(item['name'], item['version']): item['checksum']
                for item in provenance['registry_packages']}
    assert packages == expected and len(packages) == 14
    assert len(provenance['diagnostic_nodes']) == 14
    assert all(item['name'] != 'libc' for item in provenance['diagnostic_nodes'])
    manifest = tomllib.loads((HERE/'Cargo.toml').read_text(encoding='utf8'))
    assert manifest['features']['default'] == []
    assert manifest['dependencies']['equihash']['version'] == '=0.3.0'
    assert manifest['dependencies']['sha2']['version'] == '=0.11.1'
    assert all(not item['default-features'] for item in manifest['dependencies'].values())
    record = json.loads((HERE/'validation.json').read_text(encoding='utf8'))
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native_attempts'] == 1
    guard = record['native_guard']
    assert guard['accepted'] and guard['exit_code'] == 0 and guard['test_counts_verified']
    assert guard['actual_passed'] == 1 and guard['actual_failed'] == guard['actual_ignored'] == 0
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert guard['hard_limit_installed'] and guard['launched']
    assert not any(guard[key] for key in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    assert record['post_native_files_verified'] == 1878
    assert record['result'] == identity(HERE/'results/native.txt', raw=True)
    expected_counts = 'HEADER_WORK_RESULT positives=2 metadata_refusals=15 target_literals=14 numeric_checks=5 equihash_refusals=10 encoding_literals=8'
    assert expected_counts in (HERE/'results/native.txt').read_text(encoding='utf8')
    assert record['expected_hash_display'] == '00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08'
    assert record['expected_bits'] == '1f07ffff'
    assert len(record['preparations']) == 4 and all(item['accepted'] for item in record['preparations'])
    print('Header source, locked provenance and saved work evidence verified. No crypto replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized inspection refused')
    check()
