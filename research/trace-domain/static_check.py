"""Check source and recorded direct guard evidence without native execution."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path, raw=False):
    with path.open('rb') as source:
        data = source.read(16777217)
    assert len(data) <= 16777216
    if not raw:
        data = data.replace(b'\r\n', b'\n')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def check():
    provenance = json.loads((HERE/'provenance.json').read_bytes())
    for group, base in (('source_files', HERE), ('repository_files', ROOT)):
        for name, pin in provenance[group].items():
            assert identity(base/name) == pin, name
    for name, pin in provenance['raw_fixtures'].items():
        assert identity(ROOT/name, raw=True) == pin, name
    registry = provenance['registry_packages']
    assert provenance['metadata_nodes'] == 66 and len(registry) == 62
    assert len({(p['name'], p['version']) for p in registry}) == 62
    assert all(p['license'] and 'parallel' not in p['features'] for p in registry)
    record = json.loads((HERE/'validation.json').read_bytes())
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native'] == identity(HERE/'results/native-v1.json', raw=True)
    assert record['native_attempts'] == 1
    assert len(record['compiler_preparations']) == 3
    assert all(p['accepted'] and p['exit_code'] == 0 for p in record['compiler_preparations'])
    guard = record['guard']
    assert guard['accepted'] and guard['test_counts_verified'] and guard['exit_code'] == 0
    assert guard['actual_passed'] == 1 and guard['actual_failed'] == guard['actual_ignored'] == 0
    assert guard['hard_limit_installed']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_private_commit_bytes'] <= 536870912
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[k] for k in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    result = json.loads((HERE/'results/native-v1.json').read_bytes())
    assert result['format'] == 'kova.trace-domain.native.v1'
    assert (result['literal_controls'], result['same_owner_refusals'], result['failed_reentries']) == (6, 1, 1)
    assert result['flag_before'] is False and result['flag_after'] is False
    assert result['guard_counts_equal'] and result['shared_read_closed']
    assert result['producer_initializations'] == result['proofs_produced'] == result['live_ood_samples'] == 0
    assert (result['reserved_files'], result['reserved_bytes']) == (13, 1325056)
    counts = result['counts']
    assert (counts['input_commits'], counts['get_matrices'], counts['mmcs_clones']) == (1, 1, 1)
    assert counts['extension_commits'] == counts['input_multi_opens'] == counts['extension_multi_opens'] == counts['verify_calls'] == 0
    assert counts['dft']['coset_lde_batch'] == 2
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    for name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        assert (HERE/name).read_bytes() == (ROOT/'research/opening-domain'/name).read_bytes()
    print('Trace domain source and recorded native evidence verified. No native replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
