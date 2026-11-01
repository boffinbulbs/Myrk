"""Inspect saved source and bounded admission evidence without native execution."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path, raw=False):
    with path.open('rb') as source:
        data = source.read(16_777_217)
    if len(data) > 16_777_216:
        raise ValueError('Source identity bound exceeded')
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
    assert provenance['metadata_nodes'] == 66
    registry = provenance['registry_packages']
    assert len(registry) == 62
    assert len({(p['name'], p['version']) for p in registry}) == 62
    assert all('parallel' not in p['features'] and p['license'] for p in registry)
    record = json.loads((HERE/'validation.json').read_bytes())
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['native'] == identity(HERE/'results/native-v1.json', raw=True)
    assert record['native_attempts'] == 1
    assert [r['accepted'] for r in record['compiler_preparations']] == [False, False, True, True, True]
    guard = record['guard']
    assert guard['accepted'] and guard['test_counts_verified']
    assert guard['actual_passed'] == 1 and guard['actual_failed'] == guard['actual_ignored'] == 0
    assert guard['exit_code'] == 0 and guard['hard_limit_installed']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_private_commit_bytes'] <= 536870912
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[k] for k in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    result = json.loads((HERE/'results/native-v1.json').read_bytes())
    assert (result['literal_controls'], result['typed_prover_refusals'], result['typed_verifier_refusals']) == (9, 1, 4)
    assert result['flag_after_refusal'] is False and result['flag_after_shared_requests'] is True
    assert (result['input_commits'], result['get_matrices']) == (1, 6)
    assert (result['mask_bytes'], result['salt_bytes']) == (10948, 279800)
    reference = json.loads((ROOT/'research/fallible-main/results/native.json').read_bytes())
    assert result['mask_bytes'] == reference['counts']['mask']['bytes']
    assert result['salt_bytes'] == reference['counts']['salt']['bytes']
    assert reference['counts']['initial_salt_bytes'] == 32
    assert (result['reserved_files'], result['reserved_bytes']) == (13, 1325056)
    assert result['proofs_produced'] == result['cryptographic_verifier_calls'] == 0
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    for name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        assert (HERE/name).read_bytes() == (ROOT/'research/fallible-source'/name).read_bytes()
    print('Opening domain source and native records verified. No native or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
