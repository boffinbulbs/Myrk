"""Saved inventory verification. Never imports or replays the evaluator."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def data(path):
    with path.open('rb') as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError('fixed evidence bound exceeded')
    return raw.replace(b'\r\n', b'\n')


def identity(path):
    raw = data(path)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def check():
    validation = json.loads(data(HERE / 'validation.json'))
    for group in ('execution_files', 'artifacts'):
        for name, pin in validation[group].items():
            assert identity(HERE / name) == pin, name
    inventory = json.loads(data(HERE / 'inventory.json'))
    for name, pin in inventory['source_files'].items():
        assert identity(ROOT / name) == pin, name
    small, full = inventory['small_reference'], inventory['conditional_overlay']
    assert [small['retained_field_file_bytes'], small['main_only_field_file_bytes']] == [1325056,112640]
    assert small['fri']['rounds'] == 9
    assert [full['raw_shape'],full['constraints'],full['public_values']] == [[8192,42178],71623,196]
    assert list(full['roles'].values()) == [4194304,1048576,22115516416,2764439552,33554432,1382088704]
    assert full['retained_field_file_bytes'] == 26300841984
    assert full['fri']['rounds'] == 14
    assert [full['fri'][k] for k in ('retained_field_bytes','retained_salt_bytes','retained_digest_bytes')] == [4194048,8388096,16775296]
    assert full['queries']['main_data_bytes'] == 10798592
    assert full['queries']['main_two_point_extension_claim_bytes'] == 1349824
    assert full['queries']['duplicate_rows_preserved']
    assert not any(full['boundaries'].values())
    assert not small['boundaries']['execution_admitted']
    assert inventory['invalid_metadata_refusals'] == 8
    assert inventory['achieved_security_bits'] is None
    assert not inventory['payment_witness_joins_established']
    assert not inventory['whole_salt_rng_byte_coverage_established']
    assert [inventory[k] for k in ('field_instances','prover_instances','backend_proofs')] == [0,0,0]
    guard = validation['guard']
    assert guard['accepted'] and guard['exit_code'] == 0 and guard['hard_limit_installed']
    assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[k] for k in ('timed_out','working_guard_terminated','output_limit_exceeded'))
    print('Saved complete overlay inventory and source identities verified. No evaluator replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
