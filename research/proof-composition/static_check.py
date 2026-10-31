"""Saved source and projection checks. The model is not imported or replayed."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def data(path, cap=1_048_576):
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('fixed evidence read bound exceeded')
    return raw.replace(b'\r\n', b'\n')


def identity(path):
    raw = data(path)
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def check():
    record = json.loads(data(HERE / 'validation.json', 32768))
    for name, pin in record['execution_files'].items():
        assert identity(HERE / name) == pin, name
    for name, pin in record['artifacts'].items():
        assert identity(HERE / name) == pin, name
    projection = json.loads(data(HERE / 'projection.json', 32768))
    for name, pin in projection['source_files'].items():
        assert identity(ROOT / name) == pin, name
    guard = record['guard']
    assert guard['accepted'] and guard['exit_code'] == 0
    assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert not any(guard[name] for name in ['timed_out', 'working_guard_terminated', 'output_limit_exceeded'])
    assert projection['achieved_security_bits'] is None
    assert not projection['same_witness_multi_input_payment_cost_established']
    assert projection['invalid_metadata_refusals'] == 4
    small, packed = projection['small_source_crosscheck'], projection['conditional_packed_relation']
    assert (small['reserved_role_count'], small['reserved_field_bytes']) == (13, 1325056)
    assert small['legacy_prepared_and_commitment_bytes'] == 1290240
    assert packed['raw_shape'] == [8192, 43176] and packed['public_values'] == 196
    assert packed['reserved_field_bytes'] == 26922188800
    assert packed['main_query_fields_at_64_distinct_indices_bytes'] == 11054080
    assert not any(packed[key] for key in ['current_raw_width_accepts', 'current_stored_shape_accepts',
                                         'current_field_budget_accepts', 'current_public_value_shape_accepts', 'execution_admitted'])
    assert not small['execution_admitted']
    assert projection['challenge_cardinality_binary_interval'] == [123, 124]
    print('Saved packed projection and source identities verified. No model, field or prover execution.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
