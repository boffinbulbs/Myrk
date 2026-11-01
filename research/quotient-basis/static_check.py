"""Read saved basis evidence only. Never import or execute the model."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    with path.open('rb') as source:
        raw = source.read(16_777_217)
    if len(raw) > 16_777_216:
        raise ValueError('source record bound exceeded')
    raw = raw.replace(b'\r\n', b'\n')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def check():
    provenance = json.loads((HERE/'provenance.json').read_bytes())
    for group, base in (('source_files', HERE), ('repository_files', ROOT)):
        for name, pin in provenance[group].items():
            assert identity(base/name) == pin, name
    assert provenance['python_packages'] == []
    ast.parse((HERE/'model.py').read_text(encoding='utf8'))
    record = json.loads((HERE/'validation.json').read_bytes())
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['reference'] == identity(HERE/'results/reference.json')
    assert record['reference_attempts'] == 1
    guard = record['guard']
    assert guard['accepted'] and guard['hard_limit_installed'] and guard['exit_code'] == 0
    assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_private_commit_bytes'] <= 536870912
    assert 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[k] for k in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    result = json.loads((HERE/'results/reference.json').read_bytes())
    assert (result['field'], result['height'], result['chunks']) == (17, 2, 4)
    assert result['normalizers'] == [4, 4, 4, 4]
    assert result['transformed_masks'] == [[0], [1, 7], [12, 1], [14, 11]]
    assert result['masked_segments'] == [[1, 2, 1, 7], [2, 14, 12, 1], [10, 5, 14, 11], [10, 14]]
    assert result['coefficient_image'] == result['coefficient_tuples_enumerated'] == 4913
    assert result['adversarial_controls'] == ['mixed_normalization', 'uncoupled_mask', 'permuted_chunks',
        'transposed_transform', 'wrong_segment_spacing', 'altered_chunk', 'overlapping_masked_domains']
    assert result['restored_positive_checks'] == 7
    assert [result[k] for k in ('production_field_runs', 'commitments', 'transcripts', 'proofs', 'security_scores')] == [0, 0, 0, 0, 0]
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Saved quotient-basis identities verified. No model or proof replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
