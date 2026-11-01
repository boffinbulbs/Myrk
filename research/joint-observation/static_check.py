"""Inspect recorded joint observation evidence without reference execution."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    with path.open('rb') as source:
        data = source.read(16777217)
    assert len(data) <= 16777216
    data = data.replace(b'\r\n', b'\n')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def check():
    provenance = json.loads((HERE/'provenance.json').read_bytes())
    for group, base in (('source_files', HERE), ('repository_files', ROOT)):
        for name, pin in provenance[group].items():
            assert identity(base/name) == pin, name
    assert provenance['dependencies'] == 'Python standard library only'
    record = json.loads((HERE/'validation.json').read_bytes())
    assert record['provenance'] == identity(HERE/'provenance.json')
    assert record['result'] == identity(HERE/'results/reference-v1.json')
    assert record['reference_attempts'] == 1
    guard = record['guard']
    assert guard['accepted'] and guard['exit_code'] == 0 and guard['hard_limit_installed']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert 0 < guard['peak_private_commit_bytes'] < 536870912
    assert 0 < guard['peak_job_commit_bytes'] < 536870912
    assert not any(guard[k] for k in ('timed_out', 'working_guard_terminated', 'output_limit_exceeded'))
    result = json.loads((HERE/'results/reference-v1.json').read_bytes())
    assert result['format'] == 'kova.joint-observation.reference.v1'
    assert (result['prime'], result['raw_height'], result['chunks']) == (257, 8, 8)
    assert (result['physical_points'], result['anchors'], result['nonanchors']) == (128, 64, 64)
    assert (result['single_query_rank'], result['single_recomposition_rank']) == (21, 3)
    assert (result['joint_rank'], result['joint_recomposition_rank']) == (28, 4)
    assert result['main_ranks'] == [6, 6, 8]
    assert (result['honest_quotient_degree'], result['construction_degree_bound']) == (52, 64)
    assert result['hostile_alternatives'] == 8
    assert result['kova_runtime_calls'] == result['cryptographic_proofs'] == 0
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Joint observation source and recorded integer evidence verified. No reference replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized evidence checks refused')
    check()
