"""Check saved identities and arithmetic evidence without executing the reference."""
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
    assert provenance['primary_source']['raw_pdf_identity'] is None
    assert provenance['primary_source']['typeset_reviewed'] is False
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
    assert result['format'] == 'kova.joint-hiding.reference.v1'
    assert (result['prime'], result['extension_degree'], result['degree_bound']) == (17, 2, 8)
    assert (result['alpha_values'], result['basis_cases'], result['full_rank'], result['proper_subfield']) == (289, 83521, 272, 17)
    assert (result['four_column_assignments'], result['four_column_images'], result['equal_fibers']) == (83521, 289, 289)
    assert (result['polynomial_modes'], result['translated_coverage'], result['deficient_conditional_shifts']) == (5, 272, 16)
    assert result['literal_polynomials'] == result['hostile_alternatives'] == result['restored_checks'] == 6
    assert result['kova_runtime_calls'] == result['cryptographic_proofs'] == 0
    assert (HERE/'LICENSE').read_bytes() == (ROOT/'LICENSE').read_bytes()
    print('Joint hiding source and recorded integer evidence verified. No reference replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized evidence checks refused')
    check()
