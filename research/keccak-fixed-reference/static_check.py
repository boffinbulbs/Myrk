"""Inspect saved evidence without importing or evaluating the reference."""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def read(name, limit=262144):
    with open(name, 'rb') as stream:
        raw = stream.read(limit + 1)
    assert len(raw) <= limit
    return raw


def identity(name, raw_mode):
    raw = read(name)
    if not raw_mode:
        raw = raw.replace(b'\r\n', b'\n')
    return len(raw), hashlib.sha256(raw).hexdigest()


def main():
    source = json.loads(read(os.path.join(HERE, 'provenance.json')))
    for name, pin in source['source_files'].items():
        assert identity(os.path.join(HERE, name), pin['raw']) == (pin['bytes'], pin['sha256']), name
    for name, pin in source['repository_context'].items():
        assert identity(os.path.join(ROOT, name), pin['raw']) == (pin['bytes'], pin['sha256']), name
    record = json.loads(read(os.path.join(HERE, 'validation.json')))
    for name, pin in record['publication_sources'].items():
        assert identity(os.path.join(HERE, name), pin['raw']) == (pin['bytes'], pin['sha256']), name
    for name, pin in record['artifacts'].items():
        assert identity(os.path.join(HERE, name), True) == (pin['bytes'], pin['sha256']), name
    guard = record['guard']
    assert guard['accepted'] and guard['launched'] and guard['exit_code'] == 0
    assert guard['hard_limit_installed'] and guard['installed_job_flags'] == 8960
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and 0 < guard['peak_job_commit_bytes'] <= 536870912
    assert not any(guard[key] for key in ('working_guard_terminated', 'timed_out', 'output_limit_exceeded'))
    result = json.loads(read(os.path.join(HERE, 'results', 'result.json')))
    anchors = json.loads(read(os.path.join(HERE, 'fixtures', 'anchors.json')))
    assert result['status'] == 'PASS' and result['python'] == '3.14.5'
    assert result['primary_outputs'] == [anchors['s1'], anchors['s2']]
    assert (result['primary_kats'], result['forward_maps'], result['reverse_maps']) == (2, 2, 4)
    assert (result['nodes'], result['operations'], result['variable_references']) == (156736, 155136, 308736)
    assert (result['graph_builds'], result['whole_graph_evaluations']) == (13, 16)
    assert result['final_export_values'] == [0, 1]
    assert result['round_constant_bits'] == 1536 and result['routing_bijection'] == 1600
    assert len(result['row_refusal_causes']) == result['row_restorations'] == 9
    assert result['graph_refusal_causes'] == ['BitValue', 'GraphReference']
    assert result['input_refusal_causes'] == ['InputShape', 'InputWord', 'InputWord', 'InputWord']
    assert len(result['functional_alternatives']) == result['alternative_restorations'] == 6
    assert result['missing_bitness_gate_equations_hold'] and result['missing_bitness_actual_refusal'] == 'BitValue'
    print('Saved whole Keccak reference evidence verified. No graph, permutation, AIR or proof replay.')


if __name__ == '__main__':
    main()
