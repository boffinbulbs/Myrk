"""Saved inventory validation without source helper or AIR execution."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def data(path, cap=131072):
    with path.open('rb') as stream:
        raw = stream.read(cap+1)
    if len(raw) > cap:
        raise ValueError('fixed evidence size exceeded')
    return raw.replace(b'\r\n', b'\n')


def identity(path):
    raw = data(path)
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def check():
    validation = json.loads(data(HERE/'validation.json',32768))
    for name,pin in validation['execution_files'].items():
        assert identity(HERE/name) == pin, name
    for name,pin in validation['artifacts'].items():
        assert identity(HERE/name) == pin, name
    for name,pin in validation['reviewed_figures'].items():
        assert identity(HERE/name) == pin, name
    inventory = json.loads(data(HERE/'inventory.json',65536))
    for name,pin in inventory['source_files'].items():
        assert identity(ROOT/name) == pin, name
    guard = validation['guard']
    assert guard['accepted'] and guard['exit_code'] == 0
    assert guard['expected_tests'] == 0 and not guard['test_counts_verified']
    assert guard['installed_process_commit_limit_bytes'] == guard['installed_job_commit_limit_bytes'] == 536870912
    assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
    assert guard['timeout_seconds'] == 120 and guard['installed_job_flags'] == 8960
    assert not any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded'])
    assert inventory['physical_columns'] == 43176 and len(inventory['physical_regions']) == 67
    assert not any(r['reuse_certified'] for r in inventory['physical_regions'])
    assert len(inventory['eight_bank_remap_refusals']) == 8
    assert all(c['conflicting_logical_outputs'] for c in inventory['eight_bank_remap_refusals'])
    assert inventory['constant_expression_refusals'] == 4 and inventory['whole_bank_calendar_peak'] == 9
    assert inventory['arithmetic_phase_counts'] == dict(both=0,inverse_hints=256,neither=4608,ntt_and_matrix=1700,ntt_products=3328)
    candidate = inventory['conditional_mode_overlay']
    assert (candidate['height'],candidate['width'],candidate['public_values']) == (8192,42178,196)
    assert candidate['constraint_count'] is candidate['constraint_degree'] is None
    assert not candidate['execution_admitted']
    for name in ['schedule.svg','schedule-dark.svg']:
        svg = ET.fromstring(data(HERE/name))
        assert svg.attrib['viewBox'] == '0 0 1000 470'
        assert svg.find('{http://www.w3.org/2000/svg}title') is not None
    print('Saved lifetime inventory, source identities and diagrams verified. No inventory helper or AIR replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    check()
