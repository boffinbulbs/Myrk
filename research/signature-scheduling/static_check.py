"""Verify source identities and the isolated measurement boundary."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def identity(path):
    raw = path.read_bytes().replace(b'\r\n', b'\n')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

provenance = json.loads((HERE / 'provenance.json').read_text(encoding='utf8'))
for name, expected in provenance['reference_files'].items():
    if identity(ROOT / name) != expected:
        raise SystemExit('Reference source changed: ' + name)
for name, expected in provenance['experiment_files'].items():
    if identity(HERE / name) != expected:
        raise SystemExit('Experiment source changed: ' + name)
record = json.loads((HERE / 'validation.json').read_text(encoding='utf8'))
assert record['provenance'] == identity(HERE / 'provenance.json')
assert (record['height'], record['width'], record['constraints_per_row'], record['degree']) == (8192, 47058, 74725, 4)
assert record['backend_proofs'] == 0 and record['native_trace_allocations'] == 11
assert record['format'] == 'kova.signature-scheduling.validation.v6'
assert record['ordinary_tests_passed'] == 8
assert record['native_signature_tuple_validation']
assert len(record['native_tuple_checks']) == 10
assert sum(value == 'AcceptConditional' for value in record['native_tuple_checks'].values()) == 5
assert record['max_simultaneous_native_traces'] == 1
assert set(record['native_guards']) == {'a0', 'corpus', 'hostile'}
for name, deadline in [('a0', 300), ('corpus', 1200), ('hostile', 1800)]:
    guard = record['native_guards'][name]
    assert guard['readback_verified'] and guard['aggregate_limit_bytes'] == 2147483648
    assert 0 < guard['peak_job_commit_bytes'] <= 2147483648
    assert guard['minimum_available_bytes'] == 5368709120 and guard['timeout_seconds'] == deadline
assert record['hostile_unique_routes'] == 77
assert record['hostile_full_positive_checks'] == 4 and record['hostile_full_negative_checks'] == 15
assert record['transformed_assertions_removed'] == 106496
prior = json.loads((HERE / 'records/provenance-v5.json').read_text(encoding='utf8'))
for name in provenance['preserved_equation_files']:
    assert identity(HERE / 'src' / name) == prior['experiment_files']['src/' + name]
packages = (HERE / 'Cargo.lock').read_text(encoding='utf8')
reference = (HERE.parent / 'signature-complete-native/Cargo.lock').read_text(encoding='utf8')
assert packages.replace('name = "kova-signature-scheduling"\nversion = "0.3.0"', 'name = "thorum-signature-complete-native"\nversion = "0.1.0"') == reference
assert identity(HERE / 'LICENSE') == identity(HERE.parent / 'signature-complete-native/LICENSE')
print('Pinned reference and experiment sources match the recorded native and symbolic scope')
