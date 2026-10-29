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
assert (record['height'], record['width'], record['constraints_per_row'], record['degree']) == (8192, 47049, 181203, 6)
assert record['backend_proofs'] == record['native_trace_allocations'] == 0
assert not record['native_signature_tuple_validation']
packages = (HERE / 'Cargo.lock').read_text(encoding='utf8')
reference = (HERE.parent / 'signature-complete-native/Cargo.lock').read_text(encoding='utf8')
assert packages.replace('name = "kova-signature-scheduling"', 'name = "thorum-signature-complete-native"') == reference
assert identity(HERE / 'LICENSE') == identity(HERE.parent / 'signature-complete-native/LICENSE')
print('Pinned reference and experiment sources match the recorded symbolic scope')
