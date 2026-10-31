"""Bounded synthetic capture preparation and independent quotient comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
RESULTS = HERE / 'results'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def read(name, cap):
    path = RESULTS / name
    return bounded(path, cap)


def bounded(path, cap):
    with path.open('rb') as file:
        data = file.read(cap + 1)
    if len(data) > cap:
        raise ValueError('artifact exceeds fixed byte cap')
    return data


def write(name, data, cap):
    if len(data) > cap:
        raise ValueError('artifact exceeds fixed byte cap')
    with (RESULTS / name).open('xb') as file:
        file.write(data)
        file.flush()


def prepare():
    payload = read('synthetic-capture.json', 196608)
    measurement_bytes = read('measurement.json', 16384)
    measurement = json.loads(measurement_bytes)
    assert measurement['input_commits'] == 1 and measurement['proofs'] == 0
    assert measurement['main_fast_view_fields_compared'] == 4096
    assert measurement['quotient_coefficients'] == 8192
    provenance_bytes = bounded(HERE / 'provenance.json', 65536)
    receipt = {
        'schema': 'kova.quotient-source.capture.v1',
        'payload_sha256': hashlib.sha256(payload).hexdigest(),
        'measurement_sha256': hashlib.sha256(measurement_bytes).hexdigest(),
        'source_manifest_sha256': hashlib.sha256(provenance_bytes).hexdigest(),
        'main_commitment': measurement['main_commitment'],
        'meaning': 'Fixed actual diagnostic capture provenance, not independent root verification',
    }
    receipt_bytes = canonical(receipt)
    obj = json.loads(payload)
    obj.update(schema='kova-quartic-quotient-reference-v40-input',
               field='babybear-power-basis-x4-minus11',
               capture_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())
    literal = canonical(obj)
    write('capture-receipt.json', receipt_bytes, 16384)
    write('reference-input.json', literal, 196608)
    write('reference-input-identity.json', canonical({
        'bytes': len(literal), 'sha256': hashlib.sha256(literal).hexdigest(),
        'receipt_sha256': hashlib.sha256(receipt_bytes).hexdigest(),
    }), 16384)
    print('Prepared fixed captured input. No reference arithmetic executed.')


def run_reference():
    literal = read('reference-input.json', 196608)
    identity = json.loads(read('reference-input-identity.json', 16384))
    assert len(literal) == identity['bytes']
    assert hashlib.sha256(literal).hexdigest() == identity['sha256']
    assert hashlib.sha256(read('capture-receipt.json', 16384)).hexdigest() == identity['receipt_sha256']
    module = runpy.run_path(str(HERE / 'reference.py'))
    report = module['compare_literal'](literal)
    write('reference-report.json', report, 16384)
    checked = json.loads(report)
    assert checked['rows_compared'] == 2048 and checked['coefficients_compared'] == 8192
    assert checked['arithmetic_equivalent'] is True
    assert checked['all_controls_separate'] is True
    assert all(checked['identities'].values())
    print('All8192 captured coefficients match. Nine mutation controls separate.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'run'))
    args = parser.parse_args()
    if args.mode == 'prepare':
        prepare()
    else:
        run_reference()
