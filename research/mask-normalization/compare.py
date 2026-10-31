"""Bounded native capture receipt and independent integer comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy

HERE=Path(__file__).resolve().parent
RESULTS=HERE/'results'
NATIVE_EXE_SHA='674ab394791dbbad2fcd0ee7b26fe3cb6a25a17d1a65c731ab7c5ccbefa1c959'

def bounded(path, cap):
    with path.open('rb') as source:
        data=source.read(cap+1)
    if len(data)>cap:
        raise ValueError('Artifact exceeds fixed class')
    return data

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')

def write(name,data,cap):
    if len(data)>cap:
        raise ValueError('Artifact exceeds fixed class')
    with (RESULTS/name).open('xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())

def prepare():
    payload=bounded(RESULTS/'synthetic-capture.json',65536)
    measurement=bounded(RESULTS/'measurement.json',16384)
    meter=json.loads(measurement)
    if (meter['normalizer_calls'],meter['final_coordinates'],meter['shape_refusals'],meter['proofs'])!=(1,2048,2,0):
        raise ValueError('Unexpected native measurement')
    raw_guard=bounded(RESULTS/'normalization-v1-memory-result.json',16384)
    guard=json.loads(raw_guard)
    if not (guard['accepted'] and guard['hard_limit_installed'] and guard['launched']
            and guard['test_counts_verified'] and guard['exit_code']==0
            and guard['actual_passed']==1 and guard['actual_failed']==0 and guard['actual_ignored']==0):
        raise ValueError('Native guard did not establish the selected successful run')
    if (guard['installed_process_commit_limit_bytes'],guard['installed_job_commit_limit_bytes'],
            guard['minimum_available_bytes'],guard['installed_job_flags'])!=(536870912,536870912,2147483648,8960):
        raise ValueError('Native resource class differs')
    if guard['available_before_bytes']<2147483648 or not 0<guard['timeout_seconds']<=120 or guard['expected_tests']!=1:
        raise ValueError('Native admission differs')
    if any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded']):
        raise ValueError('Native guard failed')
    if bounded(RESULTS/'normalization-v1.stderr.txt',16384):
        raise ValueError('Unexpected native stderr')
    if digest(bounded(Path(guard['executable']),2097152))!=NATIVE_EXE_SHA:
        raise ValueError('Native executable identity differs')
    receipt={
        'format':'kova.mask-normalization.capture-receipt.v1',
        'payload_sha256':digest(payload),'measurement_sha256':digest(measurement),
        'native_guard_sha256':digest(raw_guard),'native_executable_sha256':NATIVE_EXE_SHA,
        'source_manifest_sha256':digest(bounded(HERE/'provenance.json',131072).replace(b'\r\n',b'\n')),
        'meaning':'Local captured execution provenance, not cryptographic source authentication',
    }
    write('capture-receipt.json',canonical(receipt),16384)
    write('reference-input.json',payload,65536)
    print('Native capture prepared. No reference import or arithmetic executed.')

def run_reference():
    payload=bounded(RESULTS/'reference-input.json',65536)
    receipt_raw=bounded(RESULTS/'capture-receipt.json',16384)
    receipt=json.loads(receipt_raw)
    if digest(payload)!=receipt['payload_sha256']:
        raise ValueError('Captured input identity differs')
    if payload!=bounded(RESULTS/'synthetic-capture.json',65536):
        raise ValueError('Native capture changed after preparation')
    if digest(bounded(RESULTS/'measurement.json',16384))!=receipt['measurement_sha256']:
        raise ValueError('Native measurement changed after preparation')
    if digest(bounded(RESULTS/'normalization-v1-memory-result.json',16384))!=receipt['native_guard_sha256']:
        raise ValueError('Native guard changed after preparation')
    if digest(bounded(HERE/'provenance.json',131072).replace(b'\r\n',b'\n'))!=receipt['source_manifest_sha256']:
        raise ValueError('Source record changed after preparation')
    module=runpy.run_path(str(HERE/'reference.py'))
    report=module['compare'](payload)
    for key in ['domain_order_equal','normalizers_equal','final_bank_equal','all_selected_controls_separate']:
        if report[key] is not True:
            raise ValueError('Independent arithmetic comparison failed: '+key)
    if report['coordinates_compared']!=2048 or report['zero_residual_coordinates']!=2048:
        raise ValueError('Incomplete cancellation equality')
    report['capture_receipt_sha256']=digest(receipt_raw)
    report['capture_sha256']=digest(payload)
    write('reference-report.json',canonical(report),16384)
    print('Independent domains, normalizers and all 2048 final coordinates match. Six controls separate.')

if __name__=='__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['prepare','run'])
    mode=parser.parse_args().mode
    if mode=='prepare':
        prepare()
    else:
        run_reference()
