"""Source and saved evidence validation without arithmetic replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]

def identity(path):
    data=path.read_bytes().replace(b'\r\n',b'\n')
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def check(results):
    source=json.loads((HERE/'provenance.json').read_bytes())
    for key,base in [('source_files',HERE),('repository_files',ROOT)]:
        for name,pin in source[key].items():
            assert identity(base/name)==pin,name
    packages=lambda path:{(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(path.read_text())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock')<=packages(ROOT/'Cargo.lock')
    assert source['features_retained_basis_subset']
    if results:
        validation=json.loads((HERE/'validation.json').read_bytes())
        assert validation['source_manifest_sha256']==identity(HERE/'provenance.json')['sha256']
        for name,pin in validation['artifacts'].items():
            assert identity(HERE/name)==pin,name
        meter=json.loads((HERE/'results/measurement.json').read_bytes())
        assert meter['normalizer_calls']==1 and meter['final_coordinates']==2048
        assert meter['coupled_updates']==14336 and meter['shape_refusals']==2 and meter['proofs']==0
        report=json.loads((HERE/'results/reference-report.json').read_bytes())
        assert all(report[k] is True for k in ['domain_order_equal','normalizers_equal',
            'final_bank_equal','all_selected_controls_separate'])
        assert report['coordinates_compared']==report['zero_residual_coordinates']==2048
        assert report['capture_receipt_sha256']==validation['capture_receipt_sha256']
        assert len(report['controls'])==6 and all(v>0 for v in report['controls'].values())
        for guard in validation['guards'].values():
            assert guard['accepted'] and guard['exit_code']==0
            assert guard['installed_process_commit_limit_bytes']==guard['installed_job_commit_limit_bytes']==536870912
            assert guard['available_before_bytes']>=guard['minimum_available_bytes']==2147483648
            assert guard['installed_job_flags']==8960
            assert not any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded'])
    print('Source and saved normalization evidence verified. No arithmetic replay.')

if __name__=='__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser=argparse.ArgumentParser()
    parser.add_argument('--check-results',action='store_true')
    check(parser.parse_args().check_results)
