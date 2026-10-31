"""Source and saved-result verification without construction replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def identity(path):
    data=path.read_bytes().replace(b'\r\n',b'\n')
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def check(results):
    source=json.loads((HERE/'provenance.json').read_bytes())
    for name,pin in source['source_files'].items():
        assert identity(HERE/name)==pin,name
    for name,pin in source['repository_files'].items():
        assert identity(ROOT/name)==pin,name
    packages=lambda path:{(p['name'],p['version'],p['source'],p['checksum'])
        for p in tomllib.loads(path.read_text())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    assert source['features_retained_basis_subset']
    if results:
        record=json.loads((HERE/'validation.json').read_bytes())
        assert record['source_manifest_sha256']==identity(HERE/'provenance.json')['sha256']
        for name,pin in record['artifacts'].items():
            assert identity(HERE/name)==pin,name
        result=json.loads((HERE/'results/measurement.json').read_bytes())
        assert result['proofs']==0
        assert result['candidate_input_commits']==result['reference_input_commits']==2
        assert result['chunk_fields_compared']==262144 and result['main_fields_compared']==24576
        assert all(result[k] for k in ['main_roots_equal','quotient_roots_equal',
            'delivered_rng_fingerprints_equal','continuing_mask_marker_equal'])
        assert len(result['controls']['completed'])==10
        assert result['controls']['sealed_constant_fixtures']==6
        guard=record['guard']
        assert guard['accepted'] and guard['exit_code']==0 and guard['test_counts_verified']
        assert guard['installed_process_commit_limit_bytes']==guard['installed_job_commit_limit_bytes']==536870912
        assert guard['available_before_bytes']>=guard['minimum_available_bytes']==2147483648
        assert guard['installed_job_flags']==8960
        assert not any(guard[k] for k in ['timed_out','working_guard_terminated','output_limit_exceeded'])
    print('Source identities and selected saved results verified. No construction replay.')

if __name__=='__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser=argparse.ArgumentParser()
    parser.add_argument('--check-results',action='store_true')
    check(parser.parse_args().check_results)
