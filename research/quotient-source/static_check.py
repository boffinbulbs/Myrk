"""Portable source and saved-result checks without construction replay."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes().replace(b'\r\n', b'\n')
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def check(results=False):
    manifest = json.loads((HERE / 'provenance.json').read_bytes())
    for name, pin in manifest['source_files'].items():
        assert identity(HERE / name) == pin, name
    for name, pin in manifest['repository_files'].items():
        assert identity(ROOT / name) == pin, name
    packages = lambda path: {(p['name'], p['version'], p['source'], p['checksum'])
        for p in tomllib.loads(path.read_text())['package'] if 'source' in p}
    assert packages(HERE/'Cargo.lock') <= packages(ROOT/'Cargo.lock')
    assert manifest['features_retained_basis_subset']
    assert 'fn prove(' not in (HERE/'src/context.rs').read_text()
    assert 'finish_produced' not in (HERE/'src/construction.rs').read_text().replace(
        '// access because no actual proof was produced. There is no finish_produced call.', '')
    if results:
        validation = json.loads((HERE/'validation.json').read_bytes())
        assert validation['source_manifest_sha256'] == identity(HERE/'provenance.json')['sha256']
        for name, pin in validation['artifacts'].items():
            assert identity(HERE/name) == pin, name
        measurement = json.loads((HERE/'results/measurement.json').read_bytes())
        reference = json.loads((HERE/'results/reference-report.json').read_bytes())
        assert measurement['input_commits'] == 1 and measurement['proofs'] == 0
        assert measurement['coset_lde_boundary_calls'] == 2
        assert measurement['main_fast_view_fields_compared'] == 4096
        assert measurement['quotient_coefficients'] == 8192
        assert len(measurement['owner_controls']['completed']) == 9
        assert reference['capture_receipt_sha256'] == validation['reference_receipt_sha256']
        assert reference['arithmetic_equivalent'] and reference['all_controls_separate']
        assert reference['rows_compared'] == 2048 and reference['coefficients_compared'] == 8192
        assert all(reference['identities'].values())
        assert len(reference['controls']) == 9
        assert all(c['distinct_rows'] > 0 for c in reference['controls'].values())
        for guard in validation['guards'].values():
            assert guard['accepted'] and guard['exit_code'] == 0
            assert guard['installed_process_commit_limit_bytes'] == 536870912
            assert guard['installed_job_commit_limit_bytes'] == 536870912
            assert guard['available_before_bytes'] >= guard['minimum_available_bytes'] == 2147483648
            assert guard['installed_job_flags'] == 8960
            assert not any(guard[k] for k in ['timed_out', 'working_guard_terminated', 'output_limit_exceeded'])
    print('Source identities and selected saved results verified. No construction or reference replay.')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Optimized validation refused')
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-results', action='store_true')
    check(parser.parse_args().check_results)
