"""Check finite probe identities and retained dependency boundaries."""
import hashlib
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path, binary=False):
    raw = path.read_bytes()
    if not binary:
        raw = raw.replace(b'\r\n', b'\n')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def registry_tuples(path):
    # Cargo writes these four identity fields as literal single line strings.
    # This checks that restricted representation, not arbitrary TOML syntax.
    result = set()
    for block in path.read_text(encoding='utf8').split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\r\n\\]+)"$', block, re.MULTILINE))
        if 'source' in fields:
            if not all(name in fields for name in ['name', 'version', 'source', 'checksum']):
                raise ValueError('complete literal registry identity required')
            if not fields['source'].startswith('registry+'):
                raise ValueError('registry package identity required')
            result.add(tuple(fields[name] for name in ['name', 'version', 'source', 'checksum']))
    return result


def main():
    provenance = json.loads((HERE / 'provenance.json').read_text(encoding='utf8'))
    for name, expected in provenance['repository_files'].items():
        assert identity(ROOT / name, name.endswith('.bin')) == expected, name
    for name, expected in provenance['experiment_files'].items():
        assert identity(HERE / name, name.endswith('.bin')) == expected, name
    home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
    for name, expected in provenance['registry_files'].items():
        crate, version, relative = name.split('/', 2)
        candidates = list((home / 'registry/src').glob('*' + '/' + crate + '-' + version + '/' + relative))
        assert len(candidates) == 1 and identity(candidates[0]) == expected, name
    own = registry_tuples(HERE / 'Cargo.lock')
    assert own <= registry_tuples(ROOT / 'Cargo.lock') and len(own) == 45
    record = json.loads((HERE / 'validation.json').read_text(encoding='utf8'))
    assert record['provenance'] == identity(HERE / 'provenance.json')
    assert record['scenarios'] == 4 and record['invalid_profile_controls'] == 6
    assert record['signature_trace_allocations'] == record['symbolic_air_evaluations'] == record['backend_proofs'] == 0
    assert not record['parameter_selection'] and not record['quantum_security_established'] and not record['knowledge_soundness_established']
    assert record['guard']['process_limit_bytes'] == record['guard']['aggregate_limit_bytes'] == 536870912
    assert record['guard']['minimum_available_bytes'] == 2147483648 and record['guard']['timeout_seconds'] == 120
    assert record['guard']['readback_verified'] and record['guard']['test_counts_verified']
    assert 0 < record['guard']['peak_job_commit_bytes'] <= 536870912
    print('Conditional profile identities, model scope and retained lock boundary match')


if __name__ == '__main__':
    main()
