"""Fixed integer payload projection. No field, witness or prover construction."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUTS = [
    'research/signature-packed-native/fixtures-native.json',
    'research/signature-packed-shape/validation.json',
    'research/source-prover/results/measurement.json',
    'research/storage-pcs/validation.json',
    'research/storage-pcs/resources/record.json',
    'research/proof-preflight/src/preflight.rs',
    'research/storage-pcs/backend/src/hiding_pcs.rs',
    'research/source-consumption/src/composite.rs',
    'research/storage-pcs/tests/common/mod.rs',
]


def read(path):
    with path.open('rb') as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError('source exceeds fixed one MiB read bound')
    return raw.replace(b'\r\n', b'\n')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def project(height, width, constraints, public_values):
    for value, cap in zip((height, width, constraints, public_values),
                          (8192, 65536, 1000000, 1024), strict=True):
        if type(value) is not int or not 0 < value <= cap:
            raise ValueError('bounded positive integer required')
    if height & (height - 1):
        raise ValueError('power of two height required')
    h, w, n = height, width + 4, 16 * height
    roles = {
        'raw': 4 * h * width,
        'prepared': 8 * h * w,
        'main_lde': 4 * n * w,
        'quotient_ldes': 8 * 4 * n * 8,
        'auxiliary_lde': 4 * n * 8,
        'canonical_quotient_source': 8 * h * 4 * 4,
    }
    field_files = sum(roles.values())
    return {
        'raw_shape': [h, width], 'public_values': public_values,
        'constraints_per_row': constraints, 'role_field_bytes': roles,
        'reserved_role_count': 13, 'reserved_field_bytes': field_files,
        'legacy_prepared_and_commitment_bytes': field_files - roles['raw'] - roles['canonical_quotient_source'],
        'base_salt_field_bytes': 10 * n * 16 * 4,
        'base_digest_content_bytes': 3 * (2 * n - 1) * 64,
        'main_query_fields_at_64_distinct_indices_bytes': 64 * w * 4,
        'main_two_point_extension_claim_bytes': 2 * w * 4 * 4,
        'constraint_row_positions': 8 * h * constraints,
        'current_raw_width_accepts': width <= 8,
        'current_stored_shape_accepts': n <= 4096 and max(w, 8) <= 12,
        'current_field_budget_accepts': field_files <= 2097152,
        'current_public_value_shape_accepts': public_values <= 8,
        'execution_admitted': False,
    }


def main():
    sources = {name: read(ROOT / name) for name in INPUTS}
    native = json.loads(sources[INPUTS[0]])
    symbolic = json.loads(sources[INPUTS[1]])
    small = json.loads(sources[INPUTS[2]])
    storage = json.loads(sources[INPUTS[3]])
    legacy = json.loads(sources[INPUTS[4]])
    expected_profile = dict(raw_height=256, raw_width=2, constraint_degree=4,
                            extension_degree=4, log_blowup=3, queries=64,
                            random_codewords=4, salt_columns=16, fold_arity=2, grinding_bits=0)
    if storage['profile'] != expected_profile:
        raise ValueError('retained comparison profile changed')
    if (native['height'], native['width'], native['constraints_per_row'], native['public_values']) != (8192,43176,69242,196):
        raise ValueError('packed source shape changed')
    if (symbolic['columns'], symbolic['constraints_per_row'], symbolic['public_values'], symbolic['degree']) != (43176,69242,196,4):
        raise ValueError('symbolic source shape changed')
    if native['backend_proofs'] != 0 or symbolic['backend_proofs'] != 0:
        raise ValueError('source proof status needs renewed review')
    baseline = project(256, 2, 4, 2)
    if (small['raw_height'], small['main_width'], small['extension_degree'], small['queries']) != (256,2,4,64):
        raise ValueError('small proof shape changed')
    if (baseline['reserved_role_count'], baseline['reserved_field_bytes']) != (small['reserved_files'], small['reserved_field_bytes']):
        raise ValueError('actual source owner reservation mismatch')
    if baseline['legacy_prepared_and_commitment_bytes'] != legacy['measured_small_shape']['all_field_file_bytes']:
        raise ValueError('independent prior storage projection mismatch')
    # Literal quantities come from the actual small owner and retained file inventory.
    if list(baseline['role_field_bytes'].values()) != [2048,12288,98304,1048576,131072,32768]:
        raise ValueError('independent small role inventory mismatch')
    refused = 0
    for invalid in [(True,2,4,2),(256,2.0,4,2),(255,2,4,2),(8192,65537,4,2)]:
        try:
            project(*invalid)
        except ValueError:
            refused += 1
    if refused != 4:
        raise ValueError('invalid metadata accepted')
    projection = project(native['height'],native['width'],native['constraints_per_row'],native['public_values'])
    cardinality = 2013265921 ** 4
    if not 2 ** 123 < cardinality < 2 ** 124:
        raise ValueError('challenge cardinality interval mismatch')
    record = {
        'format': 'kova.proof-composition.projection.v1',
        'scope': 'fixed integer metadata projection, no field or prover execution',
        'source_files': {name: identity(raw) for name,raw in sources.items()},
        'small_source_crosscheck': baseline, 'conditional_packed_relation': projection,
        'comparison_profile': expected_profile,
        'extension_four_cardinality': cardinality,
        'challenge_cardinality_binary_interval': [123,124],
        'achieved_security_bits': None, 'invalid_metadata_refusals': refused,
        'same_witness_multi_input_payment_cost_established': False,
        'unmodeled': ['Allocator and DFT scratch overlap', 'AIR folding and reduction scratch',
                      'FRI trees, salts, folds and opening structures', 'Serialized transport and parser limits',
                      'Physical disk allocation, cache and runtime', 'Complete hiding, soundness, knowledge and quantum composition'],
    }
    output = json.dumps(record, indent=2, sort_keys=True).encode() + b'\n'
    if len(output) > 32768:
        raise ValueError('fixed report size exceeded')
    with (HERE / 'projection.json').open('xb') as stream:
        stream.write(output)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    print('Static projection completed. Small owner and prior storage records match. Four invalid metadata cases refuse. No execution admitted.')


if __name__ == '__main__':
    main()
