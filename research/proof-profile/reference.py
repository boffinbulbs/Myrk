"""Independent cardinality, cost and partial model arithmetic checks."""
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 2013265921


def cost(extension, random, queries):
    if any(type(value) is not int for value in [extension, random, queries]):
        raise ValueError('integer model dimensions required')
    if extension not in [4, 8] or not extension <= random <= 16 or not 1 <= queries <= 4096:
        raise ValueError('unsupported conditional profile')
    minimum = 2 * (queries + 2 * extension)
    if minimum > 8192:
        raise ValueError('insufficient conditional mask height')
    main_width = 47058 + random
    prepared = 4 * 16384 * main_width
    committed = 4 * 131072 * (main_width + 9 * (extension + random))
    return dict(prepared_field_bytes=prepared, commitment_field_bytes=committed,
                all_field_bytes=prepared + committed, minimum_mask_height=minimum,
                main_query_field_bytes_at_distinct_indices=4 * queries * main_width)


def validate(record):
    if record['base_modulus'] != P or record['grinding_bits'] != 0 or record['hash_collision_assumption_classical_bits'] != 256:
        raise ValueError('unexpected field or uncredited model assumptions')
    if record['parameter_selection'] or record['quantum_security_established'] or record['knowledge_soundness_established']:
        raise ValueError('a model report cannot establish these protocol properties')
    if record['signature_trace_allocations'] or record['backend_proofs']:
        raise ValueError('unexpected execution scope')
    if (record['height'], record['width'], record['stored_degree_bits']) != (8192, 47058, 14):
        raise ValueError('unexpected validated relation shape')
    if len(record['reports']) != 4:
        raise ValueError('four conditional scenarios required')
    if [row['name'] for row in record['reports']] != ['before_routing', 'current_comparison', 'more_queries', 'larger_extension_candidate']:
        raise ValueError('unexpected conditional scenario set')
    for row in record['reports']:
        fields = row['costs']
        extension, random, queries = [fields[name] for name in ['extension_degree', 'random_codewords', 'queries']]
        expected = cost(extension, random, queries)
        if any(fields[name] != value for name, value in expected.items()):
            raise ValueError('conditional resource arithmetic mismatch')
        bits = (P ** extension).bit_length() - 1
        batching = 2 * (47058 + random) + 9 * (extension + random)
        if row['challenge_field_bits_floor'] != bits or row['batched_opening_functions'] != batching:
            raise ValueError('field or batched opening shape mismatch')
        unique = {term['label']: term['bits'] for term in row['report']['udr']['terms']}
        ali = bits - math.log2(row['constraints'])
        deep_factor = max(4 * (16384 + 1) + 16383, 9 * 16384 + 1)
        deep = bits - math.log2(deep_factor)
        if abs(unique['air-composition'] - ali) > 1e-10 or abs(unique['deep-ali'] - deep) > 1e-10:
            raise ValueError('unique regime ALI or DEEP arithmetic mismatch')
        regimes = [row['report']['udr']]
        if row['report']['ldr'] is not None:
            regimes.append(row['report']['ldr'])
        bound = max(min(term['bits'] for term in regime['terms']) for regime in regimes)
        if abs(bound - row['library_classical_rbr_bits']) > 1e-10:
            raise ValueError('classical report aggregation mismatch')
    return dict(scenarios=4, field_cardinalities={str(e): str(P ** e) for e in [4, 8]},
                whole_fri_model_independently_verified=False, quantum_security_established=False)


def main():
    data = HERE / 'fixtures/report.json'
    if data.stat().st_size > 65536:
        raise SystemExit('Model fixture exceeds its finite bound')
    print(json.dumps(validate(json.loads(data.read_text(encoding='utf8')))))


if __name__ == '__main__':
    main()
