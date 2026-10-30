"""Conditional costs from actual symbolic dimensions. No prover execution."""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent

def costs(height, width, degree, constraints):
    if any(type(value) is not int or not 0 < value <= 2**31 for value in [height, width, degree, constraints]):
        raise ValueError('positive bounded integer dimensions required')
    if height & (height - 1):
        raise ValueError('power of two height required')
    quotient_factor = 1 << (degree - 1).bit_length()
    chunks = 2 * quotient_factor
    lde_height = 16 * height
    commitment_count = chunks + 2
    width_sum = width + 4 + 8 * (chunks + 1)
    source_bytes = 2 * height * (width + 4) * 4
    return dict(
        raw_trace_bytes=height * width * 4,
        quotient_chunks=chunks,
        quotient_domain_rows=chunks * height,
        minimum_two_adic_blowup=quotient_factor,
        retained_blowup_eight_covers_domain=quotient_factor <= 8,
        constraint_row_positions=constraints * chunks * height,
        main_prepared_source_bytes=source_bytes,
        commitment_field_bytes=lde_height * width_sum * 4,
        all_field_file_bytes=source_bytes + lde_height * width_sum * 4,
        field_file_count=commitment_count + 1,
        current_sixteen_file_limit_accepts=commitment_count + 1 <= 16,
        current_shape_limit_accepts=lde_height <= 4096 and max(width + 4, 8) <= 12,
        current_two_mib_field_limit_accepts=source_bytes + lde_height * width_sum * 4 <= 2 * 1024**2,
        base_salt_field_payload_bytes=commitment_count * lde_height * 16 * 4,
        base_digest_payload_bytes=3 * (2 * lde_height - 1) * 64,
        coupled_mask_field_bytes=chunks * height * 8 * 4,
        main_query_payload_at_64_distinct_indices_bytes=64 * (width + 4) * 4,
    )

def record():
    original = json.loads((HERE.parent / 'signature-complete-native/execution_record.json').read_text(encoding='utf8'))
    measured = json.loads((HERE / 'validation.json').read_text(encoding='utf8'))
    prior = json.loads((HERE / 'records/validation-v1.json').read_text(encoding='utf8'))
    bound = json.loads((HERE / 'records/validation-v5.json').read_text(encoding='utf8'))
    return dict(format='kova.signature-scheduling.costs.v3',
        scope='Conditional shape accounting at retained B8, extension4, random4, salt16 and query64. No proof or parameter selection.',
        original=costs(original['height'], original['width'], original['degree'], original['constraints_per_row']),
        factorized=costs(prior['height'], prior['width'], prior['degree'], prior['constraints_per_row']),
        bound_factorized=costs(bound['height'], bound['width'], bound['degree'], bound['constraints_per_row']),
        aggregate_routing=costs(measured['height'], measured['width'], measured['degree'], measured['constraints_per_row']))

def main():
    expected = json.dumps(record(), indent=2) + '\n'
    path = HERE / 'costs.json'
    if sys.argv[1:] == ['--check']:
        if path.read_text(encoding='utf8') != expected:
            raise SystemExit('Conditional resource accounting changed')
        print('Conditional schedule accounting matches measured dimensions')
    elif not sys.argv[1:]:
        path.write_text(expected, encoding='utf8', newline='\n')
    else:
        raise SystemExit('Expected --check or no arguments')

if __name__ == '__main__':
    main()
