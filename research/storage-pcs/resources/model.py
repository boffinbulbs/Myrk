"""Static field payload accounting. This program never constructs a trace."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SOURCES = [
    'research/signature-complete-native/execution_record.json',
    'research/storage-pcs/validation.json',
    'research/signature-complete-native/src/layout.rs',
    'research/signature-complete-native/src/air.rs',
    'research/signature-complete-native/src/full_program.rs',
    'research/storage-pcs/Cargo.lock',
    'research/storage-pcs/tests/common/mod.rs',
    'research/storage-pcs/tests/common/air.rs',
    'research/storage-pcs/tests/common/store.rs',
    'research/storage-pcs/backend/src/hiding_pcs.rs',
    'research/storage-pcs/backend/src/two_adic_pcs.rs',
    'research/storage-pcs/backend/src/storage.rs',
    'research/storage-matrix/src/lib.rs',
]


def payloads(height, width, constraints):
    """Apply only the retained degree four synthetic profile to a given shape."""
    for value in (height, width, constraints):
        if type(value) is not int or value <= 0 or value > 2**31:
            raise ValueError('positive bounded integer required')
    if height & (height - 1):
        raise ValueError('power of two height required')

    # Four byte field encoding, extension degree four, four random columns,
    # blowup eight and eight coupled quotient chunks are fixed here.
    prepared_height = 2 * height
    prepared_width = width + 4
    lde_height = 16 * height
    output_widths = [prepared_width] + [8] * 9
    output_shapes = [[lde_height, value] for value in output_widths]
    source_bytes = prepared_height * prepared_width * 4
    output_bytes = sum(h * w * 4 for h, w in output_shapes)
    maximum_distinct_queries = 64
    main_query_fields = maximum_distinct_queries * prepared_width
    return {
        'raw_trace_bytes': height * width * 4,
        'prepared_source_shape': [prepared_height, prepared_width],
        'prepared_source_bytes': source_bytes,
        'main_mask_field_draws': height * (width + 8),
        'committed_field_file_shapes': output_shapes,
        'committed_field_file_bytes': output_bytes,
        'all_field_file_bytes': source_bytes + output_bytes,
        'prior_scalar_main_window_reads': prepared_height * prepared_width,
        'main_preparation_window_reads': prepared_height * ((prepared_width + 3) // 4),
        'all_source_window_reads': prepared_height * ((prepared_width + 3) // 4) + 20 * height,
        'all_source_fields_read': prepared_height * prepared_width + 80 * height,
        'commitment_scalar_field_writes': sum(h * w for h, w in output_shapes),
        'commitment_row_span_writes': sum(h * ((w + 3) // 4) for h, w in output_shapes),
        'tile_columns': 4,
        'forward_dft_batches': sum((w + 3) // 4 for w in output_widths),
        'quotient_inverse_dft_batches': 16,
        'largest_explicit_input_tile_bytes': prepared_height * min(4, prepared_width) * 4,
        'largest_explicit_output_tile_bytes': lde_height * min(4, max(output_widths)) * 4,
        'forward_column_dfts': sum(output_widths),
        'quotient_inverse_column_dfts': 64,
        'largest_explicit_column_bytes': lde_height * 4,
        'quotient_domain_rows': 8 * height,
        'constraint_row_positions': 8 * height * constraints,
        'separate_randomization_input_bytes': prepared_height * 8 * 4,
        'prepared_quotient_fields_bytes': 8 * height * 8 * 4,
        'coupled_quotient_masks_bytes': 8 * height * 8 * 4,
        'base_commitment_salt_payload_bytes': 10 * lde_height * 16 * 4,
        'base_commitment_digest_payload_bytes': 3 * (2 * lde_height - 1) * 64,
        'main_query_field_payload_at_64_distinct_queries_bytes': main_query_fields * 4,
        'main_two_point_claim_extension_payload_bytes': 2 * prepared_width * 4 * 4,
        'current_field_store_shape_accepts': lde_height <= 4096 and max(output_widths) <= 12,
        'current_field_store_byte_budget_accepts': source_bytes + output_bytes <= 2 * 1024**2,
    }


def record():
    native = json.loads((ROOT / SOURCES[0]).read_text(encoding='utf8'))
    small = json.loads((ROOT / SOURCES[1]).read_text(encoding='utf8'))
    if native['degree'] != 4 or small['profile'] != {
        'raw_height': 256, 'raw_width': 2, 'constraint_degree': 4,
        'extension_degree': 4, 'log_blowup': 3, 'queries': 64,
        'random_codewords': 4, 'salt_columns': 16, 'fold_arity': 2,
        'grinding_bits': 0,
    }:
        raise ValueError('source profile needs renewed analysis')
    sources = {}
    for name in SOURCES:
        # Source identities use the repository LF representation on Windows.
        raw = (ROOT / name).read_bytes().replace(b'\r\n', b'\n')
        sources[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return {
        'format': 'kova.storage-pcs.resource-model.v2',
        'scope': 'Static shape arithmetic with the retained synthetic profile. No native proof execution or resource admission.',
        'source_files': sources,
        'measured_small_shape': payloads(256, 2, 4),
        'conditional_native_shape': payloads(native['height'], native['width'], native['constraints_per_row']),
        'native_backend_proofs_in_reference_record': native['backend_proofs'],
        'unmodeled': [
            'Allocator overhead and peak buffer overlap',
            'DFT implementation scratch and twiddle tables',
            'Native AIR expression storage and constraint evaluation scratch',
            'FRI salts, trees, reductions, folds and query structures',
            'Opening reductions, point weights and serialization',
            'Operating system file cache, physical disk use and runtime',
            'Production entropy and secret storage protection',
            'Complete payment relation and cryptographic security parameters',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    arguments = parser.parse_args()
    path = HERE / 'record.json'
    expected = json.dumps(record(), indent=2) + '\n'
    if arguments.check:
        if path.read_text(encoding='utf8') != expected:
            raise SystemExit('Resource model or source identity changed')
        print('Static resource model and source identities match')
    else:
        path.write_text(expected, encoding='utf8', newline='\n')


if __name__ == '__main__':
    main()
