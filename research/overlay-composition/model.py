"""Fixed scalar inventory. No witness, field, tree, proof or old model execution."""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUTS = (
    'research/signature-overlay/results/symbolic.json',
    'research/fallible-main/results/native.json',
    'research/source-prover/results/measurement.json',
    'research/storage-pcs/validation.json',
    'research/storage-pcs/resources/record.json',
    'research/signature-overlay/src/layout.rs',
    'research/signature-overlay/src/air.rs',
    'research/fallible-input/src/lib.rs',
    'research/fallible-source/src/extension.rs',
    'research/fallible-source/src/source.rs',
    'research/fallible-source/src/composite.rs',
    'research/fallible-main/src/context.rs',
    'research/fallible-main/src/hiding_pcs.rs',
    'research/fallible-main/src/diagnostics_setup.rs',
    'research/fallible-source/src/owned_prover.rs',
    'research/quotient-source/src/quotient_kernel.rs',
    'research/proof-preflight/src/preflight.rs',
    'research/storage-pcs/backend/src/hiding_pcs.rs',
    'research/storage-pcs/backend/src/two_adic_pcs.rs',
    'research/storage-pcs/backend/src/prover.rs',
    'research/storage-pcs/backend/src/config.rs',
    'research/storage-pcs/backend/src/transcript.rs',
    'research/source-prover/src/diagnostics.rs',
    'research/storage-pcs/tests/common/mod.rs',
    'research/overlay-composition/source-evidence.json',
)


def read(path):
    with path.open('rb') as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError('fixed one MiB evidence bound exceeded')
    return raw.replace(b'\r\n', b'\n')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def inventory(height, width, constraints, public):
    for value, cap in zip((height, width, constraints, public),
                          (8192, 65536, 1000000, 1024), strict=True):
        if type(value) is not int or not 0 < value <= cap:
            raise ValueError('bounded positive scalar required')
    if height < 256 or height & (height - 1):
        raise ValueError('bounded power of two height required')
    h, w, n = height, width + 4, 16 * height
    roles = dict(raw=4*h*width, prepared=8*h*w, main_lde=4*n*w,
                 quotient_ldes=8*4*n*8, auxiliary_lde=4*n*8,
                 canonical_quotient_source=8*h*4*4)
    heights = [n >> i for i in range(1, n.bit_length() - 3)]
    if not 9 <= len(heights) <= 14 or heights[-1] != 8:
        raise ValueError('fixed comparator FRI shape required')
    fri_rows = sum(heights)
    if fri_rows != n - 8:
        raise ValueError('geometric row sum mismatch')
    return {
        'raw_shape': [h, width], 'constraints': constraints, 'public_values': public,
        'prepared_shape': [2*h, w], 'lde_height': n,
        'roles': roles, 'reserved_roles': 13, 'retained_field_file_bytes': sum(roles.values()),
        'main_only_field_file_bytes': roles['raw'] + roles['prepared'] + roles['main_lde'],
        'base_salt_bytes': 10*n*16*4, 'base_digest_bytes': 3*(2*n-1)*64,
        'fri': {'tree_heights': heights, 'rounds': len(heights),
                'retained_field_bytes': fri_rows*8*4,
                'retained_salt_bytes': fri_rows*16*4,
                'retained_digest_bytes': (2*fri_rows-len(heights))*64},
        'accepted_random_fields': {'main': h*(width+8), 'quotient': 88*h,
                                   'auxiliary': 16*h, 'whole': h*(width+112)},
        'accepted_base_salt_fields': 10*n*16,
        'queries': {
            'indices': 64, 'duplicate_rows_preserved': True,
            'main_data_bytes': 64*w*4, 'quotient_data_bytes': 64*8*8*4,
            'auxiliary_data_bytes': 64*8*4, 'base_salt_bytes': 64*10*16*4,
            'fri_sibling_extension_bytes': len(heights)*64*4*4,
            'fri_salt_bytes': len(heights)*64*16*4,
            'main_two_point_extension_claim_bytes': 2*w*4*4,
            'all_ood_extension_claim_bytes': (2*w+72)*4*4,
            'batched_functions': 2*w+72,
            'serialized_bytes_established': False,
        },
        'construction': {
            'column_tile': 4, 'tiles': (w+3)//4,
            'tile_input_payload_bytes': 2*h*4*4, 'tile_output_payload_bytes': n*4*4,
            'dft_moves_and_grows_same_vector': True,
            'main_leaf_preimage_bytes_per_row': (w+16)*4,
            'quotient_batch_leaf_preimage_bytes_per_row': 8*(8+16)*4,
            'auxiliary_leaf_preimage_bytes_per_row': (8+16)*4,
            'quotient_mask_bank_bytes': 7*h*8*4,
            'quotient_random_bank_bytes': 8*h*4*4,
            'auxiliary_dense_input_bytes': 2*h*8*4,
            'normalized_selector_contents_bytes': 4*(8*h)*4,
            'reduced_opening_vector_bytes': n*4*4,
            'compressed_matrix_vector_bytes': n*4*4,
            'peak_memory_established': False,
        },
        'boundaries': {
            'raw_width': width <= 8, 'stored_shape': n <= 4096 and w <= 12,
            'field_files': sum(roles.values()) <= 2097152, 'public_shape': public <= 8,
            'kernel_width': width <= 8, 'kernel_quotient_rows': 8*h <= 4096,
            'kernel_constraints_after_layout': constraints <= 256,
            'general_transport_cap_enforced': False, 'execution_admitted': False,
        },
    }


def main():
    sources = {name: read(ROOT / name) for name in INPUTS}
    if sum(map(len, sources.values())) > 4_194_304:
        raise ValueError('fixed total evidence bound exceeded')
    overlay, main_record, proof, profile, legacy = (
        json.loads(sources[name]) for name in INPUTS[:5])
    if profile['profile'] != dict(raw_height=256, raw_width=2, constraint_degree=4,
                                  extension_degree=4, log_blowup=3, queries=64,
                                  random_codewords=4, salt_columns=16, fold_arity=2, grinding_bits=0):
        raise ValueError('experimental comparator changed')
    if [overlay[k] for k in ('height', 'columns', 'constraints', 'degree', 'public_values')] != [8192,42178,71623,4,196]:
        raise ValueError('measured overlay metadata changed')
    if overlay['backend_proofs'] != 0 or overlay['native_traces'] != 0:
        raise ValueError('symbolic snapshot status changed')
    small = inventory(256, 2, 4, 2)
    if [small['reserved_roles'], small['retained_field_file_bytes'], small['main_only_field_file_bytes']] != [main_record['reserved_files'], main_record['reserved_bytes'], main_record['retained_main_field_bytes']]:
        raise ValueError('independent actual owner contents disagree')
    if main_record['source_shape'] != [256,2] or main_record['complete_proofs'] != 0:
        raise ValueError('main only reference scope changed')
    if small['roles']['main_lde']//4 != main_record['returned_main_fields']:
        raise ValueError('actual returned main field count disagrees')
    if small['construction']['main_leaf_preimage_bytes_per_row']*4096 != main_record['captured_leaf_bytes']:
        raise ValueError('actual leaf preimage length disagrees')
    if 4096*16 != main_record['committed_salt_preimage_fields']:
        raise ValueError('actual salt preimage count disagrees')
    if small['retained_field_file_bytes'] - small['roles']['raw'] - small['roles']['canonical_quotient_source'] != legacy['measured_small_shape']['all_field_file_bytes']:
        raise ValueError('independent original storage contents disagree')
    observations = proof['prover_observations']
    if [proof['raw_height'],proof['main_width'],proof['extension_degree'],proof['queries']] != [256,2,4,64]:
        raise ValueError('complete proof reference shape changed')
    if small['fri']['rounds'] != observations['extension_commits'] or len(proof['commit_roots']) != small['fri']['rounds']+observations['input_commits']:
        raise ValueError('independent complete proof FRI count disagrees')
    if not (small['accepted_random_fields']['main'] <= main_record['counts']['mask']['next_u32']
            and small['accepted_random_fields']['whole'] <= observations['mask']['next_u32']
            and small['accepted_base_salt_fields'] <= observations['salt']['next_u32']):
        raise ValueError('accepted fields exceed delivered source RNG draws')
    refusals = 0
    for args in ((True,2,4,2), (256,2.0,4,2), (255,2,4,2), (256,0,4,2),
                 (16384,2,4,2), (256,65537,4,2), (256,2,1000001,2), (256,2,4,1025)):
        try:
            inventory(*args)
        except ValueError:
            refusals += 1
    if refusals != 8:
        raise ValueError('invalid scalar metadata accepted')
    record = {
        'format': 'kova.overlay-composition.inventory.v1',
        'scope': 'Fixed integer source inventory, no field or proof execution',
        'source_files': {name: pin(raw) for name, raw in sources.items()},
        'small_reference': small,
        'conditional_overlay': inventory(8192,42178,71623,196),
        'invalid_metadata_refusals': refusals, 'comparison_profile': profile['profile'],
        'saved_small_proof_encoded_bytes': proof['encoded_proof_bytes'],
        'saved_small_proof_is_full_signature': False,
        'whole_salt_rng_byte_coverage_established': False,
        'achieved_security_bits': None, 'payment_witness_joins_established': False,
        'field_instances': 0, 'prover_instances': 0, 'backend_proofs': 0,
    }
    encoded = (json.dumps(record, indent=2, sort_keys=True)+'\n').encode()
    if len(encoded) > 32768:
        raise ValueError('fixed output bound exceeded')
    with (HERE / 'inventory.json').open('xb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    print('Independent saved boundaries and eight metadata refusals verified. Scalar inventory only.')


if __name__ == '__main__':
    main()
