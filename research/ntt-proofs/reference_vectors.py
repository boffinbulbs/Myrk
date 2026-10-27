#!/usr/bin/env python3
"""Independent normal residue NTT, direct negacyclic DFT and exact stage references."""

import argparse
import copy
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
Q = 8_380_417
P = 2_013_265_921
N = 256
PSI = 1753
B = 4096
INVERSE_N = pow(N, -1, Q)
CONTEXT = bytes(range(64))
MASK64 = (1 << 64) - 1


def bit_reverse(value):
    result = 0
    for _ in range(8):
        result = 2 * result + value % 2
        value //= 2
    assert value == 0
    return result


ZETAS = [0, *[pow(PSI, bit_reverse(index), Q) for index in range(1, N)]]
ROOTS = [pow(PSI, 2 * bit_reverse(index) + 1, Q) for index in range(N)]
assert pow(PSI, N, Q) == Q - 1 and pow(PSI, 2 * N, Q) == 1
assert len(set(ROOTS)) == N and INVERSE_N == 8_347_681 and ZETAS[1] == 4_808_194


def direct_forward(polynomial):
    """Evaluate at all odd roots by Horner evaluation, without butterfly stages."""
    values = []
    for point in ROOTS:
        total = 0
        for coefficient in reversed(polynomial):
            total = (point * total + coefficient) % Q
        values.append(total)
    return values


def direct_inverse(evaluations):
    """Direct inverse DFT with independent inverse root powers, not a round trip."""
    coefficients = [0] * N
    for value, point in zip(evaluations, ROOTS):
        inverse_point = pow(point, -1, Q)
        power = 1
        for index in range(N):
            coefficients[index] = (coefficients[index] + value * power) % Q
            power = power * inverse_point % Q
    return [value * INVERSE_N % Q for value in coefficients]


def multiplication(x, y, altered_result=None):
    quotient, result = divmod(x * y, Q)
    if altered_result is not None:
        quotient, result = altered_result
    x0, x1 = x % B, x // B
    y0, y1 = y % B, y // B
    k0, k1 = quotient % B, quotient // B
    z0, z1 = result % B, result // B
    c0 = (x0 * y0 - k0 - z0) // B
    c1 = (x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0) // B
    return result, quotient, c0, c1


def transform(polynomial, mode, alteration=None, record=False):
    state = list(polynomial)
    states = [list(state)]
    operations = []
    false_product = None
    for stage in range(8):
        length = (128 >> stage) if mode == 1 else (1 << stage)
        groups = N // (2 * length)
        before = list(state)
        for group in range(groups):
            k = (1 << stage) + group if mode == 1 else (256 >> stage) - 1 - group
            twiddle = ZETAS[k] if mode == 1 else (-ZETAS[k]) % Q
            if alteration == "wrong_twiddle" and stage == 0 and group == 0:
                twiddle = (twiddle + 1) % Q
            if alteration == "sequential_power_twiddles":
                twiddle = pow(PSI, k, Q) if mode == 1 else (-pow(PSI, k, Q)) % Q
            if alteration == "wrong_inverse_sign" and mode == 2:
                twiddle = ZETAS[k]
            for local in range(length):
                left = 2 * group * length + local
                right = left + length
                u, v = before[left], before[right]
                alias = None
                if mode == 1:
                    product_input = v
                    if alteration == "air_field_product_alias" and stage == 0 and group == 0 and local == 0:
                        candidate_k = (twiddle * v - P) // Q
                        candidate_z = twiddle * v - P - Q * candidate_k
                        assert 0 <= candidate_k < Q and 0 <= candidate_z < Q
                        alias = candidate_k, candidate_z
                        false_product = {"x": twiddle, "y": v, "quotient": candidate_k, "result": candidate_z,
                                         "integer_residual": twiddle * v - Q * candidate_k - candidate_z,
                                         "naive_field_residual": (twiddle * v - Q * candidate_k - candidate_z) % P}
                    product, quotient, c0, c1 = multiplication(twiddle, product_input, alias)
                    add_carry = int(u + product >= Q)
                    sub_borrow = int(u < product)
                    out_left = u + product - add_carry * Q
                    out_right = u - product + sub_borrow * Q
                else:
                    add_carry = int(u + v >= Q)
                    sub_borrow = int(u < v)
                    product_input = u - v + sub_borrow * Q
                    product, quotient, c0, c1 = multiplication(twiddle, product_input)
                    out_left = u + v - add_carry * Q
                    out_right = product
                if alteration == "skip_middle_stage" and stage == 4:
                    out_left, out_right = u, v
                state[left], state[right] = out_left, out_right
                if record:
                    operations.append({"stage": stage, "kind": "forward" if mode == 1 else "inverse",
                                       "slot": group * length + local, "length": length, "group": group,
                                       "left_index": left, "right_index": right, "twiddle_index": k,
                                       "twiddle": twiddle, "input_left": u, "input_right": v,
                                       "mul_x": twiddle, "mul_y": product_input, "mul_quotient": quotient,
                                       "mul_result": product, "carry0": c0, "carry1": c1,
                                       "add_carry": add_carry, "sub_borrow": sub_borrow,
                                       "output_left": out_left, "output_right": out_right})
        states.append(list(state))
    if mode == 2:
        factor = INVERSE_N
        if alteration == "missing_normalization":
            factor = 1
        if alteration == "wrong_normalization":
            factor = (INVERSE_N + 1) % Q
        if alteration == "negative_normalization":
            factor = (-INVERSE_N) % Q
        for half in range(2):
            for slot in range(128):
                index = 128 * half + slot
                current = state[index]
                product, quotient, c0, c1 = multiplication(factor, current)
                state[index] = product
                if record:
                    operations.append({"stage": 8 + half, "kind": "normalization", "slot": slot,
                                       "length": 0, "group": half, "left_index": index, "right_index": "",
                                       "twiddle_index": "", "twiddle": factor, "input_left": current,
                                       "input_right": "", "mul_x": factor, "mul_y": current,
                                       "mul_quotient": quotient, "mul_result": product, "carry0": c0,
                                       "carry1": c1, "add_carry": 0, "sub_borrow": 0,
                                       "output_left": product, "output_right": ""})
            states.append(list(state))
    assert len(states) == (9 if mode == 1 else 11)
    assert all(0 <= value < Q for value in state)
    if alteration is None:
        expected = direct_forward(polynomial) if mode == 1 else direct_inverse(polynomial)
        assert state == expected
    return state, states, operations, false_product


def vector(public):
    result = [public["mode"]]
    for name in ["input", "output"]:
        result.extend(byte for value in public[name] for byte in value.to_bytes(4, "little"))
    result.extend(bytes.fromhex(public["context_hex"]))
    assert len(result) == 2113
    return result


def classify(public):
    mode = public["mode"]
    shape = (mode in [1, 2] and len(public["input"]) == len(public["output"]) == N
             and len(bytes.fromhex(public["context_hex"])) == 64)
    canonical = all(0 <= value < Q for value in [*public["input"], *public["output"]])
    valid = False
    if shape and canonical:
        expected = direct_forward(public["input"]) if mode == 1 else direct_inverse(public["input"])
        valid = expected == public["output"]
    return {"shape_valid": shape, "canonical_coefficients_valid": canonical,
            "direct_transform_valid": valid, "valid_component": shape and canonical and valid}


def polynomial_cases():
    cases = [("zero", [0] * N)]
    for index in [0, 1, 128, 255]:
        value = [0] * N
        value[index] = 1
        cases.append((f"basis_{index:03}", value))
    cases.extend([
        ("constant_polynomial_7", [7, *([0] * 255)]),
        ("all_coefficients_one", [1] * N),
        ("all_coefficients_q_minus_one", [Q - 1] * N),
        ("alternating_zero_top", [0 if index % 2 == 0 else Q - 1 for index in range(N)]),
        ("alternating_one_top", [1 if index % 2 == 0 else Q - 1 for index in range(N)]),
        ("coefficient_ramp", list(range(N))),
    ])
    state = 0x54484F52554D4E54
    for sample in range(3):
        polynomial = []
        for _ in range(N):
            state ^= (state << 13) & MASK64
            state ^= state >> 7
            state ^= (state << 17) & MASK64
            state &= MASK64
            polynomial.append(state % Q)
        cases.append((f"dense_deterministic_{sample}", polynomial))
    sparse = [0] * N
    for index, value in [(0, Q - 1), (1, Q - 1), (127, 1), (128, Q - 1), (255, 4096)]:
        sparse[index] = value
    cases.append(("sparse_boundary_coefficients", sparse))
    assert len(cases) == 15
    return cases


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("ascii")


def csv_bytes(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("ascii")


def adapters():
    result = []
    for suffix, values, width in [
        ("leaf.v1", [0, 1, P - 1, 0x12345678], 4),
        ("node.v1", [0, 1, MASK64, *range(13)], 8),
        ("transcript.v1", list(range(64)), 1),
    ]:
        domain = ("thorum.ntt-proof-lab." + suffix).encode("ascii")
        message = len(domain).to_bytes(4, "big") + domain
        message += b"".join(value.to_bytes(width, "little") for value in values)
        message += len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(message).digest()
        result.append({"domain_suffix": suffix, "preimage_hex": message.hex(), "digest_hex": digest.hex(),
                       "little_endian_u64_words": ":".join(str(int.from_bytes(digest[i:i + 8], "little")) for i in range(0, 64, 8))})
    return result


def construction_checks(public, states, operations):
    exact_multiplications = True
    modular_add_sub = True
    twiddles = True
    normalization = True
    state_links = True
    for operation in operations:
        stage = operation["stage"]
        x, y, k, z = [operation[name] for name in ["mul_x", "mul_y", "mul_quotient", "mul_result"]]
        c0, c1 = operation["carry0"], operation["carry1"]
        r0 = (x % B) * (y % B) - k % B - z % B - B * c0
        r1 = ((x % B) * (y // B) + (x // B) * (y % B) - 2046 * (k % B)
              - k // B - z // B + c0 - B * c1)
        r2 = (x // B) * (y // B) - 2046 * (k // B) + c1
        exact_multiplications &= (x * y == Q * k + z and r0 == r1 == r2 == 0
                                  and all(0 <= value < Q for value in [x, y, k, z])
                                  and -2 <= c0 <= 8189 and -4096 <= c1 <= 12287)
        left = operation["left_index"]
        state_links &= states[stage][left] == operation["input_left"]
        state_links &= states[stage + 1][left] == operation["output_left"]
        if operation["kind"] == "normalization":
            normalization &= operation["twiddle"] == INVERSE_N
            continue
        right = operation["right_index"]
        state_links &= states[stage][right] == operation["input_right"]
        state_links &= states[stage + 1][right] == operation["output_right"]
        expected_twiddle = ZETAS[operation["twiddle_index"]]
        if public["mode"] == 2:
            expected_twiddle = (-expected_twiddle) % Q
        twiddles &= operation["twiddle"] == expected_twiddle
        u, v = operation["input_left"], operation["input_right"]
        add, borrow = operation["add_carry"], operation["sub_borrow"]
        modular_add_sub &= add in [0, 1] and borrow in [0, 1]
        if public["mode"] == 1:
            modular_add_sub &= operation["output_left"] == u + z - Q * add
            modular_add_sub &= operation["output_right"] == u - z + Q * borrow
        else:
            modular_add_sub &= operation["output_left"] == u + v - Q * add
            modular_add_sub &= y == u - v + Q * borrow
    half_copy = True
    if public["mode"] == 2:
        half_copy &= states[8][128:] == states[9][128:]
        half_copy &= states[9][:128] == states[10][:128]
    return {"all_stage_coefficients_canonical": all(0 <= value < Q for state in states for value in state),
            "recorded_multiplications_exact": exact_multiplications,
            "recorded_additions_and_subtractions_exact": modular_add_sub,
            "twiddle_schedule_valid": twiddles, "normalization_factor_valid": normalization,
            "recorded_row_links_valid": state_links, "untouched_normalization_half_valid": half_copy,
            "public_output_matches_recorded_state": public["output"] == states[-1]}


def outputs():
    cases, stage_cases, operations = [], [], []

    def add(name, mode, polynomial, output=None, alteration=None, context=CONTEXT):
        calculated, states, auxiliary, alias = transform(polynomial, mode, alteration, record=True)
        public = {"mode": mode, "input": polynomial, "output": calculated if output is None else output,
                  "context_hex": context.hex()}
        case = {"name": name, "public": public, "public_values": vector(public), "expected": classify(public)}
        case["construction_checks"] = construction_checks(public, states, auxiliary)
        if alteration:
            case["alteration"] = alteration
        if alias:
            case["false_product"] = alias
        cases.append(case)
        stage_cases.append({"name": name, "mode": mode, "alteration": alteration,
                            "states": states, "final_output": calculated})
        operations.extend({"case_name": name, **operation} for operation in auxiliary)
        return case

    patterns = polynomial_cases()
    for name, polynomial in patterns:
        for mode in [1, 2]:
            case = add(f"{name}_{'forward' if mode == 1 else 'inverse'}", mode, polynomial)
            assert case["expected"]["valid_component"]
            assert direct_inverse(direct_forward(polynomial)) == polynomial
    assert len(cases) == 30
    dense = next(value for name, value in patterns if name == "dense_deterministic_0")
    fresh = add("same_transform_under_fresh_context", 1, dense, context=bytes([0xE7]) * 64)
    assert fresh["expected"]["valid_component"]
    honest_count = len(cases)
    for mode in [1, 2]:
        for alteration in ["wrong_twiddle", "sequential_power_twiddles", "skip_middle_stage"]:
            case = add(f"{alteration}_{'forward' if mode == 1 else 'inverse'}", mode, dense, alteration=alteration)
            assert not case["expected"]["valid_component"]
    for alteration in ["wrong_inverse_sign", "missing_normalization", "wrong_normalization", "negative_normalization"]:
        case = add(alteration, 2, dense, alteration=alteration)
        assert not case["expected"]["valid_component"]
    case = add("air_field_product_alias_forward", 1, dense, alteration="air_field_product_alias")
    assert case["false_product"]["integer_residual"] == P
    assert not case["expected"]["valid_component"]
    forward = direct_forward(dense)
    wrong = list(forward)
    wrong[255] = (wrong[255] + 1) % Q
    add("wrong_output_last_coefficient", 1, dense, output=wrong)
    wrong_order = [forward[bit_reverse(index)] for index in range(N)]
    add("wrong_output_bit_reversal_order", 1, dense, output=wrong_order)
    add("forward_output_under_inverse_mode", 2, dense, output=forward)
    cyclic = []
    for index in range(N):
        point = pow(PSI, 2 * bit_reverse(index), Q)
        total = 0
        for value in reversed(dense):
            total = (total * point + value) % Q
        cyclic.append(total)
    add("cyclic_roots_instead_of_negacyclic", 1, dense, output=cyclic)
    changed_input = list(dense)
    changed_input[128] = (changed_input[128] + 1) % Q
    add("changed_input_with_old_output", 1, changed_input, output=forward)
    assert len(cases) == 47 and honest_count == 31
    assert sum(case["expected"]["valid_component"] for case in cases) == honest_count
    for case in cases:
        failed_checks = sum(not value for value in case["construction_checks"].values())
        assert failed_checks == (0 if case["expected"]["valid_component"] else 1), case["name"]

    api = []
    baseline = copy.deepcopy(next(case for case in cases if case["name"] == "dense_deterministic_0_forward"))
    for mode in [0, 3]:
        case = copy.deepcopy(baseline)
        case["name"] = f"unsupported_mode_{mode}"
        case["public"]["mode"] = mode
        case["public_values"] = vector(case["public"])
        case["expected"] = classify(case["public"])
        api.append(case)
    for side in ["input", "output"]:
        for value in [Q, (1 << 32) - 1, baseline["public"][side][0] + P]:
            case = copy.deepcopy(baseline)
            case["name"] = f"noncanonical_{side}_{value}"
            case["public"][side][0] = value
            case["public_values"] = vector(case["public"])
            case["expected"] = classify(case["public"])
            api.append(case)
    assert len(api) == 8 and all(not case["expected"]["valid_component"] for case in api)
    rebinding = {
        "scope": "The transform remains valid under fresh opaque context, but an existing proof must fail verification under a changed expected statement. This is a verifier obligation rather than an invalid transform equation.",
        "source_case": "dense_deterministic_0_forward", "fresh_context_case": "same_transform_under_fresh_context",
        "old_proof_under_fresh_context_expected": "reject",
    }
    metadata = {
        "format": "thorum.ntt-proof-lab.reference.v1", "public_synthetic_fixture": True,
        "q": Q, "air_field_prime": P, "length": N, "psi": PSI, "inverse_256": INVERSE_N,
        "residue_representation": "Canonical normal residues, not Montgomery form or signed coefficient decoding",
        "forward_order": "Evaluation at psi^(2*bitrev8(index)+1)",
        "independent_forward": "Direct Horner evaluation at all 256 odd roots, without butterflies",
        "independent_inverse": "Direct inverse DFT coefficient sums with inverse root powers and inverse 256, without butterfly reuse",
        "case_count": len(cases), "valid_case_count": honest_count, "api_rejection_count": len(api),
        "stage_case_count": len(stage_cases), "operation_row_count": len(operations),
        "valid_forward_stage_count": 8, "valid_inverse_stage_count": 10,
        "coefficients_per_state": N, "butterflies_per_layer": 128,
        "normalization_halves": [[0, 128], [128, 256]], "public_vector_length": 2113,
        "scope": "Public input and output polynomial primitive harness. No actual signature polynomial decoding, complete ML-DSA verifier, owner permission, hidden ledger input disclosure or production payment mode is established.",
    }
    sources = {
        "format": "thorum.ntt-proof-lab.source-record.v1",
        "standard": {"name": "NIST FIPS 204", "publication_date": "2024-08-13",
                     "algorithms": [41, 42], "record": "https://csrc.nist.gov/pubs/fips/204/final",
                     "potential_errata_recorded": True},
        "schedule_source": {"package": "ml-dsa", "version": "0.1.1",
                            "vcs_commit": "f75d5b829948988f18d9463f286805fb9410bcdd",
                            "path": "ml-dsa/src/ntt.rs",
                            "source_sha256": "6461fa2933c816906a9baae09df8b6f989a2e9e058fd7607cdc7c8951100af06",
                            "source_url": "https://github.com/RustCrypto/signatures/blob/f75d5b829948988f18d9463f286805fb9410bcdd/ml-dsa/src/ntt.rs"},
        "algebra_source": {"package": "module-lattice", "version": "0.2.3",
                           "vcs_commit": "ac34c85db783520bda5a8fbe8e7b694c7c72d6fe",
                           "path": "module-lattice/src/algebra.rs",
                           "source_sha256": "61f486ec36d712898b080cd13788d3909b6a6c48856a1b597668168e832e19e3",
                           "scope": "Pinned generic algebra dependency. The ML-DSA package implements the inspected butterfly schedule."},
        "reference_scope": "The generator does not import or execute either Rust source. Independent direct DFT and inverse DFT establish its comparison outputs.",
    }
    return {"ntt_vectors.json": json_bytes({"format": metadata["format"], "cases": cases}),
            "api_rejections.json": json_bytes({"format": metadata["format"], "cases": api}),
            "stage_vectors.json": json_bytes({"format": metadata["format"], "cases": stage_cases}),
            "butterfly_operations.csv": csv_bytes(operations),
            "zetas.json": json_bytes({"q": Q, "psi": PSI, "zetas": ZETAS, "evaluation_roots": ROOTS}),
            "statement_rebinding.json": json_bytes(rebinding), "hash_vectors.csv": csv_bytes(adapters()),
            "profile.json": json_bytes(metadata), "source_record.json": json_bytes(sources)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, encoded in outputs().items():
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_bytes() != encoded:
                parser.exit(1, f"Reference differs: {name}\n")
        else:
            path.write_bytes(encoded)
    print("NTT and independent negacyclic DFT references match" if args.check else "NTT references generated")


if __name__ == "__main__":
    main()
