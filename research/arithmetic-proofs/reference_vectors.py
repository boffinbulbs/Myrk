#!/usr/bin/env python3
"""Independent bounded integer multiplication references for the ML-DSA modulus."""

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
B = 4096
VALUE_BITS = 23
COMPLEMENTS = 4 * VALUE_BITS
CARRY0 = 8 * VALUE_BITS
CARRY1 = CARRY0 + 13
WIDTH = CARRY1 + 14
CONTEXT = bytes(range(64))
MASK64 = (1 << 64) - 1


def encode_bits(value, width):
    assert 0 <= value < 1 << width
    return [(value >> bit) & 1 for bit in range(width)]


def decode_bits(bits):
    return sum(value << bit for bit, value in enumerate(bits))


def limbs(value):
    return value % B, value // B


def residuals(values, c0, c1):
    x, y, k, z = values
    x0, x1 = limbs(x)
    y0, y1 = limbs(y)
    k0, k1 = limbs(k)
    z0, z1 = limbs(z)
    return [x0 * y0 - k0 - z0 - B * c0,
            x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0 - B * c1,
            x1 * y1 - 2046 * k1 + c1]


def inferred_carries(values):
    x, y, k, z = values
    x0, x1 = limbs(x)
    y0, y1 = limbs(y)
    k0, k1 = limbs(k)
    z0, z1 = limbs(z)
    c0 = (x0 * y0 - k0 - z0) // B
    c1 = (x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0) // B
    return c0, c1


def witness_row(values, c0=None, c1=None):
    assert len(values) == 4 and all(0 <= value < 1 << 23 for value in values)
    if c0 is None or c1 is None:
        c0, c1 = inferred_carries(values)
    complements = [(Q - 1 - value) % (1 << 23) for value in values]
    row = [bit for value in values for bit in encode_bits(value, 23)]
    row.extend(bit for value in complements for bit in encode_bits(value, 23))
    assert -2 <= c0 <= 8189 and -4096 <= c1 <= 12287
    row.extend(encode_bits(c0 + 2, 13))
    row.extend(encode_bits(c1 + 4096, 14))
    assert len(row) == WIDTH == 211
    return row


def public_values(public):
    values = [byte for name in ["x", "y", "z"] for byte in public[name].to_bytes(4, "little")]
    values.extend(bytes.fromhex(public["context_hex"]))
    assert len(values) == 76
    return values


def oracle(row, public):
    assert len(row) == WIDTH and all(0 <= value < P for value in row)
    values = [decode_bits(row[index * 23:(index + 1) * 23]) for index in range(4)]
    complements = [decode_bits(row[COMPLEMENTS + index * 23:COMPLEMENTS + (index + 1) * 23]) for index in range(4)]
    c0_shifted = decode_bits(row[CARRY0:CARRY1])
    c1_shifted = decode_bits(row[CARRY1:])
    c0, c1 = c0_shifted - 2, c1_shifted - 4096
    trace_limbs = [(decode_bits(row[index * 23:index * 23 + 12]),
                    decode_bits(row[index * 23 + 12:(index + 1) * 23])) for index in range(4)]
    (x0, x1), (y0, y1), (k0, k1), (z0, z1) = trace_limbs
    equations = [x0 * y0 - k0 - z0 - B * c0,
                 x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0 - B * c1,
                 x1 * y1 - 2046 * k1 + c1]
    complement_equations = [value + complement - (Q - 1) for value, complement in zip(values, complements)]
    value_bits = all(value in (0, 1) for value in row[:COMPLEMENTS])
    complement_bits = all(value in (0, 1) for value in row[COMPLEMENTS:CARRY0])
    carry_bits = all(value in (0, 1) for value in row[CARRY0:])
    complement_equalities = all(residual % P == 0 for residual in complement_equations)
    ranges = value_bits and complement_bits and complement_equalities
    naive_bindings = all((values[index] - public[name]) % P == 0 for index, name in [(0, "x"), (1, "y"), (3, "z")])
    bindings = True
    for slot, name in [(0, "x"), (1, "y"), (3, "z")]:
        for byte, expected_byte in enumerate(public[name].to_bytes(4, "little")):
            start = slot * 23 + byte * 8
            actual = decode_bits(row[start:slot * 23 + min(byte * 8 + 8, 23)]) if byte < 3 else 0
            bindings &= (actual - expected_byte) % P == 0
    public_valid = all(0 <= public[name] < Q for name in ["x", "y", "z"])
    field_equations = all(residual % P == 0 for residual in equations)
    x, y, k, z = values
    integer_residual = x * y - Q * k - z
    expected = {
        "statement_valid": public_valid, "value_bits_valid": value_bits,
        "complement_bits_valid": complement_bits,
        "complement_equations_valid": complement_equalities,
        "range_constraints_valid": ranges, "carry_bits_valid": carry_bits,
        "canonical_values_valid": all(0 <= value < Q for value in values),
        "public_bindings_valid": bindings, "naive_packed_public_bindings_valid": naive_bindings,
        "integer_limb_equations_valid": equations == [0, 0, 0],
        "field_limb_equations_valid": field_equations,
        "integer_product_valid": integer_residual == 0,
        "naive_field_product_valid": integer_residual % P == 0,
        "valid_component": public_valid and ranges and carry_bits and bindings and field_equations,
    }
    if expected["valid_component"]:
        assert expected["canonical_values_valid"] and expected["integer_limb_equations_valid"]
        assert expected["integer_product_valid"]
        assert divmod(x * y, Q) == (k, z)
    diagnostics = {
        "values_x_y_k_z": values, "trace_limbs_low_high": trace_limbs, "complements": complements,
        "carry0_shifted": c0_shifted, "carry1_shifted": c1_shifted,
        "carry0": c0, "carry1": c1, "limb_residuals": equations,
        "complement_residuals": complement_equations,
        "integer_product_residual": integer_residual,
        "integer_product_residual_mod_p": integer_residual % P,
        "field_limb_residuals": [residual % P for residual in equations],
    }
    return expected, diagnostics


def bound_derivation():
    assert Q == 2046 * B + 1
    valid_c0_numerator = [-2 * (B - 1), (B - 1) ** 2]
    valid_c0 = [(valid_c0_numerator[0] + B - 1) // B, valid_c0_numerator[1] // B]
    valid_c1_numerator = [-2046 * (B - 1) - 2046 - 2046 + valid_c0[0],
                          2 * (B - 1) * 2046 + valid_c0[1]]
    valid_c1 = [(valid_c1_numerator[0] + B - 1) // B, valid_c1_numerator[1] // B]
    encoded_c0 = [-2, (1 << 13) - 1 - 2]
    encoded_c1 = [-4096, (1 << 14) - 1 - 4096]
    r0 = [-2 * (B - 1) - B * encoded_c0[1], (B - 1) ** 2 - B * encoded_c0[0]]
    r1 = [-2046 * (B - 1) - 2046 - 2046 + encoded_c0[0] - B * encoded_c1[1],
          2 * (B - 1) * 2046 + encoded_c0[1] - B * encoded_c1[0]]
    r2 = [-2046 * 2046 + encoded_c1[0], 2046 * 2046 + encoded_c1[1]]
    complement_residual = [-(Q - 1), 2 * ((1 << 23) - 1) - (Q - 1)]
    assert valid_c0 == [-1, 4094] and valid_c1 == [-2046, 4092]
    assert r0 == [-33550334, 16777217]
    assert r1 == [-58710016, 33542145]
    assert r2 == [-4190212, 4198403]
    assert all(-P < lower <= upper < P for lower, upper in [r0, r1, r2, complement_residual])
    return {
        "q": Q, "air_field_prime": P, "radix": B, "q_limbs_low_high": [1, 2046],
        "value_bit_width": 23, "value_unconstrained_bit_maximum": (1 << 23) - 1,
        "canonical_value_range": [0, Q - 1], "canonical_high_limb_maximum": 2046,
        "low_limb_range": [0, B - 1], "complement_residual_range_before_canonicality": complement_residual,
        "valid_carry0_numerator_range": valid_c0_numerator, "valid_carry0_conservative_range": valid_c0,
        "valid_carry1_numerator_range": valid_c1_numerator, "valid_carry1_conservative_range": valid_c1,
        "carry0_shift": 2, "carry0_bits": 13, "encoded_carry0_signed_range": encoded_c0,
        "carry1_shift": 4096, "carry1_bits": 14, "encoded_carry1_signed_range": encoded_c1,
        "limb_residual_ranges_under_all_encoded_carries": [r0, r1, r2],
        "bounds_are_conservative_not_all_claimed_attainable": True,
        "recombination_identity": "R0 + B*R1 + B^2*R2 = x*y - q*k - z",
        "soundness_steps": [
            "Boolean value and complement bits bound each decoded integer by 2^23-1.",
            "The complement residual lies strictly between -p and p, so its field zero is exact integer zero.",
            "Each value and its nonnegative complement sum to q-1, so each value is canonical.",
            "Boolean shifted carry bits establish the recorded signed intervals.",
            "Each limb residual lies strictly between -p and p under these bounds.",
            "Each field limb equality is therefore an exact integer equality.",
            "The weighted sum cancels both carries and gives exact x*y=q*k+z.",
            "Canonical z and nonnegative k make k and z the unique Euclidean quotient and remainder.",
        ],
    }


def outputs():
    cases = []

    def add(name, values, row=None, public=None, note=None):
        row = witness_row(values) if row is None else row
        public = ({"x": values[0], "y": values[1], "z": values[3], "context_hex": CONTEXT.hex()}
                  if public is None else public)
        expected, diagnostics = oracle(row, public)
        case = {"name": name, "expected": expected, "public": public,
                "public_values": public_values(public), "witness": {"raw_bits": row},
                "diagnostics": diagnostics}
        if note:
            case["classification_note"] = note
        cases.append(case)
        return case

    def honest(name, x, y):
        k, z = divmod(x * y, Q)
        case = add(name, [x, y, k, z])
        assert case["expected"]["valid_component"]
        return case

    for x in [0, 1, Q - 1]:
        for y in [0, 1, Q - 1]:
            honest(f"corner_x_{x}_y_{y}", x, y)
    boundaries = [2, 2045, 2046, 2047, 4095, 4096, 4097, 8191, 8192,
                  (1 << 22) - 1, 1 << 22, Q - 4097, Q - 4096, Q - 2]
    for value in boundaries:
        honest(f"boundary_square_{value}", value, value)
        honest(f"boundary_times_q_minus_one_{value}", value, Q - 1)
    honest("carry0_upper_bound_attained", 20479, 6705151)
    state = 0x54484F52554D0087

    def next_word():
        nonlocal state
        state ^= (state << 13) & MASK64
        state ^= state >> 7
        state ^= (state << 17) & MASK64
        state &= MASK64
        return state

    for index in range(128):
        honest(f"deterministic_pair_{index:03}", next_word() % Q, next_word() % Q)
    valid_count = len(cases)
    assert valid_count == 166

    base = next(case for case in cases if case["name"] == f"corner_x_{Q - 1}_y_{Q - 1}")
    base_values = base["diagnostics"]["values_x_y_k_z"]

    def changed(name, values=None, raw=None, public=None, note=None):
        selected_values = base_values if values is None else values
        selected_row = witness_row(selected_values) if raw is None else raw
        selected_public = copy.deepcopy(base["public"]) if public is None else public
        case = add(name, selected_values, selected_row, selected_public, note)
        assert not case["expected"]["valid_component"]
        return case

    for name, values in [
        ("wrong_quotient", [Q - 1, Q - 1, Q - 3, 1]),
        ("wrong_remainder", [Q - 1, Q - 1, Q - 2, 2]),
        ("zero_quotient_for_nonzero_product", [Q - 1, Q - 1, 0, 1]),
    ]:
        changed(name, values)
    for index, name in enumerate(["x", "y", "quotient", "remainder"]):
        for value in [Q, (1 << 23) - 1]:
            values = list(base_values)
            values[index] = value
            changed(f"noncanonical_private_{name}_{value}", values, note="The 23 bit representation exists, but the complement equation must reject a value at or above q.")
    for section, start, width in [("value", 0, 92), ("complement", COMPLEMENTS, 92),
                                  ("carry0", CARRY0, 13), ("carry1", CARRY1, 14)]:
        row = list(base["witness"]["raw_bits"])
        row[start] = 2
        changed(f"nonboolean_{section}_bit", raw=row)
    for index in range(4):
        row = list(base["witness"]["raw_bits"])
        row[COMPLEMENTS + index * 23] ^= 1
        changed(f"wrong_complement_{index}", raw=row)
    for name, start, width, encoded in [
        ("carry0_signed_lower_endpoint", CARRY0, 13, 0),
        ("carry0_signed_upper_endpoint", CARRY0, 13, (1 << 13) - 1),
        ("carry1_signed_lower_endpoint", CARRY1, 14, 0),
        ("carry1_signed_upper_endpoint", CARRY1, 14, (1 << 14) - 1),
    ]:
        row = list(base["witness"]["raw_bits"])
        row[start:start + width] = encode_bits(encoded, width)
        changed(name, raw=row)
    for name, start, width, field_value in [
        ("unshifted_negative_carry0_field_alias", CARRY0, 13, P - 1),
        ("unshifted_negative_carry1_field_alias", CARRY1, 14, P - 2046),
    ]:
        row = list(base["witness"]["raw_bits"])
        row[start:start + width] = [field_value, *([0] * (width - 1))]
        changed(name, raw=row, note="A raw negative field residue cannot replace the required bounded nonnegative shifted carry bit representation.")
    for multiplier, x, y in [(1, Q - 1, Q - 1), (2, Q - 1, Q - 1),
                              (4, Q - 1, Q - 1), (-1, 0, 0), (-2, 0, 0), (-4, 1, 1)]:
        k = (x * y - multiplier * P) // Q
        z = x * y - multiplier * P - k * Q
        assert 0 <= k < Q and 0 <= z < Q
        values = [x, y, k, z]
        public = {"x": x, "y": y, "z": z, "context_hex": CONTEXT.hex()}
        case = changed(f"naive_field_alias_{multiplier:+}_regular_carries", values, public=public)
        assert case["expected"]["canonical_values_valid"] and case["expected"]["naive_field_product_valid"]
        assert case["diagnostics"]["integer_product_residual"] == multiplier * P
        x0, x1 = limbs(x)
        y0, y1 = limbs(y)
        k0, k1 = limbs(k)
        z0, z1 = limbs(z)
        inverse_b = pow(B, -1, P)
        c0_field = (x0 * y0 - k0 - z0) * inverse_b % P
        c1_field = (x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0_field) * inverse_b % P
        assert (x1 * y1 - 2046 * k1 + c1_field) % P == 0
        row = witness_row(values)
        for start, width, shifted in [(CARRY0, 13, (c0_field + 2) % P),
                                       (CARRY1, 14, (c1_field + 4096) % P)]:
            row[start:start + width] = (encode_bits(shifted, width) if shifted < 1 << width else
                                        [shifted, *([0] * (width - 1))])
        case = changed(f"field_limb_alias_{multiplier:+}_unbounded_carry", values, row, public,
                       "All three field limb equations vanish and all four values are canonical, but a shifted carry bit is nonboolean. Bounded carries reject this genuine field alias.")
        assert case["expected"]["field_limb_equations_valid"]
        assert not case["expected"]["carry_bits_valid"]
        assert not case["expected"]["integer_product_valid"]
    for name in ["x", "y", "z"]:
        public = copy.deepcopy(base["public"])
        public[name] ^= 1
        changed(f"changed_public_{name}", raw=list(base["witness"]["raw_bits"]), public=public)
    api_rejections = []
    for name in ["x", "y", "z"]:
        for value in [Q, (1 << 32) - 1, base["public"][name] + P]:
            public = copy.deepcopy(base["public"])
            public[name] = value
            expected, diagnostics = oracle(base["witness"]["raw_bits"], public)
            assert not expected["statement_valid"]
            api_rejections.append({"name": f"public_{name}_out_of_range_{value}", "public": public,
                                   "public_values": public_values(public), "expected": expected,
                                   "witness": base["witness"], "diagnostics": diagnostics})
    for case in cases:
        expected, diagnostics = oracle(case["witness"]["raw_bits"], case["public"])
        assert expected == case["expected"] and diagnostics == case["diagnostics"]
        for offset in [COMPLEMENTS, CARRY0, CARRY1]:
            assert 0 < offset < WIDTH
    bounds = bound_derivation()
    metadata = {
        "format": "thorum.arithmetic-proof-lab.reference.v1", "public_synthetic_fixture": True,
        "scope": "Primitive exact multiplication only. The test harness publishes operands and result, not a private NTT, signature, owner or ledger proof.",
        "q": Q, "air_field_prime": P, "radix": B, "trace_width": WIDTH,
        "value_offsets": [0, 23, 46, 69], "complement_offsets": [92, 115, 138, 161],
        "carry0_offset": CARRY0, "carry1_offset": CARRY1,
        "trace_height": 256, "public_vector_length": 76,
        "case_count": len(cases), "valid_case_count": valid_count,
        "invalid_case_count": len(cases) - valid_count, "api_rejection_count": len(api_rejections),
        "deterministic_pair_count": 128, "deterministic_generator": "xorshift64 with shifts 13,7,17 and explicit 64 bit masking",
        "deterministic_seed_hex": "54484f52554d0087",
        "observed_valid_carry0_range": [min(case["diagnostics"]["carry0"] for case in cases[:valid_count]), max(case["diagnostics"]["carry0"] for case in cases[:valid_count])],
        "observed_valid_carry1_range": [min(case["diagnostics"]["carry1"] for case in cases[:valid_count]), max(case["diagnostics"]["carry1"] for case in cases[:valid_count])],
    }
    encode = lambda value: (json.dumps(value, indent=2) + "\n").encode("ascii")
    hashes = []
    for suffix, values, width in [
        ("leaf.v1", [0, 1, P - 1, 0x12345678], 4),
        ("node.v1", [0, 1, MASK64, *range(13)], 8),
        ("transcript.v1", list(range(64)), 1),
    ]:
        domain = ("thorum.arithmetic-proof-lab." + suffix).encode("ascii")
        message = len(domain).to_bytes(4, "big") + domain
        message += b"".join(value.to_bytes(width, "little") for value in values)
        message += len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(message).digest()
        hashes.append({"domain_suffix": suffix, "preimage_hex": message.hex(), "digest_hex": digest.hex(),
                       "little_endian_u64_words": ":".join(str(int.from_bytes(digest[i:i + 8], "little")) for i in range(0, 64, 8))})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(hashes[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(hashes)
    return {"multiplication_vectors.json": encode({"format": metadata["format"], "cases": cases}),
            "api_rejections.json": encode({"format": metadata["format"], "cases": api_rejections}),
            "bounds.json": encode(bounds), "profile.json": encode(metadata),
            "hash_vectors.csv": buffer.getvalue().encode("ascii")}


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
    print("Exact multiplication references match" if args.check else "Exact multiplication references generated")


if __name__ == "__main__":
    main()
