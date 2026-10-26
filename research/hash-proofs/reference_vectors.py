#!/usr/bin/env python3
"""Independent SHA3 and SHAKE primitive relation reference states."""

import argparse
import copy
import csv
import functools
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_INPUT = 2592
MAX_OUTPUT = 840
MASK = (1 << 64) - 1
MODES = {1: (72, 6, "sha3_512"), 2: (168, 31, "shake128"), 3: (136, 31, "shake256")}
CONTEXT = bytes(range(64))
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)


def rotate(value, amount):
    amount %= 64
    return ((value << amount) | (value >> ((64 - amount) % 64))) & MASK


def permutation(lanes, round_constant):
    """FIPS 202 round with rho offsets derived from the coordinate recurrence."""
    parity = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
    state = [lanes[x + 5 * y] ^ parity[(x + 4) % 5] ^ rotate(parity[(x + 1) % 5], 1) for y in range(5) for x in range(5)]
    rotated = state.copy()
    x, y = 1, 0
    for t in range(24):
        rotated[x + 5 * y] = rotate(state[x + 5 * y], (t + 1) * (t + 2) // 2)
        x, y = y, (2 * x + 3 * y) % 5
    moved = [0] * 25
    for y in range(5):
        for x in range(5):
            moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotated[x + 5 * y]
    result = [moved[x + 5 * y] ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]) for y in range(5) for x in range(5)]
    result[0] ^= round_constant
    return result


def state_bytes(state):
    return b"".join(value.to_bytes(8, "little") for value in state)


def frame(value):
    return len(value).to_bytes(4, "big") + value


def padded_message(message, rate, suffix):
    padded = bytearray(message)
    padded.append(suffix)
    padded.extend(bytes((-len(padded)) % rate))
    padded[-1] |= 128
    return bytes(padded)


def sponge(message, mode, output_length, record=False, alteration=None):
    rate, suffix, _ = MODES[mode]
    if alteration == "wrong_rate":
        rate = 136 if rate != 136 else 168
    if alteration == "wrong_suffix":
        suffix = 6 if suffix == 31 else 31
    padded = padded_message(message, rate, suffix)
    if alteration in {"missing_terminal_bit", "changed_zero_padding"}:
        changed = bytearray(padded)
        if alteration == "missing_terminal_bit":
            changed[-1] ^= 128
        else:
            assert len(message) + 1 < len(changed) - 1
            changed[len(message) + 1] ^= 1
        padded = bytes(changed)
    states, rounds = [], []
    state = [0] * 25

    def step(phase, block):
        nonlocal state
        before = state_bytes(state)
        if phase == "squeeze" and alteration == "reset_squeeze_capacity":
            state[rate // 8:] = [0] * (25 - rate // 8)
        if phase == "squeeze" and alteration == "reset_squeeze_state":
            state = [0] * 25
        if phase == "squeeze" and alteration == "nonzero_squeeze_absorption":
            block = bytes([1, *block[1:]])
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:lane * 8 + 8], "little")
        absorbed = state_bytes(state)
        stage = len(states)
        for round_index, constant in enumerate(ROUND_CONSTANTS):
            state = permutation(state, constant)
            if record:
                rounds.append({"stage": stage, "phase": phase, "round": round_index, "state_hex": state_bytes(state).hex()})
        states.append({"stage": stage, "phase": phase, "rate": rate, "input_hex": block.hex(), "state_before_hex": before.hex(), "state_absorbed_hex": absorbed.hex(), "state_after_hex": state_bytes(state).hex()})

    for offset in range(0, len(padded), rate):
        step("absorb", padded[offset:offset + rate])
    result = bytearray(state_bytes(state)[:rate])
    while len(result) < output_length:
        step("squeeze", bytes(rate))
        result.extend(state_bytes(state)[:rate])
    output = bytes(result[:output_length])
    if alteration is None:
        expected = (hashlib.sha3_512(message).digest() if mode == 1 else
                    hashlib.shake_128(message).digest(output_length) if mode == 2 else
                    hashlib.shake_256(message).digest(output_length))
        assert output == expected
    return output, padded, states if record else [], rounds


@functools.lru_cache(maxsize=None)
def exact_hash(message, mode, output_length):
    return sponge(message, mode, output_length)[0]


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("ascii")


def csv_bytes(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("ascii")


def public_vector(public):
    return [public["mode"], *public["input_length"].to_bytes(4, "big"),
            *public["output_length"].to_bytes(4, "big"),
            *bytes.fromhex(public["output_hex"]), *bytes.fromhex(public["context_hex"])]


def oracle(witness, public):
    message = bytes.fromhex(witness["input_hex"])
    output = bytes.fromhex(public["output_hex"])
    mode, input_length, length = public["mode"], public["input_length"], public["output_length"]
    shape = (mode in MODES and 0 <= input_length <= MAX_INPUT and
             1 <= length <= MAX_OUTPUT and (mode != 1 or length == 64) and
             len(output) == MAX_OUTPUT and not any(output[length:]) and
             len(bytes.fromhex(public["context_hex"])) == 64)
    input_matches = len(message) == input_length
    output_matches = (shape and exact_hash(message, mode, length) == output[:length])
    return {"shape_valid": shape, "input_length_valid": input_matches,
            "output_valid": output_matches,
            "valid_component": shape and input_matches and output_matches}


def application_inputs():
    source = json.loads((ROOT / "source_public_key.json").read_text())
    pk = bytes.fromhex(source["public_key_hex"])
    assert len(pk) == 2592
    assert hashlib.sha256(pk).hexdigest() == source["public_key_sha256"]
    chain = bytes(range(32))
    version = 7
    validation_tag = bytes([0xA1]) * 32
    anchor = bytes([0xB2]) * 64
    input_nullifier = bytes([0xC3]) * 64
    output_commitment = bytes([0xD4]) * 64
    kem_ciphertext = bytes((i * 13 + 7) % 256 for i in range(1568))
    nonce = bytes(range(12))
    ciphertext_and_tag = bytes((i * 17 + 9) % 256 for i in range(418 + 16))
    envelope = (b"THMLAB01" + (1).to_bytes(2, "big") + frame(kem_ciphertext)
                + frame(nonce) + frame(ciphertext_and_tag))
    transaction = (frame(b"thorum.relation-lab.payment-statement.v1") + frame((1).to_bytes(2, "big"))
                   + frame(chain) + frame(version.to_bytes(4, "big"))
                   + frame(validation_tag) + frame(anchor)
                   + frame((1).to_bytes(4, "big")) + frame(input_nullifier)
                   + frame((1).to_bytes(4, "big")) + frame(output_commitment)
                   + frame(envelope) + frame((1).to_bytes(8, "big")))
    authorization_message = exact_hash(frame(b"thorum.relation-lab.payment-authorization.v1") + frame(transaction), 1, 64)
    tag = exact_hash(frame(b"thorum.relation-lab.payment-auth-context.v1") + frame(authorization_message), 1, 64)[:32]
    crypto_context = frame(chain) + frame(version.to_bytes(4, "big")) + frame(tag)
    authorization = (frame(b"thorum.crypto-lab.authorization.v1") + frame((1).to_bytes(2, "big"))
                     + frame(crypto_context) + frame(authorization_message))
    fips_context = b"Thorum crypto laboratory authorization v1"
    tr = exact_hash(pk, 3, 64)
    mu_message = tr + bytes([0, len(fips_context)]) + fips_context + authorization
    matrix_input = pk[:32] + bytes([0, 0])
    mu = exact_hash(mu_message, 3, 64)
    encoded_w1 = bytes((index * 19 + 3) % 256 for index in range(1024))
    challenge_input = mu + encoded_w1
    assert len(envelope) == 2036
    assert len(crypto_context) == 80 and len(authorization) == 196
    assert len(fips_context) == 41 and len(mu_message) == 303
    assert len(matrix_input) == 34 and len(transaction) <= MAX_INPUT
    assert len(challenge_input) == 1088
    return source, {
        "format": "thorum.hash-proof-lab.application-inputs.v1",
        "public_synthetic_fixture": True,
        "scope": "Public hash primitive examples. The envelope is structurally encoded synthetic bytes, without valid encapsulation, ciphertext, signature or transaction acceptance evidence. No composed AIR transaction or owner binding is established.",
        "chain_hex": chain.hex(), "current_protocol_version": version,
        "validation_tag_hex": validation_tag.hex(), "anchor_hex": anchor.hex(),
        "input_nullifier_hex": input_nullifier.hex(), "output_commitment_hex": output_commitment.hex(),
        "native_fee": 1, "kem_ciphertext_hex": kem_ciphertext.hex(), "nonce_hex": nonce.hex(),
        "ciphertext_and_tag_hex": ciphertext_and_tag.hex(), "encoded_envelope_hex": envelope.hex(),
        "transaction_hex": transaction.hex(), "transaction_length": len(transaction),
        "authorization_message_hex": authorization_message.hex(),
        "crypto_context_hex": crypto_context.hex(), "authorization_input_hex": authorization.hex(),
        "fips_context_hex": fips_context.hex(), "tr_hex": tr.hex(),
        "mu_input_hex": mu_message.hex(), "matrix_input_hex": matrix_input.hex(),
        "mu_hex": mu.hex(), "synthetic_encoded_w1_hex": encoded_w1.hex(),
        "challenge_input_hex": challenge_input.hex(),
        "matrix_row": 0, "matrix_column": 0,
    }, pk


def adapter_vectors():
    rows = []
    for suffix, values, width in [
        (b"leaf.v1", [0, 1, 2013265920, 0x12345678], 4),
        (b"node.v1", [0, 1, MASK, *range(13)], 8),
        (b"transcript.v1", list(range(64)), 1),
    ]:
        message = (frame(b"thorum.hash-proof-lab." + suffix)
                   + b"".join(value.to_bytes(width, "little") for value in values)
                   + len(values).to_bytes(8, "big"))
        output = exact_hash(message, 1, 64)
        rows.append({"domain_suffix": suffix.decode("ascii"), "preimage_hex": message.hex(),
                     "digest_hex": output.hex(),
                     "little_endian_u64_words": ":".join(str(int.from_bytes(output[i:i + 8], "little")) for i in range(0, 64, 8))})
    return rows


def self_check():
    count = 0
    for mode, (rate, _, _) in MODES.items():
        for length in [*range(0, 218), 2592]:
            message = bytes((index * 29 + length * 11) % 256 for index in range(length))
            output_lengths = [64] if mode == 1 else [1, rate - 1, rate, rate + 1, 840]
            for output_length in output_lengths:
                exact_hash(message, mode, output_length)
                count += 1
    assert count == 2409
    return count


def outputs():
    source, application, pk = application_inputs()
    cases = []
    input_lengths = [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 2592]
    output_lengths = [1, 63, 64, 135, 136, 137, 167, 168, 169, 839, 840]

    def add(name, message, mode, output_length, output=None, rationale=None):
        if output is None:
            output = exact_hash(message, mode, output_length)
        assert len(output) == output_length
        public = {"mode": mode, "input_length": len(message), "output_length": output_length,
                  "output_hex": (output + bytes(MAX_OUTPUT - output_length)).hex(),
                  "context_hex": CONTEXT.hex()}
        witness = {"input_hex": message.hex()}
        case = {"name": name, "expected": oracle(witness, public), "public": public, "witness": witness}
        if rationale:
            case["classification_note"] = rationale
        cases.append(case)
        return case

    for mode, (_, _, label) in MODES.items():
        for length in input_lengths:
            message = bytes((index * 29 + length * 11) % 256 for index in range(length))
            add(f"{label}_input_{length:04}_output_0064", message, mode, 64)
    sample = bytes((index * 31 + 5) % 256 for index in range(34))
    for mode in [2, 3]:
        for length in output_lengths:
            add(f"{MODES[mode][2]}_input_0034_output_{length:04}", sample, mode, length)
        message = bytes((index * 7 + 13) % 256 for index in range(MAX_INPUT))
        add(f"{MODES[mode][2]}_maximum_input_and_output", message, mode, MAX_OUTPUT)

    add("mldsa87_public_key_owner_sha3_512", pk, 1, 64,
        rationale="The existing owner hash is unframed SHA3-512 over all 2592 public key bytes. Its preimage is not spending authorization.")
    add("mldsa87_public_key_tr_shake256", pk, 3, 64,
        rationale="This hash is tr, without a claim that the remaining ML-DSA verifier is constrained.")
    add("synthetic_canonical_transaction_authorization_digest", frame(b"thorum.relation-lab.payment-authorization.v1") + frame(bytes.fromhex(application["transaction_hex"])), 1, 64,
        rationale="The T example has one input and one output with a structurally encoded synthetic envelope. Encryption and signature validity are not established.")
    add("pure_contextual_mldsa_mu_shake256", bytes.fromhex(application["mu_input_hex"]), 3, 64,
        rationale="Exact tr || 00 || 29 || context41 || A196. This is contextual pure ML-DSA input rather than the HashML-DSA interface.")
    add("mldsa_matrix_seed_shake128_five_output_blocks", bytes.fromhex(application["matrix_input_hex"]), 2, 840,
        rationale="rho32 || column0 || row0 supplies five SHAKE128 output blocks. Rejection sampling is not implemented by this hash component.")
    add("synthetic_mldsa_challenge_hash_shake256", bytes.fromhex(application["challenge_input_hex"]), 3, 64,
        rationale="mu64 || synthetic encoded w1 with 1024 bytes gives 1088 bytes. No polynomial computation, hint application or signature validity is established.")
    assert len(cases) == 66 and all(case["expected"]["valid_component"] for case in cases)

    def altered_case(name, source_case, change, rationale):
        case = copy.deepcopy(source_case)
        case["name"] = name
        change(case)
        case["expected"] = oracle(case["witness"], case["public"])
        case["classification_note"] = rationale
        assert not case["expected"]["valid_component"]
        cases.append(case)
        return case

    base = next(case for case in cases if case["name"] == "shake256_input_0034_output_0064")
    assert base["public"]["mode"] == 3 and base["public"]["output_length"] == 64

    def flip_public(case, byte):
        changed = bytearray.fromhex(case["public"]["output_hex"])
        changed[byte] ^= 1
        case["public"]["output_hex"] = changed.hex()

    altered_case("wrong_public_output_first_byte", base, lambda case: flip_public(case, 0), "Valid shape with an incorrect first output byte.")
    altered_case("wrong_public_output_last_active_byte", base, lambda case: flip_public(case, 63), "Valid shape with an incorrect last active output byte.")
    altered_case("wrong_public_mode_with_other_mode_output", base, lambda case: case["public"].update(mode=2), "SHAKE128 mode with SHAKE256 output.")
    altered_case("wrong_declared_input_length", base, lambda case: case["public"].update(input_length=35), "Private input bytes do not match the declared public length.")

    def change_input(case):
        message = bytearray.fromhex(case["witness"]["input_hex"])
        message[0] ^= 1
        case["witness"]["input_hex"] = message.hex()

    altered_case("wrong_private_input_with_same_public_output", base, change_input, "Same public length and output with altered private input bytes.")
    expected65 = exact_hash(sample, 3, 65)
    wrong65 = expected65[:64] + bytes([expected65[64] ^ 1])
    add("wrong_output_after_extended_public_length", sample, 3, 65, wrong65)
    assert not cases[-1]["expected"]["valid_component"]
    for mode in [1, 2, 3]:
        output_length = 64 if mode == 1 else 840
        for alteration in ["wrong_suffix", "missing_terminal_bit", "changed_zero_padding"]:
            result, _, _, _ = sponge(sample, mode, output_length, alteration=alteration)
            add(f"{MODES[mode][2]}_{alteration}", sample, mode, output_length, result,
                "Genuine standalone permutation calculations under altered padding produce the wrong expected canonical hash.")
            assert not cases[-1]["expected"]["valid_component"]
    for mode in [2, 3]:
        for alteration in ["wrong_rate", "reset_squeeze_capacity", "reset_squeeze_state", "nonzero_squeeze_absorption"]:
            result, _, _, _ = sponge(sample, mode, 840, alteration=alteration)
            add(f"{MODES[mode][2]}_{alteration}", sample, mode, 840, result,
                "Each altered permutation calculation is explicit. The canonical sponge state or XOF transition is violated.")
            assert not cases[-1]["expected"]["valid_component"]
    for case in cases:
        case["public_values"] = public_vector(case["public"])
        assert len(case["public_values"]) == 913
        assert case["expected"] == oracle(case["witness"], case["public"])
    assert len(cases) == 89
    assert sum(case["expected"]["valid_component"] for case in cases) == 66

    api_rejections = []
    for name, changes in [
        ("unsupported_mode_zero", {"mode": 0}), ("unsupported_mode_four", {"mode": 4}),
        ("input_above_limit", {"input_length": 2593}), ("shake_zero_output", {"output_length": 0}),
        ("shake_output_above_limit", {"output_length": 841}),
        ("sha3_output_below_64", {"mode": 1, "output_length": 63}),
        ("sha3_output_above_64", {"mode": 1, "output_length": 65}),
    ]:
        case = copy.deepcopy(base)
        case["name"] = name
        case["public"].update(changes)
        case["expected"] = oracle(case["witness"], case["public"])
        case["public_values"] = public_vector(case["public"])
        assert not case["expected"]["shape_valid"]
        api_rejections.append(case)
    case = copy.deepcopy(base)
    case["name"] = "nonzero_output_padding"
    flip_public(case, 64)
    case["expected"] = oracle(case["witness"], case["public"])
    case["public_values"] = public_vector(case["public"])
    assert not case["expected"]["shape_valid"]
    api_rejections.append(case)

    records, stage_rows, round_rows = [], [], []
    selected_names = [case["name"] for case in cases[60:66]]
    selected_names.extend(["sha3_512_input_0071_output_0064", "shake128_input_0167_output_0064",
                           "shake256_input_0135_output_0064", "shake128_maximum_input_and_output",
                           "shake256_maximum_input_and_output"])
    for name in selected_names:
        case = next(case for case in cases if case["name"] == name)
        p = case["public"]
        message = bytes.fromhex(case["witness"]["input_hex"])
        output, padded, stages, rounds = sponge(message, p["mode"], p["output_length"], record=True)
        assert output == bytes.fromhex(p["output_hex"])[:p["output_length"]]
        rate, suffix, _ = MODES[p["mode"]]
        assert len(stages) <= 37
        records.append({"name": name, "mode": p["mode"], "rate": rate, "suffix": suffix,
                        "input_length": len(message), "output_length": len(output),
                        "input_hex": message.hex(), "padded_input_hex": padded.hex(), "output_hex": output.hex(),
                        "absorb_permutations": len(padded) // rate,
                        "squeeze_permutations": len(stages) - len(padded) // rate,
                        "total_permutations": len(stages)})
        stage_rows.extend({"case_name": name, **stage} for stage in stages)
        if name in {"mldsa87_public_key_owner_sha3_512", "pure_contextual_mldsa_mu_shake256",
                    "mldsa_matrix_seed_shake128_five_output_blocks"}:
            round_rows.extend({"case_name": name, **round_state} for round_state in rounds)
    assert len(records) == 11
    metadata = {
        "format": "thorum.hash-proof-lab.reference.v1", "public_synthetic_fixture": True,
        "scope": "Standalone unframed FIPS 202 hash primitive relation. Outputs and lengths are public in this component only. No owner permission, private signature verification, composed transaction binding, hiding of these public results or production payment format is established.",
        "mode_codes": {"1": "SHA3-512", "2": "SHAKE128", "3": "SHAKE256"},
        "maximum_input_length": MAX_INPUT, "maximum_output_length": MAX_OUTPUT,
        "public_vector_length": 913, "original_trace_height": 1024,
        "maximum_permutations": 37, "case_count": len(cases), "valid_case_count": 66,
        "api_rejection_count": len(api_rejections), "selected_trace_count": len(records),
        "selected_stage_count": len(stage_rows), "selected_round_state_count": len(round_rows),
        "input_boundary_lengths": input_lengths, "output_boundary_lengths": output_lengths,
        "hashlib_self_check_count": self_check(), "state_lane_index": "x + 5*y",
        "state_lane_byte_order": "little endian", "permutation_rounds": 24,
        "source_public_key_sha256": source["public_key_sha256"],
    }
    return {
        "hash_relation_vectors.json": json_bytes({"format": metadata["format"], "cases": cases}),
        "api_rejections.json": json_bytes({"format": metadata["format"], "cases": api_rejections}),
        "application_inputs.json": json_bytes(application),
        "hash_preimages.json": json_bytes({"public_synthetic_fixture": True, "hashes": records}),
        "sponge_stages.csv": csv_bytes(stage_rows), "keccak_rounds.csv": csv_bytes(round_rows),
        "hash_vectors.csv": csv_bytes(adapter_vectors()), "profile.json": json_bytes(metadata),
    }


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
    print("SHA3 and SHAKE references match" if args.check else "SHA3 and SHAKE references generated")


if __name__ == "__main__":
    main()
