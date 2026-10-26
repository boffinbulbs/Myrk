#!/usr/bin/env python3
"""Independent stable nullifier, hidden membership and SHA3-512 reference states."""

import argparse
import copy
import csv
import functools
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PREFIX = b"thorum.relation-lab."
OPENING_DOMAIN = PREFIX + b"note-opening.v2"
COMMITMENT_DOMAIN = PREFIX + b"note-commitment.v2"
LEAF_DOMAIN = PREFIX + b"merkle-leaf.v1"
PARENT_DOMAIN = PREFIX + b"merkle-node.v1"
BINDING_DOMAIN = PREFIX + b"nullifier-secret-binding.v2"
NULLIFIER_DOMAIN = PREFIX + b"note-nullifier.v2"
RATE = 72
MASK = (1 << 64) - 1
DEPTH = 32
CHAIN = bytes(range(32))
ASSET = bytes([0xA7]) * 32
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


def frame(value):
    return len(value).to_bytes(4, "big") + value


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


def pad(message):
    output = bytearray(message)
    output.append(6)
    output.extend(bytes((-len(output)) % RATE))
    output[-1] |= 128
    return bytes(output)


def sponge(message, record=False, padded_override=None):
    state = [0] * 25
    blocks, rounds = [], []
    padded = pad(message) if padded_override is None else padded_override
    assert len(padded) % RATE == 0
    for index, offset in enumerate(range(0, len(padded), RATE)):
        block = padded[offset:offset + RATE]
        before = state_bytes(state)
        for lane in range(RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:lane * 8 + 8], "little")
        absorbed = state_bytes(state)
        for round_index, constant in enumerate(ROUND_CONSTANTS):
            state = permutation(state, constant)
            if record:
                rounds.append({"block": index, "round": round_index, "state_hex": state_bytes(state).hex()})
        if record:
            blocks.append({"block": index, "input_hex": block.hex(), "state_before_hex": before.hex(), "state_absorbed_hex": absorbed.hex(), "state_after_hex": state_bytes(state).hex()})
    result = state_bytes(state)[:64]
    if padded_override is None:
        assert result == hashlib.sha3_512(message).digest()
    return result, blocks, rounds


@functools.lru_cache(maxsize=None)
def checked_hash(message):
    return sponge(message)[0]


def digest_message(domain, *fields):
    return frame(domain) + b"".join(frame(value) for value in fields)


def digest(domain, *fields):
    return checked_hash(digest_message(domain, *fields))


def payment_opening(amount, ordinal, secret=bytes([0x5B]) * 32, chain=CHAIN, creation=None):
    """Exact v2 payment codec written without an external note adapter."""
    public_key = bytes(i % 251 for i in range(2592))
    encryption_key = bytes(1536) + bytes(range(32))
    fields = [
        OPENING_DOMAIN, (2).to_bytes(2, "big"), chain,
        (ordinal + 1 if creation is None else creation).to_bytes(4, "big"), ASSET, amount.to_bytes(8, "big"),
        checked_hash(public_key),
        digest(BINDING_DOMAIN, chain, secret),
        digest(PREFIX + b"recipient-key-binding.v2", chain, encryption_key),
        bytes([0xD3 + ordinal]) * 32, bytes([0xC4 + ordinal]) * 32, b"\0",
    ]
    opening = b"".join(frame(value) for value in fields)
    assert len(opening) == 418
    assert int.from_bytes(opening[129:137], "big") == amount
    return opening


def commitment(opening):
    return digest(COMMITMENT_DOMAIN, opening)


def leaf(commitment_bytes, chain=CHAIN):
    return digest(LEAF_DOMAIN, chain, commitment_bytes)


def parent(left, right, chain=CHAIN):
    return digest(PARENT_DOMAIN, chain, left, right)


class SparseTree:
    """Only occupied branches are materialized, with explicit empty subtree hashes."""

    def __init__(self, occupied, chain=CHAIN):
        assert occupied and all(0 <= position < (1 << DEPTH) for position in occupied)
        self.empty = [leaf(bytes(64), chain)]
        for _ in range(DEPTH):
            self.empty.append(parent(self.empty[-1], self.empty[-1], chain))
        self.layers = [{position: leaf(value, chain) for position, value in occupied.items()}]
        for level in range(DEPTH):
            previous = self.layers[-1]
            self.layers.append({position: parent(previous.get(position * 2, self.empty[level]), previous.get(position * 2 + 1, self.empty[level]), chain) for position in sorted({index // 2 for index in previous})})
        assert len(self.layers[-1]) == 1
        self.root = self.layers[-1][0]

    def path(self, position):
        assert 0 <= position < (1 << DEPTH)
        return [self.layers[level].get((position >> level) ^ 1, self.empty[level]) for level in range(DEPTH)]


def path_root(value, position, siblings, chain=CHAIN):
    assert len(siblings) == DEPTH and 0 <= position < (1 << DEPTH)
    result = leaf(value, chain)
    for level, sibling in enumerate(siblings):
        result = parent(result, sibling, chain) if ((position >> level) & 1) == 0 else parent(sibling, result, chain)
    return result


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("ascii")


def csv_bytes(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("ascii")


def oracle(witness, public):
    openings = [bytes.fromhex(value) for value in witness["openings_hex"]]
    commitments = [commitment(opening) for opening in openings]
    decoded = []
    framing = True
    for opening in openings:
        cursor, fields = 0, []
        for width in [35, 2, 32, 4, 32, 8, 64, 64, 64, 32, 32, 1]:
            framing &= int.from_bytes(opening[cursor:cursor + 4], "big") == width
            fields.append(opening[cursor + 4:cursor + 4 + width])
            cursor += 4 + width
        assert cursor == len(opening) == 418
        decoded.append(fields)
    canonical = framing and all(fields[0] == OPENING_DOMAIN and fields[1] == b"\0\2" and fields[11] == b"\0" for fields in decoded)
    bindings = all(fields[2].hex() == public["chain_hex"] and fields[4].hex() == public["asset_hex"] for fields in decoded)
    bindings &= [int.from_bytes(fields[3], "big") for fields in decoded[2:]] == public["output_creation_versions"]
    amounts = [int.from_bytes(fields[5], "big") for fields in decoded]
    calculated = [path_root(commitments[i], item["index"], [bytes.fromhex(value) for value in item["siblings_hex"]], bytes.fromhex(public["chain_hex"])) for i, item in enumerate(witness["inputs"])]
    expected_root = bytes.fromhex(public["root_hex"])
    members = all(value == expected_root for value in calculated)
    distinct = commitments[0] != commitments[1]
    integer = amounts[0] + amounts[1] == amounts[2] + amounts[3] + public["fee"] <= MASK
    outputs = [value.hex() for value in commitments[2:]] == public["output_commitments_hex"]
    secrets = [bytes.fromhex(value) for value in witness["nullifier_secrets_hex"]]
    chain = bytes.fromhex(public["chain_hex"])
    secret_bindings = all(digest(BINDING_DOMAIN, chain, secrets[i]) == decoded[i][7] for i in range(2))
    nullifiers = [digest(NULLIFIER_DOMAIN, chain, secrets[i], commitments[i]) for i in range(2)]
    nullifier_derivation = [value.hex() for value in nullifiers] == public["nullifiers_hex"]
    nullifier_distinctness = public["nullifiers_hex"][0] != public["nullifiers_hex"][1]
    checks = {"canonical_openings_valid": canonical, "statement_bindings_valid": bindings, "membership_valid": members, "distinct_inputs": distinct, "integer_valid": integer, "output_commitments_valid": outputs, "secret_bindings_valid": secret_bindings, "nullifiers_valid": nullifier_derivation, "distinct_nullifiers": nullifier_distinctness}
    checks["valid_component"] = all(checks.values())
    return checks


def self_check():
    messages = [b"", b"abc", bytes(200), bytes(range(256)), b"a" * 1000]
    messages.extend(bytes((index * 29 + length * 11) % 256 for index in range(length)) for length in range(0, 217))
    for message in messages:
        checked_hash(message)
    return len(messages)


def adapter_vectors():
    result = []
    for suffix, values, width in [
        (b"leaf.v1", [0, 1, 2013265920, 0x12345678], 4),
        (b"node.v1", [0, 1, MASK, *range(13)], 8),
        (b"transcript.v1", list(range(64)), 1),
    ]:
        message = (
            frame(b"thorum.nullifier-proof-lab." + suffix)
            + b"".join(value.to_bytes(width, "little") for value in values)
            + len(values).to_bytes(8, "big")
        )
        output = checked_hash(message)
        result.append({
            "domain_suffix": suffix.decode("ascii"), "preimage_hex": message.hex(),
            "digest_hex": output.hex(),
            "little_endian_u64_words": ":".join(str(int.from_bytes(output[i:i + 8], "little")) for i in range(0, 64, 8)),
        })
    return result


def outputs():
    secret = bytes([0x5B]) * 32
    other_secret = bytes([0x6C]) * 32
    openings = [payment_opening(amount, index) for index, amount in enumerate([50, 50, 60, 39])]
    commitments = [commitment(opening) for opening in openings]
    nullifiers = [digest(NULLIFIER_DOMAIN, CHAIN, secret, value) for value in commitments[:2]]
    assert nullifiers[0] != nullifiers[1]
    occupied = {0: commitments[0], (1 << DEPTH) - 1: commitments[0]}
    occupied.update({1 << bit: commitments[1] for bit in range(DEPTH)})
    tree = SparseTree(occupied)
    public = {"chain_hex": CHAIN.hex(), "asset_hex": ASSET.hex(), "root_hex": tree.root.hex(), "output_creation_versions": [3, 4], "output_commitments_hex": [value.hex() for value in commitments[2:]], "fee": 1, "nullifiers_hex": [value.hex() for value in nullifiers], "context_hex": CONTEXT.hex()}
    forbidden = {"commitments_hex", "input_commitments_hex", "input_creation_versions", "indices", "paths", "openings_hex", "nullifier_secrets_hex", "secret_bindings_hex"}
    assert not forbidden.intersection(public)

    def make_witness(first=0, second=1, selected_openings=None, secrets=None, selected_tree=None):
        selected = openings if selected_openings is None else selected_openings
        retained = [secret, secret] if secrets is None else secrets
        membership = tree if selected_tree is None else selected_tree
        return {"openings_hex": [value.hex() for value in selected], "nullifier_secrets_hex": [value.hex() for value in retained], "inputs": [{"index": index, "siblings_hex": [value.hex() for value in membership.path(index)]} for index in [first, second]]}

    cases = []

    def add(name, witness=None, changed_public=None, rationale=None):
        statement = copy.deepcopy(public if changed_public is None else changed_public)
        witness = make_witness() if witness is None else witness
        case = {"name": name, "expected": oracle(witness, statement), "public": statement, "witness": witness}
        if rationale:
            case["classification_note"] = rationale
        cases.append(case)
        return case

    def rebuilt_case(name, changed_openings, secrets=None, positions=(0, 1), fee=1, chain=CHAIN, rationale=None):
        retained = [secret, secret] if secrets is None else secrets
        cm = [commitment(value) for value in changed_openings]
        selected_tree = SparseTree({positions[0]: cm[0], positions[1]: cm[1]}, chain)
        statement = copy.deepcopy(public)
        statement.update({"chain_hex": chain.hex(), "root_hex": selected_tree.root.hex(), "output_commitments_hex": [value.hex() for value in cm[2:]], "output_creation_versions": [int.from_bytes(value[85:89], "big") for value in changed_openings[2:]], "fee": fee, "nullifiers_hex": [digest(NULLIFIER_DOMAIN, chain, retained[i], cm[i]).hex() for i in range(2)]})
        return add(name, make_witness(*positions, selected_openings=changed_openings, secrets=retained, selected_tree=selected_tree), statement, rationale)

    for bit in range(DEPTH):
        add(f"honest_direction_bit_{bit:02}", make_witness(0, 1 << bit))
    add("honest_all_direction_bits", make_witness((1 << DEPTH) - 1, 1 << (DEPTH - 1)))

    duplicate_public = copy.deepcopy(public)
    duplicate_public["nullifiers_hex"] = [nullifiers[0].hex()] * 2
    add("duplicate_commitment_and_nullifier_at_distinct_positions", make_witness(0, (1 << DEPTH) - 1, [openings[0], openings[0], *openings[2:]]), duplicate_public)
    wrong = make_witness()
    sibling = bytearray.fromhex(wrong["inputs"][0]["siblings_hex"][17])
    sibling[31] ^= 1
    wrong["inputs"][0]["siblings_hex"][17] = sibling.hex()
    add("wrong_sibling", wrong)
    wrong = make_witness()
    wrong["inputs"][0]["index"] ^= 1 << 31
    add("wrong_index", wrong)
    wrong = make_witness()
    replacement = bytearray(openings[0])
    replacement[345] ^= 1
    wrong["openings_hex"][0] = replacement.hex()
    add("disconnected_input_commitment", wrong)
    wrong_root = copy.deepcopy(public)
    wrong_root["root_hex"] = bytes([tree.root[0] ^ 1, *tree.root[1:]]).hex()
    add("wrong_public_root", changed_public=wrong_root)
    wrong = make_witness()
    replacement = bytearray(openings[0])
    replacement[88] ^= 1
    wrong["openings_hex"][0] = replacement.hex()
    add("changed_private_input_creation_version_without_new_membership", wrong)
    wrong_public = copy.deepcopy(public)
    wrong_public["output_creation_versions"] = [4, 4]
    add("wrong_public_output_creation_version", changed_public=wrong_public)
    assert len(cases) == 40
    assert sum(case["expected"]["valid_component"] for case in cases) == 33
    assert all(case["public"] == public for case in cases[:33])

    alternate = rebuilt_case("same_notes_under_alternate_root_and_paths", openings, positions=(5, 0xF0010020), rationale="The immutable inputs and nullifiers are unchanged. A new expected root and proof are required.")
    assert alternate["expected"]["valid_component"]
    assert alternate["public"]["root_hex"] != public["root_hex"]
    assert alternate["public"]["nullifiers_hex"] == public["nullifiers_hex"]
    changed_context = copy.deepcopy(public)
    changed_context["context_hex"] = bytes([0xE2]) * 64
    changed_context["context_hex"] = changed_context["context_hex"].hex()
    add("same_notes_under_different_transaction_context", changed_public=changed_context)
    changed_context = copy.deepcopy(alternate["public"])
    changed_context["context_hex"] = bytes([0xD4] * 64).hex()
    add("same_notes_under_alternate_root_paths_and_context", copy.deepcopy(alternate["witness"]), changed_context)

    distinct_openings = list(openings)
    distinct_openings[1] = payment_opening(50, 1, other_secret)
    rebuilt_case("honest_distinct_retained_secrets", distinct_openings, [secret, other_secret])

    changed_creation = list(openings)
    changed_creation[0] = payment_opening(50, 0, creation=9)
    case = rebuilt_case("changed_committed_creation_version_is_a_different_note", changed_creation)
    assert case["public"]["nullifiers_hex"][0] != public["nullifiers_hex"][0]

    wrong = make_witness(secrets=[other_secret, secret])
    wrong_public = copy.deepcopy(public)
    wrong_public["nullifiers_hex"][0] = digest(NULLIFIER_DOMAIN, CHAIN, other_secret, commitments[0]).hex()
    case = add("wrong_secret_with_correct_recomputed_nullifier", wrong, wrong_public)
    assert case["expected"]["membership_valid"] and case["expected"]["nullifiers_valid"]
    assert not case["expected"]["secret_bindings_valid"]
    add("mixed_binding_and_nullifier_keys", make_witness(secrets=[other_secret, secret]), rationale="The committed binding uses the original key while the witness and public nullifier use different retained authorities.")
    changed = list(openings)
    changed[0] = payment_opening(50, 0, other_secret)
    case = rebuilt_case("new_binding_with_nullifier_from_other_key", changed, [other_secret, secret])
    case["public"]["nullifiers_hex"][0] = digest(NULLIFIER_DOMAIN, CHAIN, secret, commitment(changed[0])).hex()
    case["expected"] = oracle(case["witness"], case["public"])
    assert case["expected"]["secret_bindings_valid"] and not case["expected"]["nullifiers_valid"]

    for message_byte in [143, 144]:
        fake_commitment = bytearray(commitments[0])
        fake_commitment[message_byte - 117] ^= 1
        changed_public = copy.deepcopy(public)
        changed_public["nullifiers_hex"][0] = digest(NULLIFIER_DOMAIN, CHAIN, secret, bytes(fake_commitment)).hex()
        add(f"detached_nullifier_commitment_message_byte_{message_byte}", changed_public=changed_public, rationale="Membership and note hashing remain valid for the real hidden commitment. Only the independently computed public nullifier uses a changed commitment byte.")

    for message_byte in [287, 288]:
        replacement = bytearray(openings[0])
        replacement[message_byte - 46] ^= 1
        changed = [bytes(replacement), *openings[1:]]
        case = rebuilt_case(f"detached_opening_binding_message_byte_{message_byte}", changed)
        assert case["expected"]["membership_valid"] and case["expected"]["nullifiers_valid"]
        assert not case["expected"]["secret_bindings_valid"]

    changed_public = copy.deepcopy(public)
    changed_public["nullifiers_hex"][0] = digest(PREFIX + b"note-nullifier.v1", CHAIN, secret, commitments[0]).hex()
    add("v1_nullifier_domain_in_v2_component", changed_public=changed_public)
    replacement = bytearray(openings[0])
    replacement[209:273] = digest(PREFIX + b"nullifier-secret-binding.v1", CHAIN, secret)
    rebuilt_case("v1_binding_domain_in_v2_opening", [bytes(replacement), *openings[1:]])
    other_chain = bytes([CHAIN[0] ^ 1, *CHAIN[1:]])
    changed_public = copy.deepcopy(public)
    changed_public["nullifiers_hex"][0] = digest(NULLIFIER_DOMAIN, other_chain, secret, commitments[0]).hex()
    add("wrong_chain_inside_nullifier_message", changed_public=changed_public)
    changed_public = copy.deepcopy(public)
    changed_public["chain_hex"] = other_chain.hex()
    add("wrong_public_chain", changed_public=changed_public)
    changed_public = copy.deepcopy(public)
    changed_public["nullifiers_hex"][1] = changed_public["nullifiers_hex"][0]
    add("duplicate_public_nullifier_with_distinct_private_notes", changed_public=changed_public)
    changed_public = copy.deepcopy(public)
    replacement = bytearray.fromhex(changed_public["nullifiers_hex"][0])
    replacement[63] ^= 1
    changed_public["nullifiers_hex"][0] = replacement.hex()
    add("changed_public_nullifier_last_byte", changed_public=changed_public)

    changed_outputs = list(openings)
    replacement = bytearray(openings[2])
    replacement[209] ^= 1
    changed_outputs[2] = bytes(replacement)
    changed_public = copy.deepcopy(public)
    changed_public["output_commitments_hex"][0] = commitment(changed_outputs[2]).hex()
    add("output_secret_binding_remains_opaque_committed_bytes", make_witness(selected_openings=changed_outputs), changed_public, "This component derives only the two input bindings. Output authority and encryption policy remain outside the relation.")

    for name, amounts, fee in [
        ("zero_amounts_with_distinct_canonical_notes", [0, 0, 0, 0], 0),
        ("maximum_total_without_overflow", [MASK, 0, MASK, 0], 0),
        ("maximum_total_with_fee", [MASK - 1, 1, MASK - 1, 0], 1),
        ("equal_overflowing_input_and_output_totals", [MASK, 1, MASK, 0], 1),
        ("integer_imbalance", [1, 0, 0, 0], 0),
    ]:
        rebuilt_case(name, [payment_opening(amount, i) for i, amount in enumerate(amounts)], fee=fee)

    for case in cases:
        assert case["expected"] == oracle(case["witness"], case["public"])
        assert not forbidden.intersection(case["public"])
        p = case["public"]
        vector = [(p["fee"] >> bit) & 1 for bit in range(64)]
        vector.extend(bytes.fromhex(p["chain_hex"]))
        vector.extend(b"".join(version.to_bytes(4, "big") for version in p["output_creation_versions"]))
        for field in ["asset_hex", "root_hex"]:
            vector.extend(bytes.fromhex(p[field]))
        for field in ["output_commitments_hex", "nullifiers_hex"]:
            vector.extend(b"".join(bytes.fromhex(value) for value in p[field]))
        vector.extend(bytes.fromhex(p["context_hex"]))
        assert len(vector) == 520
        case["public_values"] = vector

    hash_cases, block_rows, round_rows = [], [], []

    def record(name, kind, message, complete_rounds=False):
        result, blocks, rounds = sponge(message, record=True)
        hash_cases.append({"name": name, "kind": kind, "preimage_hex": message.hex(), "padded_preimage_hex": pad(message).hex(), "digest_hex": result.hex(), "preimage_length": len(message), "padded_length": len(pad(message)), "absorb_blocks": len(blocks)})
        block_rows.extend({"hash_name": name, **block} for block in blocks)
        if complete_rounds:
            round_rows.extend({"hash_name": name, **round_state} for round_state in rounds)
        return result

    for index, opening in enumerate(openings):
        assert record(f"note_{index}", "note_commitment", digest_message(COMMITMENT_DOMAIN, opening), index == 0) == commitments[index]
    for input_index, position in enumerate([0, 1]):
        assert record(f"input_{input_index}_binding", "nullifier_secret_binding", digest_message(BINDING_DOMAIN, CHAIN, secret), input_index == 0) == openings[input_index][209:273]
        assert record(f"input_{input_index}_nullifier", "note_nullifier", digest_message(NULLIFIER_DOMAIN, CHAIN, secret, commitments[input_index]), input_index == 0) == nullifiers[input_index]
        result = record(f"input_{input_index}_leaf", "merkle_leaf", digest_message(LEAF_DOMAIN, CHAIN, commitments[input_index]), input_index == 0)
        for level, sibling in enumerate(tree.path(position)):
            left, right = (result, sibling) if ((position >> level) & 1) == 0 else (sibling, result)
            result = record(f"input_{input_index}_node_{level:02}", "merkle_parent", digest_message(PARENT_DOMAIN, CHAIN, left, right), input_index == 0 and level == 0)
        assert result == tree.root
    assert len(hash_cases) == 74
    assert len(block_rows) == sum(item["absorb_blocks"] for item in hash_cases) == 234
    assert len(round_rows) == (7 + 2 + 3 + 2 + 3) * 24 == 408

    malformed = []
    for hash_kind, domain, fields in [
        ("binding", BINDING_DOMAIN, [CHAIN, secret]),
        ("nullifier", NULLIFIER_DOMAIN, [CHAIN, secret, commitments[0]]),
    ]:
        message = digest_message(domain, *fields)
        padded = pad(message)
        assert len(message) == (123 if hash_kind == "binding" else 181)
        variants = {}
        altered = bytearray(padded)
        altered[len(message)] ^= 1
        variants["sha3_suffix"] = bytes(altered)
        altered = bytearray(padded)
        altered[len(message) + 1] = 1
        variants["zero_padding"] = bytes(altered)
        altered = bytearray(padded)
        altered[-1] ^= 128
        variants["terminal_padding_bit"] = bytes(altered)
        altered_message = digest_message(domain[:-1] + b"1", *fields)
        variants["v1_domain"] = pad(altered_message)
        altered = bytearray(padded)
        altered[3] ^= 1
        variants["domain_length_prefix"] = bytes(altered)
        for suffix, altered_padded in variants.items():
            result, _, _ = sponge(message, padded_override=altered_padded)
            malformed.append({"name": f"{hash_kind}_{suffix}", "canonical_preimage_hex": message.hex(), "canonical_padded_preimage_hex": padded.hex(), "altered_padded_preimage_hex": altered_padded.hex(), "altered_digest_hex": result.hex(), "canonical_message_valid": False, "standalone_permutation_valid": True})
    assert len(malformed) == 10

    valid_count = sum(case["expected"]["valid_component"] for case in cases)
    assert len(cases) == 64 and valid_count == 42
    metadata = {
        "format": "thorum.nullifier-proof-lab.reference.v1", "synthetic_fixture": True,
        "depth": DEPTH, "index_bits": DEPTH, "direction_order": "least significant bit first",
        "empty_commitment_hex": bytes(64).hex(), "occupied_leaf_count": len(occupied),
        "fixture_scope": "Public synthetic relation data, not an anonymity experiment. Repeated commitments at distinct positions do not create independent notes.",
        "materialized_node_count": sum(len(layer) for layer in tree.layers),
        "full_leaf_capacity_decimal": str(1 << DEPTH), "root_hex": tree.root.hex(),
        "case_count": len(cases), "valid_case_count": valid_count, "public_vector_length": 520,
        "opening_length": 418, "note_preimage_length": 464, "note_absorb_blocks": 7,
        "binding_domain_length": len(BINDING_DOMAIN), "binding_preimage_length": 123, "binding_padded_length": 144, "binding_absorb_blocks": 2,
        "nullifier_domain_length": len(NULLIFIER_DOMAIN), "nullifier_preimage_length": 181, "nullifier_padded_length": 216, "nullifier_absorb_blocks": 3,
        "leaf_preimage_length": 142, "leaf_padded_length": 144, "leaf_absorb_blocks": 2,
        "parent_preimage_length": 210, "parent_padded_length": 216, "parent_absorb_blocks": 3,
        "per_input_hash_count": 35, "per_input_absorb_blocks": 103,
        "combined_hash_count": 74, "combined_absorb_blocks": 234, "real_round_rows": 5616,
        "selected_round_state_count": len(round_rows), "malformed_message_count": len(malformed),
        "nullifier_commitment_split_message_bytes": [143, 144], "opening_binding_split_message_bytes": [287, 288],
        "rate_bytes": RATE, "capacity_bits": 1024, "permutation_rounds": 24,
        "state_lane_index": "x + 5*y", "state_lane_byte_order": "little endian",
        "hashlib_cross_checks": self_check(),
        "scope_limits": "No authenticated current protocol version, ownership, unspent state, root policy, encrypted delivery, PRF proof or composed quantum security claim.",
    }
    tree_data = {"format": metadata["format"], "depth": DEPTH, "root_hex": tree.root.hex(), "empty_subtree_hashes_hex": [value.hex() for value in tree.empty], "occupied_leaves": [{"index": position, "commitment_hex": value.hex()} for position, value in sorted(occupied.items())], "layers": [{"level": level, "nodes": [{"index": position, "hash_hex": value.hex()} for position, value in sorted(layer.items())]} for level, layer in enumerate(tree.layers)]}
    return {
        "nullifier_vectors.json": json_bytes({"format": metadata["format"], "synthetic_fixture": True, "cases": cases}),
        "sparse_tree.json": json_bytes(tree_data),
        "hash_preimages.json": json_bytes({"synthetic_fixture": True, "hashes": hash_cases}),
        "sponge_blocks.csv": csv_bytes(block_rows), "keccak_rounds.csv": csv_bytes(round_rows),
        "hash_vectors.csv": csv_bytes(adapter_vectors()), "malformed_messages.json": json_bytes({"synthetic_fixture": True, "cases": malformed}),
        "profile.json": json_bytes(metadata),
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
    print("Stable nullifier and hidden membership references match" if args.check else "Stable nullifier and hidden membership references generated")


if __name__ == "__main__":
    main()
