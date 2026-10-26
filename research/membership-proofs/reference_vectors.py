#!/usr/bin/env python3
"""Independent sparse membership, canonical note and SHA3-512 reference states."""

import argparse
import csv
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


def sponge(message, record=False):
    state = [0] * 25
    blocks, rounds = [], []
    padded = pad(message)
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
    assert result == hashlib.sha3_512(message).digest()
    return result, blocks, rounds


def checked_hash(message):
    return sponge(message)[0]


def digest_message(domain, *fields):
    return frame(domain) + b"".join(frame(value) for value in fields)


def digest(domain, *fields):
    return checked_hash(digest_message(domain, *fields))


def payment_opening(amount, ordinal):
    """Exact v2 payment codec written without an external note adapter."""
    public_key = bytes(i % 251 for i in range(2592))
    encryption_key = bytes(1536) + bytes(range(32))
    receiver_secret = bytes([0x5B]) * 32
    fields = [
        OPENING_DOMAIN, (2).to_bytes(2, "big"), CHAIN,
        (ordinal + 1).to_bytes(4, "big"), ASSET, amount.to_bytes(8, "big"),
        checked_hash(public_key),
        digest(PREFIX + b"nullifier-secret-binding.v2", CHAIN, receiver_secret),
        digest(PREFIX + b"recipient-key-binding.v2", CHAIN, encryption_key),
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

    def __init__(self, occupied):
        assert occupied and all(0 <= position < (1 << DEPTH) for position in occupied)
        self.empty = [leaf(bytes(64))]
        for _ in range(DEPTH):
            self.empty.append(parent(self.empty[-1], self.empty[-1]))
        self.layers = [{position: leaf(value) for position, value in occupied.items()}]
        for level in range(DEPTH):
            previous = self.layers[-1]
            self.layers.append({position: parent(previous.get(position * 2, self.empty[level]), previous.get(position * 2 + 1, self.empty[level])) for position in sorted({index // 2 for index in previous})})
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
    for opening in openings:
        cursor, fields = 0, []
        for width in [35, 2, 32, 4, 32, 8, 64, 64, 64, 32, 32, 1]:
            assert int.from_bytes(opening[cursor:cursor + 4], "big") == width
            fields.append(opening[cursor + 4:cursor + 4 + width])
            cursor += 4 + width
        assert cursor == len(opening) == 418
        decoded.append(fields)
    canonical = all(fields[0] == OPENING_DOMAIN and fields[1] == b"\0\2" and fields[11] == b"\0" for fields in decoded)
    bindings = all(fields[2].hex() == public["chain_hex"] and fields[4].hex() == public["asset_hex"] for fields in decoded)
    bindings &= [int.from_bytes(fields[3], "big") for fields in decoded[2:]] == public["output_creation_versions"]
    amounts = [int.from_bytes(fields[5], "big") for fields in decoded]
    calculated = [path_root(commitments[i], item["index"], [bytes.fromhex(value) for value in item["siblings_hex"]], bytes.fromhex(public["chain_hex"])) for i, item in enumerate(witness["inputs"])]
    expected_root = bytes.fromhex(public["root_hex"])
    members = all(value == expected_root for value in calculated)
    distinct = commitments[0] != commitments[1]
    integer = amounts[0] + amounts[1] == amounts[2] + amounts[3] + public["fee"] <= MASK
    outputs = [value.hex() for value in commitments[2:]] == public["output_commitments_hex"]
    return {"canonical_openings_valid": canonical, "statement_bindings_valid": bindings, "membership_valid": members, "distinct_inputs": distinct, "integer_valid": integer, "output_commitments_valid": outputs, "valid_component": canonical and bindings and members and distinct and integer and outputs}


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
            frame(b"thorum.membership-proof-lab." + suffix)
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
    openings = [payment_opening(amount, index) for index, amount in enumerate([50, 50, 60, 39])]
    commitments = [commitment(opening) for opening in openings]
    occupied = {0: commitments[0], (1 << DEPTH) - 1: commitments[0]}
    occupied.update({1 << bit: commitments[1] for bit in range(DEPTH)})
    tree = SparseTree(occupied)
    public = {"chain_hex": CHAIN.hex(), "asset_hex": ASSET.hex(), "root_hex": tree.root.hex(), "output_creation_versions": [3, 4], "output_commitments_hex": [value.hex() for value in commitments[2:]], "fee": 1, "context_hex": CONTEXT.hex()}
    forbidden = {"commitments_hex", "input_commitments_hex", "input_creation_versions", "indices", "paths", "openings_hex"}
    assert not forbidden.intersection(public)

    def make_witness(first, second, same=False):
        return {"openings_hex": [value.hex() for value in ([openings[0], openings[0], *openings[2:]] if same else openings)], "inputs": [{"index": index, "siblings_hex": [value.hex() for value in tree.path(index)]} for index in [first, second]]}

    cases = []

    def add(name, witness, changed_public=None):
        statement = changed_public or public
        cases.append({"name": name, "expected": oracle(witness, statement), "public": statement, "witness": witness})

    for bit in range(DEPTH):
        add(f"honest_direction_bit_{bit:02}", make_witness(0, 1 << bit))
    add("honest_all_direction_bits", make_witness((1 << DEPTH) - 1, 1 << (DEPTH - 1)))
    add("duplicate_commitment_at_distinct_positions", make_witness(0, (1 << DEPTH) - 1, same=True))
    wrong = make_witness(0, 1)
    sibling = bytearray.fromhex(wrong["inputs"][0]["siblings_hex"][17])
    sibling[31] ^= 1
    wrong["inputs"][0]["siblings_hex"][17] = sibling.hex()
    add("wrong_sibling", wrong)
    wrong = make_witness(0, 1)
    wrong["inputs"][0]["index"] ^= 1 << 31
    add("wrong_index", wrong)
    wrong = make_witness(0, 1)
    replacement = bytearray(openings[0])
    replacement[345] ^= 1
    wrong["openings_hex"][0] = replacement.hex()
    add("disconnected_input_commitment", wrong)
    wrong_root = dict(public)
    wrong_root["root_hex"] = bytes([tree.root[0] ^ 1, *tree.root[1:]]).hex()
    add("wrong_public_root", make_witness(0, 1), wrong_root)
    wrong = make_witness(0, 1)
    replacement = bytearray(openings[0])
    replacement[88] ^= 1
    wrong["openings_hex"][0] = replacement.hex()
    add("changed_private_input_creation_version", wrong)
    wrong_output_version = dict(public)
    wrong_output_version["output_creation_versions"] = [4, 4]
    add("wrong_public_output_creation_version", make_witness(0, 1), wrong_output_version)
    assert len(cases) == 40
    assert sum(case["expected"]["valid_component"] for case in cases) == 33
    assert cases[33]["expected"] == {"canonical_openings_valid": True, "statement_bindings_valid": True, "membership_valid": True, "distinct_inputs": False, "integer_valid": True, "output_commitments_valid": True, "valid_component": False}
    assert all(case["public"] == public for case in cases[:37])

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
    # Both input paths include every preimage and every 1600 bit block state.
    for input_index, position in enumerate([0, 1]):
        result = record(f"input_{input_index}_leaf", "merkle_leaf", digest_message(LEAF_DOMAIN, CHAIN, commitments[input_index]), input_index == 0)
        for level, sibling in enumerate(tree.path(position)):
            left, right = (result, sibling) if ((position >> level) & 1) == 0 else (sibling, result)
            result = record(f"input_{input_index}_node_{level:02}", "merkle_parent", digest_message(PARENT_DOMAIN, CHAIN, left, right), input_index == 0 and level == 0)
        assert result == tree.root
    assert len(hash_cases) == 70
    assert sum(item["absorb_blocks"] for item in hash_cases) == 224
    assert len(block_rows) == 224
    assert len(round_rows) == (7 + 2 + 3) * 24
    metadata = {
        "format": "thorum.membership-proof-lab.reference.v1", "synthetic_fixture": True,
        "depth": DEPTH, "index_bits": DEPTH, "direction_order": "least significant bit first",
        "empty_commitment_hex": bytes(64).hex(), "occupied_leaf_count": len(occupied),
        "fixture_scope": "Public synthetic relation data, not an anonymity experiment. Repeated commitments at distinct positions do not create independent notes.",
        "materialized_node_count": sum(len(layer) for layer in tree.layers),
        "full_leaf_capacity_decimal": str(1 << DEPTH),
        "root_hex": tree.root.hex(), "case_count": len(cases), "valid_case_count": 33,
        "opening_length": 418, "note_preimage_length": 464, "note_absorb_blocks": 7,
        "leaf_domain_length": len(LEAF_DOMAIN), "leaf_preimage_length": 142, "leaf_padded_length": 144, "leaf_absorb_blocks": 2,
        "parent_domain_length": len(PARENT_DOMAIN), "parent_preimage_length": 210, "parent_padded_length": 216, "parent_absorb_blocks": 3,
        "per_input_hash_count": 33, "per_input_membership_blocks": 98,
        "combined_hash_count": 70, "combined_absorb_blocks": 224,
        "rate_bytes": RATE, "capacity_bits": 1024, "permutation_rounds": 24,
        "state_lane_index": "x + 5*y", "state_lane_byte_order": "little endian",
        "hashlib_cross_checks": self_check(),
    }
    tree_data = {"format": metadata["format"], "depth": DEPTH, "root_hex": tree.root.hex(), "empty_subtree_hashes_hex": [value.hex() for value in tree.empty], "occupied_leaves": [{"index": position, "commitment_hex": value.hex()} for position, value in sorted(occupied.items())], "layers": [{"level": level, "nodes": [{"index": position, "hash_hex": value.hex()} for position, value in sorted(layer.items())]} for level, layer in enumerate(tree.layers)]}
    return {
        "membership_vectors.json": json_bytes({"format": metadata["format"], "synthetic_fixture": True, "cases": cases}),
        "sparse_tree.json": json_bytes(tree_data),
        "hash_preimages.json": json_bytes({"synthetic_fixture": True, "hashes": hash_cases}),
        "sponge_blocks.csv": csv_bytes(block_rows),
        "keccak_rounds.csv": csv_bytes(round_rows),
        "hash_vectors.csv": csv_bytes(adapter_vectors()),
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
    print("Sparse membership and SHA3 references match" if args.check else "Sparse membership and SHA3 references generated")


if __name__ == "__main__":
    main()
