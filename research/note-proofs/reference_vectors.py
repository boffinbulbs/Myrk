#!/usr/bin/env python3
"""Independent canonical payment opening and SHA3-512 reference states."""

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
RATE = 72
MASK = (1 << 64) - 1
ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
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


def frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def rotate(value: int, count: int) -> int:
    return ((value << count) | (value >> ((64 - count) % 64))) & MASK


def state_bytes(lanes: list[int]) -> bytes:
    # State lane index is x + 5*y. A byte within a lane is little endian.
    return b"".join(lane.to_bytes(8, "little") for lane in lanes)


def keccak_round(lanes: list[int], round_constant: int) -> list[int]:
    parity = [0] * 5
    for x in range(5):
        for y in range(5):
            parity[x] ^= lanes[x + 5 * y]
    delta = [parity[(x - 1) % 5] ^ rotate(parity[(x + 1) % 5], 1) for x in range(5)]
    theta = [lanes[x + 5 * y] ^ delta[x] for y in range(5) for x in range(5)]
    relocated = [0] * 25
    for y in range(5):
        for x in range(5):
            relocated[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(theta[x + 5 * y], ROTATION[x][y])
    result = [
        relocated[x + 5 * y]
        ^ ((~relocated[(x + 1) % 5 + 5 * y]) & relocated[(x + 2) % 5 + 5 * y])
        for y in range(5) for x in range(5)
    ]
    result[0] ^= round_constant
    return result


def padded(message: bytes) -> bytes:
    # FIPS 202 SHA3 suffix 01 and pad10*1 give byte suffix 0x06.
    result = bytearray(message)
    result.append(0x06)
    result.extend(bytes((-len(result)) % RATE))
    result[-1] |= 0x80
    return bytes(result)


def sha3_512(message: bytes, record: bool = False) -> tuple[bytes, list[dict], list[dict]]:
    lanes = [0] * 25
    blocks = []
    rounds = []
    encoded = padded(message)
    for block_index in range(len(encoded) // RATE):
        block = encoded[block_index * RATE:(block_index + 1) * RATE]
        before = state_bytes(lanes)
        for lane in range(RATE // 8):
            lanes[lane] ^= int.from_bytes(block[8 * lane:8 * (lane + 1)], "little")
        absorbed = state_bytes(lanes)
        for round_index, constant in enumerate(ROUND_CONSTANTS):
            lanes = keccak_round(lanes, constant)
            if record:
                rounds.append({"block": block_index, "round": round_index, "state_hex": state_bytes(lanes).hex()})
        if record:
            blocks.append({
                "block": block_index, "input_hex": block.hex(),
                "state_before_hex": before.hex(), "state_absorbed_hex": absorbed.hex(),
                "state_after_hex": state_bytes(lanes).hex(),
            })
    # SHA3-512 requests 64 bytes, so one squeeze of the rate is sufficient.
    return state_bytes(lanes)[:64], blocks, rounds


def checked_hash(message: bytes) -> bytes:
    digest, _, _ = sha3_512(message)
    assert digest == hashlib.sha3_512(message).digest()
    return digest


def digest(label: bytes, *fields: bytes) -> bytes:
    return checked_hash(frame(PREFIX + label) + b"".join(map(frame, fields)))


def opening_fields(
    amount: int,
    creation_version: int = 1,
    serial: bytes = bytes([0xD3]) * 32,
    blinding: bytes = bytes([0xC4]) * 32,
) -> list[tuple[str, bytes, str]]:
    chain = bytes(range(32))
    owner_key = bytes(i % 251 for i in range(2592))
    kem_key = bytes(1536) + bytes(range(32))
    secret = bytes([0x5B]) * 32
    return [
        ("opening_domain", OPENING_DOMAIN, "constant"),
        ("encoding_version", (2).to_bytes(2, "big"), "constant"),
        ("chain_id", chain, "parameter"),
        ("creation_version", creation_version.to_bytes(4, "big"), "parameter"),
        ("asset_id", bytes([0xA7]) * 32, "parameter"),
        ("amount", amount.to_bytes(8, "big"), "parameter"),
        ("owner_key_binding", checked_hash(owner_key), "parameter"),
        ("nullifier_secret_binding", digest(b"nullifier-secret-binding.v2", chain, secret), "parameter"),
        ("recipient_key_binding", digest(b"recipient-key-binding.v2", chain, kem_key), "parameter"),
        ("serial", serial, "parameter"),
        ("blinding", blinding, "parameter"),
        ("payment_policy", bytes([0]), "constant"),
    ]


def csv_bytes(rows: list[dict]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("ascii")


def self_check() -> int:
    messages = [b"", b"abc", bytes(200), bytes(range(256)), b"a" * 1000]
    for length in range(0, 217):
        messages.append(bytes((index * 29 + length * 11) % 256 for index in range(length)))
    for message in messages:
        checked_hash(message)
    return len(messages)


def combined_vectors() -> dict:
    """Four canonical openings with a separate exact integer oracle."""
    maximum = MASK
    definitions = [
        ("normal", [50, 50, 60, 39], 1),
        ("near_maximum", [maximum - 1000, 0, maximum - 1002, 1], 1),
        ("zero", [0, 0, 0, 0], 0),
        ("one_as_fee", [1, 0, 0, 0], 1),
        ("cross_32_bit_carry", [(1 << 32) - 1, 1, (1 << 32) - 1, 0], 1),
        ("maximum_fee", [maximum, 0, 0, 0], maximum),
        ("maximum_sum", [maximum - 1, 1, maximum - 2, 1], 1),
        ("equal_overflow", [maximum, 1, maximum, 1], 0),
        ("input_overflow", [maximum, 1, maximum, 0], 0),
        ("output_overflow", [maximum, 0, maximum, 1], 0),
        ("fee_overflow", [maximum, 0, maximum, 0], 1),
        ("one_atom_inflation", [50, 50, 60, 40], 1),
        ("field_modulus_alias", [2013265921, 0, 0, 0], 0),
    ]
    cases = []
    versions = [1, 2, 3, 4]
    for name, amounts, fee in definitions:
        openings = []
        commitments = []
        serials = []
        blindings = []
        for index, (amount, version) in enumerate(zip(amounts, versions)):
            serial = bytes([0xD3 + index]) * 32
            blinding = bytes([0xC4 + index]) * 32
            fields = opening_fields(amount, version, serial, blinding)
            opening = b"".join(frame(value) for _, value, _ in fields)
            assert len(opening) == 418
            assert int.from_bytes(opening[129:137], "big") == amount
            openings.append(opening.hex())
            commitments.append(checked_hash(frame(COMMITMENT_DOMAIN) + frame(opening)).hex())
            serials.append(serial.hex())
            blindings.append(blinding.hex())
        input_sum = amounts[0] + amounts[1]
        output_sum = amounts[2] + amounts[3] + fee
        valid_integer = input_sum <= maximum and output_sum <= maximum and input_sum == output_sum
        cases.append({
            "name": name,
            "amounts": amounts,
            "valid_integer": valid_integer,
            "input_sum_decimal": str(input_sum),
            "output_sum_with_fee_decimal": str(output_sum),
            "public": {
                "chain_hex": bytes(range(32)).hex(),
                "asset_hex": (bytes([0xA7]) * 32).hex(),
                "creation_versions": versions,
                "fee": fee,
                "context_hex": bytes(range(64)).hex(),
                "commitments_hex": commitments,
            },
            "openings_hex": openings,
            "serials_hex": serials,
            "blindings_hex": blindings,
        })
        assert len(set(commitments)) == 4
    assert [case["valid_integer"] for case in cases] == [True] * 7 + [False] * 6
    return {
        "format": "thorum.note-proof-lab.reference.v1",
        "opening_format_version": 2,
        "note_order": ["input_0", "input_1", "output_0", "output_1"],
        "integer_rule": "a0 + a1 = b0 + b1 + fee <= 2^64 - 1",
        "synthetic_fixture": True,
        "cases": cases,
    }


def adapter_vectors() -> list[dict]:
    """New laboratory hash domains with canonical values, without Rust adapters."""
    result = []
    for suffix, values, width in [
        (b"leaf.v1", [0, 1, 2013265920, 0x12345678], 4),
        (b"node.v1", [0, 1, MASK, *range(13)], 8),
        (b"transcript.v1", list(range(64)), 1),
    ]:
        domain = b"thorum.note-proof-lab." + suffix
        material = (
            frame(domain)
            + b"".join(value.to_bytes(width, "little") for value in values)
            + len(values).to_bytes(8, "big")
        )
        output = checked_hash(material)
        result.append({
            "domain_suffix": suffix.decode("ascii"),
            "preimage_hex": material.hex(),
            "digest_hex": output.hex(),
            "little_endian_u64_words": ":".join(
                str(int.from_bytes(output[index:index + 8], "little"))
                for index in range(0, 64, 8)
            ),
        })
    return result


def outputs() -> dict[str, bytes]:
    cases = []
    main_amount = 123456789012345
    for name, amount in [("zero", 0), ("one", 1), ("maximum", MASK), ("recipient_payment", main_amount)]:
        opening = b"".join(frame(value) for _, value, _ in opening_fields(amount))
        preimage = frame(COMMITMENT_DOMAIN) + frame(opening)
        cases.append({"case": name, "amount": amount, "opening_hex": opening.hex(),
                      "preimage_hex": preimage.hex(), "commitment_hex": checked_hash(preimage).hex()})
    opening = bytes.fromhex(cases[-1]["opening_hex"])
    preimage = bytes.fromhex(cases[-1]["preimage_hex"])
    commitment, blocks, rounds = sha3_512(preimage, record=True)
    assert len(opening) == 418 and len(preimage) == 464 and len(blocks) == 7
    assert preimage[175:183] == main_amount.to_bytes(8, "big")
    assert commitment == hashlib.sha3_512(preimage).digest()
    offsets = []
    opening_start = len(frame(COMMITMENT_DOMAIN)) + 4
    cursor = 0
    for name, value, kind in opening_fields(main_amount):
        offsets.append({
            "field": name, "opening_frame_start": cursor, "opening_value_start": cursor + 4,
            "preimage_frame_start": opening_start + cursor,
            "preimage_value_start": opening_start + cursor + 4,
            "value_length": len(value), "kind": kind,
        })
        cursor += 4 + len(value)
    mask = bytearray(len(padded(preimage)))
    fixed = bytearray(len(mask))
    # Commitment domain, opening length and all nested field lengths are fixed.
    mask[:opening_start] = bytes([255]) * opening_start
    fixed[:opening_start] = preimage[:opening_start]
    for field in offsets:
        start = field["preimage_frame_start"]
        mask[start:start + 4] = bytes([255]) * 4
        fixed[start:start + 4] = preimage[start:start + 4]
        if field["kind"] == "constant":
            start = field["preimage_value_start"]
            end = start + field["value_length"]
            mask[start:end] = bytes([255]) * (end - start)
            fixed[start:end] = preimage[start:end]
    mask[len(preimage):] = bytes([255]) * (len(mask) - len(preimage))
    fixed[len(preimage):] = padded(preimage)[len(preimage):]
    metadata = {
        "source_standard": "NIST FIPS 202",
        "source_url": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
        "state_lane_index": "x + 5*y",
        "state_lane_byte_order": "little endian",
        "opening_length": len(opening), "commitment_preimage_length": len(preimage),
        "opening_preimage_offset": opening_start,
        "rate_bytes": RATE, "capacity_bits": 1024, "permutation_rounds": 24,
        "padded_length": len(padded(preimage)), "absorb_blocks": len(blocks),
        "amount_opening_start": 129, "amount_preimage_start": 175, "amount_length": 8,
        "amount_byte_order": "big endian", "suffix_offset": 464, "suffix_byte": 6,
        "zero_padding_start": 465, "zero_padding_end_exclusive": 503,
        "final_padding_offset": 503, "final_padding_byte": 128,
        "commitment_hex": commitment.hex(),
        "padded_preimage_hex": padded(preimage).hex(),
        "structural_fixed_mask_hex": mask.hex(), "structural_fixed_bytes_hex": fixed.hex(),
        "structural_fixed_byte_count": sum(byte != 0 for byte in mask),
        "structural_zero_offsets": [index for index, (flag, byte) in enumerate(zip(mask, fixed)) if flag and byte == 0],
        "hashlib_cross_checks": self_check(),
        "synthetic_fixture": True,
    }
    return {
        "commitment_vectors.csv": csv_bytes(cases),
        "opening_offsets.csv": csv_bytes(offsets),
        "sponge_blocks.csv": csv_bytes(blocks),
        "keccak_rounds.csv": csv_bytes(rounds),
        "profile.json": (json.dumps(metadata, indent=2) + "\n").encode("ascii"),
        "combined_vectors.json": (json.dumps(combined_vectors(), indent=2) + "\n").encode("ascii"),
        "hash_vectors.csv": csv_bytes(adapter_vectors()),
    }


def main() -> int:
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
    print("Canonical payment opening and SHA3 references match" if args.check else "Canonical payment opening and SHA3 references generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
