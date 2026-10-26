#!/usr/bin/env python3
"""Reproduce integer conservation, trace and hash fixtures without the Rust backend."""

import argparse
import csv
import hashlib
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1
PRIME = 2013265921
PREFIX = b"thorum.proof-lab."


def csv_bytes(rows: list[list]) -> bytes:
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    return stream.getvalue().encode("ascii")


def bounded_conservation(amounts: tuple[int, int, int, int], fee: int) -> bool:
    left = amounts[0] + amounts[1]
    right = amounts[2] + amounts[3] + fee
    return all(0 <= value <= MAX for value in (*amounts, fee, left, right)) and left == right


def traces(amounts: tuple[int, int, int, int], fee: int) -> list[list[int]]:
    rows = []
    carry_a = carry_b = 0
    for bit in range(64):
        bits = [(amount >> bit) & 1 for amount in amounts]
        fee_bit = (fee >> bit) & 1
        left = bits[0] + bits[1] + carry_a
        right = bits[2] + bits[3] + fee_bit + carry_b
        for phase in range(4):
            rows.append([
                len(rows), bit, phase, *bits, left & 1,
                carry_a, left >> 1, carry_b, right >> 1, fee_bit,
            ])
        carry_a = left >> 1
        carry_b = right >> 1
    return rows


def hash_vector(label: bytes, values: list[int], width: int) -> list[str]:
    domain = PREFIX + label
    material = (
        len(domain).to_bytes(4, "big") + domain
        + b"".join(value.to_bytes(width, "little") for value in values)
        + len(values).to_bytes(8, "big")
    )
    digest = hashlib.sha3_512(material).digest()
    words = ":".join(str(int.from_bytes(digest[i:i + 8], "little")) for i in range(0, 64, 8))
    return [label.decode("ascii"), material.hex(), digest.hex(), words]


def artifacts() -> dict[str, bytes]:
    busy = (MAX - 1000000, 1234, 0xABCD0123456789AB, 0)
    busy_fee = 2147483647
    busy = (*busy[:3], busy[0] + busy[1] - busy[2] - busy_fee)
    cases = [
        ("zero", (0, 0, 0, 0), 0),
        ("small", (1, 2, 1, 1), 1),
        ("carry", (100, 100, 199, 0), 1),
        ("maximum", (MAX, 0, MAX - 1, 0), 1),
        ("maximum_fee", (MAX, 0, 0, 0), MAX),
        ("busy", busy, busy_fee),
        ("one_atom_inflation", (100, 0, 100, 0), 1),
        ("unequal", (100, 0, 98, 0), 1),
        ("field_modulus_alias", (PRIME, 0, 0, 0), 0),
        ("equal_overflow", (MAX, 1, MAX, 1), 0),
        ("input_overflow", (MAX, 1, MAX, 0), 0),
        ("output_overflow", (MAX, 0, MAX, 1), 0),
        ("fee_overflow", (MAX, 0, 1, 0), MAX),
    ]
    case_rows = [["id", "a0", "a1", "b0", "b1", "fee", "valid"]]
    for name, amounts, fee in cases:
        case_rows.append([name, *amounts, fee, int(bounded_conservation(amounts, fee))])
    trace_rows = [[
        "row", "bit", "phase", "a0", "a1", "b0", "b1", "sum",
        "carry_a", "next_a", "carry_b", "next_b", "fee_bit",
    ], *traces(busy, busy_fee)]
    public_rows = [["index", "value"]]
    public_rows.extend([[i, (busy_fee >> i) & 1] for i in range(64)])
    public_rows.extend([[64 + i, i] for i in range(64)])
    hash_rows = [["domain_suffix", "preimage_hex", "digest_hex", "little_endian_u64_words"]]
    hash_rows.append(hash_vector(b"leaf.v1", [0, 1, PRIME - 1, 0x12345678], 4))
    hash_rows.append(hash_vector(b"node.v1", [0, 1, (1 << 64) - 1, *range(13)], 8))
    hash_rows.append(hash_vector(b"transcript.v1", list(range(64)), 1))
    return {
        "conservation_vectors.csv": csv_bytes(case_rows),
        "trace_vector.csv": csv_bytes(trace_rows),
        "public_values.csv": csv_bytes(public_rows),
        "hash_vectors.csv": csv_bytes(hash_rows),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, expected in artifacts().items():
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_bytes() != expected:
                parser.exit(1, f"Proof reference artifact differs: {name}\n")
        else:
            path.write_bytes(expected)
    print("Proof reference vectors match" if args.check else "Proof reference vectors generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
