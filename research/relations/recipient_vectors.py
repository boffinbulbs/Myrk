#!/usr/bin/env python3
"""Reproduce recipient capability v2 encoding vectors independently of Rust."""

import argparse
import hashlib
from pathlib import Path


DESTINATION = Path(__file__).resolve().parent / "recipient_vectors.csv"
PREFIX = b"thorum.relation-lab."


def frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def digest(label: bytes, *fields: bytes) -> bytes:
    return hashlib.sha3_512(frame(PREFIX + label) + b"".join(map(frame, fields))).digest()


def vectors() -> dict[str, bytes]:
    chain = bytes(range(32))
    owner = bytes(i % 251 for i in range(2592))
    voter = bytes(250 - i % 251 for i in range(2592))
    # Canonical polynomial encoding for codec tests, without an honest key generation claim.
    kem_key = bytes(1536) + bytes(range(32))
    secret = bytes([0x5B]) * 32
    serial = bytes([0xD3]) * 32
    blinding = bytes([0xC4]) * 32
    owner_binding = hashlib.sha3_512(owner).digest()
    voting_binding = hashlib.sha3_512(voter).digest()
    secret_binding = digest(b"nullifier-secret-binding.v2", chain, secret)
    encryption_binding = digest(b"recipient-key-binding.v2", chain, kem_key)
    capability = b"".join(map(frame, [
        PREFIX + b"recipient-capability.v2", (2).to_bytes(2, "big"),
        chain, owner_binding, secret_binding, kem_key,
    ]))
    result = {
        "chain": chain,
        "owner_public_key": owner,
        "voting_public_key": voter,
        "recipient_public_key": kem_key,
        "nullifier_secret": secret,
        "serial": serial,
        "blinding": blinding,
        "owner_key_binding": owner_binding,
        "voting_key_binding": voting_binding,
        "nullifier_secret_binding": secret_binding,
        "recipient_key_binding": encryption_binding,
        "capability": capability,
    }
    for name, asset, amount, policy in (
        ("payment", bytes([0xA7]) * 32, 123456789012345, [bytes([0])]),
        ("bond", bytes(32), 987654321, [
            bytes([1]), voting_binding,
            (5).to_bytes(8, "big"), (7).to_bytes(8, "big"), (20).to_bytes(8, "big"),
        ]),
    ):
        opening = b"".join(map(frame, [
            PREFIX + b"note-opening.v2", (2).to_bytes(2, "big"), chain,
            (1).to_bytes(4, "big"), asset, amount.to_bytes(8, "big"),
            owner_binding, secret_binding, encryption_binding, serial, blinding, *policy,
        ]))
        commitment = digest(b"note-commitment.v2", opening)
        nullifier = digest(b"note-nullifier.v2", chain, secret, commitment)
        vote_nullifier = digest(
            b"vote-nullifier.v2", chain, secret, commitment,
            (9).to_bytes(8, "big"), bytes([0x39]) * 32,
        )
        leaf = digest(b"merkle-leaf.v1", chain, commitment)
        root = leaf
        for level, byte in enumerate((0x10, 0x20, 0x30)):
            sibling = bytes([byte]) * 64
            left, right = (sibling, root) if (5 >> level) & 1 else (root, sibling)
            root = digest(b"merkle-node.v1", chain, left, right)
        result.update({
            f"{name}_opening": opening,
            f"{name}_commitment": commitment,
            f"{name}_nullifier": nullifier,
            f"{name}_vote_nullifier": vote_nullifier,
            f"{name}_merkle_leaf": leaf,
            f"{name}_merkle_root_index_5": root,
        })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = ("field,hex\n" + "".join(
        f"{name},{value.hex()}\n" for name, value in vectors().items()
    )).encode("ascii")
    if args.check:
        if not DESTINATION.exists() or DESTINATION.read_bytes() != output:
            parser.exit(1, "Recipient capability vectors differ\n")
        print("Recipient capability vectors match")
    else:
        DESTINATION.write_bytes(output)
        print("Recipient capability vectors generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
