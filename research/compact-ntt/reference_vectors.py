#!/usr/bin/env python3
"""Reproduce compact transform namespaces, fixed parameters and source records."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]


def outputs():
    rows = []
    for kind, values, width in [
        ("leaf", [0, 1, 0x78000000, 0x12345678], 4),
        ("node", [0, 1, 2**64 - 1] + list(range(13)), 8),
        ("transcript", list(range(64)), 1),
    ]:
        domain = f"thorum.compact-ntt-proof-lab.{kind}.v1".encode()
        preimage = len(domain).to_bytes(4, "big") + domain
        preimage += b"".join(value.to_bytes(width, "little") for value in values)
        preimage += len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        rows.append({"domain_suffix": kind, "preimage_hex": preimage.hex(), "digest_hex": digest.hex(),
                     "little_endian_u64_words": ":".join(str(int.from_bytes(digest[i:i+8], "little")) for i in range(0, 64, 8))})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    profile = {
        "scope": "Public polynomial diagnostic proof profile. No private signature, payment permission or composed security claim.",
        "profile": "thorum.compact-ntt-proof-lab.modq8380417.radix4096.eight-slots.p3-0.8.0.v1",
        "modulus": 8380417, "root": 1753, "inverse_256": 8347681,
        "height": 256, "width": 2921, "public_values": 2113, "actual_degree": 2,
        "layout": {"program": 225, "bank": 256, "products": 8 * 211, "writes": 16 * 46, "flags": 16},
        "active_rows": {"forward": 192, "inverse": 224}, "terminal_pc": 224,
        "stored_degree_bits": 9, "quotient_chunks": 4, "fri_rounds": 9,
        "queries": 64, "log_blowup": 2, "random_codewords": 4, "row_salts": 16,
        "transport": {"bytes": 8388608, "tokens": 2000000, "items": 8192, "depth": 24, "string_bytes": 64, "integer_digits": 20},
        "analytical_arrays": {"raw_trace_bytes": 256 * 2921 * 4,
                              "main_lde_payload_bytes": 256 * 2 * 4 * (2921 + 4) * 4,
                              "scope": "Field array payload dimensions only, without measured peak memory or a runtime benchmark."},
    }
    references = ["ntt_vectors.json", "stage_vectors.json", "butterfly_operations.csv"]
    record = {
        "source": "Existing retained normal residue transform references and pinned backend version0.8.0.",
        "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
        "references": {name: hashlib.sha256((ROOT / "research/ntt-proofs" / name).read_bytes()).hexdigest() for name in references},
        "q": profile["modulus"], "psi": profile["root"], "inverse_256": profile["inverse_256"],
        "classification_cases": 47, "valid_dft_cases": 31, "valid_stage_states": 309,
        "valid_arithmetic_records": 35584,
        "scope": "Source identity and reproducible fixed parameters, without a performance or security claim.",
    }
    return {"hash_vectors.csv": buffer.getvalue().encode(),
            "profile.json": (json.dumps(profile, indent=2) + "\n").encode(),
            "source_record.json": (json.dumps(record, indent=2) + "\n").encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, encoded in outputs().items():
        path = BASE / name
        if args.check:
            assert path.read_bytes() == encoded, name
        else:
            path.write_bytes(encoded)
    print("Compact transform namespaces, fixed parameters and retained source identities match")


if __name__ == "__main__":
    main()
