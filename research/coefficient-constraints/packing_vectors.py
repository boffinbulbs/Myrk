#!/usr/bin/env python3
"""Independent five byte windows for canonical ML DSA 87 coefficients."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
Q, GAMMA1 = 8380417, 524288


def t1_decode(raw):
    a, b, c, d, e = raw
    return [a + 256 * (b & 3), (b >> 2) + 64 * (c & 15),
            (c >> 4) + 16 * (d & 63), (d >> 6) + 4 * e]


def z_decode(raw):
    a, b, c, d, e = raw
    words = [a + 256 * b + 65536 * (c & 15), (c >> 4) + 16 * d + 4096 * e]
    return words, [(GAMMA1 - value) % Q for value in words]


def build():
    source = ROOT / "research/signatures/cases.json"
    spec = importlib.util.spec_from_file_location("signature_reference", ROOT / "research/signatures/verify_reference.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    t1, z = [], []
    for case in json.loads(source.read_bytes())["cases"]:
        if not case["expected_valid"]:
            continue
        pk, sig = bytes.fromhex(case["public_key_hex"]), bytes.fromhex(case["signature_hex"])
        _, key, _, signed, _ = oracle.decode(pk, sig)
        for group in range(512):
            raw = pk[32 + group * 5:37 + group * 5]
            values = t1_decode(raw)
            poly, offset = divmod(group, 64)
            assert values == key[poly][offset * 4:offset * 4 + 4]
            t1.append({"source": case["name"], "group": group, "bytes_hex": raw.hex(),
                       "decoded": values, "scaled": [value * 8192 for value in values]})
        for group in range(896):
            raw = sig[64 + group * 5:69 + group * 5]
            words, normal = z_decode(raw)
            poly, offset = divmod(group, 128)
            assert normal == [value % Q for value in signed[poly][offset * 2:offset * 2 + 2]]
            z.append({"source": case["name"], "group": group, "bytes_hex": raw.hex(),
                      "encoded": words, "normal": normal, "accepted": True})
    for raw in [bytes(5), bytes([255]) * 5] + [(1 << bit).to_bytes(5, "little") for bit in range(40)]:
        values = t1_decode(raw)
        t1.append({"source": "packing_boundary", "bytes_hex": raw.hex(), "decoded": values,
                   "scaled": [value * 8192 for value in values]})
    bounds = [0, 1, 120, 121, 122, GAMMA1 - 1, GAMMA1, GAMMA1 + 1, 1048454, 1048455, 1048456, 1048575]
    for first in bounds:
        for second in bounds:
            raw = (first + (second << 20)).to_bytes(5, "little")
            words, normal = z_decode(raw)
            assert words == [first, second]
            z.append({"source": "norm_boundary", "bytes_hex": raw.hex(), "encoded": words,
                      "normal": normal, "accepted": all(121 <= value <= 1048455 for value in words)})
    return {"source_cases_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "q": Q, "gamma1": GAMMA1, "beta": 120, "t1": t1, "z": z}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    values = build()
    content = (json.dumps(values, separators=(",", ":")) + "\n").encode()
    path = BASE / "packing_vectors.json"
    if args.check:
        assert path.read_bytes() == content, path.name
    else:
        path.write_bytes(content)
    print(json.dumps({"t1_windows": len(values["t1"]), "z_windows": len(values["z"]),
                      "valid_z_windows": sum(case["accepted"] for case in values["z"])}))


if __name__ == "__main__":
    main()
