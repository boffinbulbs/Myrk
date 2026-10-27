#!/usr/bin/env python3
"""Pin reviewed matrix sampler sources, fixed dimensions and closed profile.

This source change guard is not a mathematical, privacy or security proof.
The existing hash profile guard checks resolved dependencies separately.
"""

import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
SRC = ROOT / "crates/thorum-hash-proof-lab/src"
FINGERPRINTS = {
    "matrix_sampler.rs": "66b478f59f74b0ca47bebaced5a571f8d31753090961bfb8a37bbb1f1dc45291",
    "matrix_sampler/air.rs": "2801d87b1e2456537df3d3b3000243beb28a8095efd3e99e75f2147a69dcdae7",
    "matrix_sampler/hash.rs": "cc887c372bce045ff2fbbbfb933af39e88f839cdead5ec8d05b8213e994e1054",
    "matrix_sampler/proof.rs": "4ca5fea8f7b1b031e387fe4798ae70bab3922ec32cd2908ba2fcef9d771627a1",
    "matrix_sampler/tests.rs": "69b08a67ff1ea5850b49b5e953ab0d9395173a4ece0d19c7a984aa1bf8618f83",
    "matrix_sampler/proof/tests.rs": "e778944bf02dbd16ac3e900787b1cff80aa0391fe4475cac46cf3e42a3c7a8e2",
}


def fingerprint(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode()).hexdigest()


def check():
    for name, expected in FINGERPRINTS.items():
        if fingerprint((SRC / name).read_text(encoding="utf-8")) != expected:
            raise ValueError(f"Retained matrix sampler source changed: {name}")
    profile = json.loads((BASE / "profile.json").read_bytes())
    expected = {
        "profile": "thorum.matrix-sampler-proof-lab.shake128.rejnttpoly.six-blocks.serial.p3-0.8.0.v1",
        "height": 512, "width": 7276, "actual_degree": 3, "public_values": 1090,
        "rate_bytes": 168, "output_blocks": 6, "candidate_capacity": 336, "required_acceptances": 256,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10, "queries": 64,
        "log_blowup": 3, "extension_degree": 4, "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 16384, "depth": 24,
                             "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 832},
    }
    for key, value in expected.items():
        if profile[key] != value:
            raise ValueError(f"Fixed matrix sampler parameter changed: {key}")
    if 2633 + 7 + 1344 * 2 + 32 + 1008 + 256 + 337 + 257 + 24 + 23 + 1 + 10 != 7276:
        raise ValueError("The fixed column layout changed")
    arrays = profile["analytical_arrays"]
    if (arrays["raw_trace_bytes"], arrays["randomized_trace_bytes"], arrays["main_lde_payload_bytes"]) != (14901248, 29818880, 238551040):
        raise ValueError("The analytical array dimensions changed")
    corpus = json.loads((BASE / "vectors.json").read_bytes())
    if len(corpus["genuine"]) != 224 or len(corpus["injected"]) != 10:
        raise ValueError("The retained reference counts changed")
    if sum(not case["supported_complete"] for case in corpus["injected"]) != 3:
        raise ValueError("The unsupported injected classifications changed")
    if any(case["seed_claim"] for case in corpus["injected"]):
        raise ValueError("Injected streams cannot acquire a seed claim")


def main():
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: fixed connected matrix sampler, 512 by 7276 trace, degree 3 and 1090 public fields")
    print("PASS: reviewed seed and state linkage, sampling control, complete holds, closed transport and raw rejection corpus")
    print("This source change guard does not establish mathematical correctness, privacy, signature permission or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
