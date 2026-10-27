#!/usr/bin/env python3
"""Pin reviewed challenge sources, fixed dimensions and closed transport.

This source change guard is not a mathematical, privacy or security proof.
The retained hash profile guard checks resolved dependencies separately.
"""

import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
FINGERPRINTS = {
    "crates/thorum-hash-proof-lab/src/challenge_sampler.rs": "30a03c087231e22447c75ea890832ae64f26ea20e9dc07c4b4a724b143bff77c",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/air.rs": "8cf10b38aaecf618cd0ef8f4aa3fddaa0dd7cab48e0cf7b302550beaa8ec7371",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/hash.rs": "8a5e2df607b7606bd3e0bc042d70cfc422b23440201d78e6cececb3fefc67ed1",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/proof.rs": "deeac0b7a9f6b9a9af5ac98dbe150cdcb1f4d2cdb00772869a499cde18346a3a",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/tests.rs": "cea7ec0abd04b7f5a3751c00422364713f8c7b6f5fc3ca789a1935b6fb90adaa",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/proof/tests.rs": "66a305dba4ccfc92775785f0ad8858b9b855dbefe563ea7a34c505691a059c20",
    "crates/thorum-hash-proof-lab/tests/challenge_sampler.rs": "6313845f7426ccd0d6acdaf8958aa44d10de1a1c151a3ebed1e2d6efdbcce42b"
}


def fingerprint(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode()).hexdigest()


def check():
    if len(FINGERPRINTS) != 7:
        raise ValueError("The seven reviewed source records are required")
    for name, expected in FINGERPRINTS.items():
        if fingerprint((ROOT / name).read_text(encoding="utf-8")) != expected:
            raise ValueError(f"Retained challenge sampler source changed: {name}")
    profile = json.loads((BASE / "profile.json").read_bytes())
    expected = {
        "profile": "thorum.challenge-sampler-proof-lab.shake256.sampleinball.two-blocks.serial.p3-0.8.0.v1",
        "height": 512, "width": 6598, "actual_degree": 3, "public_values": 1088,
        "rate_bytes": 136, "output_blocks": 2, "candidate_capacity": 264, "required_acceptances": 60,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10,
        "queries": 64, "log_blowup": 3, "extension_degree": 4,
        "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 16384, "depth": 24,
                             "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 832},
    }
    for key, value in expected.items():
        if profile[key] != value:
            raise ValueError(f"Fixed challenge parameter changed: {key}")
    if 2633 + 3 + 1088 * 2 + 64 + 272 + 64 + 256 * 3 + 265 + 61 + 8 * 3 + 256 + 3 + 9 != 6598:
        raise ValueError("The fixed column layout changed")
    arrays = profile["analytical_arrays"]
    if (arrays["raw_trace_bytes"], arrays["randomized_trace_bytes"], arrays["main_lde_payload_bytes"]) != (13512704, 27041792, 216334336):
        raise ValueError("The analytical array dimensions changed")
    corpus = json.loads((BASE / "vectors.json").read_bytes())
    if len(corpus["genuine"]) != 6 or len(corpus["injected"]) != 267:
        raise ValueError("The retained reference counts changed")
    if sum(not case["supported_complete"] for case in corpus["injected"]) != 2:
        raise ValueError("The unsupported injected classifications changed")
    if any(case["seed_claim"] for case in corpus["injected"]):
        raise ValueError("Injected streams cannot acquire a seed claim")
    if sum(case["name"].startswith("last_step_j_") for case in corpus["injected"]) != 256:
        raise ValueError("All final candidate indices are required")


def main():
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: fixed connected sparse challenge, 512 by 6598 trace, degree 3 and 1088 public fields")
    print("PASS: reviewed source linkage, signed relocation, complete holds, closed transport and raw rejection corpus")
    print("This source change guard does not establish correctness, privacy, signature permission or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
