#!/usr/bin/env python3
"""Pin the joint signature sources, shared gadgets and closed profile.

This source change guard is not a correctness, privacy or security proof.
Resolved dependency and feature checks remain in the hash profile guard.
"""

import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
FINGERPRINTS = {
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature.rs": "5deb5a9da00230da97c1c709293820ac73095e7fe4d559a88d38829390e562c7",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/air.rs": "ebc1ab0b6b4c4f7a6bd09a2dadcf1a3ed841ad7d4398046fe5819294fa4fa7b3",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/hash.rs": "5a49266d7c66ab2050bbe11307713773db30114aab08234ff3f34c6ecd4c47b4",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/packing.rs": "fc2a47e29d1a571021bf2f2fde591cb7e201e08a94b39db8f66010e5947a3d7e",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/proof.rs": "010f14e517c1a7ae76f480920f0dbdcd8c64f831c79d4ae68a3be6dc255e2d97",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/tests.rs": "d7172ae3527574b20ebd0c648e53ffbd2a2436045f5194e047571b3de583bd02",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/proof/tests.rs": "1c3b74775c626b35cd4497f5c576dd36952919a4629778dc2b95baf3fb493ba1",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/signature/proof/raw_tests.rs": "8e29554ae8a8f515c463d1b8e071c4b830dc53683f1b02bccb6ba9e8f95ff1a7",
    "crates/thorum-hash-proof-lab/tests/signature_challenge.rs": "7ddf3fe3371e4898ab89e94802b5f08dfd1bf72fe08446b370bf836523c2fcbf",
    "crates/thorum-hash-proof-lab/src/challenge_sampler/air.rs": "8cf10b38aaecf618cd0ef8f4aa3fddaa0dd7cab48e0cf7b302550beaa8ec7371",
    "crates/thorum-hash-proof-lab/src/challenge_sampler.rs": "30a03c087231e22447c75ea890832ae64f26ea20e9dc07c4b4a724b143bff77c",
    "crates/thorum-arithmetic-proof-lab/src/packing.rs": "cb8997c15b9bd5f1db231206142cfc84e6c5561b5383ad1ba8ffec79d8533d70",
    "crates/thorum-arithmetic-proof-lab/src/mul.rs": "fdf7c8dcb834539b566dab21baf2762de25bc56f907e393f01e8d9b05b09a7e1"
}


def fingerprint(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode()).hexdigest()


def check():
    if len(FINGERPRINTS) != 13:
        raise ValueError("All thirteen joint and shared source records are required")
    for name, expected in FINGERPRINTS.items():
        if fingerprint((ROOT / name).read_text(encoding="utf-8")) != expected:
            raise ValueError(f"Retained joint signature source changed: {name}")
    profile = json.loads((BASE / "profile.json").read_bytes())
    expected = {
        "profile": "thorum.signature-challenge-proof-lab.mldsa87.canonical-sampleinball.serial.p3-0.8.0.v1",
        "height": 512, "width": 16650, "actual_degree": 3, "public_values": 1088,
        "rate_bytes": 136, "output_blocks": 2, "candidate_capacity": 264, "required_acceptances": 60,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10,
        "queries": 64, "log_blowup": 3, "extension_degree": 4,
        "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 32768,
                             "depth": 24, "string_bytes": 64, "integer_digits": 20,
                             "merkle_siblings": 832},
    }
    for key, value in expected.items():
        if profile[key] != value:
            raise ValueError(f"Fixed joint signature parameter changed: {key}")
    if 6598 + 4563 + 449 + 80 + 348 + 1792 + 76 + 56 * 2 + 49 + 8 + 1 + 14 + 8 + 112 + 256 + 2048 + 64 + 8 + 64 != 16650:
        raise ValueError("The fixed joint column layout changed")
    arrays = profile["analytical_arrays"]
    if (arrays["raw_trace_bytes"], arrays["randomized_trace_bytes"], arrays["main_lde_payload_bytes"]) != (34099200, 68214784, 545718272):
        raise ValueError("The analytical array dimensions changed")
    corpus = json.loads((BASE / "vectors.json").read_bytes())["cases"]
    if len(corpus) != 124 or sum(case["canonical"] for case in corpus) != 63:
        raise ValueError("The canonical signature corpus changed")
    if len({case["signature_hex"] for case in corpus}) != 124:
        raise ValueError("The represented signatures must be distinct")
    if corpus[-1]["name"] != "represented_prefix_a_with_canonical_tail_b" or not corpus[-1]["canonical"]:
        raise ValueError("The limited relation scope case is required")


def main():
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: fixed same signature relation, 512 by 16650 trace, degree 3 and 1088 public fields")
    print("PASS: shared challenge and response sources, complete decoding, held private banks and closed transport")
    print("This guard does not establish full signature validity, ownership, privacy or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
