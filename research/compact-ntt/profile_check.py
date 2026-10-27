#!/usr/bin/env python3
"""Check the retained compact transform source and closed diagnostic profile.

This change guard pins reviewed declarations and source. It does not establish
mathematics, privacy, authorization, knowledge soundness or a security level.
The existing NTT guard checks the resolved dependency graph separately.
"""

import hashlib
import json
from pathlib import Path
import re
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
SRC = ROOT / "crates/thorum-ntt-proof-lab/src"
PROFILE = "thorum.compact-ntt-proof-lab.modq8380417.radix4096.eight-slots.p3-0.8.0.v1"
FINGERPRINTS = {
    "compact.rs": "ec4b31d6eccbe39e923b4217d243886e24b7fcc47d1b6cb6312f46def8726c95",
    "compact/air.rs": "b7ee7a2a7bab9ecfb990507a192b671afbaaf391346ea228239f252a72a901ef",
    "compact/hash.rs": "c6f4551fbc545b89459c466199f905b47c31a1dc7e27c5350ea7beb25cd17c99",
    "compact/causal.rs": "6bf0f0942f75b2ecedca321f7966d93bdab88541cf8ab42f27cdc4e2823f1d5a",
    "compact/independent_causal.rs": "bfb833546910272a066372f1f86f50ec7399e6723bbffcb2c320a1ab59e1d275",
    "compact/proof_tests.rs": "f0e4dde7e9fafb6d53c7884f3b80989ca2a5a4ffa1bd77f9c59434c7e500e12e",
    "compact/tests.rs": "68db383822ca2aa7ffb07363f193c1d2af6f0949c509698c3c142b913b29ff3f",
}


def normalized(text):
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S))


def fingerprint(text):
    return hashlib.sha256(normalized(text).encode()).hexdigest()


def check():
    for name, expected in FINGERPRINTS.items():
        if fingerprint((SRC / name).read_text(encoding="utf-8")) != expected:
            raise ValueError(f"Retained compact source changed: {name}")
    parent = (SRC / "lib.rs").read_text(encoding="utf-8")
    start = parent.index("#[derive(Clone, Copy, Debug, Eq, PartialEq)]")
    types = parent[start:parent.index("fn fresh_rng()")]
    if fingerprint(types) != "4f8aad6fe5631c566185abf532f348478e724a058dfa2cb798ec0a37dd0f299b":
        raise ValueError("The shared typed statement, witness, mode or error changed")
    math = (SRC / "ntt.rs").read_text(encoding="utf-8")
    math = math[math.index("pub const ROOT"):math.index("pub(crate) struct Row")]
    if fingerprint(math) != "27df6e0675214360ec006fbfe41a3b848cafee9fdef487c8a67ebe531211f830":
        raise ValueError("The shared exact twiddle and product helpers changed")
    if "pubmodcompact;" not in normalized(parent):
        raise ValueError("The separately namespaced compact module is absent")
    profile = json.loads((BASE / "profile.json").read_bytes())
    expected = {
        "profile": PROFILE, "modulus": 8380417, "root": 1753, "inverse_256": 8347681,
        "height": 256, "width": 2921, "public_values": 2113, "actual_degree": 2,
        "layout": {"program": 225, "bank": 256, "products": 1688, "writes": 736, "flags": 16},
        "active_rows": {"forward": 192, "inverse": 224}, "terminal_pc": 224,
        "stored_degree_bits": 9, "quotient_chunks": 4, "fri_rounds": 9,
        "queries": 64, "log_blowup": 2, "random_codewords": 4, "row_salts": 16,
        "transport": {"bytes": 8388608, "tokens": 2000000, "items": 8192, "depth": 24, "string_bytes": 64, "integer_digits": 20},
    }
    for key, value in expected.items():
        if profile[key] != value:
            raise ValueError(f"Fixed compact profile value changed: {key}")
    if sum(profile["layout"].values()) != profile["width"]:
        raise ValueError("The compact column calculation changed")
    if profile["analytical_arrays"]["raw_trace_bytes"] != 2991104 or profile["analytical_arrays"]["main_lde_payload_bytes"] != 23961600:
        raise ValueError("The analytical field array dimensions changed")


def main():
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: retained compact profile {PROFILE}")
    print("PASS: shared types and exact math, fixed control and register dataflow, hiding configuration, canonical transport and rejection corpus")
    print("PASS: 256 by 2921 trace, degree2, 2113 public fields, stored9, four quotient chunks, nine FRI rounds, 64queries and log2")
    print("This source change guard does not establish mathematical correctness, privacy, authorization or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
