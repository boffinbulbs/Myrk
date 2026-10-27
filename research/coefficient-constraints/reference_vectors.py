#!/usr/bin/env python3
"""Independent FIPS 204 Decompose and UseHint boundary references."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parents[1]
Q, ALPHA, GAMMA = 8380417, 523776, 261888


def reference(r, hint):
    assert 0 <= r < Q and hint in (0, 1)
    low = r % ALPHA
    if low > GAMMA:
        low -= ALPHA
    if r - low == Q - 1:
        high, low = 0, low - 1
    else:
        high = (r - low) // ALPHA
    output = high if hint == 0 else (high + (1 if low > 0 else -1)) % 16
    n, u = divmod(r + GAMMA - 1, ALPHA)
    edge = int(n == 16)
    positive = int(low > 0)
    raw = high + hint * (2 * positive - 1)
    return {"high": high, "low": low, "positive": positive, "output": output,
            "n": n, "u": u, "edge": edge,
            "sign_slack": u - GAMMA - edge if positive else GAMMA + edge - 1 - u,
            "borrow": int(raw < 0), "overflow": int(raw > 15)}


def build():
    spec = importlib.util.spec_from_file_location("signature_oracle", PROJECT / "research/signatures/verify_reference.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    points = {0, 1, 2, Q - 3, Q - 2, Q - 1}
    for multiple in range(17):
        for center in (multiple * ALPHA, multiple * ALPHA + GAMMA, multiple * ALPHA - GAMMA):
            points.update(center + delta for delta in (-2, -1, 0, 1, 2) if 0 <= center + delta < Q)
    cases = []
    for r in sorted(points):
        for hint in (0, 1):
            expected = reference(r, hint)
            assert oracle.decompose(r) == (expected["high"], expected["low"])
            assert oracle.use_hint(r, hint) == expected["output"]
            cases.append({"name": f"boundary_r_{r}_hint_{hint}", "r": r, "hint": hint, "expected": expected})
    source_path = PROJECT / "research/signatures/cases.json"
    source = json.loads(source_path.read_bytes())
    signature_cases = []
    for case in source["cases"]:
        if not case["expected_valid"]:
            continue
        pk, signature, message, context = [bytes.fromhex(case[key]) for key in ("public_key_hex", "signature_hex", "message_hex", "context_hex")]
        result = oracle.verify(pk, signature, message, context)
        assert result["valid"]
        hints = oracle.decode(pk, signature)[4]
        for poly in range(8):
            for coefficient in range(256):
                r, hint = result["reconstructed_coefficients"][poly][coefficient], int(hints[poly][coefficient])
                expected = reference(r, hint)
                assert oracle.use_hint(r, hint) == expected["output"]
                packed = bytes.fromhex(result["w1_encoded_hex"])[poly * 128 + coefficient // 2]
                assert ((packed >> (4 * (coefficient % 2))) & 15) == expected["output"]
                signature_cases.append({"source": case["name"], "poly": poly, "coefficient": coefficient,
                                        "r": r, "hint": hint, "expected": expected})
    invalid = [{"name": "r_equal_q", "r": Q, "hint": 0, "output": 0},
               {"name": "r_above_q", "r": Q + 1, "hint": 1, "output": 15},
               {"name": "r_u32_max", "r": 0xffffffff, "hint": 0, "output": 0},
               {"name": "r_babybear_alias", "r": 2013265921 + GAMMA, "hint": 1, "output": 1},
               {"name": "hint_two", "r": 0, "hint": 2, "output": 0},
               {"name": "hint_max", "r": 0, "hint": 255, "output": 0},
               {"name": "output_sixteen", "r": 0, "hint": 1, "output": 16},
               {"name": "output_max", "r": 0, "hint": 1, "output": 255}]
    for r in sorted(points):
        expected = reference(r, 1)["output"]
        invalid.append({"name": f"wrong_hinted_output_r_{r}", "r": r, "hint": 1, "output": (expected + 1) % 16})
    profile = {"scope": "Decompose and UseHint constraint references. No private signature proof, payment or permission claim.",
               "q": Q, "alpha": ALPHA, "gamma2": GAMMA, "gadget_width": 125, "expected_degree": 2,
               "source_cases_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
               "pinned_native_revision": "f75d5b829948988f18d9463f286805fb9410bcdd",
               "decomposition_residual_integer_box": [-8642304, 8642303],
               "positive_branch_residual_integer_box": [-524032, 261887],
               "nonpositive_branch_residual_integer_box": [-261888, 524031],
               "output_residual_integer_box": [-32, 32]}
    adapters = []
    for suffix, width, inputs in [
        ("leaf.v1", 4, [0, 1, 2013265920, 305419896]),
        ("node.v1", 8, [0, 1, 2**64 - 1] + list(range(13))),
        ("transcript.v1", 1, list(range(64))),
    ]:
        domain = f"thorum.use-hint-proof-lab.{suffix}".encode()
        preimage = len(domain).to_bytes(4, "big") + domain
        preimage += b"".join(value.to_bytes(width, "little") for value in inputs)
        preimage += len(inputs).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        adapters.append({"domain_suffix": suffix, "inputs": inputs,
                         "preimage_hex": preimage.hex(), "digest_hex": digest.hex(),
                         "little_endian_u64_words": [int.from_bytes(digest[i:i+8], "little") for i in range(0, 64, 8)]})
    return {"boundary_vectors.json": {"cases": cases}, "signature_vectors.json": {"cases": signature_cases},
            "invalid_diagnostics.json": {"cases": invalid}, "profile.json": profile,
            "hash_adapter_vectors.json": {"vectors": adapters}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    values = build()
    for name, value in values.items():
        content = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        path = BASE / name
        if args.check:
            assert path.read_bytes() == content, name
        else:
            path.write_bytes(content)
    print(json.dumps({"boundary_cases": len(values["boundary_vectors.json"]["cases"]),
                      "full_signature_coefficient_cases": len(values["signature_vectors.json"]["cases"]),
                      "invalid_diagnostics": len(values["invalid_diagnostics.json"]["cases"])}))


if __name__ == "__main__":
    main()
