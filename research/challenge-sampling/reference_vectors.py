#!/usr/bin/env python3
"""Exact bounded challenge sampling references from retained public fixtures."""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
CAPACITY, Q = 272, 8380417


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def sample(stream):
    assert len(stream) == CAPACITY
    signs = int.from_bytes(stream[:8], "little")
    support, events, cursor = {}, [], 8
    for step in range(60):
        i = 196 + step
        while cursor < CAPACITY and stream[cursor] > i:
            events.append({"step": step, "i": i, "j": stream[cursor], "take": False,
                           "cursor": cursor, "sign": None, "old": None})
            cursor += 1
        if cursor == CAPACITY:
            break
        j = stream[cursor]
        bit = (signs >> step) & 1
        old = support.pop(j, 0)
        if old:
            support[i] = old
        support[j] = 1 - 2 * bit
        assert len(support) == step + 1
        events.append({"step": step, "i": i, "j": j, "take": True,
                       "cursor": cursor, "sign": bit, "old": old})
        cursor += 1
    polynomial = [support.get(index, 0) for index in range(256)]
    return {"supported_complete": len(support) == 60, "consumed_bytes": cursor,
            "polynomial": polynomial, "normal": [value % Q for value in polynomial],
            "events": events, "weight": len(support)}


def array_sample(stream):
    """Separate array based update order for finite injected streams."""
    values, cursor, accepted = [0] * 256, 8, 0
    bits = [((stream[bit // 8] >> (bit % 8)) & 1) for bit in range(60)]
    for i in range(196, 256):
        while True:
            if cursor == len(stream):
                return values, cursor, accepted
            j = stream[cursor]
            cursor += 1
            if j <= i:
                break
        values[i] = values[j]
        values[j] = -1 if bits[accepted] else 1
        accepted += 1
    return values, cursor, accepted


def seeds():
    selected = json.loads((ROOT / "research/crypto/vectors/selected.json").read_bytes())
    native = json.loads((ROOT / "research/signatures/synthetic_authorization.json").read_bytes())
    values = [(case["id"] + "_challenge", bytes.fromhex(case["input"]["signature"])[:64])
              for case in selected["cases"] if case["id"].startswith("ml_dsa_87_verify_")]
    values.append(("synthetic_exact_authorization_challenge", bytes.fromhex(native["signature_hex"])[:64]))
    values.extend((case["name"] + "_challenge", bytes.fromhex(case["signature_hex"])[:64])
                  for case in native["alternate_signatures"])
    assert len(values) == len({seed for _, seed in values}) == 6
    return values


def adapters():
    rows = []
    for role, values, width in [("leaf", [0, 1, 2013265920, 0x12345678], 4),
                                ("node", [0, 1, 2**64 - 1] + list(range(13)), 8),
                                ("transcript", list(range(64)), 1)]:
        domain = f"thorum.challenge-sampler-proof-lab.{role}.v1".encode()
        preimage = len(domain).to_bytes(4, "big") + domain
        preimage += b"".join(value.to_bytes(width, "little") for value in values) + len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        rows.append({"domain": role, "preimage_hex": preimage.hex(), "digest_hex": digest.hex(),
                     "words_le": ":".join(str(int.from_bytes(digest[i:i+8], "little")) for i in range(0, 64, 8))})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


def outputs():
    hashing = module("challenge_hash_reference", ROOT / "research/hash-proofs/reference_vectors.py")
    oracle = module("challenge_signature_reference", ROOT / "research/signatures/verify_reference.py")
    genuine = []
    for name, seed in seeds():
        stream, _, states, rounds = hashing.sponge(seed, 3, CAPACITY, record=True)
        assert stream == hashlib.shake_256(seed).digest(CAPACITY)
        result = sample(stream)
        full, cursors = oracle.challenge_poly(seed)
        separate, cursor, accepted = array_sample(stream)
        assert result["supported_complete"] and result["polynomial"] == full == separate
        assert result["consumed_bytes"] == cursors["bytes_consumed"] == cursor
        assert accepted == 60 and len(states) == 2 and len(rounds) == 48
        genuine.append({"name": name, "seed_hex": seed.hex(), "stream_hex": stream.hex(),
                        "sponges": [{"before_hex": state["state_absorbed_hex"], "after_hex": state["state_after_hex"]} for state in states],
                        "rounds": rounds, **result})
    signs = bytes([0x5a]) * 8
    specs = [("all_positive_repeated_zero", bytes(8), [0] * 264),
             ("unused_high_sign_bits", bytes(7) + b"\xf0", [0] * 264),
             ("all_negative_repeated_zero", bytes([255]) * 8, [0] * 264),
             ("j_equal_i", signs, list(range(196, 256)) + [0] * 204),
             ("occupied_relocation", signs, [0, 0] + [195 + i for i in range(2, 60)] + [0] * 204),
             ("acceptance_boundaries", signs, [197, 196, 198, 197, 255] + [0] * 259),
             ("continuation_after_first_block", signs, [255] * 128 + [0] * 136),
             ("completes_at_capacity", signs, [255] * 204 + [0] * 60),
             ("one_beyond_capacity", signs, [255] * 205 + [0] * 59),
             ("all_rejected", signs, [255] * 264),
             ("sign_bit_order", bytes([1, 2, 4, 8, 16, 32, 64, 128]), list(range(196, 256)) + [0] * 204)]
    for final in range(256):
        specs.append((f"last_step_j_{final}", signs, list(range(196, 255)) + [final] + [0] * 204))
    injected = []
    for name, header, candidates in specs:
        stream = header + bytes(candidates)
        result = sample(stream)
        values, cursor, accepted = array_sample(stream)
        assert result["polynomial"] == values and result["consumed_bytes"] == cursor
        assert result["supported_complete"] == (accepted == 60)
        injected.append({"name": name, "seed_claim": False, "stream_hex": stream.hex(), **result})
    assert injected[0]["polynomial"] == injected[1]["polynomial"]
    assert sum(not case["supported_complete"] for case in injected) == 2
    assert all(case["supported_complete"] for case in injected if case["name"].startswith("last_step_j_"))
    assert next(case for case in injected if case["name"] == "completes_at_capacity")["consumed_bytes"] == 272
    corpus = {"format": "thorum.challenge-sampling.references.v1", "capacity_bytes": CAPACITY,
              "candidate_capacity": 264, "genuine": genuine, "injected": injected}
    record = {"scope": "Public synthetic bounded challenge references without complete signature permission",
              "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [
                  "research/crypto/vectors/selected.json", "research/signatures/synthetic_authorization.json",
                  "research/hash-proofs/reference_vectors.py", "research/signatures/verify_reference.py"]},
              "genuine_cases": 6, "full_sponge_states": 12, "round_states": 288,
              "injected_cases": 267, "unsupported_injected_cases": 2}
    profile = {
        "scope": "Bounded sparse challenge diagnostic profile without complete signature permission or full standard completeness",
        "profile": "thorum.challenge-sampler-proof-lab.shake256.sampleinball.two-blocks.serial.p3-0.8.0.v1",
        "height": 512, "width": 6598, "actual_degree": 3, "public_values": 1088,
        "rate_bytes": 136, "output_blocks": 2, "candidate_capacity": 264, "required_acceptances": 60,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10,
        "queries": 64, "log_blowup": 3, "extension_degree": 4, "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 16384, "depth": 24,
                             "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 832},
        "analytical_arrays": {"raw_trace_bytes": 512 * 6598 * 4, "randomized_trace_bytes": 1024 * 6602 * 4,
                              "main_lde_payload_bytes": 8192 * 6602 * 4,
                              "scope": "Field array payload dimensions without measured peak memory or runtime"}}
    return {"vectors.json": (json.dumps(corpus, separators=(",", ":")) + "\n").encode(),
            "source_record.json": (json.dumps(record, indent=2) + "\n").encode(),
            "profile.json": (json.dumps(profile, indent=2) + "\n").encode(), "hash_vectors.csv": adapters()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in outputs().items():
        path = BASE / name
        if args.check:
            assert path.read_bytes() == content, name
        else:
            path.write_bytes(content)
    print("Challenge references match:6 genuine cases,12 full states,288 rounds,267 injected streams and3 adapter goldens")


if __name__ == "__main__":
    main()
