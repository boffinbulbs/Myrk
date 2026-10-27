#!/usr/bin/env python3
"""Exact bounded matrix sampling references from retained public fixtures."""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
Q, CAPACITY = 8380417, 1008


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def classify(data):
    assert len(data) == CAPACITY
    coefficients, events = [], []
    for offset in range(0, CAPACITY, 3):
        value = int.from_bytes(data[offset:offset + 3], "little") & 0x7fffff
        take = value < Q
        events.append([value, take, len(coefficients) if take else None])
        if take:
            coefficients.append(value)
        if len(coefficients) == 256:
            break
    complete = len(coefficients) == 256
    filtered = [int.from_bytes(data[offset:offset + 3], "little") & 0x7fffff for offset in range(0, CAPACITY, 3)]
    assert coefficients == [value for value in filtered if value < Q][:256]
    return {"supported_complete": complete, "consumed_bytes": 3 * len(events),
            "coefficients": coefficients, "events": events,
            "scope": "Capacity failure means unsupported experimental resources, not standard signature invalidity"}


def source_rhos():
    selected = json.loads((ROOT / "research/crypto/vectors/selected.json").read_bytes())
    native = json.loads((ROOT / "research/signatures/synthetic_authorization.json").read_bytes())
    sources = [bytes.fromhex(case["input"]["pk"])[:32] for case in selected["cases"] if case["id"].startswith("ml_dsa_87_verify_")]
    sources += [bytes.fromhex(case["public_key_hex"])[:32] for case in [native, *native["alternate_signatures"]]]
    result = list(dict.fromkeys(sources))
    assert len(result) == 4
    return result


def adapters():
    rows = []
    for role, values, width in [("leaf", [0, 1, 2013265920, 0x12345678], 4),
                                ("node", [0, 1, 2**64 - 1] + list(range(13)), 8),
                                ("transcript", list(range(64)), 1)]:
        domain = f"thorum.matrix-sampler-proof-lab.{role}.v1".encode()
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
    hashing = module("matrix_hash_reference", ROOT / "research/hash-proofs/reference_vectors.py")
    verification = module("matrix_signature_reference", ROOT / "research/signatures/verify_reference.py")
    genuine = []
    for group, rho in enumerate(source_rhos()):
        for row in range(8):
            for column in range(7):
                message = rho + bytes([column, row])
                stream, _, states, rounds = hashing.sponge(message, 2, CAPACITY, record=True)
                assert stream == hashlib.shake_128(message).digest(CAPACITY)
                result = classify(stream)
                expected, cursor = verification.matrix_poly(rho, row, column)
                assert result["supported_complete"] and expected == result["coefficients"]
                assert cursor["bytes_consumed"] == result["consumed_bytes"]
                assert len(states) == 6 and len(rounds) == 144
                case = {"name": f"rho_{group}_row_{row}_column_{column}", "rho_hex": rho.hex(), "row": row, "column": column,
                        "message_hex": message.hex(), "stream_hex": stream.hex(),
                        "sponge_blocks": [{"before_hex": state["state_absorbed_hex"], "after_hex": state["state_after_hex"]} for state in states], **result}
                if (group, row, column) in [(0, 0, 0), (3, 7, 6)]:
                    case["round_states"] = [{"stage": state["stage"], "round": state["round"], "state_hex": state["state_hex"]} for state in rounds]
                genuine.append(case)
    fill = [(index * 65537 + 19) % Q for index in range(336)]
    specs = [("zero_candidates", [0] * 336), ("canonical_baseline", fill),
             ("high_bit_equivalent", [value + (1 << 23) for value in fill]),
             ("exact840", [Q] * 24 + fill[:312]), ("requires843", [Q] * 25 + fill[:311]),
             ("completes_at_capacity", [Q] * 80 + fill[:256]), ("one_event_beyond_capacity", [Q] * 81 + fill[:255]),
             ("all_rejected", [Q] * 336), ("only255_accepted", fill[:255] + [Q] * 81),
             ("mask_and_modulus_boundaries", [0, 1, Q - 1, Q, Q + 1, (1 << 23) - 1, 1 << 23,
                                              (1 << 23) + Q - 1, (1 << 23) + Q, (1 << 24) - 1] + fill[:326])]
    injected = []
    for name, values in specs:
        stream = b"".join(value.to_bytes(3, "little") for value in values)
        injected.append({"name": name, "stream_hex": stream.hex(), "seed_claim": False, **classify(stream)})
    assert sum(not case["supported_complete"] for case in injected) == 3
    record = {"scope": "Public synthetic references for a bounded matrix sampler, without private signature permission or standard completeness",
              "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [
                  "research/crypto/vectors/selected.json", "research/signatures/synthetic_authorization.json",
                  "research/signatures/verify_reference.py", "research/hash-proofs/reference_vectors.py"]},
              "genuine_cases": 224, "full_sponge_states": 1344, "selected_round_states": 288,
              "injected_cases": 10, "unsupported_injected_cases": 3}
    corpus = {"format": "thorum.matrix-sampling.references.v1", "capacity_bytes": CAPACITY,
              "candidate_capacity": 336, "genuine": genuine, "injected": injected}
    profile = {
        "scope": "Bounded matrix sampling diagnostic profile, without complete signature permission or standard completeness",
        "profile": "thorum.matrix-sampler-proof-lab.shake128.rejnttpoly.six-blocks.serial.p3-0.8.0.v1",
        "height": 512, "width": 7276, "actual_degree": 3, "public_values": 1090,
        "rate_bytes": 168, "output_blocks": 6, "candidate_capacity": 336, "required_acceptances": 256,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10,
        "queries": 64, "log_blowup": 3, "extension_degree": 4, "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 16384, "depth": 24,
                             "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 832},
        "analytical_arrays": {"raw_trace_bytes": 512 * 7276 * 4, "randomized_trace_bytes": 1024 * 7280 * 4,
                              "main_lde_payload_bytes": 8192 * 7280 * 4,
                              "scope": "Field array payload dimensions only, without measured peak memory or runtime"}}
    return {"vectors.json": (json.dumps(corpus, separators=(",", ":")) + "\n").encode(),
            "source_record.json": (json.dumps(record, indent=2) + "\n").encode(), "hash_vectors.csv": adapters(),
            "profile.json": (json.dumps(profile, indent=2) + "\n").encode()}


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
    print("Matrix sampling references match:224 genuine cases,1344 full states,288 selected rounds,10 injected streams and3 adapter goldens")


if __name__ == "__main__":
    main()
