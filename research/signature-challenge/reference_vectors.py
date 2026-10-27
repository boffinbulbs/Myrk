#!/usr/bin/env python3
"""Canonical represented signatures and same seed challenge references.

Only retained public fixtures and reference oracles are used. Canonicality and
challenge sampling do not establish full signature validity or spending rights.
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
Q, GAMMA1 = 8380417, 524288


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def replace_word(signature, coefficient, value):
    polynomial, offset = divmod(coefficient, 256)
    window, member = divmod(offset, 2)
    start = 64 + polynomial * 640 + window * 5
    result = bytearray(signature)
    encoded = int.from_bytes(result[start:start + 5], "little")
    shift = 20 * member
    mask = ((1 << 20) - 1) << shift
    result[start:start + 5] = ((encoded & ~mask) | (value << shift)).to_bytes(5, "little")
    return bytes(result)


def replace_hints(signature, indices, cuts):
    assert len(indices) <= 75 and len(cuts) == 8
    return signature[:4544] + bytes(indices) + bytes(75 - len(indices)) + bytes(cuts)


def represented_strings(repository):
    retained = json.loads((repository / "research/signatures/cases.json").read_bytes())
    baseline = json.loads((repository / "research/signatures/synthetic_authorization.json").read_bytes())
    public_key = bytes.fromhex(baseline["public_key_hex"])
    signature = bytes.fromhex(baseline["signature_hex"])
    records = []

    def add(name, key, value):
        assert len(key) == 2592 and len(value) == 4627
        records.append((name, key, value))

    for case in retained["cases"]:
        key = bytes.fromhex(case["public_key_hex"])
        value = bytes.fromhex(case["signature_hex"])
        if len(key) == 2592 and len(value) == 4627:
            add("native_reference_" + case["name"], key, value)
    for polynomial in range(7):
        for coefficient in [0, 255]:
            for word in [120, 121, 1048455, 1048456]:
                add(f"z_poly_{polynomial}_coefficient_{coefficient}_word_{word}", public_key,
                    replace_word(signature, polynomial * 256 + coefficient, word))
    for polynomial in [0, 6]:
        for coefficient in [1, 254]:
            for word in [0, 1048575]:
                add(f"z_nibble_poly_{polynomial}_coefficient_{coefficient}_word_{word}", public_key,
                    replace_word(signature, polynomial * 256 + coefficient, word))
    hints = [
        ("empty_hints_repeated_cuts", [], [0] * 8),
        ("first_index_zero", [0], [1] * 8),
        ("last_poly_index_255", [255], [0] * 7 + [1]),
        ("same_index_distinct_polys", [5, 5], [1, 2, 2, 2, 2, 2, 2, 2]),
        ("descending_across_distinct_polys", [7, 5], [1, 2, 2, 2, 2, 2, 2, 2]),
        ("duplicate_within_poly", [5, 5], [2] * 8),
        ("descending_within_poly", [7, 5], [2] * 8),
        ("nonzero_unused_tail", [1], [0] * 8),
        ("maximum_weight_75", list(range(75)), [75] * 8),
        ("cut_above_weight", [], [76] * 8),
        ("decreasing_cuts", [0], [1, 0, 1, 1, 1, 1, 1, 1]),
    ]
    for polynomial in range(8):
        for index in [0, 255]:
            hints.append((f"single_hint_poly_{polynomial}_index_{index}", [index],
                          [0] * polynomial + [1] * (8 - polynomial)))
        cuts = [0] * 8
        cuts[polynomial] = 76
        hints.append((f"cut_byte_{polynomial}_above_75", [], cuts))
    for polynomial in range(1, 8):
        cuts = [1] * 8
        cuts[polynomial] = 0
        hints.append((f"cut_byte_{polynomial}_descending", [0], cuts))
    for name, indices, cuts in hints:
        add("hint_" + name, public_key, replace_hints(signature, indices, cuts))
    unique = {}
    for name, key, value in records:
        unique.setdefault(value, (name, key))
    assert len(unique) == 123
    return [(name, key, value) for value, (name, key) in unique.items()]


def canonical_tail(signature):
    """Independent fixed windows and sparse hint classification."""
    assert len(signature) == 4627
    words = []
    for offset in range(64, 4544, 5):
        a, b, c, d, e = signature[offset:offset + 5]
        words.extend([a + 256 * b + 65536 * (c & 15),
                      (c >> 4) + 16 * d + 4096 * e])
    if not all(121 <= value <= 1048455 for value in words):
        return False, [], []
    indices, cuts = signature[4544:4619], signature[4619:4627]
    if any(value > 75 for value in cuts) or any(a > b for a, b in zip(cuts, cuts[1:])):
        return False, [], []
    if any(indices[cuts[-1]:]):
        return False, [], []
    hints = [[0] * 256 for _ in range(8)]
    start = 0
    for polynomial, end in enumerate(cuts):
        segment = indices[start:end]
        if any(a >= b for a, b in zip(segment, segment[1:])):
            return False, [], []
        for index in segment:
            hints[polynomial][index] = 1
        start = end
    normal = [(GAMMA1 - value) % Q for value in words]
    z = [normal[start:start + 256] for start in range(0, 1792, 256)]
    return True, z, hints


def adapters():
    rows = []
    for role, values, width in [("leaf", [0, 1, 2013265920, 0x12345678], 4),
                                ("node", [0, 1, 2**64 - 1] + list(range(13)), 8),
                                ("transcript", list(range(64)), 1)]:
        domain = f"thorum.signature-challenge-proof-lab.{role}.v1".encode()
        preimage = len(domain).to_bytes(4, "big") + domain
        preimage += b"".join(value.to_bytes(width, "little") for value in values) + len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        rows.append({"role": role, "preimage_hex": preimage.hex(), "digest_hex": digest.hex(),
                     "words_le": ":".join(str(int.from_bytes(digest[i:i + 8], "little")) for i in range(0, 64, 8))})
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def outputs(repository):
    oracle = module("signature_challenge_verifier", repository / "research/signatures/verify_reference.py")
    sampler = module("signature_challenge_sampler", repository / "research/challenge-sampling/reference_vectors.py")
    cases = []
    for name, key, signature in represented_strings(repository):
        canonical, z, hints = canonical_tail(signature)
        try:
            _, _, _, signed, decoded_hints = oracle.decode(key, signature)
            decoded = True
            assert canonical
            assert [[value % Q for value in row] for row in signed] == z
            assert decoded_hints == hints
        except ValueError:
            decoded = False
        assert decoded == canonical, name
        challenge = sampler.sample(hashlib.shake_256(signature[:64]).digest(272))
        full_challenge, cursor = oracle.challenge_poly(signature[:64])
        assert challenge["supported_complete"]
        assert challenge["normal"] == [value % Q for value in full_challenge]
        assert challenge["consumed_bytes"] == cursor["bytes_consumed"]
        cases.append({"name": name, "signature_hex": signature.hex(), "canonical": canonical,
                      "z_q": z, "hints": hints, "challenge_normal": challenge["normal"]})
    first, second = cases[:2]
    joined = first["signature_hex"][:128] + second["signature_hex"][128:]
    assert joined not in {case["signature_hex"] for case in cases}
    canonical, z, hints = canonical_tail(bytes.fromhex(joined))
    assert canonical and z == second["z_q"] and hints == second["hints"]
    cases.append({"name": "represented_prefix_a_with_canonical_tail_b", "signature_hex": joined,
                  "canonical": True, "z_q": z, "hints": hints,
                  "challenge_normal": first["challenge_normal"]})
    assert len(cases) == 124 and sum(case["canonical"] for case in cases) == 63
    corpus = {"format": "thorum.signature-challenge.references.v1",
              "scope": "Canonical represented signature and sparse challenge without full signature validity or spending permission",
              "cases": cases}
    sources = {name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in [
        "research/signatures/cases.json", "research/signatures/synthetic_authorization.json",
        "research/signatures/verify_reference.py", "research/challenge-sampling/reference_vectors.py"]}
    sources["research/signature-challenge/reference_vectors.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record = {"scope": "Public retained and synthetic fixtures for canonicality plus sparse challenge only",
              "source_sha256": sources, "represented_signatures": 124, "canonical": 63,
              "noncanonical": 61, "unique_before_join": 123, "adapter_goldens": 3}
    profile = {
        "scope": "Same represented signature canonicality and sparse challenge without full signature validity or spending permission",
        "profile": "thorum.signature-challenge-proof-lab.mldsa87.canonical-sampleinball.serial.p3-0.8.0.v1",
        "height": 512, "width": 16650, "actual_degree": 3, "public_values": 1088,
        "rate_bytes": 136, "output_blocks": 2, "candidate_capacity": 264, "required_acceptances": 60,
        "stored_degree_bits": 10, "quotient_chunks": 8, "fri_rounds": 10,
        "queries": 64, "log_blowup": 3, "extension_degree": 4, "random_codewords": 4,
        "row_salts": 16, "grinding_bits": 0,
        "closed_transport": {"bytes": 16777216, "tokens": 2000000, "items": 32768, "depth": 24,
                             "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 832},
        "analytical_arrays": {"raw_trace_bytes": 34099200, "randomized_trace_bytes": 68214784,
                              "main_lde_payload_bytes": 545718272,
                              "scope": "Field array payload dimensions without measured peak memory or runtime"}}
    return {"vectors.json": (json.dumps(corpus, separators=(",", ":")) + "\n").encode(),
            "source_record.json": (json.dumps(record, indent=2) + "\n").encode(),
            "profile.json": (json.dumps(profile, indent=2) + "\n").encode(), "hash_vectors.csv": adapters()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=BASE.parents[1],
                        help="Override the repository root while staging outside research/signature-challenge")
    arguments = parser.parse_args()
    for name, content in outputs(arguments.repository_root.resolve()).items():
        path = BASE / name
        if arguments.check:
            assert path.read_bytes() == content, name
        else:
            path.write_bytes(content)
    print("Signature challenge references match:124 represented strings,63 canonical,61 rejected and3 adapter goldens")


if __name__ == "__main__":
    main()
