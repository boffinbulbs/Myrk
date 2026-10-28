"""Independent exact transaction, note and complete signature reference data.

This script never signs, launches Rust or imports a Rust trace builder. Execution
is a separate reviewed gate. It reads one six-signature public synthetic record.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("Optimized Python is unsupported for source and reference checks")

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from static_check import BASE, ROOT, check as check_sources

FIXED_CONTEXT = b"Thorum crypto laboratory authorization v1"
IDS = ("A0", "A1", "B0", "B1", "A0_empty_context", "A0_wrong_context41")
Q = 8380417
MAX_RAW_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


def load_module(name, relative):
    source = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frame(value):
    return len(value).to_bytes(4, "big") + value


def digest(domain, *fields):
    return hashlib.sha3_512(frame(domain) + b"".join(map(frame, fields))).digest()


def transaction(fee):
    envelope = lambda i: (b"THMLAB01" + b"\0\1" + frame(bytes([0x70+i])*1568)
                          + frame(bytes([0x80+i])*12) + frame(bytes([0x90+i])*32))
    fields = [b"thorum.relation-lab.payment-statement.v1", b"\0\1", bytes(range(32)),
              (7).to_bytes(4, "big"), bytes([0x33])*32, bytes([0x44])*64,
              (2).to_bytes(4, "big"), bytes([0x50])*64, bytes([0x51])*64,
              (2).to_bytes(4, "big")]
    for i in range(2):
        fields.extend([bytes([0x60+i])*64, envelope(i)])
    fields.append(fee.to_bytes(8, "big"))
    canonical = b"".join(map(frame, fields))
    assert len(canonical) <= 65536
    message = digest(b"thorum.relation-lab.payment-authorization.v1", canonical)
    tag = digest(b"thorum.relation-lab.payment-auth-context.v1", message)[:32]
    context = b"".join(map(frame, [bytes(range(32)), (7).to_bytes(4, "big"), tag]))
    a = b"".join(map(frame, [b"thorum.crypto-lab.authorization.v1", b"\0\1", context, message]))
    pure = b"\0\x29" + FIXED_CONTEXT + a
    assert len(context) == 80 and len(a) == 196 and len(pure) == 239
    return {"id": f"T{fee-5}", "fee_atoms": fee, "canonical_T_hex": canonical.hex(),
            "authorization_message_hex": message.hex(), "Context80_hex": context.hex(),
            "A196_hex": a.hex(), "pure_fips_message239_hex": pure.hex()}


def note(key, ordinal):
    chain = bytes(range(32))
    secret = bytes([0x5b])*32
    codec_kem_key = bytes(1536) + bytes(range(32))
    fields = [b"thorum.relation-lab.note-opening.v2", b"\0\2", chain,
              (1).to_bytes(4, "big"), bytes(32), (50).to_bytes(8, "big"),
              hashlib.sha3_512(key).digest(),
              digest(b"thorum.relation-lab.nullifier-secret-binding.v2", chain, secret),
              digest(b"thorum.relation-lab.recipient-key-binding.v2", chain, codec_kem_key),
              bytes([0xd3+ordinal])*32, bytes([0xc4+ordinal])*32, b"\0"]
    opening = b"".join(map(frame, fields))
    assert len(opening) == 418 and opening[49:81] == chain
    assert opening[141:205] == hashlib.sha3_512(key).digest()
    return {"opening_hex": opening.hex(),
            "commitment_hex": digest(b"thorum.relation-lab.note-commitment.v2", opening).hex(),
            "creation_version": 1, "scope": "Canonical synthetic Payment codec. No membership, encryption or spending acceptance."}


def read_bounded(path, maximum):
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("fixture file exceeds its byte bound")
    return raw


def read_raw(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate fixture JSON key")
            result[key] = value
        return result
    raw = read_bounded(path, MAX_RAW_BYTES)
    data = json.loads(raw, object_pairs_hook=unique)
    assert set(data) == {"format", "scope", "signing_api_calls", "public_seed_source", "keys", "transactions", "signatures"}
    assert data["format"] == "thorum.private-signature-owner.raw.v1" and data["signing_api_calls"] == 6
    assert [v["id"] for v in data["signatures"]] == list(IDS)
    assert [v["id"] for v in data["keys"]] == ["A", "B"]
    assert [v["id"] for v in data["transactions"]] == ["T0", "T1"]
    selected = json.loads((ROOT / "research/crypto/vectors/selected.json").read_bytes())
    original = json.loads((ROOT / "research/signatures/synthetic_authorization.json").read_bytes())
    keygen = next(v for v in selected["cases"] if v["id"] == "ml_dsa_87_keygen")
    seeds = [bytes.fromhex(keygen["input"]["seed"])]
    changed = bytearray(seeds[0]); changed[0] ^= 1; seeds.append(bytes(changed))
    provenance = data["public_seed_source"]
    assert provenance["case"] == "ml_dsa_87_keygen" and provenance["upstream_commit"] == selected["upstream_commit"]
    assert provenance["seed_a_hex"] == seeds[0].hex() and provenance["seed_b_hex"] == seeds[1].hex()
    keys = {v["id"]: bytes.fromhex(v["public_key_hex"]) for v in data["keys"]}
    retained_b = next(v for v in original["alternate_signatures"] if v["name"] == "different_owner")
    assert keys["A"] == bytes.fromhex(keygen["expected"]["pk"]) == bytes.fromhex(original["public_key_hex"])
    assert keys["B"] == bytes.fromhex(retained_b["public_key_hex"])
    assert all(len(v) == 2592 for v in keys.values())
    expected_t = [transaction(5), transaction(6)]
    assert data["transactions"] == expected_t
    assert expected_t[0]["A196_hex"] != original["message_hex"]
    return raw, data, keys, {v["id"]: v for v in expected_t}


def expanded(key, signature, target, oracle, transforms, hints_oracle, matrices):
    rho, t1, seed, z, hints = oracle.decode(key, signature)
    records = []
    def transform(kind, values, mode):
        normal = [v % Q for v in values]
        result, stages, operations, fault = transforms.transform(normal, mode)
        assert not operations and not fault
        direct = oracle.ntt(normal) if mode == 1 else oracle.inverse_ntt(normal)
        assert result == direct
        records.append({"kind": kind, "mode": mode, "input": normal,
                        "stages": stages, "output": result})
        return result
    zhat = [transform(f"z{j}", v, 1) for j, v in enumerate(z)]
    c, challenge_cursor = oracle.challenge_poly(seed)
    chat = transform("challenge", c, 1)
    rows, encoded = [], bytearray()
    for row in range(8):
        accumulator = [0]*256
        columns = []
        for column in range(7):
            matrix = matrices[row*7+column]
            assert matrix["row"] == row and matrix["column"] == column
            products = [x*y % Q for x, y in zip(matrix["coefficients"], zhat[column])]
            after = [(old+product) % Q for old, product in zip(accumulator, products)]
            columns.append({"column": column, "prior": accumulator, "products": products, "after": after})
            accumulator = after
        t1hat = transform(f"t1_row{row}", [8192*v for v in t1[row]], 1)
        challenge_products = [x*y % Q for x, y in zip(chat, t1hat)]
        reduced = [(x-y) % Q for x, y in zip(accumulator, challenge_products)]
        inverse = transform(f"inverse_row{row}", reduced, 2)
        assert inverse == target["reconstructed_coefficients"][row]
        hint_steps = [hints_oracle.reference(value, int(hint)) for value, hint in zip(inverse, hints[row])]
        high = [item["output"] for item in hint_steps]
        assert high == [oracle.use_hint(value, hint) for value, hint in zip(inverse, hints[row])]
        packed = oracle.pack(high, 4)
        assert len(packed) == 128
        encoded.extend(packed)
        rows.append({"row": row, "columns": columns, "t1hat": t1hat,
                     "challenge_products": challenge_products, "inverse_input": reduced,
                     "inverse_output": inverse, "hints": hints[row], "hint_steps": hint_steps,
                     "w1_coefficients": high, "packed_w1_hex": packed.hex()})
    assert len(records) == 24 and len(rows) == 8 and len(encoded) == 1024
    assert encoded.hex() == target["w1_encoded_hex"]
    capacity = {"matrix_blocks": 6, "matrix_bytes": 1008, "matrix_candidate_events": 336,
                "challenge_bytes": 272, "challenge_candidate_events": 264,
                "matrix_supported": all(v["cursor"]["bytes_consumed"] <= 1008 for v in matrices),
                "challenge_supported": challenge_cursor["bytes_consumed"] <= 272,
                "challenge_cursor": challenge_cursor}
    capacity["classification"] = ("SupportedBoundedClass" if capacity["matrix_supported"] and capacity["challenge_supported"]
                                  else "UnsupportedCapacity")
    expected = bytes.fromhex(target["challenge_expected_hex"])
    equality = [x == y for x, y in zip(expected, seed)]
    assert len(expected) == 64 and len(equality) == 64 and all(equality) == target["valid"]
    return {"rho_hex": rho.hex(), "t1": t1, "z_signed": z, "zhat": zhat,
            "challenge_signed": c, "chat": chat, "transform_count": 24, "transforms": records,
            "rows": rows, "packed_w1_hex": encoded.hex(), "capacity": capacity,
            "mu_hex": target["mu_hex"], "mu_preimage_hex": target["mu_preimage_hex"],
            "challenge_expected_hex": expected.hex(), "challenge_received_hex": seed.hex(),
            "challenge_equality_bytes": equality}


def generate(path):
    inventory = check_sources()
    raw, data, keys, transactions = read_raw(path)
    oracle = load_module("full_integer_signature_oracle", "research/signatures/verify_reference.py")
    transforms = load_module("direct_transform_oracle", "research/ntt-proofs/reference_vectors.py")
    hint_oracle = load_module("decomposition_oracle", "research/coefficient-constraints/reference_vectors.py")
    matrices = {}
    for key_id, key in keys.items():
        values = []
        for row in range(8):
            for column in range(7):
                coefficients, cursor = oracle.matrix_poly(key[:32], row, column)
                stream = hashlib.shake_128(key[:32] + bytes([column, row])).digest(1008)
                values.append({"row": row, "column": column, "coefficients": coefficients,
                               "cursor": cursor, "six_block_stream_hex": stream.hex(),
                               "supported_six_blocks": cursor["bytes_consumed"] <= 1008})
        assert len(values) == 56
        matrices[key_id] = values
    notes = {"N_A": note(keys["A"], 0), "N_B": note(keys["B"], 1), "N_A_alt": note(keys["A"], 2)}
    results, signature_lookup = [], {}
    for index, item in enumerate(data["signatures"]):
        expected_key = "B" if index in (2, 3) else "A"
        expected_tid = "T1" if index in (1, 3) else "T0"
        expected_context = b"" if index == 4 else FIXED_CONTEXT[:-1]+b"0" if index == 5 else FIXED_CONTEXT
        assert item["key_id"] == expected_key and item["transaction_id"] == expected_tid
        message = bytes.fromhex(transactions[expected_tid]["A196_hex"])
        signature, context = bytes.fromhex(item["signature_hex"]), bytes.fromhex(item["context_hex"])
        assert len(signature) == 4627 and context == expected_context and item["message_hex"] == message.hex()
        own = oracle.verify(keys[expected_key], signature, message, context)
        target = own if context == FIXED_CONTEXT else oracle.verify(keys[expected_key], signature, message, FIXED_CONTEXT)
        assert own["valid"] and item["native_own_context_valid"] is True
        assert target["valid"] == (index < 4) == item["native_fixed_context_valid"]
        assert item["native_wrapper_valid"] is target["valid"]
        stage = expanded(keys[expected_key], signature, target, oracle, transforms, hint_oracle, matrices[expected_key])
        assert len(bytes.fromhex(stage["mu_preimage_hex"])) == 303
        results.append({"id": item["id"], "key_id": expected_key, "transaction_id": expected_tid,
                        "signed_context_hex": context.hex(), "own_context_valid": True,
                        "fixed_context_valid": target["valid"], "own_context_mu_hex": own["mu_hex"],
                        "fixed_target_stages": stage})
        signature_lookup[item["id"]] = item
    tuples = []
    def add_tuple(identifier, signature_id, key_id, tid, note_id):
        item = signature_lookup[signature_id]
        sigma = bytes.fromhex(item["signature_hex"])
        key = keys[key_id]
        verdict = oracle.verify(key, sigma, bytes.fromhex(transactions[tid]["A196_hex"]), FIXED_CONTEXT)
        opening = bytes.fromhex(notes[note_id]["opening_hex"])
        owner = opening[141:205] == hashlib.sha3_512(key).digest()
        bounded = (all(v["bytes_consumed"] <= 1008 for v in verdict.get("matrix_cursors", []))
                   and verdict.get("challenge_cursor", {}).get("bytes_consumed", 273) <= 272)
        relation = "Reject" if not verdict["valid"] or not owner else "AcceptConditional" if bounded else "UnsupportedCapacity"
        tuples.append({"id": identifier, "signature_id": signature_id, "key_id": key_id,
                       "transaction_id": tid, "note_id": note_id,
                       "fixed_signature_valid": verdict["valid"], "owner_match": owner,
                       "bounded_supported": bounded, "conditional_verdict": relation})
    for item in data["signatures"]:
        add_tuple(item["id"], item["id"], item["key_id"], item["transaction_id"], "N_"+item["key_id"])
    add_tuple("A0_same_owner_alternate_note", "A0", "A", "T0", "N_A_alt")
    add_tuple("A0_wrong_owner_note", "A0", "A", "T0", "N_B")
    add_tuple("A0_wrong_verification_key", "A0", "B", "T0", "N_B")
    add_tuple("A1_wrong_expected_transaction", "A1", "A", "T0", "N_A")
    assert all(t["conditional_verdict"] == "Reject" for t in tuples[-3:])
    return {"format": "thorum.private-signature-owner.reference.v1", "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "scope": "Synthetic complete integer signature and canonical owner note references. No native AIR, proof, accepted membership, nullifier coupling or payment acceptance.",
            "source_inventory_sha256": hashlib.sha256((BASE/"source_inventory.json").read_bytes()).hexdigest(),
            "parameters": {"q": Q, "n": 256, "k": 8, "l": 7, "tau": 60, "omega": 75,
                           "context_hex": FIXED_CONTEXT.hex(), "signature_count": 6},
            "transactions": list(transactions.values()), "keys": data["keys"], "notes": notes,
            "key_matrices": matrices, "signature_records": results, "tuples": tuples,
            "retained_source_pins": inventory["retained"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Existing frozen six-signature raw record")
    parser.add_argument("--output", type=Path, required=True, help="New reference file, or existing file with --check")
    parser.add_argument("--check", action="store_true", help="Recompute math without signing or writes")
    args = parser.parse_args()
    assert args.input.resolve() != args.output.resolve()
    if not args.check and args.output.exists():
        raise FileExistsError("reference output already exists")
    result = generate(args.input)
    encoded = (json.dumps(result, separators=(",", ":")) + "\n").encode()
    assert len(encoded) <= MAX_OUTPUT_BYTES
    if args.check:
        assert read_bounded(args.output, MAX_OUTPUT_BYTES) == encoded, "reference bytes differ"
    else:
        with args.output.open("xb") as destination:
            destination.write(encoded)
    print(json.dumps({"signatures": 6, "full_rows_per_signature": 8, "transforms_per_signature": 24,
                      "final_comparison_bytes_per_signature": 64, "bytes": len(encoded),
                      "sha256": hashlib.sha256(encoded).hexdigest(), "check": args.check}))


if __name__ == "__main__":
    main()
