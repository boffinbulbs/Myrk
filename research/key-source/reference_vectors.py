#!/usr/bin/env python3
"""Independent private key source decoding, hashes, schedule and lifetime data.

Only public mathematical Python references and hashlib are imported. No Rust
trace, builder, native signer or proof backend supplies an expected result.
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
DEFAULT_REPOSITORY = Path(__file__).resolve().parents[2]
PUBLIC_INPUT_REVISION = "061a4ba5a930f8031ea39aa93595311305d07bd8"
PREVIOUS_INPUT_REVISION = "a586c32004f9ef499a855caf4c9574976ad6bd25"
PROOF_PROFILE = "thorum.private-key-source-proof-lab.mldsa87.two-slots.four-rounds.serial.p3-0.8.0.v1"
HEIGHT, ROUND_SLOTS, PERMUTATIONS_PER_KEY = 1024, 4, 57
ROWS_PER_KEY, KEY_BYTES, T1_COUNT = 342, 2592, 2048


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def csv_bytes(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def state_bytes(state):
    return b"".join(value.to_bytes(8, "little") for value in state)


def lanes(data):
    assert len(data) == 200
    return [int.from_bytes(data[offset:offset + 8], "little") for offset in range(0, 200, 8)]


def pack_t1(values):
    assert len(values) == T1_COUNT and all(0 <= value <= 1023 for value in values)
    return sum(value << (10 * index) for index, value in enumerate(values)).to_bytes(2560, "little")


def decode_t1(key):
    assert len(key) == KEY_BYTES
    values = []
    for start in range(32, KEY_BYTES, 5):
        a, b, c, d, e = key[start:start + 5]
        values.extend([a + 256 * (b & 3), (b >> 2) + 64 * (c & 15),
                       (c >> 4) + 16 * (d & 63), (d >> 6) + 4 * e])
    assert len(values) == T1_COUNT and all(0 <= value <= 1023 for value in values)
    assert pack_t1(values) == key[32:]
    return [values[start:start + 256] for start in range(0, T1_COUNT, 256)]


def source_keys(repository):
    source = json.loads((repository / "research/signatures/synthetic_authorization.json").read_bytes())
    first = bytes.fromhex(source["public_key_hex"])
    alternate = next(record for record in source["alternate_signatures"] if record["name"] == "different_owner")
    second = bytes.fromhex(alternate["public_key_hex"])
    assert len(first) == len(second) == KEY_BYTES and first != second
    keys = {"retained_a": first, "retained_b": second,
            "t1_all_zero": first[:32] + pack_t1([0] * T1_COUNT),
            "t1_all_1023": first[:32] + pack_t1([1023] * T1_COUNT),
            "t1_alternating_endpoints": first[:32] + pack_t1([1023 if i % 2 else 0 for i in range(T1_COUNT)])}
    for name, offset, mask in [("rho_first_byte_changed", 0, 1),
                               ("first_t1_byte_changed", 32, 1),
                               ("last_t1_byte_changed", 2591, 128)]:
        changed = bytearray(first)
        changed[offset] ^= mask
        keys[name] = bytes(changed)
    for name, left, right in [("sha3_boundary_71_72_swapped", 71, 72),
                               ("shake_boundary_135_136_swapped", 135, 136),
                               ("t1_poly_boundary_351_352_swapped", 351, 352)]:
        changed = bytearray(first)
        assert changed[left] != changed[right]
        changed[left], changed[right] = changed[right], changed[left]
        keys[name] = bytes(changed)
    keys["represented_rho_a_tail_b"] = first[:32] + second[32:]
    changed = bytearray(first)
    assert changed[32:42] != changed[42:52]
    changed[32:42], changed[42:52] = changed[42:52], changed[32:42]
    keys["t1_ten_byte_windows_swapped"] = bytes(changed)
    assert len(keys) == 13 and len(set(keys.values())) == 13
    return keys


def logical_position(logical):
    assert 0 <= logical < HEIGHT * ROUND_SLOTS
    row, slot = divmod(logical, ROUND_SLOTS)
    permutation, round_index = divmod(logical, 24)
    meaningful = permutation < 114
    key_slot = permutation // PERMUTATIONS_PER_KEY if meaningful else None
    stage = permutation % PERMUTATIONS_PER_KEY if meaningful else None
    kind = "owner" if meaningful and stage < 37 else "tr" if meaningful else "dummy"
    block = stage if kind == "owner" else stage - 37 if kind == "tr" else None
    return {"logical_round": logical, "physical_row": row, "round_slot": slot,
            "keccak_column_start": 2633 * slot, "permutation": permutation,
            "round": round_index, "input_slot": key_slot, "kind": kind, "block": block,
            "logical_first": logical == 0, "logical_last": logical == HEIGHT * ROUND_SLOTS - 1,
            "intra_transition": slot < ROUND_SLOTS - 1,
            "outer_transition": slot == ROUND_SLOTS - 1 and row < HEIGHT - 1,
            "logical_transition": logical < HEIGHT * ROUND_SLOTS - 1,
            "permutation_first": round_index == 0, "permutation_last": round_index == 23,
            "meaningful": meaningful,
            "source_kind": ("private_key_hash" if meaningful else
                            "explicit_zero_dummy" if logical < 4080 else "automatic_zero_padding")}


def hash_adapters(hashing):
    """Full independent adapter preimages, digest bytes and all eight words."""
    leaves = [0, 1, 2013265920, 0x12345678]
    nodes = [0, 1, 2**64 - 1, *range(13)]
    payloads = [
        ("leaf", leaves, b"".join(value.to_bytes(4, "little") for value in leaves)),
        ("node", nodes, b"".join(value.to_bytes(8, "little") for value in nodes)),
        ("transcript", list(range(64)), bytes(range(64))),
    ]
    rows, preimages = [], []
    for kind, values, payload in payloads:
        domain = f"thorum.private-key-source-proof-lab.{kind}.v1".encode("ascii")
        preimage = len(domain).to_bytes(4, "big") + domain + payload + len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        manual, _, _, _ = hashing.sponge(preimage, 1, 64)
        assert digest == manual and len(digest) == 64
        words = [int.from_bytes(digest[start:start + 8], "little") for start in range(0, 64, 8)]
        assert b"".join(word.to_bytes(8, "little") for word in words) == digest
        rows.append({"kind": kind, "domain": domain.decode("ascii"), "digest_hex": digest.hex(),
                     "little_endian_words": ":".join(str(word) for word in words)})
        preimages.append({"kind": kind, "domain": domain.decode("ascii"), "domain_bytes": len(domain),
                          "input_values": values, "item_count": len(values), "payload_hex": payload.hex(),
                          "preimage_hex": preimage.hex(), "digest_hex": digest.hex(), "little_endian_words": words})
    return rows, {"format": "thorum.private-key-source-proof-lab.hash-adapters.v1",
                  "scope": "Independent complete SHA3-512 adapter examples, without a proof or verifier verdict",
                  "framing": "u32 big endian domain length, domain, typed little endian values, u64 big endian item count",
                  "cases": preimages}


def dummy_reference(hashing, owner_reference):
    state, rounds = [0] * 25, []
    for index, constant in enumerate(hashing.ROUND_CONSTANTS):
        before = state_bytes(state)
        state = hashing.permutation(state, constant)
        assert state == owner_reference.permutation(lanes(before), owner_reference.ROUND_CONSTANTS[index])
        rounds.append({"round": index, "round_before_hex": before.hex(), "state_hex": state_bytes(state).hex()})
    return {"scope": "Independent raw Keccak zero-input permutation and final four-slot padding prefix",
            "preimage_hex": bytes(200).hex(), "rounds": rounds,
            "final_physical_row": [{"position": logical_position(4092 + slot),
                                    **rounds[12 + slot]} for slot in range(4)]}


def outputs(repository):
    hashing = module("key_slots_manual_hash", repository / "research/hash-proofs/reference_vectors.py")
    owner_reference = module("key_slots_owner_hash", repository / "research/owner-bindings/reference_vectors.py")
    verifier = module("key_slots_signature_decoder", repository / "research/signatures/verify_reference.py")
    packing = module("key_slots_window_decoder", repository / "research/coefficient-constraints/packing_vectors.py")
    source = json.loads((repository / "research/signatures/synthetic_authorization.json").read_bytes())
    canonical_signature = bytes.fromhex(source["signature_hex"])
    keys = source_keys(repository)
    records = {}
    for name, key in keys.items():
        t1 = decode_t1(key)
        _, full_t1, _, _, _ = verifier.decode(key, canonical_signature)
        assert t1 == full_t1
        windows = []
        for event in range(256):
            start = 32 + event * 10
            raw = key[start:start + 10]
            decoded = packing.t1_decode(raw[:5]) + packing.t1_decode(raw[5:])
            polynomial, offset = divmod(event, 32)
            assert decoded == t1[polynomial][offset * 8:offset * 8 + 8]
            windows.append({"event": event, "source_start": start, "source_end_exclusive": start + 10,
                            "bytes_hex": raw.hex(), "polynomial": polynomial,
                            "first_coefficient": offset * 8, "decoded": decoded})
        sponges, rounds, digests, padded_records = [], [], {}, {}
        for kind, mode, rate, count, stage_offset in [("owner", 1, 72, 37, 0), ("tr", 3, 136, 20, 37)]:
            digest, padded, stages, round_records = hashing.sponge(key, mode, 64, record=True)
            expected = hashlib.sha3_512(key).digest() if kind == "owner" else hashlib.shake_256(key).digest(64)
            assert digest == expected and len(stages) == count and len(round_records) == count * 24
            if kind == "owner":
                assert padded == key + bytes([6]) + bytes(70) + bytes([128])
                other_digest, other_stages, other_rounds = owner_reference.sponge(key, record=True)
                assert other_digest == digest and len(other_stages) == 37 and len(other_rounds) == 888
                for left, right in zip(stages, other_stages):
                    for field in ["input_hex", "state_before_hex", "state_absorbed_hex", "state_after_hex"]:
                        assert left[field] == right[field]
                assert [item["state_hex"] for item in round_records] == [item["state_hex"] for item in other_rounds]
            else:
                assert padded == key + bytes([31]) + bytes(126) + bytes([128])
            digests[kind] = digest.hex()
            padded_records[kind] = padded.hex()
            for block, stage in enumerate(stages):
                relative_stage = stage_offset + block
                global_start = relative_stage * 24
                before = bytes.fromhex(stage["state_before_hex"])
                block_bytes = bytes.fromhex(stage["input_hex"])
                absorbed = bytearray(before)
                for index, value in enumerate(block_bytes):
                    absorbed[index] ^= value
                assert absorbed.hex() == stage["state_absorbed_hex"]
                assert absorbed[rate:] == before[rate:]
                if block == 0:
                    assert before == bytes(200)
                else:
                    assert before.hex() == stages[block - 1]["state_after_hex"]
                sponges.append({"kind": kind, "block": block, "stage": relative_stage, "rate": rate,
                                "capacity_bytes": 200 - rate, "input_hex": stage["input_hex"],
                                "state_before_hex": stage["state_before_hex"],
                                "state_absorbed_hex": stage["state_absorbed_hex"],
                                "state_after_hex": stage["state_after_hex"],
                                "source_start": min(block * rate, KEY_BYTES),
                                "source_count": min(rate, max(KEY_BYTES - block * rate, 0)),
                                "first_physical_row_in_key": global_start // 4,
                                "last_physical_row_in_key": (global_start + 23) // 4})
                round_before = bytes(absorbed)
                for round_index in range(24):
                    logical = global_start + round_index
                    recorded = round_records[block * 24 + round_index]
                    after = bytes.fromhex(recorded["state_hex"])
                    independent = owner_reference.permutation(lanes(round_before), owner_reference.ROUND_CONSTANTS[round_index])
                    assert state_bytes(independent) == after
                    rounds.append({"kind": kind, "block": block, "stage": relative_stage,
                                   "round": round_index, "logical_round_in_key": logical,
                                   "physical_row_in_key": logical // 4, "slot": logical % 4,
                                   "preimage_hex": stage["state_absorbed_hex"],
                                   "round_before_hex": round_before.hex(), "state_hex": after.hex()})
                    round_before = after
                assert round_before.hex() == stage["state_after_hex"]
        assert len(sponges) == 57 and len(rounds) == 1368 and len(windows) == 256
        assert sponges[36]["source_count"] == 0 and sponges[56]["source_count"] == 8
        records[name] = {"key_hex": key.hex(), "rho_hex": key[:32].hex(), "t1": t1,
                         "owner_hex": digests["owner"], "tr_hex": digests["tr"],
                         "padded_owner_hex": padded_records["owner"], "padded_tr_hex": padded_records["tr"],
                         "t1_windows": windows, "sponges": sponges, "rounds": rounds}

    pair_specs = [("retained_distinct_slots", "retained_a", "retained_b"),
                  ("retained_equal_a_slots", "retained_a", "retained_a"),
                  ("complete_slot_permutation", "retained_b", "retained_a"),
                  ("retained_equal_b_slots", "retained_b", "retained_b"),
                  ("ten_bit_zero_and_maximum", "t1_all_zero", "t1_all_1023"),
                  ("endpoint_and_represented_joined_keys", "t1_alternating_endpoints", "represented_rho_a_tail_b")]
    for name in list(keys)[5:]:
        pair_specs.append(("slot0_" + name, name, "retained_b"))
    cases = []
    for name, left, right in pair_specs:
        ids = [left, right]
        cases.append({"name": name, "key_ids": ids, "keys_hex": [records[i]["key_hex"] for i in ids],
                      "rho_hex": [records[i]["rho_hex"] for i in ids],
                      "owner_hex": [records[i]["owner_hex"] for i in ids],
                      "tr_hex": [records[i]["tr_hex"] for i in ids], "t1": [records[i]["t1"] for i in ids],
                      "valid_key_encoding_relation": True, "full_authorization_claim": False})
    assert len(cases) == 14

    logical = [logical_position(index) for index in range(HEIGHT * ROUND_SLOTS)]
    assert sum(item["meaningful"] for item in logical) == 2736
    assert sum(item["intra_transition"] for item in logical) == 3072
    assert sum(item["outer_transition"] for item in logical) == 1023
    assert logical[-1]["permutation"] == 170 and logical[-1]["round"] == 15
    assert [item["round"] for item in logical[-4:]] == [12, 13, 14, 15]
    blocks, decode_windows = [], []
    for slot in range(2):
        for stage in range(57):
            kind, rate, block = ("owner", 72, stage) if stage < 37 else ("tr", 136, stage - 37)
            first_row = slot * ROWS_PER_KEY + stage * 6
            last_row = first_row + 5
            blocks.append({"input_slot": slot, "stage_in_key": stage, "kind": kind,
                           "block": block, "global_permutation": slot * 57 + stage, "rate": rate,
                           "first_row": first_row, "last_row": last_row,
                           "source_start": min(block * rate, KEY_BYTES),
                           "source_count": min(rate, max(KEY_BYTES - block * rate, 0)),
                           "fresh_hash_initialization": stage in [0, 37],
                           "last_hash_block": stage in [36, 56]})
        for event in range(256):
            row = slot * ROWS_PER_KEY + event
            decode_windows.append({"input_slot": slot, "event": event, "physical_row": row,
                                   "write_available_row": row + 1, "source_start": 32 + event * 10,
                                   "source_end_exclusive": 42 + event * 10,
                                   "first_t1_index": event * 8, "decoded_count": 8,
                                   "polynomial": event // 32})
    lifetime = {"scope": "Fixed source and private result lifetimes, not host key equality tests",
                "height": 1024, "physical_slots": 4, "rows_per_key": 342,
                "key_bank": {"slot0_rows": [0, 341], "slot1_rows": [342, 1023],
                             "only_reload_transition": [341, 342]},
                "results": [{"input_slot": slot, "initialized_zero_row": 0,
                             "rho_write_transition": [slot * 342, slot * 342 + 1],
                             "owner_write_transition": [slot * 342 + 221, slot * 342 + 222],
                             "tr_write_transition": [slot * 342 + 341, slot * 342 + 342],
                             "t1_event_rows": [slot * 342, slot * 342 + 255],
                             "t1_final_write_transition": [slot * 342 + 255, slot * 342 + 256],
                             "retained_through_row": 1023} for slot in range(2)],
                "terminal_first_row": 684,
                "initialization_boundaries": [logical_position(i) for i in [0, 887, 888, 1367, 1368, 2255, 2256, 2735, 2736]],
                "final_logical_positions": logical[-4:]}

    def faulty_hash(name, key_name, kind, change, initial=None):
        key = keys[key_name]
        rate, mode, expected_count = (72, 1, 37) if kind == "owner" else (136, 3, 20)
        suffix = 6 if kind == "owner" else 31
        padded = hashing.padded_message(key, rate, suffix)
        state = lanes(bytes(200) if initial is None else initial)
        stages, selected_rounds = [], []
        for block, start in enumerate(range(0, len(padded), rate)):
            before = state_bytes(state)
            message = bytearray(padded[start:start + rate])
            state_before_absorb = bytearray(before)
            replace_rate = change(block, state_before_absorb, message)
            absorbed = bytearray(state_before_absorb)
            for index, value in enumerate(message):
                absorbed[index] = value if replace_rate else absorbed[index] ^ value
            state = lanes(absorbed)
            is_target = before != bytes(state_before_absorb) or bytes(message) != padded[start:start + rate] or replace_rate or (block == 0 and initial is not None)
            for round_index, constant in enumerate(hashing.ROUND_CONSTANTS):
                round_before = state_bytes(state)
                state = hashing.permutation(state, constant)
                if is_target:
                    selected_rounds.append({"block": block, "round": round_index,
                                            "round_before_hex": round_before.hex(), "state_hex": state_bytes(state).hex()})
            stages.append({"block": block, "input_hex": bytes(message).hex(),
                           "state_before_hex": before.hex(), "supplied_state_before_hex": bytes(state_before_absorb).hex(),
                           "state_absorbed_hex": bytes(absorbed).hex(), "state_after_hex": state_bytes(state).hex()})
        assert len(stages) == expected_count
        wrong_digest = state_bytes(state)[:64].hex()
        assert wrong_digest != records[key_name][kind + "_hex"]
        return {"name": name, "key_id": key_name, "kind": kind,
                "correct_digest_hex": records[key_name][kind + "_hex"], "supplied_digest_hex": wrong_digest,
                "sponges": stages, "target_rounds": selected_rounds,
                "same_key_hash_relation_valid": False,
                "classification": "Reject required: local permutations are real but source, absorption or initialization is false",
                "alternative_key_preimage_claim": False}

    def unchanged(block, state, message):
        return False

    def drop_capacity(rate):
        def change(block, state, message):
            if block == 1:
                state[rate:] = bytes(200 - rate)
            return False
        return change

    def replace_rate(block, state, message):
        return block == 1

    def wrong_owner_padding(block, state, message):
        if block == 36:
            assert message[0] == 6 and message[-1] == 128
            message[-1] = 0
        return False

    def wrong_tr_padding(block, state, message):
        if block == 19:
            assert message[8] == 31 and message[-1] == 128
            message[8] = 6
        return False

    hostile_hashes = [
        faulty_hash("owner_capacity_reset_block1", "retained_a", "owner", drop_capacity(72)),
        faulty_hash("tr_capacity_reset_block1", "retained_a", "tr", drop_capacity(136)),
        faulty_hash("owner_rate_replacement_instead_of_xor", "retained_a", "owner", replace_rate),
        faulty_hash("tr_rate_replacement_instead_of_xor", "retained_a", "tr", replace_rate),
        faulty_hash("owner_to_tr_missing_fresh_initialization", "retained_a", "tr", unchanged,
                    bytes.fromhex(records["retained_a"]["sponges"][36]["state_after_hex"])),
        faulty_hash("slot0_tr_to_slot1_owner_missing_fresh_initialization", "retained_b", "owner", unchanged,
                    bytes.fromhex(records["retained_a"]["sponges"][56]["state_after_hex"])),
        faulty_hash("owner_full_padding_block_missing_terminal_bit", "retained_a", "owner", wrong_owner_padding),
        faulty_hash("tr_last_tail_block_wrong_suffix", "retained_a", "tr", wrong_tr_padding),
    ]
    zero_owner_without_padding = records["retained_a"]["sponges"][35]["state_after_hex"][:128]
    assert zero_owner_without_padding != records["retained_a"]["owner_hex"]
    mixed_t1 = [row[:] for row in records["retained_a"]["t1"]]
    for event in range(222, 256):
        polynomial, event_in_poly = divmod(event, 32)
        start = event_in_poly * 8
        mixed_t1[polynomial][start:start + 8] = records["retained_b"]["t1"][polynomial][start:start + 8]
    assert mixed_t1 != records["retained_a"]["t1"]
    wrong_bindings = [
        {"name": "owner_from_other_slot", "target_slot": 0, "field": "owner", "wrong_source": "retained_b",
         "classification": "Reject with held keyA: copying a real ownerB hash is not same source linkage"},
        {"name": "tr_from_other_slot", "target_slot": 0, "field": "tr", "wrong_source": "retained_b",
         "classification": "Reject with held keyA: a real trB cannot replace trA"},
        {"name": "rho_from_other_slot", "target_slot": 0, "field": "rho", "wrong_source": "retained_b",
         "classification": "Reject with held keyA: rho must come from exact bytes0through31"},
        {"name": "t1_from_other_slot", "target_slot": 0, "field": "t1", "wrong_source": "retained_b",
         "classification": "Reject with held keyA: correctly decoded coefficients for B do not bind A"},
        {"name": "early_key_reload_at_owner_to_tr", "forbidden_transition": [221, 222],
         "owner_hex": records["retained_a"]["owner_hex"], "tr_hex": records["retained_b"]["tr_hex"],
         "rho_hex": records["retained_a"]["rho_hex"], "t1": mixed_t1,
         "classification": "Reject: keybank must hold until341, including remaining t1 and tr consumers"},
        {"name": "retained_slot0_owner_changed_during_slot1", "forbidden_row": 342,
         "supplied_owner_hex": records["retained_b"]["owner_hex"],
         "classification": "Reject: owner0 must hold after its write at222throughrow1023"},
        {"name": "omitted_owner_exact_rate_padding_block", "wrong_terminal_row": 216,
         "supplied_owner_hex": zero_owner_without_padding,
         "classification": "Reject:2592bytes exactly fill36blocks and require a37th full padding permutation"},
        {"name": "t1_output_equal_1024", "key_id": "t1_all_zero", "input_slot": 0, "coefficient": 0, "supplied": 1024,
         "classification": "Reject: output must be the same constrained10bit value rather than a free scalar"},
        {"name": "key_byte_pair_field_alias", "input_slot": 0,
         "scalar_updates": [{"byte": 0, "delta": 256}, {"byte": 1, "delta": -1}],
         "classification": "Reject: each held byte must bind separately to eight Boolean source bits"},
    ]
    hostile = {"scope": "Required rejection classifications and independent computations, not actual AIR or proof verdicts",
               "baseline_pair": "retained_distinct_slots", "hash_faults": hostile_hashes,
               "source_and_lifetime_faults": wrong_bindings,
               "equal_key_scope": "Equal keys in two ordered slots are valid. No inequality predicate or deduplication shortcut is permitted",
               "represented_join_scope": "A complete represented rhoA/tailB encoding is a valid limited key relation, not an authorized owner key"}
    source_names = ["research/signatures/synthetic_authorization.json", "research/signatures/verify_reference.py",
                    "research/hash-proofs/reference_vectors.py", "research/owner-bindings/reference_vectors.py",
                    "research/coefficient-constraints/packing_vectors.py"]
    adapter_rows, adapter_preimages = hash_adapters(hashing)
    dummy = dummy_reference(hashing, owner_reference)
    record = {"public_input_revision": PUBLIC_INPUT_REVISION,
              "previous_input_revision": PREVIOUS_INPUT_REVISION,
              "revision_scope": "The unchanged retained public inputs and mathematical references exist at both revisions. No public revision of this new key source implementation is asserted.",
              "scope": "Independent standard-library key decoding and hash reference calculations without importing Rust trace or witness builders",
              "source_sha256": {name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in source_names},
              "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "unique_key_encodings": len(records), "ordered_two_slot_cases": len(cases),
              "t1_coefficients_per_key": 2048, "sponges_per_key": 57, "rounds_per_key": 1368,
              "full_sponge_records": len(records) * 57, "full_round_records": len(records) * 1368,
              "logical_schedule_rows": 4096, "hash_faults": len(hostile_hashes),
              "source_lifetime_faults": len(wrong_bindings),
              "independent_zero_dummy_rounds": len(dummy["rounds"]),
              "compiler_run": False, "prover_run": False, "air_acceptance_claim": False,
              "adapter_profile": PROOF_PROFILE, "adapter_sha3_goldens": len(adapter_rows),
              "interface_requirement": "Only an opaque 64 byte context may be public. All key-derived outputs here are synthetic reference expectations for private banks, not public protocol tags"}
    corpus = {"format": "thorum.private-key-slots.references.v1",
              "scope": "Two private input slot key source, hashes and canonical t1 decoding without note ownership or full signature authorization",
              "key_records": records, "cases": cases}
    profile = {"scope": "Two ordered private key sources, canonical t1 decoding and retained private hashes without note ownership, signature verification or transaction authorization",
               "profile": PROOF_PROFILE, "height": 1024, "width": 20168, "actual_degree": 4,
               "public_values": 64, "public_scope": "Opaque context only, without an AIR canonical transaction mapping",
               "key_bytes": KEY_BYTES, "input_slots": 2, "keccak_rounds_per_row": 4,
               "meaningful_permutations": 114, "owner_permutations_per_key": 37,
               "tr_permutations_per_key": 20, "t1_coefficients_per_key": T1_COUNT,
               "t1_window_events_per_key": 256, "rows_per_key": ROWS_PER_KEY,
               "terminal_first_row": 684, "stored_degree_bits": 11, "quotient_chunks": 8,
               "fri_rounds": 11, "queries": 64, "log_blowup": 3, "extension_degree": 4,
               "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
               "closed_transport": {"bytes": 25165824, "tokens": 2000000, "items": 32768,
                                    "depth": 24, "string_bytes": 64, "integer_digits": 20,
                                    "merkle_siblings": 896},
               "analytical_arrays": {"raw_trace_bytes": 4 * 1024 * 20168,
                                     "randomized_trace_bytes": 8 * 1024 * (20168 + 4),
                                     "main_lde_payload_bytes": 64 * 1024 * (20168 + 4),
                                     "scope": "Array dimensions only, without a process memory or runtime measurement"}}
    js = lambda value: (json.dumps(value, separators=(",", ":")) + "\n").encode()
    return {"vectors.json": js(corpus), "logical_round_map.csv": csv_bytes(logical),
            "block_map.csv": csv_bytes(blocks), "t1_window_map.csv": csv_bytes(decode_windows),
            "lifetimes.json": js(lifetime), "hostile_cases.json": js(hostile),
            "hash_vectors.csv": csv_bytes(adapter_rows), "hash_preimages.json": js(adapter_preimages),
            "dummy_rounds.json": js(dummy), "profile.json": (json.dumps(profile, indent=2) + "\n").encode(),
            "source_record.json": (json.dumps(record, indent=2) + "\n").encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=DEFAULT_REPOSITORY,
                        help="Override the repository root while staging outside research/key-source")
    arguments = parser.parse_args()
    for name, content in outputs(arguments.repository_root.resolve()).items():
        target = BASE / name
        if arguments.check:
            assert target.read_bytes() == content, name
        else:
            target.write_bytes(content)
    print("Private key source references match: 13 encodings, 14 ordered pairs, 741 full sponges, 17784 rounds, 8 hash faults, 9 source/lifetime obligations and 3 full SHA3 adapter goldens")


if __name__ == "__main__":
    main()
