#!/usr/bin/env python3
"""Independent complete reconstructed row math, without Rust trace inputs."""

import argparse
import copy
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPOSITORY = ROOT
Q, N, INV256 = 8380417, 256, 8347681
STREAM_SOURCE = BASE / "stream_math.py"
STREAM_SHA256 = "6ab75a2334e2993b30d325942acf5dc1ae51e3be4fb144dee94850a2edabe9a6"
PROFILE = "thorum.reconstructed-row-proof-lab.mldsa87.private-row.four-rounds.serial.p3-0.8.0.v1"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def valid_input(values):
    return (len(bytes.fromhex(values["rho_hex"])) == 32 and 0 <= values["row"] < 8
            and len(values["zhat"]) == 7 and all(len(poly) == N for poly in values["zhat"])
            and all(0 <= value < Q for poly in values["zhat"] for value in poly)
            and len(values["t1"]) == len(values["chat"]) == len(values["hint"]) == N
            and all(0 <= value <= 1023 for value in values["t1"])
            and all(0 <= value < Q for value in values["chat"])
            and all(value in [0, 1] for value in values["hint"]))


def selected_continuation_fault(repository, hashing, verify, transform, stream_ref, retained, native):
    """Rebuild one false full-state join using only retained public inputs."""
    selected = json.loads((repository / "research/crypto/vectors/selected.json").read_bytes())
    case = retained[0]
    rho = bytes.fromhex(case["rho_hex"])
    row, column = case["row"], case["column"]
    assert (row, column) == (0, 0)
    signatures = []
    for item in selected["cases"]:
        if item["id"].startswith("ml_dsa_87_verify_"):
            signatures.append((bytes.fromhex(item["input"]["pk"]),
                               bytes.fromhex(item["input"]["signature"])))
    for item in [native, *native["alternate_signatures"]]:
        signatures.append((bytes.fromhex(item["public_key_hex"]), bytes.fromhex(item["signature_hex"])))
    key, signature = next((key, signature) for key, signature in signatures if key[:32] == rho)
    polynomial = verify.decode(key, signature)[3][column]
    zhat = verify.ntt(polynomial)
    assert zhat == transform.direct_forward([value % Q for value in polynomial])
    message = rho + bytes([column, row])
    output, _, base_states, base_rounds = hashing.sponge(message, 2, 1008, record=True)
    assert output == hashlib.shake_128(message).digest(1008)
    assert output.hex() == case["stream_hex"]
    original = stream_ref.stream_model(output, zhat, [0] * N)
    assert original["supported_complete"]
    assert original["coefficients"] == case["coefficients"]
    assert original["consumed_bytes"] == case["consumed_bytes"] <= 840
    supplied = bytearray.fromhex(base_states[4]["state_after_hex"])
    supplied[168] ^= 1
    changed, states, rounds = stream_ref.changed_continuation(hashing, base_states, base_rounds, 5, bytes(supplied))
    model = stream_ref.stream_model(changed, zhat, [0] * N)
    assert changed[:840] == output[:840] and changed != output
    assert model["supported_complete"]
    for field in ["coefficients", "accumulator", "consumed_bytes"]:
        assert model[field] == original[field]
    return {"name": "unused_sixth_output_block_capacity_change", "seed_claim": False,
            "broken_join_stage": 5, "rho_hex": rho.hex(), "row": row, "column": column,
            "stream_hex": changed.hex(), "sponge_blocks": states, "round_states": rounds,
            "supported_complete": model["supported_complete"],
            "coefficients": model["coefficients"], "accumulator": model["accumulator"],
            "preserved_output_prefix_bytes": 840,
            "required_classification": "Reject the one false full-state join despite real local permutations and consistent streaming arithmetic"}


def proof_hash_goldens():
    """Full SHA3 digests and word layouts, independently framed in Python."""
    payloads = {
        "leaf": ([0, 1, 2013265920, 0x12345678], 4),
        "node": ([0, 1, 2**64 - 1] + list(range(13)), 8),
        "transcript": (list(range(64)), 1),
    }
    table = io.StringIO(newline="")
    writer = csv.writer(table, lineterminator="\n")
    writer.writerow(["kind", "domain", "payload_hex", "digest_words"])
    records = []
    for role, (values, width) in payloads.items():
        domain = f"thorum.reconstructed-row-proof-lab.{role}.v1".encode()
        payload = b"".join(value.to_bytes(width, "little") for value in values)
        framed = len(domain).to_bytes(4, "big") + domain + payload + len(values).to_bytes(8, "big")
        digest = hashlib.sha3_512(framed).digest()
        words = [int.from_bytes(digest[start:start + 8], "little") for start in range(0, 64, 8)]
        assert b"".join(value.to_bytes(8, "little") for value in words) == digest
        writer.writerow([role, domain.decode(), payload.hex(), ":".join(map(str, words))])
        records.append({"role": role, "domain": domain.decode(), "payload_hex": payload.hex(),
                        "element_bytes": width, "element_count": len(values), "preimage_hex": framed.hex(),
                        "preimage_bytes": len(framed), "sha3_512_hex": digest.hex(), "u64le_words": words})
    return table.getvalue().encode(), {"scope": "Full independent hash adapter reference math, not a proof verifier",
                                      "vectors": records}


def fixed_profile():
    return {"profile": PROFILE, "height": 1024, "width": 24794, "actual_degree": 3,
            "public_values": 65, "public_scope": "Row 0 through 7 and opaque context only, without key/signature/note/T binding",
            "private_output_bytes": 128, "keccak_rounds_per_row": 4, "matrix_columns": 7,
            "matrix_output_blocks": 6, "matrix_stream_bytes": 1008, "candidate_events_per_column": 336,
            "candidate_lanes": 8, "completion_count": 256, "matrix_end": 294,
            "forward_end": 422, "point_end": 454, "inverse_end": 582,
            "normalize_end": 614, "hint_end": 646, "stored_degree_bits": 11,
            "quotient_chunks": 8, "fri_rounds": 11, "queries": 64, "log_blowup": 3,
            "extension_degree": 4, "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
            "hiding_main_mmcs": True, "hiding_extension_mmcs": True, "independent_os_rngs": 2,
            "closed_transport": {"bytes": 33554432, "tokens": 3000000, "items": 32768,
                                 "depth": 24, "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 896},
            "hash_domains": [f"thorum.reconstructed-row-proof-lab.{role}.v1" for role in ["leaf", "node", "transcript"]],
            "analytical_arrays": {"raw_trace_bytes": 101556224, "randomized_trace_bytes": 203145216,
                                  "main_lde_payload_bytes": 1625161728},
            "scope": "Fixed conditional component profile. No actual proof, complete signature or security verdict is established by reference generation"}


def outputs(repository):
    assert hashlib.sha256(STREAM_SOURCE.read_bytes()).hexdigest() == STREAM_SHA256
    stream_ref = module("row_independent_stream_math", STREAM_SOURCE)
    verify = module("row_full_signature_math", repository / "research/signatures/verify_reference.py")
    transform = module("row_direct_transform_math", repository / "research/ntt-proofs/reference_vectors.py")
    rounding = module("row_use_hint_math", repository / "research/coefficient-constraints/reference_vectors.py")
    hashing = module("row_manual_sponge_math", repository / "research/hash-proofs/reference_vectors.py")
    packing = module("row_key_packing_math", repository / "research/coefficient-constraints/packing_vectors.py")
    native = json.loads((repository / "research/signatures/synthetic_authorization.json").read_bytes())
    retained = json.loads((repository / "research/matrix-sampling/vectors.json").read_bytes())["genuine"]
    retained_by_seed = {(case["rho_hex"], case["row"], case["column"]): case for case in retained}
    sources, matrix_records, inputs = {}, {}, {}
    records = [("a", native), ("b", next(case for case in native["alternate_signatures"] if case["name"] == "different_owner"))]
    for source_id, source in records:
        key, signature, message, context = [bytes.fromhex(source[field]) for field in
                                            ["public_key_hex", "signature_hex", "message_hex", "context_hex"]]
        result = verify.verify(key, signature, message, context)
        assert result["valid"]
        rho, t1, challenge, z, hints = verify.decode(key, signature)
        c, c_cursor = verify.challenge_poly(challenge)
        chat = verify.ntt(c)
        zhat = [verify.ntt(poly) for poly in z]
        assert chat == transform.direct_forward([value % Q for value in c])
        assert all(left == transform.direct_forward([value % Q for value in right]) for left, right in zip(zhat, z))
        sources[source_id] = {"retained_name": "synthetic_authorization" if source_id == "a" else "different_owner",
                              "source_file": "research/signatures/synthetic_authorization.json",
                              "key_sha256": hashlib.sha256(key).hexdigest(),
                              "signature_sha256": hashlib.sha256(signature).hexdigest(),
                              "rho_hex": rho.hex(), "challenge_seed_hex": challenge.hex(),
                              "challenge": c, "challenge_normal": [v % Q for v in c], "chat": chat,
                              "challenge_cursor": c_cursor, "z_signed": z, "zhat": zhat,
                              "full_reference_signature_valid": True,
                              "scope": "Independent retained full signature oracle result, not an actual signature proof"}
        for row in [0, 7]:
            name = f"{source_id}_row_{row}"
            inputs[name] = {"rho_hex": rho.hex(), "row": row, "zhat": zhat,
                            "t1": t1[row], "chat": chat, "hint": hints[row]}
            assert valid_input(inputs[name])
            # Independent five-byte key windows bind the exact selected t1 row.
            for group in range(64):
                start = 32 + row * 320 + group * 5
                assert packing.t1_decode(key[start:start + 5]) == t1[row][group * 4:group * 4 + 4]
            for column in range(7):
                matrix_id = f"{source_id}_row_{row}_column_{column}"
                expected = retained_by_seed[(rho.hex(), row, column)]
                preimage = rho + bytes([column, row])
                output, padded, sponges, rounds = hashing.sponge(preimage, 2, 1008, record=True)
                assert output == hashlib.shake_128(preimage).digest(1008)
                assert output.hex() == expected["stream_hex"]
                assert len(sponges) == 6 and len(rounds) == 144
                projection = [{"before_hex": state["state_absorbed_hex"], "after_hex": state["state_after_hex"]} for state in sponges]
                assert projection == expected["sponge_blocks"]
                assert padded == preimage + bytes([31]) + bytes(132) + bytes([128])
                ahat, cursor = verify.matrix_poly(rho, row, column)
                assert ahat == expected["coefficients"] and cursor["bytes_consumed"] == expected["consumed_bytes"]
                model = stream_ref.stream_model(output, [0] * N, [0] * N)
                assert model["supported_complete"] and model["coefficients"] == ahat
                events = [event for physical in model["rows"] for event in physical["events"]]
                item = {"matrix_id": matrix_id, "source_id": source_id, "rho_hex": rho.hex(),
                        "row": row, "column": column, "retained_case": expected["name"],
                        "message_hex": preimage.hex(), "padded_message_hex": padded.hex(),
                        "stream_hex": output.hex(), "ahat": ahat, "consumed_bytes": model["consumed_bytes"],
                        "sponges": sponges,
                        "sampling_events": [{field: event[field] for field in [
                            "event", "program", "lane", "active", "stream_candidate24", "candidate24", "candidate23", "take",
                            "count_before", "count_after", "cursor_before", "cursor_after", "index"]} for event in events]}
                if matrix_id in ["a_row_0_column_0", "b_row_7_column_6"]:
                    item["round_states"] = rounds
                matrix_records[matrix_id] = item
            inputs[name]["matrix_ids"] = [f"{source_id}_row_{row}_column_{column}" for column in range(7)]
            inputs[name]["expected_reconstructed"] = result["reconstructed_coefficients"][row]
            inputs[name]["expected_packed_hex"] = result["w1_encoded_hex"][row * 256:(row + 1) * 256]

    def row_math(values, overrides=None, full=False):
        assert valid_input(values)
        overrides = overrides or {}
        accumulator, columns = [0] * N, []
        for column, matrix_id in enumerate(values["matrix_ids"]):
            expected_matrix = matrix_records[matrix_id]
            assert (expected_matrix["rho_hex"], expected_matrix["row"], expected_matrix["column"]) == (values["rho_hex"], values["row"], column)
            selected_id = overrides.get("matrix_ids", {}).get(column, matrix_id)
            matrix = matrix_records[selected_id]
            ahat = overrides.get("ahat", {}).get(column, matrix["ahat"])
            selected_z = overrides.get("zhat_reads", {}).get(column, values["zhat"][column])
            before, products, quotients = list(accumulator), [], []
            for index, (x, y) in enumerate(zip(ahat, selected_z)):
                quotient, product, _, _ = stream_ref.multiplication(x, y)
                assert transform.multiplication(x, y)[:2] == (product, quotient)
                products.append(product)
                quotients.append(quotient)
                accumulator[index] = (accumulator[index] + product) % Q
            item = {"column": column, "expected_matrix_id": matrix_id, "selected_matrix_id": selected_id,
                    "ahat": ahat, "selected_zhat": selected_z, "accumulator_before": before,
                    "products": products, "product_quotients": quotients, "accumulator_after": list(accumulator)}
            if full:
                assert selected_id == matrix_id and ahat == matrix["ahat"]
                model = stream_ref.stream_model(bytes.fromhex(matrix["stream_hex"]), selected_z, before)
                assert model["accumulator"] == accumulator and model["coefficients"] == ahat
                item["events"] = [event for physical in model["rows"] for event in physical["events"]]
                for event in item["events"]:
                    event["global_row"] = 42 * column + event["program"]
                item["row_counts"] = [physical["counts"] for physical in model["rows"]]
                item["row_cursors"] = [physical["cursors"] for physical in model["rows"]]
            columns.append(item)
        shifted = [8192 * value for value in values["t1"]]
        assert all(0 <= value < Q for value in shifted)
        t1_bytes = sum(value << (10 * i) for i, value in enumerate(values["t1"])).to_bytes(320, "little")
        load_windows = []
        for event in range(32):
            raw = t1_bytes[10 * event:10 * event + 10]
            decoded = packing.t1_decode(raw[:5]) + packing.t1_decode(raw[5:])
            assert decoded == values["t1"][event * 8:event * 8 + 8]
            load_windows.append({"event": event, "physical_row": event, "write_available_row": event + 1,
                                 "first_input_index": 8 * event, "bytes_hex": raw.hex(), "decoded": decoded,
                                 "scaled": [8192 * value for value in decoded]})
        forward_input = overrides.get("forward_input", shifted)
        t1hat, forward_stages, forward_ops, _ = transform.transform(forward_input, 1, record=full)
        assert t1hat == verify.ntt(forward_input) == transform.direct_forward(forward_input)
        for event, operation in enumerate(forward_ops):
            operation.update({"physical_row": 294 + event // 8, "lane": event % 8})
        product_t1hat = overrides.get("product_t1hat", t1hat)
        chat_read = overrides.get("chat_read", values["chat"])
        subtractions, reduced = [], []
        for index, (a, c, t) in enumerate(zip(accumulator, chat_read, product_t1hat)):
            quotient, product, carry0, carry1 = stream_ref.multiplication(c, t)
            borrow = int(a < product)
            value = a - product + borrow * Q
            assert 0 <= value < Q
            reduced.append(value)
            subtractions.append({"index": index, "accumulator": a, "chat_read": c, "t1hat_read": t,
                                 "quotient": quotient, "product": product, "carry0": carry0, "carry1": carry1,
                                 "borrow": borrow, "reduced": value,
                                 "physical_row": 422 + index // 8, "lane": index % 8})
        inverse_input = overrides.get("inverse_input", reduced)
        polynomial, inverse_stages, inverse_ops, _ = transform.transform(inverse_input, 2, record=full)
        assert polynomial == verify.inverse_ntt(inverse_input) == transform.direct_inverse(inverse_input)
        for event, operation in enumerate(inverse_ops):
            operation.update({"physical_row": 454 + event // 8, "lane": event % 8})
        raw_inverse = inverse_stages[8]
        assert polynomial == [value * INV256 % Q for value in raw_inverse]
        hint_input = overrides.get("hint_input", polynomial)
        hint_read = overrides.get("hint_read", values["hint"])
        hint_records, w1 = [], []
        for index, (value, hint) in enumerate(zip(hint_input, hint_read)):
            result = rounding.reference(value, hint)
            assert verify.decompose(value) == (result["high"], result["low"])
            assert verify.use_hint(value, hint) == result["output"]
            hint_records.append({"index": index, "r": value, "hint_read": hint,
                                 "physical_row": 614 + index // 8, "lane": index % 8, **result})
            w1.append(result["output"])
        encoded = bytes(w1[2 * index] + 16 * w1[2 * index + 1] for index in range(128))
        assert encoded == verify.pack(w1, 4)
        packing_records = [{"byte": index, "low_index": 2 * index, "high_index": 2 * index + 1,
                            "low": w1[2 * index], "high": w1[2 * index + 1], "packed": encoded[index],
                            "producer_row": 614 + index // 4, "write_available_row": 615 + index // 4}
                           for index in range(128)]
        return {"matrix_columns": columns, "matrix_sum": accumulator, "t1_encoding_hex": t1_bytes.hex(),
                "t1_load_windows": load_windows, "t1_shifted": shifted,
                "t1_forward": {"input": forward_input, "output": t1hat,
                               "stages": forward_stages, "operations": forward_ops},
                "challenge_products_subtractions": subtractions, "subtraction_output": reduced,
                "inverse": {"input": inverse_input, "raw_butterfly_output": raw_inverse,
                            "normalization_factor": INV256, "output": polynomial,
                            "stages": inverse_stages, "operations": inverse_ops},
                "hint_input": hint_input, "hints": hint_records, "w1": w1,
                "packing": packing_records, "packed_w1_hex": encoded.hex()}

    cases, calculated = [], {}
    for name, values in inputs.items():
        row = row_math(values, full=True)
        assert row["inverse"]["output"] == values["expected_reconstructed"]
        assert row["packed_w1_hex"] == values["expected_packed_hex"]
        calculated[name] = row
        cases.append({"name": name, "category": "retained_valid_signature_row", "full_signature_source": name[0],
                      "statement": {"row": values["row"], "context_hex": bytes([0x71] * 64).hex()},
                      "input": {field: value for field, value in values.items() if not field.startswith("expected_")}, **row})
    original = inputs["a_row_0"]
    endpoint_specs = [
        ("zero_operands_zero_hints", [[0] * N for _ in range(7)], [0] * N, [0] * N, [0] * N),
        ("zero_operands_one_hints", [[0] * N for _ in range(7)], [0] * N, [0] * N, [1] * N),
        ("maximum_t1_and_operands", [[Q - 1] * N for _ in range(7)], [1023] * N, [Q - 1] * N, [i % 2 for i in range(N)]),
        ("alternating_t1_endpoints", [[Q - 1 if (i + j) % 2 else 0 for i in range(N)] for j in range(7)],
         [1023 if i % 2 else 0 for i in range(N)], [(17 * i + 1) % Q for i in range(N)], [1 - i % 2 for i in range(N)]),
    ]
    for name, zhat, t1, chat, hint in endpoint_specs:
        values = {"rho_hex": original["rho_hex"], "row": 0, "matrix_ids": original["matrix_ids"],
                  "zhat": zhat, "t1": t1, "chat": chat, "hint": hint}
        row = row_math(values, full=True)
        if name == "zero_operands_zero_hints":
            assert row["packed_w1_hex"] == bytes(128).hex()
        if name == "zero_operands_one_hints":
            assert row["packed_w1_hex"] == bytes([255] * 128).hex()
        if name == "maximum_t1_and_operands":
            assert row["t1_shifted"] == [Q - 1] * N
        cases.append({"name": name, "category": "valid_row_component_input_without_full_signature_claim",
                      "statement": {"row": 0, "context_hex": bytes([0x71] * 64).hex()}, "input": values, **row})
    assert len(cases) == 8

    faults = []
    def fault(name, overrides, broken_join, whole_operand_scope=None):
        row = row_math(original, overrides)
        faults.append({"name": name, "category": "false_join_with_real_downstream_integer_math",
                       "baseline_case": "a_row_0", "broken_join": broken_join,
                       "whole_operand_scope": whole_operand_scope,
                       "actual_air_or_proof_verdict": None, **row})
        return row

    fault("matrix_row7_window_in_public_row0", {"matrix_ids": {2: "a_row_7_column_2"}},
          "The third real SHAKE window is valid for row 7 but the expected public row remains zero")
    fault("matrix_column1_window_in_fixed_column0", {"matrix_ids": {0: "a_row_0_column_1"}},
          "A real column 1 stream cannot replace the fixed column zero stream")
    fault("matrix_other_rho_window", {"matrix_ids": {3: "b_row_0_column_3"}},
          "A complete real window from rho B is disconnected from the held same rho A")
    fault("extra_forward_transform_of_ahat", {"ahat": {0: transform.direct_forward(matrix_records["a_row_0_column_0"]["ahat"])}},
          "Sampled matrix residues already represent Ahat. An extra real NTT changes the candidate to multiplication join")
    changed_z = sources["b"]["zhat"][4]
    fault("zhat_consumer_from_other_source", {"zhat_reads": {4: changed_z}},
          "The selected canonical operand is not the held zhat column 4",
          "Replacing the entire private zhat column with this value is a valid different limited row input")
    fault("forward_t1_without_8192_shift", {"forward_input": original["t1"]},
          "The forward transform is real but its input is not the same canonical t1 multiplied by 8192")
    fault("forward_t1_from_other_row", {"forward_input": [8192 * value for value in inputs["a_row_7"]["t1"]]},
          "A real shifted t1 row 7 transform is disconnected from the held row zero key coefficients")
    permuted = [calculated["a_row_0"]["t1_forward"]["output"][transform.bit_reverse(i)] for i in range(N)]
    fault("t1hat_consumer_bit_reversal", {"product_t1hat": permuted},
          "A genuine forward transform output is consumed in the wrong NTT index order")
    rotated_chat = original["chat"][1:] + original["chat"][:1]
    fault("chat_consumer_rotated", {"chat_read": rotated_chat},
          "Each product must read the same held chat index",
          "A whole rotated private chat input is valid component input, without a challenge transform source claim")
    fault("inverse_from_other_row_subtraction", {"inverse_input": calculated["a_row_7"]["subtraction_output"]},
          "The inverse transform is real but does not consume this row's canonical subtraction output")
    fault("hint_before_inverse_normalization", {"hint_input": calculated["a_row_0"]["inverse"]["raw_butterfly_output"]},
          "Real inverse butterflies do not replace multiplication by inverse 256 before same-index UseHint")
    fault("hint_consumer_from_other_row", {"hint_read": inputs["a_row_7"]["hint"]},
          "The Boolean hint consumer reads a different row rather than the held input hint",
          "The complete different Boolean hint input is valid for this component, without global signature hint canonicality")
    baseline = calculated["a_row_0"]
    reverse = bytes(16 * baseline["w1"][2 * i] + baseline["w1"][2 * i + 1] for i in range(128))
    assert reverse.hex() != baseline["packed_w1_hex"]
    faults.append({"name": "packing_adjacent_nibbles_reversed", "category": "false_packing_source_join",
                   "baseline_case": "a_row_0", "w1": baseline["w1"], "supplied_packed_hex": reverse.hex(),
                   "expected_packed_hex": baseline["packed_w1_hex"], "actual_air_or_proof_verdict": None,
                   "local_scope": "All supplied bytes fit eight bits but odd/even four bit source positions are reversed"})
    alternatives = []
    for name, field, index, replacement in [
        ("whole_zhat_column_change", "zhat", 4, changed_z),
        ("whole_chat_change", "chat", None, rotated_chat),
        ("whole_hint_change", "hint", None, inputs["a_row_7"]["hint"]),
    ]:
        values = {key: value for key, value in original.items() if not key.startswith("expected_")}
        if index is None:
            values[field] = replacement
        else:
            values[field] = list(values[field]); values[field][index] = replacement
        rebuilt = row_math(values)
        counterpart = {"whole_zhat_column_change": "zhat_consumer_from_other_source",
                       "whole_chat_change": "chat_consumer_rotated",
                       "whole_hint_change": "hint_consumer_from_other_row"}[name]
        false_consumer = next(case for case in faults if case["name"] == counterpart)
        assert rebuilt["packed_w1_hex"] == false_consumer["packed_w1_hex"]
        alternatives.append({"name": name, "category": "valid_alternative_whole_private_input",
                             "same_math_output_as_false_consumer": counterpart,
                             "input": values, **rebuilt})
    invalid = [
        {"field": "row", "supplied": 8}, {"field": "rho_bytes", "supplied_length": 33},
        {"field": "zhat", "column": 0, "index": 0, "supplied": Q},
        {"field": "t1", "index": 0, "supplied": 1024},
        {"field": "chat", "index": 0, "supplied": Q},
        {"field": "hint", "index": 0, "supplied": 2},
        {"field": "w1", "index": 0, "supplied": 16},
        {"field": "packed_byte", "index": 0, "supplied": 256},
    ]
    for item in invalid[:6]:
        changed = copy.deepcopy(original)
        if item["field"] == "row": changed["row"] = item["supplied"]
        elif item["field"] == "rho_bytes": changed["rho_hex"] = bytes(33).hex()
        elif item["field"] == "zhat": changed["zhat"][0][0] = item["supplied"]
        else: changed[item["field"]][0] = item["supplied"]
        assert not valid_input(changed)
        item["reference_input_shape_valid"] = False
    assert invalid[6]["supplied"] >= 16 and invalid[7]["supplied"] >= 256

    injected = []
    fill = [(index * 65537 + 19) % Q for index in range(336)]
    for lane in range(8):
        candidates = [Q] * (73 + lane) + fill[:256]
        candidates += fill[:336 - len(candidates)]
        stream = b"".join(value.to_bytes(3, "little") for value in candidates)
        model = stream_ref.stream_model(stream, original["zhat"][0], [0] * N)
        assert model["supported_complete"] and model["completion_program"] == 41 and model["completion_lane"] == lane
        rebuilt = row_math(original, {"ahat": {0: model["coefficients"]}})
        assert rebuilt["matrix_columns"][0]["accumulator_after"] == model["accumulator"]
        injected.append({"name": f"column0_completion_at_program41_lane{lane}",
                         "category": "injected_supported_stream_and_real_downstream_math",
                         "seed_preimage_claim": False, "full_hash_join_claim": False,
                         "injected_column": 0, "stream_hex": stream.hex(),
                         "stream_ahat": model["coefficients"], "stream_accumulator": model["accumulator"],
                         "count": model["count"], "consumed_bytes": model["consumed_bytes"],
                         "completion_program": 41, "completion_lane": lane,
                         "events": [event for physical in model["rows"] for event in physical["events"]],
                         "row_counts": [physical["counts"] for physical in model["rows"]],
                         "row_cursors": [physical["cursors"] for physical in model["rows"]],
                         "next_column_boundary_row": 42, "next_column_initial_count": 0,
                         "next_column_accumulator": model["accumulator"], **rebuilt})
    unsupported = []
    for name, candidates in [
        ("all_rejected", [Q] * 336),
        ("only255_accepted", fill[:255] + [Q] * 81),
        ("completion_requires_event336", [Q] * 81 + fill[:255]),
    ]:
        stream = b"".join(value.to_bytes(3, "little") for value in candidates)
        model = stream_ref.stream_model(stream, original["zhat"][0], [0] * N)
        assert not model["supported_complete"] and model["count"] in [0, 255]
        unsupported.append({"name": name, "category": "injected_unsupported_capacity",
                            "seed_preimage_claim": False, "full_hash_join_claim": False,
                            "stream_hex": stream.hex(), "count": model["count"],
                            "consumed_bytes": model["consumed_bytes"],
                            "events": [event for physical in model["rows"] for event in physical["events"]],
                            "row_counts": [physical["counts"] for physical in model["rows"]],
                            "row_cursors": [physical["cursors"] for physical in model["rows"]],
                            "required_rejection": "No column transition or padding byte may complete a count below 256"})
    boundaries = []
    for value in sorted({0, 1, 261887, 261888, 261889, 523775, 523776, Q - 2, Q - 1}):
        for hint in [0, 1]:
            expected = rounding.reference(value, hint)
            assert verify.use_hint(value, hint) == expected["output"]
            boundaries.append({"r": value, "hint": hint, **expected})
    schedule = {"scope": "Fixed conditional row mathematical schedule, not a production ledger or signature verifier",
                "matrix_windows": [{"column": j, "first_row": 42 * j, "last_row": 42 * j + 41,
                                    "hash_rows": [42 * j, 42 * j + 35], "candidate_rows": 42,
                                    "candidate_lanes": 8, "permutations": 6,
                                    "meaningful_global_permutations": [7 * j, 7 * j + 5],
                                    "dummy_global_permutation": 7 * j + 6,
                                    "dummy_rows": [42 * j + 36, 42 * j + 41],
                                    "final_count_required": 256,
                                    "accumulator_available_row": 42 * (j + 1),
                                    "count_reset_transition": [42 * j + 41, 42 * (j + 1)] if j < 6 else None}
                                   for j in range(7)],
                "t1_ten_bit_input_load": [0, 31], "forward_ntt": [294, 421],
                "challenge_product_subtract": [422, 453], "inverse_butterflies": [454, 581],
                "normalization": [582, 613], "use_hint_pack": [614, 645], "output_available_row": 646,
                "forward_operation_lanes": 8, "inverse_operation_lanes": 8,
                "normalization_lanes": 8, "use_hint_lanes": 8,
                "output_scope": "Private 128 byte bank retained after its unique writes",
                "matrix_basis": "Sampled coefficients already represent Ahat, no extra matrix NTT",
                "basis_roots": "root[i] = 1753 ** (2*bit_reverse8(i)+1) modulo 8380417",
                "residue_representation": "Canonical normal residues, without a Montgomery factor",
                "inverse_normalization": INV256,
                "statement_scope": "Public row from zero through seven and an opaque context. No public key, rho, owner tag or output"}
    schedule["lifetimes"] = {
        "private_inputs": {"rho_zhat_t1_chat_hint": "Hold unchanged through every physical row"},
        "xof_reload_transitions": [[41 + 42 * i, 42 + 42 * i] for i in range(6)],
        "final_xof_hold_rows": [252, 1023],
        "final_count_sentinel_rows": [294, 1023],
        "accumulator": {"initial_zero_row": 0, "forward_hold_rows": [294, 421],
                        "final_normalized_available_row": 614, "final_hold_rows": [614, 1023]},
        "work": {"initial_zero_row": 0, "load_rows": [0, 31], "shifted_input_complete_row": 32,
                 "pre_transform_hold_rows": [32, 293], "t1hat_available_row": 422,
                 "final_hold_rows": [422, 1023]},
        "packed_output": {"initial_zero_row": 0, "producer_rows": [614, 645],
                          "complete_available_row": 646, "final_hold_rows": [646, 1023]},
        "final_dummy_positions": [{"physical_row": 1023, "slot": slot, "logical_round": 4092 + slot,
                                   "permutation": 170, "round": 12 + slot,
                                   "intra_transition": slot < 3, "outer_transition": False} for slot in range(4)]}
    source_names = ["research/signatures/synthetic_authorization.json", "research/signatures/verify_reference.py",
                    "research/ntt-proofs/reference_vectors.py", "research/coefficient-constraints/reference_vectors.py",
                    "research/coefficient-constraints/packing_vectors.py", "research/hash-proofs/reference_vectors.py",
                    "research/matrix-sampling/vectors.json", "research/crypto/vectors/selected.json"]
    record = {"scope": "Independent fixed finite row reconstruction references without Rust trace or proof code",
              "public_math_source_sha256": {name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in source_names},
              "independent_integer_model": {"path": "research/reconstructed-row/stream_math.py", "sha256": STREAM_SHA256},
              "integer_math_provenance": {"origin_source_sha256": "44b016e9977318763bd5f043485eef2434618eaa856deaa3594d7ee9db835126",
                                          "retained_functions": ["multiplication", "stream_model", "changed_continuation"],
                                          "scope": "Independently authored Python integer and manual sponge math. The exact reproducible helper is retained in this reference package."},
              "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "retained_sources": 2, "retained_complete_rows": 4, "synthetic_endpoint_rows": 4,
              "matrix_records": len(matrix_records), "full_sponge_records": len(matrix_records) * 6,
              "selected_full_round_records": 288, "candidate_events_per_row": 2352,
              "false_splices": len(faults), "valid_whole_input_alternatives": len(alternatives),
              "injected_late_completion_lanes": len(injected), "injected_unsupported_capacity": len(unsupported),
              "compiler_run": False, "prover_run": False, "actual_air_verdict_claim": False,
              "external_streamed_data_file_read": False,
              "retained_public_input_revision": "061a4ba5a930f8031ea39aa93595311305d07bd8",
              "selected_continuation_faults": 1, "full_proof_hash_goldens": 3,
              "reference_scope": "Complete mathematical row only. No final full signature challenge, key ownership, transaction, hidden note, private payment or confidential stake relation is proved"}
    corpus = {"format": "thorum.reconstructed-row.references.v1", "q": Q, "sources": sources,
              "matrix_records": matrix_records, "cases": cases}
    hostile = {"scope": "Independently rebuilt mathematical false joins, without actual constraint or proof verdicts",
               "faults": faults, "valid_alternatives": alternatives, "invalid_canonical_endpoints": invalid,
               "use_hint_boundaries": boundaries,
               "whole_row_scope": "Both retained row 0 and row 7 inputs are valid under their own public row statement. A partial row splice under an unchanged statement is false"}
    js = lambda value: (json.dumps(value, separators=(",", ":")) + "\n").encode()
    continuation = selected_continuation_fault(repository, hashing, verify, transform, stream_ref, retained, native)
    hash_csv, hash_preimages = proof_hash_goldens()
    data = {"vectors.json": js(corpus), "hostile_cases.json": js(hostile), "schedule.json": js(schedule),
            "injected_boundaries.json": js({"supported": injected, "unsupported": unsupported,
                                           "scope": "Represented bounded control/arithmetic streams without SHAKE preimage or full joined row claims"}),
            "continuation_faults.json": js({"scope": "Selected real local permutations with one false full-state join and no seed preimage claim",
                                           "hash_continuation_faults": [continuation]}),
            "hash_vectors.csv": hash_csv, "hash_preimages.json": js(hash_preimages),
            "profile.json": (json.dumps(fixed_profile(), indent=2) + "\n").encode()}
    record["generated_sha256"] = {name: hashlib.sha256(value).hexdigest() for name, value in data.items()}
    data["source_record.json"] = (json.dumps(record, indent=2) + "\n").encode()
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, data in outputs(args.repository_root.resolve()).items():
        path = BASE / name
        if args.check:
            assert path.read_bytes() == data, name
        else:
            path.write_bytes(data)
    print("Reconstructed row references match: 4 retained rows, 4 endpoint rows, 28 real matrix records, 13 false splices, 3 valid whole input alternatives, 8 injected completion lanes and 3 unsupported capacities")


if __name__ == "__main__":
    main()
