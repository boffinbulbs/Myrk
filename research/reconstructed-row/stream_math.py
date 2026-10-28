#!/usr/bin/env python3
"""Independent bounded integer stream and continuation math.

This module uses Python integers and the supplied independent manual sponge
oracle. It imports no trace builder, native signer or proof backend.
"""

Q, B, CAPACITY, EVENTS, LANES = 8380417, 4096, 1008, 336, 8


def multiplication(x, y):
    quotient, product = divmod(x * y, Q)
    x0, x1 = x % B, x // B
    y0, y1 = y % B, y // B
    k0, k1 = quotient % B, quotient // B
    z0, z1 = product % B, product // B
    c0, rem0 = divmod(x0 * y0 - k0 - z0, B)
    c1, rem1 = divmod(x0 * y1 + x1 * y0 - 2046 * k0 - k1 - z1 + c0, B)
    assert rem0 == rem1 == 0 and x1 * y1 - 2046 * k1 + c1 == 0
    assert 0 <= quotient < Q and 0 <= product < Q
    assert -2 <= c0 <= 8189 and -4096 <= c1 <= 12287
    return quotient, product, c0, c1


def stream_model(stream, zhat, prior, counter_reset_event=None, consumer_change_event=None, hold_change_after=None):
    assert len(stream) == CAPACITY and len(zhat) == len(prior) == 256
    assert all(0 <= value < Q for value in zhat + prior)
    accumulator, coefficients = list(prior), [None] * 256
    count, cursor, accepts = 0, 0, 0
    rows, events, duplicate_writes = [], [], []
    for program in range(42):
        before = list(accumulator)
        counts, cursors, local_events, destinations = [count], [cursor], [], []
        for lane in range(LANES):
            event = program * LANES + lane
            expected_count = count
            if event == counter_reset_event:
                assert count >= 1
                count -= 1
            count_before, cursor_before = count, cursor
            raw = int.from_bytes(stream[event * 3:event * 3 + 3], "little")
            active = count < 256
            candidate24 = raw if active else 0
            candidate23 = candidate24 & 0x7fffff
            take = active and candidate23 < Q
            index = count
            y = zhat[index] if active else 0
            expected_y = y
            if event == consumer_change_event:
                assert active
                y = (y + 1) % Q
                assert y != expected_y
            x = candidate23 if take else 0
            quotient, product, carry0, carry1 = multiplication(x, y)
            old = before[index] if active else 0
            addition = old + product
            add_carry, new = divmod(addition, Q)
            assert add_carry in [0, 1] and 0 <= new < Q
            if take:
                if index in destinations:
                    duplicate_writes.append({"program": program, "lane": lane, "index": index})
                destinations.append(index)
                accumulator[index] += new - old
                coefficients[index] = candidate23
                count += 1
                accepts += 1
            if active:
                cursor += 3
            item = {"event": event, "program": program, "lane": lane,
                    "active": active, "stream_candidate24": raw,
                    "candidate24": candidate24, "candidate23": candidate23, "take": take,
                    "count_before": count_before, "count_after": count,
                    "cursor_before": cursor_before, "cursor_after": cursor, "index": index,
                    "selected_zhat": y, "mul_x": x, "mul_y": y,
                    "mul_quotient": quotient, "product": product, "mul_carry0": carry0, "mul_carry1": carry1,
                    "selected_old": old, "add_carry": add_carry, "new": new, "write": take,
                    "compare_slack": (Q - 1 - candidate23 if take else candidate23 - Q if active else 0)}
            if count_before != expected_count:
                item["counter_link_residual"] = count_before - expected_count
            if y != expected_y:
                item["wrong_zhat_read"] = {"expected": expected_y, "supplied": y}
            if event == hold_change_after:
                target = 200
                assert target not in destinations
                previous = accumulator[target]
                accumulator[target] = (previous + 1) % Q
                item["unselected_hold_change"] = {"index": target, "old": previous, "supplied": accumulator[target]}
            local_events.append(item)
            events.append(item)
            counts.append(count)
            cursors.append(cursor)
        assert all(0 <= value < Q for value in accumulator)
        rows.append({"program": program, "counts": counts, "cursors": cursors,
                     "accumulator_before": before, "accumulator_after": list(accumulator),
                     "accepted_coefficients_after": [value for value in coefficients[:count] if value is not None],
                     "events": local_events})
    complete = count == 256
    clean = counter_reset_event is None and consumer_change_event is None and hold_change_after is None
    if clean:
        assert not duplicate_writes
        expected = [int.from_bytes(stream[e * 3:e * 3 + 3], "little") & 0x7fffff for e in range(EVENTS)]
        expected = [value for value in expected if value < Q][:256]
        assert expected == [value for value in coefficients if value is not None]
        assert sum(item["take"] for item in events) == count
        assert cursor == 3 * sum(item["active"] for item in events)
        for index, value in enumerate(expected):
            assert accumulator[index] == (prior[index] + value * zhat[index]) % Q
        assert accumulator[len(expected):] == prior[len(expected):]
        for row in rows:
            combined = list(row["accumulator_before"])
            for item in row["events"]:
                if item["write"]:
                    index = item["index"]
                    assert combined[index] == item["selected_old"]
                    combined[index] += item["new"] - item["selected_old"]
            assert combined == row["accumulator_after"]
    completion = next((item for item in events if item["count_after"] == 256 and item["take"]), None)
    return {"zhat": zhat, "prior_accumulator": prior, "rows": rows,
            "supported_complete": complete, "count": count, "consumed_bytes": cursor,
            "accepted_event_count": accepts,
            "coefficients": [value for value in coefficients if value is not None],
            "accumulator": accumulator, "duplicate_writes": duplicate_writes,
            "completion_program": completion["program"] if completion else None,
            "completion_lane": completion["lane"] if completion else None,
            "terminal_first_row": 42, "padding_allowed": complete,
            "canonical_padding_lane": ({"active": False, "candidate24": 0, "candidate23": 0,
                                        "take": False, "index": 256, "selected_zhat": 0,
                                        "mul_x": 0, "mul_y": 0, "mul_quotient": 0, "product": 0,
                                        "mul_carry0": 0, "mul_carry1": 0,
                                        "selected_old": 0, "add_carry": 0, "new": 0,
                                        "count_before": 256, "count_after": 256,
                                        "cursor_before": cursor, "cursor_after": cursor}
                                       if complete else None)}


def changed_continuation(hashing, original_states, original_rounds, stage, supplied):
    """Recompute real permutations after exactly one false 200-byte sponge join."""
    assert 1 <= stage < 6 and len(supplied) == 200
    states = list(original_states[:stage])
    rounds = list(original_rounds[:24 * stage])
    output = bytearray().join(bytes.fromhex(state["state_after_hex"])[:168] for state in states)
    previous = bytes.fromhex(states[-1]["state_after_hex"])
    assert supplied != previous
    for current_stage in range(stage, 6):
        absorbed = supplied if current_stage == stage else previous
        lanes = [int.from_bytes(absorbed[index:index + 8], "little") for index in range(0, 200, 8)]
        for round_index, constant in enumerate(hashing.ROUND_CONSTANTS):
            lanes = hashing.permutation(lanes, constant)
            rounds.append({"stage": current_stage, "phase": "squeeze", "round": round_index,
                           "state_hex": hashing.state_bytes(lanes).hex()})
        after = hashing.state_bytes(lanes)
        states.append({"stage": current_stage, "phase": "squeeze", "rate": 168,
                       "input_hex": bytes(168).hex(), "state_before_hex": previous.hex(),
                       "state_absorbed_hex": absorbed.hex(), "state_after_hex": after.hex()})
        output.extend(after[:168])
        previous = after
    assert len(output) == CAPACITY and len(states) == 6 and len(rounds) == 144
    return bytes(output), states, rounds
