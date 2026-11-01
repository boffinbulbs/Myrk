"""Finite unverified monetary arithmetic. No old program is imported or run."""

import csv
import hashlib
import io
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
MAX64 = (1 << 64) - 1
CAP = 6_300_000_000_000_000
PERIOD = 43_800
OLD_PERIOD = 21_900
TAIL = 50_000_000
PROFILE = "kova.monetary.paired60.v1"


class Refusal(ValueError):
    """Actual numeric input failure, not proof or consensus rejection."""


def natural(value, maximum, code):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Refusal(code)
    return value


def read_bounded(path, maximum):
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise Refusal("InputBytes")
    return data


def read_schedule():
    raw = read_bounded(HERE.parent / "emission/schedule.csv", 32768).replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != "1a06338798693b63261c76bcc4dc873437f716b4d6f413a961f32c8ecd336918":
        raise Refusal("FrozenSchedule")
    rows = list(csv.reader(io.StringIO(raw.decode("ascii"))))
    assert rows.pop(0) == ["period", "first_reward_block_index", "last_reward_block_index",
                           "first_paid_height", "last_paid_height", "reward_atoms", "reward_coins"]
    assert len(rows) == 240
    table = []
    for period, row in enumerate(rows):
        assert len(row) == 7
        assert list(map(int, row[:5])) == [period, period * OLD_PERIOD,
            (period + 1) * OLD_PERIOD - 1, period * OLD_PERIOD + 1, (period + 1) * OLD_PERIOD]
        table.append(natural(int(row[5]), MAX64, "TableAmount"))
    canonical = "".join(f"{p}:{s}\n" for p, s in enumerate(table)).encode("ascii")
    assert hashlib.sha256(canonical).hexdigest() == "ab8097f05a6993a38a3666ca5056c0cd30a6609ab2d5c3192a038bf2e27c8f7b"
    return tuple(table)


def paired(total):
    natural(total, MAX64, "PairAmount")
    first = (total // 20) * 10
    return first, total - first


def allocation(total):
    natural(total, MAX64, "AllocationAmount")
    stake, pool = total // 5, total // 10
    return total - stake - 2 * pool, stake, pool, pool


def nominal(table, height):
    natural(height, MAX64, "Height")
    if height == 0:
        return 0
    index = height - 1
    period = index // PERIOD
    total = table[period] if period < 240 else TAIL
    return paired(total)[index % 2]


def old_prefix(table, blocks):
    natural(blocks, MAX64, "PrefixHeight")
    periods, rest = divmod(min(blocks, 240 * OLD_PERIOD), OLD_PERIOD)
    total = sum(table[:periods]) * OLD_PERIOD
    if periods < 240:
        total += rest * table[periods]
    return total + max(0, blocks - 240 * OLD_PERIOD) * TAIL


def prefix(table, height):
    natural(height, MAX64, "Height")
    pairs, phase = divmod(height, 2)
    return old_prefix(table, pairs) + (nominal(table, height) if phase else 0)


def quote(total, issued):
    natural(total, MAX64, "NominalAmount")
    natural(issued, CAP, "Issued")
    capped = min(total, CAP - issued)
    return capped, allocation(capped)


def issue(total, issued, burned, earned, burn=0):
    capped, budgets = quote(total, issued)
    natural(burned, issued, "Burned")
    miner, stake, pool, developer = budgets
    natural(earned, stake, "Earned")
    actual = miner + pool + developer + earned
    after = issued + actual
    natural(burn, after - burned, "Burn")
    return {"nominal": total, "before": [issued, burned], "capped": capped,
            "budgets": budgets, "earned": earned, "unearned": stake - earned,
            "actual": actual, "burn": burn, "after": [after, burned + burn],
            "outstanding": after - burned - burn, "remaining": CAP - after}


def credited(total, issued, burned=0):
    return issue(total, issued, burned, quote(total, issued)[1][1])


def main():
    if not __debug__ or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        raise Refusal("Invocation")
    table = read_schedule()
    anchors = json.loads(read_bounded(HERE / "literals.json", 8192))
    old_metadata = json.loads(read_bounded(HERE.parent / "emission/metadata.json", 16384))
    assert old_metadata["reference_version"] == "2" and old_metadata["cap_atoms"] == CAP
    counts = {"period_pairs": 0, "phase_boundaries": 0, "previous_period_neighbors": 0,
              "nominal_literals": 0, "pair_literals": 0, "allocation_literals": 0,
              "fully_earned_cap_pairs": 0, "uncapped_earned_burn_pairs": 0,
              "wrong_alternatives": 0, "restored_checks": 0, "actual_numeric_refusals": 0}
    saved_pairs = []
    for period, total in enumerate(table):
        first, second = paired(total)
        af, ass, original = allocation(first), allocation(second), allocation(total)
        assert first + second == total and first % 10 == 0 and 0 <= second - first <= 19
        assert tuple(a + b for a, b in zip(af, ass)) == original
        start, end = period * PERIOD + 1, (period + 1) * PERIOD
        assert [nominal(table, h) for h in (start, start + 1, end - 1, end)] == [first, second, first, second]
        if period:
            assert nominal(table, start - 1) == paired(table[period - 1])[1]
            counts["previous_period_neighbors"] += 1
        saved_pairs.append([period, total, first, second, af, ass, original])
        counts["period_pairs"] += 1
        counts["phase_boundaries"] += 4
    for height, expected in anchors["nominal"]:
        assert nominal(table, int(height)) == expected
        counts["nominal_literals"] += 1
    for total, first, second in anchors["pairs"]:
        assert paired(int(total)) == (int(first), int(second))
        counts["pair_literals"] += 1
    for total, expected in anchors["allocations"]:
        assert allocation(total) == tuple(expected)
        counts["allocation_literals"] += 1

    for total in range(20, 40):
        first, second = paired(total)
        for remaining in (0, 1, 5, 7, first - 1, first, first + 1, total - 1, total, total + 1):
            original = credited(total, CAP - remaining)
            a = credited(first, CAP - remaining)
            b = credited(second, *a["after"])
            assert b["after"] == original["after"]
            assert tuple(x + y for x, y in zip(a["budgets"], b["budgets"])) == original["budgets"]
            counts["fully_earned_cap_pairs"] += 1
        for earned_a in (0, allocation(first)[1] // 2, allocation(first)[1]):
            for earned_b in (0, allocation(second)[1] // 2, allocation(second)[1]):
                a = issue(first, 0, 0, earned_a, 1)
                b = issue(second, *a["after"], earned_b, 1)
                old = issue(total, 0, 0, earned_a + earned_b, 2)
                assert b["after"] == old["after"] and b["outstanding"] == old["outstanding"]
                counts["uncapped_earned_burn_pairs"] += 1

    # A real difference between two new opportunities and one old capped budget.
    a = issue(nominal(table, 1), CAP - 100, 0, 0)
    b = issue(nominal(table, 2), *a["after"], 0)
    old = issue(table[0], CAP - 100, 0, 0)
    assert (a["actual"], b["actual"], b["remaining"], old["actual"], old["remaining"]) == (80, 16, 4, 80, 20)
    cap_difference = {"new_first": a, "new_second": b, "old_single": old}
    cap = anchors["cap"]
    final = int(cap["new_height"])
    assert old_metadata["cap_exhaustion"]["first_exhausted_height"] == int(cap["old_height"])
    assert old_metadata["cap_exhaustion"]["final_capped_reward_atoms"] == cap["remaining"]
    assert prefix(table, 10_512_000) == int(anchors["old_declining_total"])
    assert prefix(table, final - 1) == int(cap["issued_before"])
    assert min(CAP, prefix(table, final)) == CAP and prefix(table, final - 1) < CAP
    last = credited(nominal(table, final), int(cap["issued_before"]))
    assert last["budgets"] == tuple(cap["final_allocation"]) and last["actual"] == cap["remaining"]
    assert nominal(table, final + 1) > 0 and credited(nominal(table, final + 1), CAP)["actual"] == 0
    assert int(cap["old_height"]) * 120 - final * 60 == cap["nominal_seconds_earlier"]
    max_prefix = prefix(table, MAX64)
    assert max_prefix < (1 << 90) and nominal(table, MAX64) == 25_000_000

    total = table[1]
    first, second = paired(total)
    actual = issue(nominal(table, 1), 0, 0, 0)
    alternatives = [
        (2 * (total // 2), total, sum(paired(total))),
        (tuple(x + y for x, y in zip(allocation(total // 2), allocation(total - total // 2))), allocation(total),
         tuple(x + y for x, y in zip(allocation(first), allocation(second)))),
        (second, first, nominal(table, 43801)),
        (paired(table[43800 // PERIOD])[1], 800_000_000, nominal(table, 43800)),
        (25_000_000, 25_363_636, nominal(table, 10512000)),
        (tuple(min(x, 7) for x in allocation(nominal(table, 1))), (6, 1, 0, 0), quote(nominal(table, 1), CAP - 7)[1]),
        (min(nominal(table, 1), CAP - (CAP - 100)), 0, quote(nominal(table, 1), CAP)[0]),
        (actual["capped"], 640_000_000, actual["actual"]),
    ]
    for wrong, expected, restored in alternatives:
        assert wrong != expected and restored == expected
        counts["wrong_alternatives"] += 1
        counts["restored_checks"] += 1

    refusals = [(nominal, (table, h), "Height") for h in (-1, MAX64 + 1, True, "1")]
    refusals += [(paired, (s,), "PairAmount") for s in (-1, MAX64 + 1, True)]
    refusals += [(allocation, (s,), "AllocationAmount") for s in (-1, MAX64 + 1)]
    refusals += [(issue, args, code) for args, code in [
        ((800_000_000, CAP + 1, 0, 0), "Issued"),
        ((800_000_000, 0, 1, 0), "Burned"),
        ((800_000_000, 0, 0, -1), "Earned"),
        ((800_000_000, 0, 0, 160_000_001), "Earned"),
        ((800_000_000, CAP - 1, 0, 1), "Earned"),
        ((800_000_000, 0, 0, 0, 640_000_001), "Burn"),
        ((800_000_000, 0, 0, False), "Earned"),
    ]]
    for function, args, code in refusals:
        try:
            function(*args)
        except Refusal as error:
            assert error.args == (code,)
            counts["actual_numeric_refusals"] += 1
        else:
            raise AssertionError("Actual numeric refusal missing")
    burned_cap = issue(nominal(table, 1), CAP, 100, 0)
    assert burned_cap["actual"] == 0 and burned_cap["remaining"] == 0
    counts["near_cap_counterexamples"] = 1
    counts["maximum_prefix_bits"] = max_prefix.bit_length()
    output = {"profile": PROFILE, "scope": "unverified monetary arithmetic, from-genesis research only",
              "counts": counts, "period_pairs": saved_pairs, "near_cap_difference": cap_difference,
              "final_cap": {"height": str(final), "transition": last, "nominal_seconds_earlier": 60},
              "prefixes": [[str(h), str(prefix(table, h))] for h in (0, 1, 2, 43800, 43801, 10512000, final - 1, final, MAX64)]}
    encoded = (json.dumps(output, separators=(",", ":")) + "\n").encode("ascii")
    assert len(encoded) <= 131072
    with (HERE / "result.json").open("xb") as destination:
        destination.write(encoded)
    print(json.dumps({**counts, "result_bytes": len(encoded), "python": sys.version.split()[0]}, sort_keys=True))


if __name__ == "__main__":
    main()
