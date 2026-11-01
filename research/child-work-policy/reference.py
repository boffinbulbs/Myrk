"""Finite integer reference for a prospective child work policy, not a node.

ASERT polynomial and primary cases derive from Bitcoin Cash Node contributors.
Original MIT notices are retained in licenses/BCHN-COPYING. No primary generator
or Kova component is imported or executed.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX64 = (1 << 64) - 1
MAX256 = (1 << 256) - 1
HALFLIFE = 172800
RADIX = 65536


def check_inputs(ref, spacing, dt, dh, limit):
    assert all(type(x) is int for x in (ref, spacing, dt, dh, limit))
    assert 1 <= ref <= limit <= MAX256
    assert spacing in (60, 600) and -MAX64 <= dt <= MAX64 and 0 <= dh <= MAX64


def direct(ref, spacing, dt, dh, limit, mode="exact"):
    check_inputs(ref, spacing, dt, dh, limit)
    delta = dt - spacing * (dh + (0 if mode == "omit_next" else 1))
    numerator = delta * RADIX
    if mode == "floor":
        exponent = numerator // HALFLIFE
    else:
        exponent = abs(numerator) // HALFLIFE
        if numerator < 0:
            exponent = -exponent
    whole = exponent >> 16
    fraction = exponent - whole * RADIX
    assert 0 <= fraction < RADIX
    factor = RADIX + ((195766423245049 * fraction + 971821376 * fraction**2
                       + 5127 * fraction**3 + (1 << 47)) >> 48)
    if mode == "discard_fraction":
        factor = RADIX
    scaled = ref * factor
    shift = whole - (0 if mode == "omit_scale" else 16)
    if abs(shift) > 512:
        raise ValueError("Direct reference shift admission")
    raw = scaled << shift if shift >= 0 else scaled >> -shift
    if mode == "no_minimum":
        return min(limit, raw)
    if mode == "no_maximum":
        return max(1, raw)
    return max(1, min(limit, raw))


def bounded(ref, spacing, dt, dh, limit):
    check_inputs(ref, spacing, dt, dh, limit)
    n = (dt - spacing * (dh + 1)) * 65536
    q = abs(n) // 172800
    if n < 0:
        q = -q
    k, f = divmod(q, 65536)
    factor = 65536 + (((5127 * f + 971821376) * f + 195766423245049) * f
                      + 140737488355328) // 281474976710656
    product = ref * factor
    assert product.bit_length() <= 273
    shift = k - 16
    if shift >= 0:
        if product.bit_length() + shift > 256:
            return limit
        value = product << shift
    elif -shift >= product.bit_length():
        return 1
    else:
        value = product >> -shift
    return min(limit, max(1, value))


def median_previous(times):
    assert 1 <= len(times) <= 11
    assert all(type(x) is int and 0 <= x <= MAX64 for x in times)
    return sorted(times)[len(times) // 2]


def classify_numeric_time(candidate, times, utc):
    assert type(candidate) is int and 0 <= candidate <= MAX64
    if candidate <= median_previous(times):
        return "BelowOrEqualMedian"
    if utc is None:
        return "DeferMissingClock"
    assert type(utc) is int and 0 <= utc <= MAX64
    if candidate > utc + 7200:
        return "DeferFuture"
    return "NumericallyEligible"


def work(target):
    assert type(target) is int and 1 <= target <= MAX256
    return (1 << 256) // (target + 1)


def main():
    if not __debug__:
        raise RuntimeError("Optimized reference refused")
    with (HERE / "primary-cases.json").open("rb") as source:
        raw = source.read(8193)
    assert len(raw) <= 8192
    primary = json.loads(raw)
    assert primary["parent_time_added"] == primary["spacing"] == 600
    assert primary["halflife"] == HALFLIFE and len(primary["cases"]) == 18
    limit = int(primary["limit"], 16)
    assert limit == (1 << 224) - 1
    values = {"L": limit, "1": 1, "2": 2, "3": 3,
              "FFFF8_SHIFT204": 0xffff8 << 204,
              **{name: int(value, 16) for name, value in primary["constants"].items()},
              **{f"L>>{i}": limit >> i for i in range(1, 5)}}
    saved = []

    def case(label, ref, spacing, dt, dh, maximum, expected=None, compare=True):
        result = bounded(ref, spacing, dt, dh, maximum)
        if expected is not None:
            assert result == expected, (label, hex(result), hex(expected))
        if compare:
            assert direct(ref, spacing, dt, dh, maximum) == result, label
        saved.append({"label": label, "ref": f"{ref:064x}", "spacing": spacing,
                      "dt": str(dt), "dh": str(dh), "limit": f"{maximum:064x}",
                      "target": f"{result:064x}"})
        return result

    for i, (ref, extra, dh, expected) in enumerate(primary["cases"]):
        case(f"primary-{i}", values[ref], 600, 600 + extra, dh, limit, values[expected])
    assert values["FFFF8_SHIFT204"] != 0xffff << 208
    ref = 1 << 200
    literal_cases = [
        (ref, 60, 0, ref), (ref, 120, 1, ref),
        (ref, 60 + HALFLIFE, 0, ref * 2), (ref, 60 - HALFLIFE, 0, ref // 2),
        (ref, 60 + 2 * HALFLIFE, 0, ref * 4), (ref, 60 - 2 * HALFLIFE, 0, ref // 4),
        (ref, 60 * 289, 288, ref), (1, 60 - HALFLIFE, 0, 1),
        (limit, 60 + HALFLIFE, 0, limit), (limit, 60, 0, limit),
        (1, 60, 0, 1), (ref, 59, 0, ref),
    ]
    for i, (anchor, dt, dh, expected) in enumerate(literal_cases):
        case(f"literal60-{i}", anchor, 60, dt, dh, limit, expected)
    for spacing in (60, 600):
        for dh in (0, 1, 287, 288):
            for offset in (-HALFLIFE, -1, 0, HALFLIFE // 2):
                case(f"grid-{spacing}-{dh}-{offset}", ref + 0x123456789, spacing,
                     spacing * (dh + 1) + offset, dh, limit)
    case("full-width-half", MAX256, 60, 60 - HALFLIFE, 0, MAX256, MAX256 // 2)
    case("full-width-double-clamp", MAX256, 60, 60 + HALFLIFE, 0, MAX256, MAX256)
    case("huge-shift-up", 1, 60, MAX64, 0, MAX256, MAX256, compare=False)
    case("huge-shift-down", MAX256, 60, -MAX64, MAX64, MAX256, 1, compare=False)

    alternatives = [
        (direct(ref, 60, 59, 0, limit, "floor"), ref, (ref, 60, 59, 0, limit)),
        (direct(ref, 60, 60, 0, limit, "omit_next"), ref, (ref, 60, 60, 0, limit)),
        (direct(ref, 60, 0, 0, limit), ref, (ref, 60, 60, 0, limit)),
        (direct(ref, 600, 60, 0, limit), ref, (ref, 60, 60, 0, limit)),
        (direct(ref, 60, 60, 0, limit, "omit_scale"), ref, (ref, 60, 60, 0, limit)),
        (direct(limit, 600, 900, 1, limit, "discard_fraction"), values["SINGLE300"],
         (limit, 600, 900, 1, limit)),
        (direct(1, 60, 60 - HALFLIFE, 0, limit, "no_minimum"), 1,
         (1, 60, 60 - HALFLIFE, 0, limit)),
        (direct(limit, 60, 60 + HALFLIFE, 0, limit, "no_maximum"), limit,
         (limit, 60, 60 + HALFLIFE, 0, limit)),
    ]
    for wrong, expected, original in alternatives:
        assert wrong != expected
        assert bounded(*original) == direct(*original) == expected

    medians = [0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5]
    for n, expected in enumerate(medians, 1):
        assert median_previous(list(reversed(range(n)))) == expected
    assert median_previous([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1000000000]) == 6
    times = list(range(10, 21))
    for candidate, utc, expected in [
        (15, 100, "BelowOrEqualMedian"), (14, 100, "BelowOrEqualMedian"),
        (16, None, "DeferMissingClock"), (10000, 2800, "NumericallyEligible"),
        (10001, 2800, "DeferFuture"), (20, MAX64, "NumericallyEligible"),
    ]:
        assert classify_numeric_time(candidate, times, utc) == expected
    for target, expected in [(1, 1 << 255), (3, 1 << 254),
                             ((1 << 255) - 1, 2), (MAX256, 1),
                             ((1 << 128) - 1, 1 << 128)]:
        assert work(target) == expected
    maximum_sum = MAX64 * work(1)
    assert maximum_sum.bit_length() == 319 and maximum_sum < 1 << 320
    assert len(saved) == 66
    counts = {"primary_raw_cases": 18, "literal60_cases": 12, "grid_cases": 32,
              "extreme_cases": 4, "wrong_formulas": 8, "restored_checks": 8,
              "median_windows": 12, "numeric_time_cases": 6, "work_literals": 5,
              "maximum_work_sum_bits": maximum_sum.bit_length(), "saved_cases": len(saved)}
    output = json.dumps({"counts": counts, "cases": saved}, separators=(",", ":")).encode("ascii")
    assert len(output) + 1 <= 32768
    with (HERE / "result.json").open("xb") as handle:
        handle.write(output + b"\n")
    print(json.dumps({**counts, "result_bytes": len(output) + 1}, sort_keys=True))


if __name__ == "__main__":
    main()
