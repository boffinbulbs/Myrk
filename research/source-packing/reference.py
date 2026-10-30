"""Independent scalar packing and fixed address vectors for a small mechanism."""
import argparse
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate mechanism records")
HERE = Path(__file__).resolve().parent
P = 2013265921
WINDOWS = [("key", 32, 10), ("key", 0, 136), ("signature", 0, 10),
           ("note", 49, 10), ("note", 141, 10), ("signature", 4626, 1),
           ("note", 417, 1), ("signature", 0, 10)]
WORDS = [("key", i) for i in range(46)] + [("signature", i) for i in [0, 1, 2, 3, 1542]] + [("note", i) for i in [16, 17, 18, 19, 47, 48, 49, 50, 139]]
NAMES = ["wrong_source", "wrong_word", "stale_repeat", "active_hold", "inactive_hold",
         "first_anchor", "clock_restart", "last_anchor", "key_alignment", "note_alignment",
         "signature_padding", "note_padding", "note417", "non_boolean", "carry_alias",
         "unused_active_port", "inactive_port", "inactive_consumer"]


def vectors():
    sources = {name: [((i * 73 + seed) ^ (i >> 3)) & 255 for i in range(size)]
               for name, size, seed in [("key", 2592, 17), ("signature", 4627, 73), ("note", 418, 131)]}
    sources["key"][:4] = [0, 127, 128, 255]
    sources["signature"][:4] = [0, 129, 128, 255]
    sources["signature"][4626] = 7
    sources["note"][417] = 0
    packed = []
    for bank, word in WORDS:
        raw = sources[bank][word * 3:word * 3 + 3]
        packed.append(int.from_bytes(bytes(raw).ljust(3, b"\0"), "little"))
    ports, consumers, used = [], [], set()
    for row in range(16):
        reads, output = [0] * 48, [0] * 136
        if row < len(WINDOWS):
            bank, first, size = WINDOWS[row]
            words = range(first // 3, (first + size + 2) // 3)
            for port, word in enumerate(words):
                slot = WORDS.index((bank, word))
                reads[port] = packed[slot]
                used.add(slot)
            output[:size] = sources[bank][first:first + size]
        ports.append(reads)
        consumers.append(output)
    assert len(packed) == len(set(WORDS)) == len(used) == 60
    assert all(0 <= x < 2**24 < P for x in packed)
    assert ports[2] == ports[7] and consumers[2] == consumers[7]
    assert ports[5][0] == 7 and ports[6][0] == 0
    return dict(**sources, words=packed, ports=ports, consumers=consumers)


def bounded(path, limit=131072):
    with path.open("rb") as file:
        raw = file.read(limit + 1)
    assert len(raw) <= limit, path
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()
    expected = vectors()
    fixture = HERE / "fixtures/reference.json"
    if args.generate:
        fixture.parent.mkdir(exist_ok=True)
        with fixture.open("x") as file:
            json.dump(expected, file, separators=(",", ":"))
            file.write("\n")
    assert bounded(fixture) == expected
    if args.check_results:
        symbolic = bounded(HERE / "results/symbolic.json")
        assert symbolic == dict(collections=1, constraints=1451, degree=2, native_traces=0, backend_proofs=0)
        native = bounded(HERE / "results/native.json")
        assert native["native_traces"] == native["max_live_traces"] == 1
        assert native["positive_checks"] == 21 and native["restoration_checks"] == 18
        assert native["backend_proofs"] == 0 and native["failure_threshold"] == 1
        assert native["row_granular_threshold"] and native["failure_bound_per_row"] == 1451
        assert native["rows"] == 16 and native["width"] == 1364
        assert [r["name"] for r in native["rejections"]] == NAMES
        assert all(r["rejected"] and 1 <= r["failures"] <= 1451 and 0 <= r["row"] < 16 and 0 <= r["constraint"] < 1451 for r in native["rejections"])
        for index, constraint in [(10, 1263), (11, 1266), (12, 1450), (14, 117)]:
            assert native["rejections"][index]["constraint"] == constraint
            assert native["rejections"][index]["failures"] == 1
        for index, record in enumerate(native["rejections"]):
            assert bounded(HERE / "results" / f"{index:02}-{record['name']}.json") == record
    print("Independent canonical packing, repeated and unaligned byte vectors match")


if __name__ == "__main__":
    main()
