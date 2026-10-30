"""Independent reservation geometry and canonical captured field records."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate reference records")

HERE = Path(__file__).resolve().parent
P = 2013265921


def geometry():
    shapes = [(256, 2), (512, 6), (4096, 6)] + [(4096, 8)] * 9
    sizes = [4 * h * w for h, w in shapes]
    assert len(shapes) == 12 and len(shapes) <= 16
    assert max(h for h, _ in shapes) <= 4096
    assert max(w for _, w in shapes) <= 12
    assert sum(sizes) == 1292288 <= 2 * 1024 * 1024
    assert sum(sizes[2:]) == 1277952
    return shapes, sizes


def canonical(raw):
    _, sizes = geometry()
    assert len(raw) == sum(sizes[2:])
    assert all(v < P for (v,) in struct.iter_unpack("<I", raw))


def captured(directory):
    shapes, sizes = geometry()
    raw = (directory / "fields.bin").read_bytes()
    canonical(raw)
    hashes = []
    offset = 0
    for size in sizes[2:]:
        hashes.append(hashlib.sha3_256(raw[offset:offset + size]).hexdigest())
        offset += size
    assert offset == len(raw) and len(hashes) == 10
    m = json.loads((directory / "measurement.json").read_text())
    assert m == dict(input_mmcs_commits=6, fri_mmcs_commits=0, pcs_openings=0,
                    stark_proofs=0, reserved_files=len(shapes), reserved_bytes=sum(sizes),
                    captured_bytes=len(raw), matrix_sha3_256=hashes)
    roots = json.loads((directory / "roots.json").read_text())
    assert set(roots) == {"main", "quotient", "auxiliary"}
    for value in roots.values():
        assert set(value) == {"_marker", "cap"} and value["_marker"] is None
        assert len(value["cap"]) == 1 and len(value["cap"][0]) == 8
        assert all(type(v) is int and 0 <= v < 2**64 for v in value["cap"][0])
    return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()
    raw = captured(HERE / "fixtures")
    if args.check_results:
        assert captured(HERE / "results") == raw
        for name in ["roots.json", "measurement.json"]:
            assert (HERE / "results" / name).read_bytes() == (HERE / "fixtures" / name).read_bytes()
    for invalid in [raw[:-1], struct.pack("<I", P) + raw[4:]]:
        try:
            canonical(invalid)
        except AssertionError:
            continue
        raise AssertionError("Malformed reference input was accepted")
    print("Twelve reservations, ten canonical matrix records and retained digests match")


if __name__ == "__main__":
    main()
