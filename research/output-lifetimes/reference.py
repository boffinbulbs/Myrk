"""Independent integer lifetime certificate. No field trace or prover."""
import argparse
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate lifetime certificates")

ROOT = Path(__file__).resolve().parent
MAP = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 8, 6]
P = 2013265921


def windows(logical):
    if logical < 7:
        return [(648 + 384 * logical + 48 * i, 690 + 384 * logical + 48 * i) for i in range(8)]
    if logical == 7:
        return [(3330, 3586)]
    return [(3330 + 32 * (logical - 8), 3362 + 32 * (logical - 8))]


def conflicts(mapping):
    result = []
    for older in range(16):
        for newer in range(older + 1, 16):
            if mapping[older] != mapping[newer]:
                continue
            for coefficient in range(256):
                first_visible = 611 + 192 * newer + coefficient // 8
                for start, end in windows(older):
                    for row in range(max(start, first_visible), end):
                        result.append((older, newer, coefficient, row))
    return result


def certificate():
    assert len(MAP) == 16 and set(MAP) == set(range(9))
    assert not conflicts(MAP)
    unsafe = MAP.copy()
    unsafe[14] = 6
    bad = conflicts(unsafe)
    assert len(bad) == 12160
    z6_bad = [x for x in bad if x[:2] == (6, 14)]
    assert len(z6_bad) == 3968
    assert min(x[3] for x in bad) == 3299 and max(x[3] for x in bad) == 3553
    samples = [[10000 + 37 * logical + coordinate for coordinate in range(2)] for logical in range(16)]
    checks = 0
    checksum = 0
    for logical in range(16):
        # Consumer windows start after every coordinate's producer completes.
        assert min(start for start, _ in windows(logical)) >= 642 + 192 * logical
        for start, end in windows(logical):
            for row in range(start, end):
                for coordinate in range(2):
                    checks += 1
                    checksum = (checksum + samples[logical][coordinate] * (row + 1) * (logical + 1) * (coordinate + 1)) % P
    return dict(format="kova.output-lifetime.v1", height=8192, width=274, raw_field_bytes=8978432,
                map=MAP, representative_coefficients=[0, 255], sources=samples,
                read_checks=checks, read_checksum=checksum, full_coordinate_conflicts=0,
                unsafe_conflicts=len(bad), unsafe_first_row=3299, unsafe_last_row=3553, unsafe_z6_conflicts=len(z6_bad),
                omitted_producer_values="arbitrary held field elements", backend_proofs=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = ROOT / "fixtures/certificate.json"
    data = certificate()
    if args.write:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    else:
        assert json.loads(path.read_text(encoding="utf-8")) == data
    print(json.dumps({key: data[key] for key in ["read_checks", "read_checksum", "unsafe_conflicts", "backend_proofs"]}))


if __name__ == "__main__":
    main()
