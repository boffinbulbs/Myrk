"""Independent integer Merkle roots and masked polynomial opening values."""
import hashlib
import json
from pathlib import Path
import struct
import sys

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate opening references")

HERE = Path(__file__).resolve().parent
P = 2013265921
G = 31
CAP = 2 * 1024 * 1024
CAPTURE = 752896


def read_bounded(path, limit):
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Bounded regular fixture required")
    data = path.read_bytes()
    if len(data) > limit:
        raise ValueError("Fixture changed beyond bound")
    return data


def tagged(domain, values, count):
    return hashlib.sha3_512(len(domain).to_bytes(4, "big") + domain + values + count.to_bytes(8, "big")).digest()


def tree(data, rows, width):
    size = width * 4
    assert len(data) == rows * size
    nodes = [tagged(b"kova.storage-pcs.leaf.v1", data[i:i + size], width) for i in range(0, len(data), size)]
    while len(nodes) > 1:
        nodes = [tagged(b"kova.storage-pcs.node.v1", nodes[i] + nodes[i + 1], 16) for i in range(0, len(nodes), 2)]
    return [list(struct.unpack("<8Q", nodes[0]))]


def extension(value):
    if len(value) != 4 or any(type(x) is not int or not 0 <= x < P for x in value):
        raise ValueError("Canonical four-coefficient extension value required")
    return value


def multiply(left, right):
    result = [0] * 4
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % 4] += a * b * (11 if i + j >= 4 else 1)
    return [v % P for v in result]


def evaluate(coefficients, point):
    result = [0] * 4
    for value in reversed(coefficients):
        result = multiply(result, point)
        result[0] = (result[0] + value) % P
    return result


def interpolate_coset(values):
    n = len(values)
    assert n == 512
    inverse_root = pow(pow(G, (P - 1) // n, P), -1, P)
    inverse_n, inverse_shift = pow(n, -1, P), pow(G, -1, P)
    result = []
    step, shift_power = 1, 1
    for _ in range(n):
        power, total = 1, 0
        for value in values:
            total = (total + value * power) % P
            power = power * step % P
        result.append(total * inverse_n * shift_power % P)
        step = step * inverse_root % P
        shift_power = shift_power * inverse_shift % P
    return result


def main():
    if sys.argv[1:] not in [[], ["--check-results"]]:
        raise ValueError("Expected no arguments or --check-results")
    record = json.loads(read_bounded(HERE / "fixtures/measurement.json", 65536))
    capture = read_bounded(HERE / "fixtures/salted-leaves.bin", CAPTURE)
    proof_bytes = read_bounded(HERE / "fixtures/proof.json", CAP)
    proof = json.loads(proof_bytes)
    assert len(capture) == CAPTURE == record["captured_leaf_bytes"]
    assert len(proof_bytes) == record["proof_bytes"] and len(proof) == 2
    assert record["base_modulus"] == P and record["extension_nonresidue"] == 11
    assert [record[k] for k in ["raw_height", "domain_height", "original_width", "queries"]] == [256, 512, 2, 64]
    assert [record[k] for k in ["input_commit_calls", "fri_commit_calls", "successful_openings", "refused_clone_openings"]] == [3, 27, 3, 1]
    assert [record[k] for k in ["input_multi_open_calls", "fri_multi_open_calls", "scalar_open_calls", "positive_verifications", "negative_verifications", "stark_proofs"]] == [3, 27, 0, 3, 3, 0]
    fields = list(struct.unpack("<" + "I" * (CAPTURE // 4), capture))
    assert all(0 <= v < P for v in fields)
    roots = [record["input_root"], *record["fri_roots"]]
    assert len(roots) == 10
    offset = 0
    for index, (height, width) in enumerate([(4096, 22), *[(2048 >> r, 24) for r in range(9)]]):
        length = height * width * 4
        assert tree(capture[offset:offset + length], height, width) == roots[index]
        offset += length
    assert offset == CAPTURE
    assert [r["cap"] for r in proof[1]["commit_phase_commits"]] == record["fri_roots"]
    columns = []
    for col in [0, 1]:
        values = [fields[int(format(row, "09b")[::-1], 2) * 22 + col] for row in range(512)]
        columns.append(interpolate_coset(values))
    points = [extension(v) for v in record["points"]]
    assert len(points) == 2 and points[0] != points[1] and all(any(v[1:]) for v in points)
    assert len(record["opened"]) == 2 and all(len(row) == 2 for row in record["opened"])
    for i, point in enumerate(points):
        for col in [0, 1]:
            assert evaluate(columns[col], point) == extension(record["opened"][i][col])
    if sys.argv[1:]:
        assert read_bounded(HERE / "results/proof.json", CAP) == proof_bytes
        assert read_bounded(HERE / "results/salted-leaves.bin", CAPTURE) == capture
        assert json.loads(read_bounded(HERE / "results/measurement.json", 65536)) == record
    print("Ten Merkle roots and four extension opening values match independent integer arithmetic")


if __name__ == "__main__":
    main()
