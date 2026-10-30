"""Independent raw relation and Merkle nodes from actual captured leaf digests."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate reference records")

HERE = Path(__file__).resolve().parent
CAP = 2 * 1024 * 1024
CAPTURE = 1048064
ROWS = [4096] * 3 + [2048 >> i for i in range(9)]
SHAPES = [[1, 4096, 6], [8, 4096, 8], [1, 4096, 8]] + [[1, 2048 >> i, 8] for i in range(9)]


def bounded(path, limit):
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Bounded regular reference file required")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Reference file exceeded its bound")
    return data


def tree(data, rows):
    if len(data) != rows * 64:
        raise ValueError("Exact leaf digest count required")
    nodes = [data[i:i + 64] for i in range(0, len(data), 64)]
    domain = b"kova.storage-pcs.node.v1"
    prefix = len(domain).to_bytes(4, "big") + domain
    while len(nodes) > 1:
        nodes = [hashlib.sha3_512(prefix + nodes[i] + nodes[i + 1] + (16).to_bytes(8, "big")).digest()
                 for i in range(0, len(nodes), 2)]
    return dict(_marker=None, cap=[list(struct.unpack("<8Q", nodes[0]))])


def check(directory):
    raw = bounded(directory / "leaf-digests.bin", CAPTURE)
    proof_raw = bounded(directory / "proof.json", CAP)
    proof = json.loads(proof_raw)
    m = json.loads(bounded(directory / "measurement.json", 65536))
    assert len(raw) == CAPTURE == sum(ROWS) * 64
    assert m["whole_stark_proofs"] == m["retained_verifier_accepts"] == 2
    assert m["input_mmcs_commits"] == m["input_multi_open_calls"] == 6
    assert m["fri_mmcs_commits"] == m["fri_multi_open_calls"] == 18
    assert m["scalar_open_calls"] == m["false_air_proofs"] == 0
    assert m["degree_bits"] == proof["degree_bits"] == 9
    assert [m[k] for k in ["raw_height", "main_width", "queries", "extension_degree"]] == [256, 2, 64, 4]
    assert m["public_values"] == [5, 260] and m["same_complete_proof_bytes"] is True
    assert m["reserved_files"] == 12 and m["reserved_field_bytes"] == 1292288
    assert m["encoded_proof_bytes"] == len(proof_raw) <= CAP
    assert m["leaf_digest_bytes"] == CAPTURE and m["commit_shapes"] == SHAPES
    roots = m["commit_roots"]
    assert len(roots) == len(ROWS) == 12
    offset = 0
    for root, rows in zip(roots, ROWS, strict=True):
        size = rows * 64
        assert tree(raw[offset:offset + size], rows) == root
        offset += size
    assert offset == len(raw)
    assert [proof["commitments"][k] for k in ["trace", "quotient_chunks", "random"]] == roots[:3]
    assert proof["opening_proof"][1]["commit_phase_commits"] == roots[3:]
    return raw, proof_raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()
    trace = json.loads((HERE.parent / "storage-pcs/fixtures/trace.json").read_text())
    assert len(trace) == 256
    assert trace == [[5 + i, pow(5 + i, 4, 2013265921)] for i in range(256)]
    expected = check(HERE / "fixtures")
    if args.check_results:
        assert check(HERE / "results") == expected
        assert (HERE / "results/measurement.json").read_bytes() == (HERE / "fixtures/measurement.json").read_bytes()
    # Tree shape refusal is separate from the actual retained Rust verifier.
    try:
        tree(expected[0][:4096 * 64 - 1], 4096)
    except ValueError:
        pass
    else:
        raise AssertionError("Truncated digest capture accepted")
    changed = bytearray(expected[0][:4096 * 64])
    changed[0] ^= 1
    assert tree(changed, 4096) != tree(expected[0][:4096 * 64], 4096)
    print("Independent fixed relation, twelve Merkle roots and whole proof records match")


if __name__ == "__main__":
    main()
