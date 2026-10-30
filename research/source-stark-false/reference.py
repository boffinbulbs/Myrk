"""One canonical false witness and independent captured Merkle node checks."""
import argparse
import importlib.util
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate false witness records")

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("retained_owned_reference", HERE.parent / "source-stark/reference.py")
retained = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retained)


def check(directory):
    witness = json.loads(retained.bounded(directory / "witness.json", 8192))
    rows = json.loads(retained.bounded(HERE.parent / "storage-pcs/fixtures/trace.json", 65536))
    assert rows == [[5 + i, pow(5 + i, 4, 2013265921)] for i in range(256)]
    original = [value for row in rows for value in row]
    assert len(witness) == len(original) == 512
    assert all(type(v) is int and 0 <= v < 2013265921 for v in witness)
    assert [i for i, (a, b) in enumerate(zip(original, witness, strict=True)) if a != b] == [255]
    assert original[255] == 303595776 and witness[255] == 303595777
    assert witness[::2] == original[::2] and [witness[0], witness[510]] == [5, 260]
    m = json.loads(retained.bounded(directory / "measurement.json", 65536))
    proof_raw = retained.bounded(directory / "proof.json", retained.CAP)
    proof = json.loads(proof_raw)
    digests = retained.bounded(directory / "leaf-digests.bin", retained.CAPTURE)
    verification = json.loads(retained.bounded(directory / "verification.json", 8192))
    assert verification == {"observed": "Err(OodEvaluationMismatch { index: None })"}
    assert [m[k] for k in ["whole_stark_proofs", "false_air_proofs", "retained_verifier_rejects", "retained_positive_fixture_accepts"]] == [1] * 4
    assert m["fresh_positive_proofs"] == m["scalar_open_calls"] == 0
    assert m["input_mmcs_commits"] == m["input_multi_open_calls"] == 3
    assert m["fri_mmcs_commits"] == m["fri_multi_open_calls"] == 9
    assert m["verifier_error"] == "OodEvaluationMismatch" and m["verifier_error_index"] is None
    assert [m[k] for k in ["changed_flat_index", "original_value", "changed_value"]] == [255, 303595776, 303595777]
    assert m["public_values"] == [5, 260] and m["degree_bits"] == proof["degree_bits"] == 9
    assert m["encoded_proof_bytes"] == len(proof_raw) and 0 < len(proof_raw) <= retained.CAP
    assert m["leaf_digest_bytes"] == len(digests) == retained.CAPTURE
    assert m["commit_shapes"] == retained.SHAPES
    assert m["reserved_files"] == 12 and m["reserved_field_bytes"] == 1292288
    roots = m["commit_roots"]
    assert len(roots) == 12
    offset = 0
    for root, rows in zip(roots, retained.ROWS, strict=True):
        size = rows * 64
        assert retained.tree(digests[offset:offset + size], rows) == root
        offset += size
    assert offset == len(digests)
    assert [proof["commitments"][k] for k in ["trace", "quotient_chunks", "random"]] == roots[:3]
    assert proof["opening_proof"][1]["commit_phase_commits"] == roots[3:]
    return witness, proof_raw, digests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()
    expected = check(HERE / "fixtures")
    if args.check_results:
        assert check(HERE / "results") == expected
        limits = {"witness.json": 8192, "proof.json": retained.CAP,
                  "leaf-digests.bin": retained.CAPTURE, "verification.json": 8192,
                  "measurement.json": 65536}
        for name, limit in limits.items():
            assert retained.bounded(HERE / "results" / name, limit) == retained.bounded(HERE / "fixtures" / name, limit)
    print("Canonical one-cell violation, exact rejection record and twelve Merkle roots match")


if __name__ == "__main__":
    main()
