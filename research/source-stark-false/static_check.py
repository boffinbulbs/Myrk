"""Exact source identities and one complete invalid witness proof record."""
import hashlib
import json
import os
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes()
    if path.suffix != ".bin":
        data = data.replace(b"\r\n", b"\n")
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def packages(path):
    result = set()
    for block in path.read_text().split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\r\n\\]+)"$', block, re.MULTILINE))
        if "source" in fields:
            assert all(k in fields for k in ["name", "version", "source", "checksum"])
            result.add(tuple(fields[k] for k in ["name", "version", "source", "checksum"]))
    return result


def main():
    p = json.loads((HERE / "provenance.json").read_text())
    for name, expected in p["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in p["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    cargo = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for name, expected in p["registry_files"].items():
        paths = list((cargo / "registry/src").glob("*/" + name))
        assert paths and all(identity(path) == expected for path in paths), name
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    own = packages(HERE / "Cargo.lock")
    assert len(own) == 63 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text())
    basis = json.loads((ROOT / "research/source-opening/fixtures/features.json").read_text())
    assert len(features) == 63 and features.keys() == basis.keys()
    assert all(set(v) <= set(basis[k]) for k, v in features.items())
    assert not any(k.startswith("rayon") or "parallel" in v for k, v in features.items())
    v = json.loads((HERE / "validation.json").read_text())
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["test_groups_passed"] == v["whole_stark_proofs"] == v["false_air_proofs"] == 1
    assert v["retained_verifier_rejects"] == v["retained_positive_fixture_accepts"] == 1
    assert v["fresh_positive_proofs"] == v["scalar_open_calls"] == 0
    assert v["input_mmcs_commits"] == v["input_multi_open_calls"] == 3
    assert v["fri_mmcs_commits"] == v["fri_multi_open_calls"] == 9
    assert v["verifier_error"] == "OodEvaluationMismatch" and v["verifier_error_index"] is None
    assert v["degree_bits"] == 9 and v["encoded_proof_bytes"] == 600978
    assert v["leaf_digest_bytes"] == 1048064 and v["independent_merkle_roots"] == 12
    assert [v[k] for k in ["changed_flat_index", "original_value", "changed_value"]] == [255, 303595776, 303595777]
    assert v["reserved_files_per_owner"] == 12 and v["reserved_bytes_per_owner"] == 1292288
    assert not any(v[k] for k in ["native_signature_traces", "wide_symbolic_evaluations", "full_signature_proof_implemented", "full_payment_implemented", "production_security_claim"])
    g = v["guard"]
    assert g["process_limit_bytes"] == g["aggregate_limit_bytes"] == 536870912
    assert g["minimum_available_bytes"] == 2147483648 and g["timeout_seconds"] == 120
    assert g["readback_verified"] and g["test_counts_verified"]
    assert g["available_before_bytes"] >= g["minimum_available_bytes"]
    assert 0 < g["peak_process_commit_bytes"] <= g["process_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["aggregate_limit_bytes"]
    print("Frozen identities and one complete invalid witness rejection record match")


if __name__ == "__main__":
    main()
