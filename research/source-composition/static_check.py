"""Exact retained source identities and the bounded construction result."""
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
    raw = path.read_bytes()
    if path.suffix != ".bin":
        raw = raw.replace(b"\r\n", b"\n")
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


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
    for path, expected in p["repository_files"].items():
        assert identity(ROOT / path) == expected, path
    for path, expected in p["experiment_files"].items():
        assert identity(HERE / path) == expected, path
    cargo = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for path, expected in p["registry_files"].items():
        candidates = list((cargo / "registry/src").glob("*/" + path))
        assert candidates and all(identity(candidate) == expected for candidate in candidates), path
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
    assert v["test_groups_passed"] == 2 and v["input_mmcs_commits"] == 6
    assert v["new_composite_input_commits"] == v["retained_input_commits"] == 3
    assert v["pcs_openings"] == v["fri_mmcs_commits"] == v["stark_proofs"] == 0
    assert v["native_signature_traces"] == v["wide_symbolic_evaluations"] == 0
    assert v["reserved_files_per_owner"] == 12 and v["reserved_bytes_per_owner"] == 1292288
    assert v["captured_final_matrices"] == 10 and v["captured_bytes"] == 1277952
    assert not v["full_payment_implemented"] and not v["production_security_claim"]
    assert not v["whole_prover_entry_implemented"] and not v["other_file_fault_branches_executed"]
    g = v["guard"]
    assert g["process_limit_bytes"] == g["aggregate_limit_bytes"] == 536870912
    assert g["minimum_available_bytes"] == 2147483648 and g["timeout_seconds"] == 120
    assert g["readback_verified"] and g["test_counts_verified"]
    assert g["available_before_bytes"] >= g["minimum_available_bytes"]
    assert 0 < g["peak_process_commit_bytes"] <= g["process_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= 536870912
    print("Composite source identities and six input commitment scope match")


if __name__ == "__main__":
    main()
