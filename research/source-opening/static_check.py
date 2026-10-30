"""Source identities and exact finite PCS opening scope without rerunning proofs."""
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
    for block in path.read_text(encoding="utf-8").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\r\n\\]+)"$', block, re.MULTILINE))
        if "source" in fields:
            assert all(x in fields for x in ["name", "version", "source", "checksum"])
            result.add(tuple(fields[x] for x in ["name", "version", "source", "checksum"]))
    return result


def main():
    p = json.loads((HERE / "provenance.json").read_text(encoding="utf-8"))
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
    features = json.loads((HERE / "fixtures/features.json").read_text(encoding="utf-8"))
    assert len(features) == 63 and not any(k.startswith("rayon/") or k.startswith("rayon-core/") or "parallel" in v for k, v in features.items())
    r = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert r["provenance"] == identity(HERE / "provenance.json")
    assert r["test_groups_passed"] == 1 and r["pcs_opening_proofs"] == 3
    assert r["mmcs_commit_calls"] == r["mmcs_multi_open_calls"] == 30
    assert r["input_mmcs_commit_calls"] == r["input_mmcs_multi_open_calls"] == 3
    assert r["fri_mmcs_commit_calls"] == r["fri_mmcs_multi_open_calls"] == 27
    assert r["refused_clone_open_calls"] == 1 and r["scalar_mmcs_open_calls"] == 0
    assert r["retained_verifier_accepts"] == r["retained_verifier_rejects"] == 3
    assert r["encoded_proof_bytes"] == 341711 and r["captured_leaf_bytes"] == 752896
    assert r["independent_roots"] == 10 and r["independent_extension_claims"] == 4
    for name in ["stark_proofs", "native_signature_traces", "wide_symbolic_evaluations"]:
        assert r[name] == 0
    assert r["full_payment_implemented"] is False and r["production_security_claim"] is False
    guard = r["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_verified"] and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    print("Opening source identities and the finite scope of three proofs match")


if __name__ == "__main__":
    main()
