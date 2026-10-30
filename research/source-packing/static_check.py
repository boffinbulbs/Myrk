"""Exact source identities and the bounded packed source mechanism record."""
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
    assert len(own) == 42 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text())
    basis = json.loads((ROOT / "research/source-opening/fixtures/features.json").read_text())
    assert len(features) == 42 and features.keys() <= basis.keys()
    assert all(set(v) <= set(basis[k]) for k, v in features.items())
    assert not any(k.startswith("rayon") or "parallel" in v for k, v in features.items())
    v = json.loads((HERE / "validation.json").read_text())
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["test_groups_passed"] == 2
    assert v["symbolic_collections"] == v["native_traces"] == v["max_live_traces"] == 1
    assert v["positive_checks"] == 21 and v["restoration_checks"] == v["rejections"] == 18
    assert v["constraints"] == 1451 and v["degree"] == 2
    assert v["rows"] == 16 and v["width"] == 1364 and v["raw_bytes"] == 87296
    assert v["held_words"] == 60 and v["read_ports"] == 48 and v["consumer_columns"] == 136
    assert v["backend_proofs"] == v["wide_signature_traces"] == 0
    assert v["actual_native_constraint_checks"] == 39 and v["failure_threshold"] == 1
    assert v["row_granular_threshold"] and v["failure_bound_per_row"] == 1451
    assert not v["full_signature_integration"] and not v["full_payment_implemented"]
    assert not v["production_security_claim"] and not v["net_full_layout_savings_measured"]
    g = v["guard"]
    assert g["invocations"] == 2 and g["groups_per_invocation"] == 1
    assert g["symbolic_admitted_before_native"]
    assert len(g["available_before_each_bytes"]) == 2
    assert g["available_before_bytes"] == min(g["available_before_each_bytes"])
    assert g["process_limit_bytes"] == g["aggregate_limit_bytes"] == 536870912
    assert g["minimum_available_bytes"] == 2147483648 and g["timeout_seconds"] == 120
    assert g["per_invocation_timeout_seconds"] == 60
    assert g["readback_verified"] and g["test_counts_verified"]
    assert g["available_before_bytes"] >= g["minimum_available_bytes"]
    assert 0 < g["peak_process_commit_bytes"] <= g["process_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["aggregate_limit_bytes"]
    print("Packed source identities and the finite native mechanism scope match")


if __name__ == "__main__":
    main()
