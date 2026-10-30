"""Pinned source and finite root construction scope, without replaying commits."""
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
    for name in ["LICENSE-MIT", "LICENSE-APACHE"]:
        assert (HERE / name).read_bytes() == (HERE.parent / "storage-pcs/backend" / name).read_bytes()
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    own = packages(HERE / "Cargo.lock")
    assert len(own) == 63 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text(encoding="utf-8"))
    assert len(features) == 63 and features["p3-fri/0.8.0"] == []
    assert not any(k.startswith("rayon/") or k.startswith("rayon-core/") or "parallel" in v for k, v in features.items())
    r = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert r["provenance"] == identity(HERE / "provenance.json")
    assert r["test_groups_passed"] == 4 and r["input_mmcs_calls"] == 4
    assert r["returned_commitments"] == 3 and r["post_actual_mmcs_unwinds"] == 1
    for name in ["extension_mmcs_calls", "opening_calls", "backend_proofs", "native_traces", "wide_symbolic_evaluations"]:
        assert r[name] == 0
    assert r["independent_leaf_rows"] == 4096 and r["captured_leaf_bytes"] == 360448
    assert r["ordinary_trait_entry_implemented"] is False and r["production_security_claim"] is False
    assert r["guard"]["process_limit_bytes"] == r["guard"]["aggregate_limit_bytes"] == 536870912
    assert r["guard"]["minimum_available_bytes"] == 2147483648 and r["guard"]["timeout_seconds"] == 120
    assert r["guard"]["readback_verified"] and r["guard"]["test_counts_verified"]
    assert 0 < r["guard"]["peak_job_commit_bytes"] <= 536870912
    print("Commitment source, reference identities and four-call finite scope match")


if __name__ == "__main__":
    main()
