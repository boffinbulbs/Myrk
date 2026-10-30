"""Pinned preparation, streamed construction and finite execution scope."""
import hashlib
import json
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
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
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    own = packages(HERE / "Cargo.lock")
    assert len(own) == 62 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text(encoding="utf-8"))
    assert len(features) == 62 and not any(x.startswith("rayon/") or x.startswith("rayon-core/") for x in features)
    assert not any("parallel" in items for items in features.values())
    r = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert r["provenance"] == identity(HERE / "provenance.json")
    assert r["test_groups_passed"] == 8
    for name in ["backend_proofs", "commitment_calls", "opening_calls", "native_traces", "wide_symbolic_evaluations"]:
        assert r[name] == 0
    for name in ["pcs_entry_implemented", "matrix_store_dispatch_implemented", "production_secret_storage", "durable_cleanup", "production_security_claim"]:
        assert r[name] is False
    assert r["owned_field_files"] == 3 and r["owned_reserved_bytes"] == 112640
    assert r["dense_field_files"] == 2 and r["dense_reserved_bytes"] == 110592
    assert r["physical_fields_compared_per_route"] == 24576 and r["independent_cells"] == 16
    assert r["largest_input_tile_fields"] == 2048 and r["largest_output_tile_fields"] == 16384
    guard = r["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_verified"] and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    print("Streamed construction identities, features and finite scope match")


if __name__ == "__main__":
    main()
