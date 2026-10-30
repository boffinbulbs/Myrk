"""Recorded source, dependency and route result identities without route execution."""
import difflib
import hashlib
import json
from pathlib import Path
import sys
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 524288


def read(path):
    with path.open("rb") as file:
        raw = file.read(CAP + 1)
    assert len(raw) <= CAP, path
    return raw.replace(b"\r\n", b"\n")


def identity(path):
    raw = read(path)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def packages(path):
    return {
        tuple(p.get(k, "") for k in ("name", "version", "source", "checksum"))
        for p in tomllib.loads(read(path).decode())["package"] if "source" in p
    }


def main():
    p = json.loads(read(HERE / "provenance.json"))
    for name, expected in p["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in p["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    assert read(HERE / "LICENSE") == read(ROOT / "LICENSE")
    origins = json.loads(read(HERE / "origins.json"))
    patch = "".join("".join(difflib.unified_diff(
        read(ROOT / old).decode().splitlines(True),
        read(HERE / new).decode().splitlines(True),
        fromfile=old, tofile="research/signature-packed/" + new,
    )) for new, old in origins.items())
    assert patch.encode() == read(HERE / "adaptation.patch")
    selected = packages(HERE / "Cargo.lock")
    assert len(selected) == 80 and selected <= packages(ROOT / "Cargo.lock")
    features = json.loads(read(HERE / "fixtures-features.json"))
    assert set(features) == {name + "/" + version for name, version, _, _ in selected}
    assert not any(k.startswith(("rayon/", "rayon-core/")) or "parallel" in v for k, v in features.items())
    c = tomllib.loads(read(HERE / "Cargo.toml").decode())
    assert not c["package"]["autotests"] and c["features"]["default"] == []
    assert c["features"]["native-execution"] == []
    assert c["test"] == [dict(name="routes", path="tests/routes.rs")]
    route = json.loads(read(HERE / "fixtures-routes.json"))
    assert route == dict(physical_rows=8192, held_words=2547, peak_words=125, peak_row=234,
                         literal_word_selections=423569, invalid_metadata_refusals=8,
                         same_block_rank_change=True, word_lifetimes_match=True,
                         native_traces=0, symbolic_collections=0, backend_proofs=0)
    v = json.loads(read(HERE / "validation.json"))
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["columns"] == 43176 and v["raw_trace_bytes_arithmetic"] == 8192 * 43176 * 4
    assert v["constraint_count"] is None and v["constraint_degree"] is None
    assert v["air_evaluations"] == v["native_traces"] == v["symbolic_collections"] == v["backend_proofs"] == 0
    assert not v["native_execution_run"] and not v["full_payment_implemented"]
    assert not v["production_security_claim"] and v["default_execution_denied"]
    g = v["guard"]
    assert g["accepted"] and g["exit_code"] == 0 and g["actual_passed"] == 1
    assert g["actual_failed"] == g["actual_ignored"] == 0 and g["test_counts_verified"]
    assert not g["timed_out"] and not g["working_guard_terminated"] and not g["output_limit_exceeded"]
    assert g["installed_process_commit_limit_bytes"] == g["installed_job_commit_limit_bytes"] == 536870912
    assert g["installed_job_flags"] == 8960 and g["hard_limit_installed"]
    assert g["minimum_available_bytes"] == 2147483648 <= g["available_before_bytes"]
    assert g["timeout_seconds"] == 120
    assert 0 < g["peak_private_commit_bytes"] <= g["installed_process_commit_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["installed_job_commit_limit_bytes"]
    if sys.argv[1:] == ["--check-results"]:
        assert read(HERE / "results/routes.json") == read(HERE / "fixtures-routes.json")
    else:
        assert sys.argv[1:] == []
    print("Complete candidate identities and fixed route record match")


if __name__ == "__main__":
    main()
