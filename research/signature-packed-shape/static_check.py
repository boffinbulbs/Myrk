"""Identity and saved complete symbolic shape checks without AIR execution."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate symbolic source identities")
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
    return {tuple(p.get(k, "") for k in ("name", "version", "source", "checksum"))
            for p in tomllib.loads(read(path).decode())["package"] if "source" in p}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    parser.add_argument("--registry-root", type=Path)
    args = parser.parse_args()
    p = json.loads(read(HERE / "provenance.json"))
    for name, expected in p["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in p["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    if args.registry_root is not None:
        for name, expected in p["registry_source_files"].items():
            assert identity(args.registry_root / name) == expected, name
    assert read(HERE / "LICENSE") == read(ROOT / "LICENSE")
    selected = packages(HERE / "Cargo.lock")
    assert len(selected) == 80 and selected <= packages(ROOT / "Cargo.lock")
    features = json.loads(read(HERE / "fixtures-features.json"))
    assert features == json.loads(read(ROOT / "research/signature-packed/fixtures-features.json"))
    assert set(features) == {name + "/" + version for name, version, _, _ in selected}
    assert not any(k.startswith(("rayon/", "rayon-core/")) or "parallel" in v for k, v in features.items())
    manifest = tomllib.loads(read(HERE / "Cargo.toml").decode())
    assert not manifest["package"]["autotests"] and not manifest["package"]["autobins"]
    assert not manifest["dev-dependencies"]["kova-signature-packed"]["default-features"]
    assert manifest["test"] == [dict(name="shape", path="tests/shape.rs")]
    s = json.loads(read(HERE / "fixtures-symbolic.json"))
    assert s == dict(backend_proofs=0, columns=43176, constraints=69242, degree=4,
                     degree_histogram=[72, 3367, 46989, 18156, 658, 0, 0, 0],
                     degrees_outside_histogram=0, native_traces=0, public_values=196,
                     symbolic_collections=1)
    assert 71141 - 7637 + 2547 + 3000 + 125 == 69176
    assert 69176 <= s["constraints"] <= 69176 + 250
    assert sum(s["degree_histogram"]) == s["constraints"]
    v = json.loads(read(HERE / "validation.json"))
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["symbolic_collections"] == 1 and v["native_traces"] == v["backend_proofs"] == 0
    assert not v["full_payment_implemented"] and not v["production_security_claim"]
    assert not v["native_execution_feature_enabled"]
    g = v["guard"]
    assert g["accepted"] and g["exit_code"] == 0 and g["actual_passed"] == g["expected_tests"] == 1
    assert g["actual_failed"] == g["actual_ignored"] == 0 and g["test_counts_verified"]
    assert g["hard_limit_installed"] and g["installed_job_flags"] == 8960
    assert not g["timed_out"] and not g["working_guard_terminated"] and not g["output_limit_exceeded"]
    assert g["installed_process_commit_limit_bytes"] == g["installed_job_commit_limit_bytes"] == 536870912
    assert g["minimum_available_bytes"] == 2147483648 <= g["available_before_bytes"]
    assert g["timeout_seconds"] == 120
    assert 0 < g["peak_private_commit_bytes"] <= g["installed_process_commit_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["installed_job_commit_limit_bytes"]
    if args.check_results:
        assert read(HERE / "results/symbolic.json") == read(HERE / "fixtures-symbolic.json")
    print("Complete symbolic source identities and recorded shape match")


if __name__ == "__main__":
    main()
