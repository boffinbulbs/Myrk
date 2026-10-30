"""Recorded fixed relation input and nonproving resource boundary checks."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def packages(path):
    return {(p["name"], p["version"], p["source"], p["checksum"])
            for p in tomllib.loads(path.read_text(encoding="utf-8"))["package"]
            if "source" in p}


def check_observations(records):
    assert len(records) == 6
    by_kind = {kind: [r for r in records if r["kind"] == kind]
               for kind in ["public_binding", "canonical_refusal", "resource_refusal"]}
    binding = by_kind["public_binding"]
    assert [r["transaction"] for r in binding] == ["T0", "T1"]
    for record in binding:
        assert record["canonical_bytes"] == 3774 and record["public_values"] == 196
        assert record["canonical_equal"] and record["public_equal"]
        assert record["unchanged_after_external_mutation"]
    errors = by_kind["canonical_refusal"]
    assert [r["case"] for r in errors] == ["empty_inputs", "empty_outputs"]
    assert all(r["error"] == "Some(LimitExceeded)" for r in errors)
    refusals = by_kind["resource_refusal"]
    assert [r["queries"] for r in refusals] == [64, 1]
    for record in refusals:
        assert record["result"] == "Err(Resource(RawWidth))"
        assert record["before"] == record["after"] == [0, 0, 0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    parser.add_argument("--registry-root", type=Path)
    args = parser.parse_args()
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    for name, pin in provenance["repository_files"].items():
        assert identity(ROOT / name) == pin, name
    for name, pin in provenance["execution_source_files"].items():
        assert identity(HERE / name) == pin, name
    for name, pin in provenance["experiment_files"].items():
        assert identity(HERE / name) == pin, name
    if args.registry_root:
        for name, pin in provenance["registry_source_files"].items():
            assert identity(args.registry_root / name) == pin, name
    assert len(packages(HERE / "Cargo.lock")) == 90
    assert packages(HERE / "Cargo.lock") <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures-features.json").read_bytes())
    retained = json.loads((HERE.parent / "proof-preflight/fixtures/features.json").read_bytes())
    assert features.keys() == retained.keys()
    assert all(set(v) <= set(retained[k]) for k, v in features.items())
    assert not any("parallel" in v or k.startswith("rayon/") for k, v in features.items())
    assert provenance["packed_native_execution_enabled"] is False
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    fixture = json.loads((HERE / "fixtures-public.json").read_bytes())
    source = ROOT / fixture["source"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == fixture["source_sha256"]
    assert fixture["transactions"] == json.loads(source.read_bytes())["transactions"]
    observations = [json.loads(line) for line in (HERE / "fixtures-observations.jsonl").read_text().splitlines()]
    check_observations(observations)
    validation = json.loads((HERE / "validation.json").read_bytes())
    assert validation["provenance"] == identity(HERE / "provenance.json")
    assert validation["integration_tests_passed"] == 3
    assert validation["backend_proofs"] == validation["native_traces"] == 0
    assert validation["symbolic_air_evaluations"] == 0
    assert validation["complete_profile_validated"] is False
    assert validation["private_payment_verified"] is False
    guard = validation["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_flags"] == 8960 and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    if args.check_results:
        assert (HERE / "results/observations.jsonl").read_bytes() == (HERE / "fixtures-observations.jsonl").read_bytes()
        receipt = json.loads((HERE / "results/signature-proof-contract-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert receipt["accepted"] and receipt["test_counts_verified"]
        assert [receipt[k] for k in ["actual_passed", "actual_failed", "actual_ignored"]] == [3, 0, 0]
    print("Fixed signature input, retained resource refusal and recorded scope match")


if __name__ == "__main__":
    main()
