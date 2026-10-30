"""Frozen source and record checks without repeating either scalar sweep."""
import hashlib
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate inventory identities")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 524288


def read(path):
    with path.open("rb") as file:
        raw = file.read(CAP + 1)
    assert len(raw) <= CAP
    return raw


def identity(path):
    raw = read(path).replace(b"\r\n", b"\n")
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    p = json.loads(read(HERE / "provenance.json"))
    for name, expected in p["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in p["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    assert read(HERE / "LICENSE") == read(ROOT / "LICENSE")
    c = json.loads(read(HERE / "fixtures-certificate.json"))
    runtime = json.loads(read(HERE / "fixtures-runtime.json"))
    observed = [json.loads(line) for line in read(HERE / "fixtures-observations.jsonl").splitlines()]
    assert runtime["generator_passes"] == runtime["reference_passes"] == 1
    assert runtime["positive_validations"] == 9 and runtime["validation_calls"] == 17
    assert runtime["rows_per_pass"] == 8192 and runtime["restoration_accepts"] == len(observed) == 8
    assert runtime["tampered_reports_rejected"] == [case["name"] for case in observed]
    assert all(case["rejected"] is True for case in observed)
    assert runtime["symbolic_collections"] == runtime["native_traces"] == runtime["backend_proofs"] == 0
    assert c["source_manifest"] == identity(HERE / "sources.json")
    assert c["metric_maxima"][c["metric_names"].index("unique_words")] == 125
    assert c["metric_peak_rows"][c["metric_names"].index("unique_words")] == 234
    assert c["row234_lower_bound"] == 91 and len(c["fixed_note_words"]) == 25
    assert len(c["family_counts"]) == 13 and len(c["initial_blocks"]) == 69
    assert all(not bank["gaps"] for bank in c["coverage"].values())
    assert not c["analysis_limits"]["integrated_layout"] and not c["analysis_limits"]["net_savings_measured"]
    assert not c["analysis_limits"]["public_fields_intrinsically_bytes"]
    v = json.loads(read(HERE / "validation.json"))
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["certificate_bytes"] == 97665 and v["artifact_cap_bytes"] == CAP
    assert v["generic_process_receipt"] and not v["native_test_summary"]
    assert not v["integrated_signature"] and not v["full_payment_implemented"] and not v["production_security_claim"]
    g = v["guard"]
    assert g["process_limit_bytes"] == g["aggregate_limit_bytes"] == 536870912
    assert g["minimum_available_bytes"] == 2147483648 and g["timeout_seconds"] == 120
    assert g["readback_verified"] and g["available_before_bytes"] >= g["minimum_available_bytes"]
    assert 0 < g["peak_process_commit_bytes"] <= g["process_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["aggregate_limit_bytes"]
    print("Source inventory identities and the consumed finite scalar record match")


if __name__ == "__main__":
    main()
