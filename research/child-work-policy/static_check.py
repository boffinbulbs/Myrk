"""Inspect saved work-policy evidence without executing target arithmetic."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def identity(path, raw=False):
    with path.open("rb") as source:
        data = source.read(1048577)
    assert len(data) <= 1048576
    if not raw:
        data = data.replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    if not __debug__:
        raise RuntimeError("Optimized inspection refused")
    provenance = json.loads((HERE / "provenance.json").read_text(encoding="utf8"))
    for name, pin in provenance["source_files"].items():
        assert identity(HERE / name, pin["raw"]) == pin["identity"], name
    assert len(provenance["upstream_files"]) == 11
    assert sum(x["bytes"] for x in provenance["upstream_files"]) == 182896
    assert all(x["revision"] == "631badbf64766fa8c2d38f099e937f8c6cb19014"
               for x in provenance["upstream_files"])
    validation = json.loads((HERE / "validation.json").read_text(encoding="utf8"))
    assert validation["provenance"] == identity(HERE / "provenance.json")
    assert validation["reference_attempts"] == 1 and validation["post_reference_files_verified"] == 964
    guard = validation["guard"]
    assert guard["accepted"] and guard["launched"] and guard["exit_code"] == 0
    assert guard["hard_limit_installed"]
    assert guard["installed_process_commit_limit_bytes"] == guard["installed_job_commit_limit_bytes"] == 536870912
    assert guard["available_before_bytes"] >= guard["minimum_available_bytes"] == 2147483648
    assert guard["timeout_seconds"] == 120 and guard["installed_job_flags"] == 8960
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    assert not any(guard[k] for k in ("timed_out", "working_guard_terminated", "output_limit_exceeded"))
    assert validation["result"] == identity(HERE / "result.json", True)
    result = json.loads((HERE / "result.json").read_text())
    expected = {"primary_raw_cases": 18, "literal60_cases": 12, "grid_cases": 32,
                "extreme_cases": 4, "wrong_formulas": 8, "restored_checks": 8,
                "median_windows": 12, "numeric_time_cases": 6, "work_literals": 5,
                "maximum_work_sum_bits": 319, "saved_cases": 66}
    assert result["counts"] == validation["counts"] == expected
    assert len(result["cases"]) == 66 and len({x["label"] for x in result["cases"]}) == 66
    assert {x["spacing"] for x in result["cases"]} == {60, 600}
    assert all(len(x[field]) == 64 for x in result["cases"] for field in ("ref", "limit", "target"))
    primary = json.loads((HERE / "primary-cases.json").read_text())
    assert len(primary["cases"]) == 18 and primary["parent_time_added"] == 600
    single = next(x for x in result["cases"] if x["label"] == "primary-14")
    assert single["target"] == primary["constants"]["SINGLE300"]
    assert identity(HERE / "result.json", True)["bytes"] == 19194
    print("Child work source identities and saved arithmetic evidence verified. No model or verifier replay.")


if __name__ == "__main__":
    main()
