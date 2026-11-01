"""Read recorded evidence only. Does not import or execute monetary arithmetic."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent


def identity(path, raw=False):
    data = path.read_bytes()
    if not raw:
        data = data.replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    if not __debug__:
        raise RuntimeError("Optimized evidence check refused")
    provenance = json.loads((ROOT / "provenance.json").read_bytes())
    validation = json.loads((ROOT / "validation.json").read_bytes())
    assert identity(ROOT / "provenance.json") == validation["provenance"]
    for name, expected in provenance["files"].items():
        path = (ROOT / name).resolve()
        assert path.is_relative_to(ROOT)
        assert identity(path, expected["raw"]) == {k: expected[k] for k in ("bytes", "sha256")}
    for name, expected in provenance["repository_context"].items():
        path = (REPO / name).resolve()
        assert path.is_relative_to(REPO)
        assert identity(path, expected["raw"]) == {k: expected[k] for k in ("bytes", "sha256")}
    policy = provenance["policy"]
    assert identity(REPO / policy["path"]) == policy["identity"]
    result = json.loads((ROOT / "result.json").read_bytes())
    assert result["profile"] == "kova.monetary.paired60.v1" and len(result["period_pairs"]) == 240
    expected_counts = {"period_pairs": 240, "phase_boundaries": 960, "previous_period_neighbors": 239,
                       "nominal_literals": 13, "pair_literals": 7, "allocation_literals": 6,
                       "fully_earned_cap_pairs": 200, "uncapped_earned_burn_pairs": 180,
                       "wrong_alternatives": 8, "restored_checks": 8, "actual_numeric_refusals": 16,
                       "near_cap_counterexamples": 1, "maximum_prefix_bits": 89}
    assert result["counts"] == expected_counts == validation["counts"]
    guard = validation["guard"]
    assert validation["reference_attempts"] == 1 and guard["accepted"] and guard["exit_code"] == 0
    assert guard["installed_process_commit_limit_bytes"] == 536870912
    assert guard["installed_job_commit_limit_bytes"] == 536870912 and guard["installed_job_flags"] == 8960
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert not guard["timed_out"] and not guard["working_guard_terminated"]
    assert validation["post_reference_inputs"] == 1643
    assert identity(ROOT / "result.json", True) == validation["result"]
    print(f"Recorded evidence PASS {len(provenance['files'])} files/{len(provenance['repository_context'])} contexts, no model replay")


if __name__ == "__main__":
    main()
