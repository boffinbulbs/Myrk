"""Check the retained source, fixture and execution identities."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def validate_execution(execution):
    require(execution["actual_constraints_per_row"] == 146260 and execution["actual_degree"] == 4, "Symbolic shape differs")
    require(execution["backend_proofs"] == 0, "Execution scope differs")
    expected = {
        "tests::shape_schedule_and_private_routes": 60,
        "tests::actual_symbolic_shape_and_degree": 180,
        "tests::sixteen_direct_source_transforms_and_locally_exact_crosswires": 1200,
    }
    tests = execution["selected_tests"]
    require(len(tests) == 3 and {test["test"] for test in tests} == set(expected), "Selected test set differs")
    for test in tests:
        require(test["harness"] == [1, 0, 0, 0, 2], "Selected test result differs")
        require(test["installed_process_limit_bytes"] == test["installed_aggregate_limit_bytes"] == 2147483648, "Resource limit differs")
        require(test["installed_flags"] == 8960 and test["accepted"] and not test["timed_out"], "Resource result differs")
        require(test["minimum_available_bytes"] == 5368709120 and test["available_before_bytes"] >= test["minimum_available_bytes"], "Memory admission differs")
        require(0 < test["peak_job_commit_bytes"] <= 2147483648, "Observed memory differs")
        require(test["timeout_seconds"] == expected[test["test"]], "Deadline differs")
        summary = re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in [0-9.]+s$", test["stdout"], re.MULTILINE)
        require(len(summary) == 1, "Raw harness summary differs")


def main():
    source = json.loads((ROOT / "source_record.json").read_text(encoding="utf-8"))
    expected = {"Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "static_check.py"}
    expected.update(path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.rs"))
    require(set(source["files"]) == expected, "Source file set differs")
    for name, value in source["files"].items():
        require(identity(ROOT / name) == value, f"Source identity differs: {name}")
    for name in ("../signature-ownership/raw-fixture.json", "../signature-ownership/reference-fixture.json"):
        require(identity(ROOT / name) == source["runtime_fixtures"][name], f"Fixture identity differs: {name}")
    for name, value in source["public_source_origins"].items():
        require(identity(ROOT.parent.parent / name) == value, f"Retained origin differs: {name}")
    shape = source["shape"]
    require((shape["height"], shape["width"], shape["public_values"]) == (8192, 44678, 196), "Shape differs")
    execution = json.loads((ROOT / "execution_record.json").read_text(encoding="utf-8"))
    require(execution["source_record_sha256"] == identity(ROOT / "source_record.json")["sha256"], "Execution source differs")
    validate_execution(execution)
    print("Native signature source, fixtures and scoped execution identities match.")


if __name__ == "__main__":
    main()
