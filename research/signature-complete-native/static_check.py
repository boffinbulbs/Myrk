"""Check source, fixture and recorded native execution identities."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
SELECTORS = {
    "full_tests::declared_shape_schedule_and_full_state_routes": 60,
    "full_tests::bounded_typed_reference_reader_without_json_value_tree": 180,
    "full_tests::actual_symbolic_full_shape_count_and_degree": 300,
    "full_tests::single_a0_construction_without_air_evaluation": 600,
    "full_tests::ten_bounded_same_witness_relations_against_independent_integer_reference": 1200,
    "full_tests::locally_exact_detached_suffixes_and_source_boundary_mutations_reject": 1800,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def module_body_identity(data):
    lines = data.splitlines(keepends=True)
    while lines and lines[0].startswith(b"//!"):
        lines.pop(0)
    return hashlib.sha256(b"".join(lines)).hexdigest()


def validate_execution(record):
    require((record["height"], record["width"], record["public_values"]) == (8192, 55049, 196), "Relation shape differs")
    require((record["constraints_per_row"], record["degree"]) == (205201, 4), "Symbolic relation differs")
    require(record["backend_proofs"] == 0, "Execution scope differs")
    require(record["reference_tuples"] == {"accepted": 5, "rejected": 5}, "Reference classification differs")
    require(record["hostile_assertions"] == {
        "mutation_cases": 77, "full_air_negative": 15,
        "localized_negative": 64, "localized_positive": 128,
        "full_air_positive": 4, "diagnostic_positive": 4,
        "full_trace_seed_crosschecks": 2,
    }, "Hostile evaluation scope differs")
    tests = record["selected_tests"]
    require(len(tests) == 6 and {test["test"] for test in tests} == set(SELECTORS), "Exact test set differs")
    for test in tests:
        require(test["accepted"] and not test["timed_out"] and not test["terminated"], "Action did not finish normally")
        require(test["harness"] == [1, 0, 0, 0, 5], "Selected harness differs")
        require(test["process_limit_bytes"] == test["aggregate_limit_bytes"] == 2147483648, "Installed memory limits differ")
        require(test["installed_flags"] == 8960, "Installed job flags differ")
        require(test["minimum_available_bytes"] == 5368709120 and test["available_before_bytes"] >= test["minimum_available_bytes"], "Memory admission differs")
        require(0 < test["peak_job_commit_bytes"] <= 2147483648, "Observed memory differs")
        require(test["timeout_seconds"] == SELECTORS[test["test"]], "Deadline differs")
        summary = re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in [0-9.]+s$", test["stdout"], re.MULTILINE)
        require(len(summary) == 1 and not test["stderr"], "Raw selected outcome differs")


def main():
    source = json.loads((ROOT / "provenance.json").read_text(encoding="utf-8"))
    actual_files = {
        p.relative_to(ROOT).as_posix()
        for p in ROOT.rglob("*")
        if p.is_file()
        and not {"__pycache__", "target"}.intersection(p.relative_to(ROOT).parts)
        and p.relative_to(ROOT).as_posix() not in ("provenance.json", "execution_record.json")
    }
    require(set(source["local_files"]) == actual_files, "Package file set differs")
    for name, value in source["local_files"].items():
        require(identity(ROOT / name) == value, "Local source differs: " + name)
    for name, value in source["repository_references"].items():
        require(identity(REPO / name) == value, "Retained repository source differs: " + name)
    record = json.loads((ROOT / "execution_record.json").read_text(encoding="utf-8"))
    require(record["provenance_sha256"] == identity(ROOT / "provenance.json")["sha256"], "Execution source record differs")
    rust_files = {p.relative_to(ROOT).as_posix() for p in (ROOT / "src").rglob("*.rs")}
    require(set(record["measured_module_body_sha256"]) == rust_files, "Measured Rust source set differs")
    require(set(record["measured_source_file_sha256"]) == rust_files, "Measured full file set differs")
    changes = record["documentation_only_changes"]
    require(set(changes) == {"src/air.rs", "src/build.rs"}, "Documentation patch set differs")
    for name, value in record["measured_source_file_sha256"].items():
        data = (ROOT / name).read_bytes()
        if name in changes:
            change = changes[name]
            before = bytes.fromhex(change["before_line_hex"])
            after = change["after_line"].encode()
            require(before.startswith((b"///", b"//!")) and after.startswith((b"///", b"//!")), "Non Rustdoc patch")
            require(len(before.splitlines()) == len(after.splitlines()) == 1, "Multiline documentation patch")
            require(data.splitlines(keepends=True).count(after) == 1, "Current documentation differs")
            require(identity(ROOT / name)["sha256"] == change["current_file_sha256"], "Current documented file differs")
            require(change["measured_file_sha256"] == value, "Documentation measurement differs")
            data = data.replace(after, before, 1)
        require(hashlib.sha256(data).hexdigest() == value, "Measured full Rust source reconstruction differs: " + name)
        require(module_body_identity(data) == record["measured_module_body_sha256"][name], "Measured executable source body differs: " + name)
    validate_execution(record)
    print("Complete native signature source, fixture and scoped execution identities match.")


if __name__ == "__main__":
    main()
