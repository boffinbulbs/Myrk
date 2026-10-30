"""Source identities and independent native record checks without AIR execution."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate native evidence")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def read(path):
    limit = 9 * 1024 * 1024 if path.name == "reference-fixture.json" else 524288
    with path.open("rb") as file:
        raw = file.read(limit + 1)
    assert len(raw) <= limit, path
    return raw.replace(b"\r\n", b"\n")


def identity(path):
    raw = read(path)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def packages(path):
    return {tuple(p.get(k, "") for k in ("name", "version", "source", "checksum"))
            for p in tomllib.loads(read(path).decode())["package"] if "source" in p}


def check_records(native_path, observations_path):
    n = json.loads(read(native_path))
    assert n == dict(tuple="A0", key="A", signature="A0", transaction="T0", note="N_A",
                     height=8192, width=43176, public_values=196, constraints_per_row=69242,
                     constructed_traces=1, maximum_live_traces=1, full_positive_scans=1,
                     negative_borrowed_checks=6, restored_positive_borrowed_checks=6,
                     borrowed_frame_evaluations=24, independent_byte_comparisons=5,
                     independent_bytes=288, canonical_transaction_match=True,
                     authorization_values_match=True, symbolic_collections=0, backend_proofs=0)
    records = [json.loads(line) for line in read(observations_path).splitlines()]
    assert len(records) == 15
    assert records[0] == dict(phase="constructed", height=8192, width=43176, raw_field_bytes=1414791168)
    assert records[1] == dict(phase="independent_bytes", comparisons=5, bytes=288,
                              canonical_transaction_match=True, authorization_values_match=True)
    assert records[2] == dict(phase="baseline", accepted=True, reported_trace_height=8192,
                              constraints_per_row=69242, all_rows_checked=True, failures=0, first_failures=[])
    # Independent source ledger and selected fixture arithmetic determine these
    # exact roots and cells, rather than learning them from a native observation.
    cases = [
        ("unread_word_hold", [599, 600], [10724], [[580], [580]]),
        ("compensated_boolean_pair", [8191, 0], [13511, 13512], [[], [3367, 3368]]),
        ("key_source_read", [8191, 0], [13511], [[], [6141, 25047]]),
        ("signature_prefix_boundary", [8191, 0], [14111], [[], [6182, 21797]]),
        ("note_owner_read", [233, 234], [15503], [[], [6280, 25052]]),
        ("late_note_context", [8190, 8191], [13759], [[], [6157, 24958]]),
    ]
    for i, (name, rows, cells, indices) in enumerate(cases):
        mutated, restored = records[3 + 2*i:5 + 2*i]
        assert mutated == dict(name=name, phase="mutated", frame_rows=rows, changed_columns=cells,
                                failures=[len(v) for v in indices], first_indices=indices,
                                all_held_only=i == 0, all_boolean_only=i == 1,
                                has_port_failure=i >= 2, has_consumer_failure=i >= 2,
                                exact_port_match=[False, i >= 2], exact_consumer_match=[False, i >= 2])
        assert restored == dict(name=name, phase="restored", frame_rows=rows, failures=[0, 0],
                                 first_indices=[[], []], all_held_only=True, all_boolean_only=True,
                                 has_port_failure=False, has_consumer_failure=False,
                                 exact_port_match=[False, False], exact_consumer_match=[False, False])


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
    dependency = manifest["dev-dependencies"]["kova-signature-packed"]
    assert not dependency["default-features"] and dependency["features"] == ["native-execution"]
    assert manifest["test"] == [dict(name="native", path="tests/native.rs")]
    assert not manifest["package"]["autotests"] and not manifest["package"]["autobins"]
    check_records(HERE / "fixtures-native.json", HERE / "fixtures-observations.jsonl")
    v = json.loads(read(HERE / "validation.json"))
    assert v["provenance"] == identity(HERE / "provenance.json")
    assert v["native_traces"] == 1 and v["symbolic_collections"] == v["backend_proofs"] == 0
    assert not v["full_payment_implemented"] and not v["production_security_claim"]
    g = v["guard"]
    assert g["accepted"] and g["exit_code"] == 0 and g["actual_passed"] == g["expected_tests"] == 1
    assert g["actual_failed"] == g["actual_ignored"] == 0 and g["test_counts_verified"]
    assert g["hard_limit_installed"] and g["installed_job_flags"] == 8960
    assert not g["timed_out"] and not g["working_guard_terminated"] and not g["output_limit_exceeded"]
    assert g["installed_process_commit_limit_bytes"] == g["installed_job_commit_limit_bytes"] == 2147483648
    assert g["minimum_available_bytes"] == 5368709120 <= g["available_before_bytes"]
    assert g["timeout_seconds"] == 300
    assert 0 < g["peak_private_commit_bytes"] <= g["installed_process_commit_limit_bytes"]
    assert 0 < g["peak_job_commit_bytes"] <= g["installed_job_commit_limit_bytes"]
    if args.check_results:
        check_records(HERE / "results/native.json", HERE / "results/observations.jsonl")
        assert read(HERE / "results/native.json") == read(HERE / "fixtures-native.json")
        assert read(HERE / "results/observations.jsonl") == read(HERE / "fixtures-observations.jsonl")
    print("Complete native source identities and causal control records match")


if __name__ == "__main__":
    main()
