"""Recorded initial hash construction and same owner decoding scope."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

if not __debug__:
    raise RuntimeError("Optimized Python cannot check source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def packages(path):
    return {(p["name"], p["version"], p["source"], p["checksum"])
            for p in tomllib.loads(path.read_text(encoding="utf-8"))["package"] if "source" in p}


def observations(records):
    assert len(records) == 24
    def selected(kind):
        return [r for r in records if r["kind"] == kind]
    checkpoints = selected("bank_checkpoint")
    assert [r["row"] for r in checkpoints] == [0, 1, 5, 6, 11, 12, 233, 234, 353, 354, 371, 372, 413, 414, 8191]
    assert all(r["bytes_compared"] == 560 for r in checkpoints)
    shape = selected("shape_refusal")
    assert [r["row"] for r in shape] == [0, 1]
    assert shape[0]["before"] == shape[0]["after"] == [0, 0, 0]
    assert shape[1]["before"] == shape[1]["after"] == [1, 1, 1]
    assert all(r["result"] == "Err(RowShape)" and r["unchanged"] for r in shape)
    corrupt = selected("comparator_corruption")
    assert [(r["row"], r["column"]) for r in corrupt] == [(1, 18959), (6, 19247), (234, 18991), (414, 16271), (8191, 10531)]
    assert all(r["detected"] for r in corrupt)
    exhausted = selected("exhaustion")
    assert len(exhausted) == 1
    assert exhausted[0]["result"] == "Err(Exhausted)" and exhausted[0]["unchanged"]
    assert exhausted[0]["before"] == exhausted[0]["after"] == [70, 70, 1]
    summaries = selected("hash_summary")
    assert len(summaries) == 1
    summary = summaries[0]
    expected = {"hash_emissions": 8192, "decoder_emissions": 8192, "reference_rows": 8192,
        "reference_blocks": 1366, "owned_comparisons": 8192*13780, "outside_comparisons": 8192*29396,
        "composed_hash_comparisons": 8192*13780, "composed_outside_comparisons": 8192*22304,
        "independent_bank_bytes": 8400, "checkpoints": 15, "corruption_controls": 5, "restored_controls": 5,
        "candidate_generation": [70,70,1], "reference_generation": [70,70,1]}
    assert summary == {"kind": "hash_summary", **expected}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-results", action="store_true")
    parser.add_argument("--registry-root", type=Path)
    args = parser.parse_args()
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    for group, root in [("repository_files", ROOT), ("execution_source_files", HERE), ("experiment_files", HERE)]:
        for name, pin in provenance[group].items():
            assert identity(root / name) == pin, name
    if args.registry_root:
        for name, pin in provenance["registry_source_files"].items():
            assert identity(args.registry_root / name) == pin, name
    assert len(packages(HERE / "Cargo.lock")) == 89
    assert packages(HERE / "Cargo.lock") <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures-features.json").read_bytes())
    retained = json.loads((HERE.parent / "proof-preflight/fixtures/features.json").read_bytes())
    assert features.keys() <= retained.keys() and len(features) == 89
    assert all(set(v) <= set(retained[k]) for k, v in features.items())
    assert not any(k.startswith("rayon/") or "parallel" in v for k, v in features.items())
    assert provenance["local_features"]["kova-signature-hash-source"] == ["default", "hash-controls"]
    assert provenance["native_execution_enabled"] is False
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    adaptation = json.loads((HERE / "adaptation.json").read_bytes())
    assert adaptation["build_prefix_unchanged"] and not adaptation["old_opaque_conversion"]
    assert adaptation["tail_is_provisional"] and not adaptation["complete_row_source_implemented"]
    assert (HERE / "src/build.rs").read_text().startswith((ROOT / adaptation["build_origin"]).read_text())
    fixture = json.loads((HERE / "fixtures-hash.json").read_bytes())
    raw = json.loads((HERE.parent / "signature-ownership/raw-fixture.json").read_bytes())
    ref = json.loads((HERE.parent / "signature-ownership/reference-fixture.json").read_bytes())
    stages = next(r for r in ref["signature_records"] if r["id"] == "B0")["fixed_target_stages"]
    key = next(r["public_key_hex"] for r in raw["keys"] if r["id"] == "B")
    signature = next(r["signature_hex"] for r in raw["signatures"] if r["id"] == "B0")
    note = ref["notes"]["N_B"]
    assert fixture["key_hex"] == key and fixture["signature_hex"] == signature
    assert fixture["note_hex"] == note["opening_hex"]
    e = fixture["expected"]
    assert e["rho_hex"] == key[:64] == stages["rho_hex"]
    assert bytes.fromhex(e["owner_hex"]) == bytes.fromhex(note["opening_hex"])[141:205]
    assert bytes.fromhex(e["tr_hex"]) == bytes.fromhex(stages["mu_preimage_hex"])[:64]
    assert e["mu_hex"] == stages["mu_hex"] and e["note_commitment_hex"] == note["commitment_hex"]
    assert fixture["transaction"] == next(t for t in ref["transactions"] if t["id"] == "T0")
    new = fixture["new_reference"]
    assert new["algorithm"] == "SHAKE256" and new["computation_count"] == 1
    assert new["input_hex"] == signature[:128] and new["input_bytes"] == 64 and new["output_bytes"] == 272
    assert len(bytes.fromhex(e["challenge_xof272_hex"])) == 272
    # Saved values and recorded provenance only. No independent hash is rerun.
    assert fixture["reference_provenance"]["new_SHAKE256_computations"] == 1
    records = [json.loads(line) for line in (HERE / "fixtures-observations.jsonl").read_text().splitlines()]
    observations(records)
    validation = json.loads((HERE / "validation.json").read_bytes())
    assert validation["provenance"] == identity(HERE / "provenance.json")
    assert validation["integration_tests_passed"] == 1 and validation["observation_records"] == 24
    assert validation["trace_generator_calls"] == 140 and validation["source_inferred_internal_round_traces"] == 280
    assert validation["independent_scalar_hash_computations"] == 1
    for field in ["complete_signature_traces", "air_evaluations", "backend_proofs", "pcs_calls"]:
        assert validation[field] == 0
    for field in ["complete_row_source_implemented", "private_payment_verified", "full_security_profile_validated"]:
        assert validation[field] is False
    guard = validation["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_flags"] == 8960 and guard["test_counts_verified"]
    assert guard["available_before_bytes"] >= guard["minimum_available_bytes"]
    assert 0 < guard["peak_process_private_commit_bytes"] <= guard["process_limit_bytes"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    assert guard["hard_limit_installed"] and guard["exit_code"] == 0
    assert not any(guard[field] for field in ["timed_out", "output_limit_exceeded", "working_guard_terminated"])
    scalar = validation["scalar_reference"]
    assert scalar["guard_process_limit_bytes"] == scalar["guard_aggregate_limit_bytes"] == 536870912
    assert scalar["guard_minimum_available_bytes"] == 2147483648 and scalar["guard_timeout_seconds"] == 120
    assert scalar["guard_readback_flags"] == 8960 and scalar["hard_limit_installed"]
    assert scalar["available_before_bytes"] >= scalar["guard_minimum_available_bytes"]
    assert 0 < scalar["peak_process_private_commit_bytes"] <= scalar["guard_process_limit_bytes"]
    assert 0 < scalar["peak_job_commit_bytes"] <= scalar["guard_aggregate_limit_bytes"]
    assert scalar["expected_tests"] == 0 and not scalar["test_counts_verified"] and scalar["exit_code"] == 0
    assert not any(scalar[field] for field in ["timed_out", "output_limit_exceeded", "working_guard_terminated"])
    if args.check_results:
        assert (HERE / "results/observations.jsonl").read_bytes() == (HERE / "fixtures-observations.jsonl").read_bytes()
        receipt = json.loads((HERE / "results/signature-hash-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert receipt["accepted"] and receipt["test_counts_verified"]
        assert [receipt[k] for k in ["actual_passed", "actual_failed", "actual_ignored"]] == [1,0,0]
        assert receipt["expected_tests"] == 1 and receipt["launched"]
        mapping = {"process_limit_bytes":"installed_process_commit_limit_bytes",
            "aggregate_limit_bytes":"installed_job_commit_limit_bytes","minimum_available_bytes":"minimum_available_bytes",
            "available_before_bytes":"available_before_bytes","timeout_seconds":"timeout_seconds",
            "readback_flags":"installed_job_flags","peak_job_commit_bytes":"peak_job_commit_bytes",
            "peak_process_private_commit_bytes":"peak_private_commit_bytes","test_counts_verified":"test_counts_verified",
            "exit_code":"exit_code","hard_limit_installed":"hard_limit_installed","timed_out":"timed_out",
            "output_limit_exceeded":"output_limit_exceeded","working_guard_terminated":"working_guard_terminated"}
        assert all(guard[public] == receipt[raw] for public, raw in mapping.items())
    print("Initial hash construction, independent reference and recorded composition scope match")


if __name__ == "__main__":
    main()
