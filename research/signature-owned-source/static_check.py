"""Recorded ownership, decoder equivalence and finite diagnostic scope."""
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
    assert len(records) == 15
    def selected(kind):
        return [r for r in records if r["kind"] == kind]
    walks = selected("decode_equivalence")
    assert [r["case"] for r in walks] == ["baseline", "z_endpoints"]
    for r in walks:
        assert r["rows"] == 8192 and r["reference_rows"] == 449
        assert r["owned_cells"] == 8192 * 7092
        assert r["preserved_cells"] == 8192 * 36084
        assert r["independent_terminal_values"] == 5888 and r["public_values"] == 196
        assert r["corruption_controls"] == r["restored_controls"] == 2
        assert r["exhausted_without_writes"]
    exhausted = selected("exhaustion")
    assert [r["case"] for r in exhausted] == ["baseline", "z_endpoints"]
    assert all(r["result"] == "Err(Exhausted)" and r["unchanged"] for r in exhausted)
    shape = selected("shape_refusal")
    assert [r["expected_next"] for r in shape] == [0, 1]
    for r in shape:
        assert r["error"] == "Err(RowShape)" and r["unchanged"]
        assert r["actual_next"] == r["expected_next"]
    errors = selected("encoding_refusal")
    assert [r["case"] for r in errors] == ["fixed_note", "z_below_range", "z_above_range",
        "descending_cuts", "cut_above_limit", "duplicate_hint", "hint_padding"]
    assert all(r["error"] == "Encoding(InvalidEncoding)" for r in errors)
    assert selected("shape_guards") == [{"kind": "shape_guards", "count": 2}]
    assert selected("encoding_refusals") == [{"kind": "encoding_refusals", "count": 7}]


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
    assert provenance["native_execution_enabled"] is False
    assert provenance["local_features"]["kova-signature-owned-source"] == ["decode-controls", "default"]
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    adaptation = json.loads((HERE / "adaptation.json").read_bytes())
    assert adaptation["build_prefix_unchanged"] and not adaptation["old_opaque_conversion"]
    assert adaptation["subset_writer_only"] and not adaptation["full_streamed_source_implemented"]
    assert (HERE / "src/build.rs").read_text().startswith((ROOT / adaptation["build_origin"]).read_text())
    fixture = json.loads((HERE / "fixtures-decode.json").read_bytes())
    raw_path = HERE.parent / "signature-ownership/raw-fixture.json"
    ref_path = HERE.parent / "signature-ownership/reference-fixture.json"
    assert hashlib.sha256(raw_path.read_bytes()).hexdigest() == fixture["raw_source_sha256"]
    assert hashlib.sha256(ref_path.read_bytes()).hexdigest() == fixture["reference_source_sha256"]
    raw = json.loads(raw_path.read_bytes())
    ref = json.loads(ref_path.read_bytes())
    stages = next(r for r in ref["signature_records"] if r["id"] == "B0")["fixed_target_stages"]
    assert fixture["key_hex"] == next(k["public_key_hex"] for k in raw["keys"] if k["id"] == "B")
    assert fixture["signature_hex"] == next(s["signature_hex"] for s in raw["signatures"] if s["id"] == "B0")
    assert fixture["note_hex"] == ref["notes"]["N_B"]["opening_hex"]
    assert fixture["t1"] == stages["t1"] and fixture["z_signed"] == stages["z_signed"]
    assert fixture["hints"] == [row["hints"] for row in stages["rows"]]
    assert fixture["transaction"] == next(t for t in ref["transactions"] if t["id"] == "T0")
    records = [json.loads(line) for line in (HERE / "fixtures-observations.jsonl").read_text().splitlines()]
    observations(records)
    validation = json.loads((HERE / "validation.json").read_bytes())
    assert validation["provenance"] == identity(HERE / "provenance.json")
    assert validation["integration_tests_passed"] == 3 and validation["observation_records"] == 15
    assert validation["main_decode_emissions"] == 16384 and validation["shape_control_emissions"] == 2
    assert validation["reference_prefix_rows"] == 898 and validation["maximum_live_reference_buffers"] == 1
    for field in ["complete_signature_traces", "air_evaluations", "backend_proofs", "pcs_calls"]:
        assert validation[field] == 0
    for field in ["full_streamed_source_implemented", "private_payment_verified", "full_security_profile_validated"]:
        assert validation[field] is False
    guard = validation["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_flags"] == 8960 and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    if args.check_results:
        assert (HERE / "results/observations.jsonl").read_bytes() == (HERE / "fixtures-observations.jsonl").read_bytes()
        receipt = json.loads((HERE / "results/signature-owned-source-v1-memory-result.json").read_text(encoding="utf-8-sig"))
        assert receipt["accepted"] and receipt["test_counts_verified"]
        assert [receipt[k] for k in ["actual_passed", "actual_failed", "actual_ignored"]] == [3, 0, 0]
    print("Owned decoder source, bounded equivalence and recorded scope match")


if __name__ == "__main__":
    main()
