"""Inspect saved bytes and identities. Never import or run either producer."""
import hashlib
import json
from pathlib import Path
import tomllib

HERE = Path(__file__).resolve().parent


def identity(path, raw=False):
    with path.open("rb") as source:
        data = source.read(1048577)
    assert len(data) <= 1048576, str(path)
    if not raw:
        data = data.replace(b"\r\n", b"\n")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    provenance = json.loads((HERE / "provenance.json").read_text(encoding="utf8"))
    for name, pin in provenance["source_files"].items():
        assert identity(HERE / name, pin["raw"]) == pin["identity"], name
    packages = {(p["name"], p["version"]): p["checksum"]
                for p in tomllib.loads((HERE / "Cargo.lock").read_text())["package"] if "source" in p}
    assert packages == {(p["name"], p["version"]): p["checksum"] for p in provenance["registry_packages"]}
    assert len(packages) == 10 and len(provenance["diagnostic_nodes"]) == 9
    assert not {"cpufeatures", "libc"}.intersection(p["name"] for p in provenance["diagnostic_nodes"])
    manifest = tomllib.loads((HERE / "Cargo.toml").read_text())
    assert manifest["features"]["default"] == []
    assert set(manifest["dependencies"]) == {"sha3"}
    assert manifest["dependencies"]["sha3"] == {"version": "=0.12.0", "default-features": False, "optional": True}
    expected = json.loads((HERE / "fixtures/identities.json").read_text())
    assert identity(HERE / "fixtures/synthetic-job.bin", True) == {
        "bytes": 927, "sha256": expected["fixture_sha256"]}
    assert expected["fixture_bytes"] == 927 and expected["reference_alternatives"] == 4
    assert len(expected["effects"]) == len(expected["authorizations"]) == 2
    record = json.loads((HERE / "validation.json").read_text())
    assert record["provenance"] == identity(HERE / "provenance.json")
    assert record["native_attempts"] == record["reference_attempts"] == 1
    assert record["post_native_files_verified"] == 2546
    for guard in [record["native_guard"], record["reference_guard"], *record["preparations"]]:
        assert guard["accepted"] and guard["exit_code"] == 0 and guard["launched"]
        assert guard["hard_limit_installed"]
        assert guard["installed_process_commit_limit_bytes"] == guard["installed_job_commit_limit_bytes"] == 536870912
        assert guard["available_before_bytes"] >= guard["minimum_available_bytes"] == 2147483648
        assert guard["timeout_seconds"] == 120 and guard["installed_job_flags"] == 8960
        assert 0 < guard["peak_job_commit_bytes"] <= 536870912
        assert not any(guard[k] for k in ("timed_out", "working_guard_terminated", "output_limit_exceeded"))
    assert len(record["preparations"]) == 6
    assert record["native_guard"]["test_counts_verified"]
    assert record["native_guard"]["actual_passed"] == 1
    assert record["native_guard"]["actual_failed"] == record["native_guard"]["actual_ignored"] == 0
    assert identity(HERE / "results/native.txt", True) == record["result"]
    lines = (HERE / "results/native.txt").read_text().splitlines()
    result_line = next(line for line in lines if '"independent_ids"' in line)
    counts = json.loads(result_line[result_line.index("{"):])
    assert counts == record["counts"]
    assert counts["independent_ids"] == 5 and counts["fixture_bytes"] == 927
    assert counts["truncated_prefixes"] == 927 and counts["maximum_bytes"] == 51130
    assert counts["mutated_frames"] == 22 and counts["association_controls"] == 4
    assert counts["fixed_width_refusals"] == 18 and counts["variable_length_refusals"] == 14
    print("Preseal sources, provenance and saved byte evidence verified. No producer or verifier replay.")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Optimized inspection refused")
    main()
