"""Canonical source identities and finite resource preflight scope."""
import hashlib
import json
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def packages(path):
    result = set()
    for block in path.read_text(encoding="utf-8").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\r\n\\]+)"$', block, re.MULTILINE))
        if "source" in fields:
            if not all(x in fields for x in ["name", "version", "source", "checksum"]):
                raise ValueError("Complete literal package identity required")
            result.add(tuple(fields[x] for x in ["name", "version", "source", "checksum"]))
    return result


def main():
    provenance = json.loads((HERE / "provenance.json").read_text(encoding="utf-8"))
    for name, expected in provenance["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in provenance["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    assert (HERE / "LICENSE-APACHE").read_bytes() == (HERE.parent / "storage-pcs/backend/LICENSE-APACHE").read_bytes()
    own = packages(HERE / "Cargo.lock")
    assert len(own) == 90 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text(encoding="utf-8"))
    assert len(features) == 90 and not any(x.startswith("rayon/") for x in features)
    assert not any("parallel" in items for items in features.values())
    record = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert record["provenance"] == identity(HERE / "provenance.json")
    assert record["integration_tests_passed"] == 4
    for field in ["backend_proofs", "commitment_calls", "native_traces", "wide_symbolic_evaluations", "preflight_rng_draws_observed", "field_files_created"]:
        assert record[field] == 0
    for field in ["serialized_compatibility_tested", "storage_reserved", "transcript_profile_bound", "complete_transport_bound", "production_security_claim"]:
        assert record[field] is False
    guard = record["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_verified"] and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    print("Preflight source identities, recorded features and finite scope match")


if __name__ == "__main__":
    main()
