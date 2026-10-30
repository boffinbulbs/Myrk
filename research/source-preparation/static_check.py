"""Source identities and scope of the bounded preparation experiment."""
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
            assert all(x in fields for x in ["name", "version", "source", "checksum"])
            result.add(tuple(fields[x] for x in ["name", "version", "source", "checksum"]))
    return result


def main():
    provenance = json.loads((HERE / "provenance.json").read_text(encoding="utf-8"))
    for name, expected in provenance["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in provenance["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    assert (HERE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    own = packages(HERE / "Cargo.lock")
    assert len(own) == 50 and own <= packages(ROOT / "Cargo.lock")
    features = json.loads((HERE / "fixtures/features.json").read_text(encoding="utf-8"))
    assert len(features) == 50 and not any(x.startswith("rayon/") for x in features)
    assert not any("parallel" in items for items in features.values())
    record = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert record["provenance"] == identity(HERE / "provenance.json")
    assert record["test_groups_passed"] == 8
    for field in ["backend_proofs", "commitment_calls", "native_traces", "wide_symbolic_evaluations"]:
        assert record[field] == 0
    for field in ["pcs_entry_implemented", "production_secret_storage", "durable_cleanup", "external_namespace_authenticated", "production_security_claim"]:
        assert record[field] is False
    assert record["actual_controls"] == ["noncanonical file", "truncated file", "owner mutex poison", "writer unwind", "replacement preservation"]
    assert record["injected_controls"] == ["missing window", "short window", "reader poison", "partial write", "cleanup refusal"]
    guard = record["guard"]
    assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
    assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
    assert guard["readback_verified"] and guard["test_counts_verified"]
    assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    print("Preparation source identities, recorded features and finite scope match")


if __name__ == "__main__":
    main()
