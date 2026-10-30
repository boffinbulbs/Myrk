"""Retained source identities and finite temporal experiment boundary."""
import hashlib
import json
import os
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source identities")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def identity(path):
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def registry_tuples(path):
    result = set()
    for block in path.read_text(encoding="utf-8").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"\r\n\\]+)"$', block, re.MULTILINE))
        if "source" in fields:
            if not all(key in fields for key in ["name", "version", "source", "checksum"]):
                raise ValueError("Complete literal registry identity required")
            if not fields["source"].startswith("registry+"):
                raise ValueError("Only retained registry packages are permitted")
            result.add(tuple(fields[key] for key in ["name", "version", "source", "checksum"]))
    return result


def main():
    provenance = json.loads((HERE / "provenance.json").read_text(encoding="utf-8"))
    for name, expected in provenance["repository_files"].items():
        assert identity(ROOT / name) == expected, name
    for name, expected in provenance["experiment_files"].items():
        assert identity(HERE / name) == expected, name
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for name, expected in provenance["registry_files"].items():
        crate, version, relative = name.split("/", 2)
        paths = list((home / "registry/src").glob("*/" + crate + "-" + version + "/" + relative))
        assert len(paths) == 1 and identity(paths[0]) == expected, name
    own = registry_tuples(HERE / "Cargo.lock")
    assert len(own) == 42 and own <= registry_tuples(ROOT / "Cargo.lock")
    assert not any(name in {"p3-uni-stark", "p3-fri", "rayon"} for name, _, _, _ in own)
    record = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert record["provenance"] == identity(HERE / "provenance.json")
    assert (record["height"], record["width"], record["assertions_per_row"], record["degree"]) == (8192, 274, 776, 3)
    assert record["synthetic_traces"] == record["full_positive_checks"] == 1
    assert record["representative_reads"] == 5728 and record["restored_cell_rejections"] == 12
    assert record["unsafe_alias_local_frames"] == 1 and record["complete_unsafe_traces"] == 0
    assert record["signature_traces"] == record["backend_proofs"] == 0
    assert record["initial_symbolic_degree_expectation"] == 4
    assert record["corrected_symbolic_degree_expectation"] == 3
    for guard in record["guards"].values():
        assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == 536870912
        assert guard["minimum_available_bytes"] == 2147483648 and guard["timeout_seconds"] == 120
        assert guard["readback_verified"] and guard["test_counts_verified"]
        assert 0 < guard["peak_job_commit_bytes"] <= 536870912
    print("Output lifetime identities, fixed scope and retained dependencies match")


if __name__ == "__main__":
    main()
