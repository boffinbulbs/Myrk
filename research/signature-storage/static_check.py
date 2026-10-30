"""Complete signature storage source identities and native scope."""
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
    assert len(own) == 80 and own <= registry_tuples(ROOT / "Cargo.lock")
    assert not any(name in {"p3-uni-stark", "p3-fri", "rayon"} for name, _, _, _ in own)
    record = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    assert record["provenance"] == identity(HERE / "provenance.json")
    assert (record["height"], record["width"], record["public_values"], record["assertions_per_row"], record["degree"]) == (8192,45266,196,71141,4)
    assert record["native_tuple_cases"] == 10 and record["accepted"] == record["rejected"] == 5
    assert record["activity_local_rejections"] == 9 and record["output_handoff_local_rejections"] == 12
    assert record["hostile_routes_rejected"] == 77 and record["full_hostile_negatives"] == 15
    assert record["maximum_live_traces"] == 1 and record["backend_proofs"] == 0
    for name, guard in record["guards"].items():
        symbolic = name == "symbolic"
        assert guard["process_limit_bytes"] == guard["aggregate_limit_bytes"] == (536870912 if symbolic else 2147483648)
        assert guard["minimum_available_bytes"] == (2147483648 if symbolic else 5368709120)
        assert guard["readback_verified"] and guard["test_counts_verified"]
        assert 0 < guard["peak_job_commit_bytes"] <= guard["aggregate_limit_bytes"]
    original = provenance["unchanged_local_sources"]
    for name in original:
        assert identity(HERE / "src" / name) == identity(HERE.parent / "signature-scheduling/src" / name)
    costs = json.loads((HERE / "costs.json").read_text(encoding="utf-8"))
    assert costs["current"]["raw_trace_bytes"] == 1483276288
    assert costs["current"]["all_field_file_bytes"] == 26739081216
    print("Complete output storage identities, native scope and retained dependencies match")



if __name__ == "__main__":
    main()
