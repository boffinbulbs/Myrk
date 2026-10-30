"""Independent preparation accounting against the retained small record."""
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate preparation references")

HERE = Path(__file__).resolve().parent


def main():
    data = json.loads((HERE / "fixtures/reference.json").read_text(encoding="utf-8"))
    previous = json.loads((HERE.parent / "storage-pcs/validation.json").read_text(encoding="utf-8"))
    for case in data["cases"]:
        h, w, r = [case[x] for x in ["height", "width", "random_columns"]]
        assert case["prepared_shape"] == [2 * h, w + r]
        assert case["raw_bytes"] == 4 * h * w
        assert case["prepared_bytes"] == 4 * 2 * h * (w + r)
        assert case["reserved_bytes"] == case["raw_bytes"] + case["prepared_bytes"]
        assert case["sampled_fields"] == h * (w + 2 * r)
        assert case["field_files"] == 2
    first = data["cases"][0]
    assert first["prepared_shape"] == previous["prepared_source_shape"]
    assert first["prepared_bytes"] == previous["prepared_source_bytes"]
    assert first["sampled_fields"] == previous["prepared_field_draws"]
    assert data["backend_proofs"] == 0
    print("Preparation dimensions, reservations and sampling order match")


if __name__ == "__main__":
    main()
