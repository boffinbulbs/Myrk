"""Independent integer resource checks against the retained proof record."""
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate preflight references")

HERE = Path(__file__).resolve().parent


def main():
    data = json.loads((HERE / "fixtures/reference.json").read_text(encoding="utf-8"))
    old = json.loads((HERE.parent / "storage-pcs/validation.json").read_text(encoding="utf-8"))
    h, w, e, r, q, c = [data[x] for x in ["height", "width", "extension", "random_columns", "queries", "quotient_chunks"]]
    assert r >= e
    assert data["mask_minimum_heights"] == [2 * (q + e * p) for p in [2, 1, 1]]
    assert h >= max(data["mask_minimum_heights"])
    assert data["batched_functions"] == 2 * (w + r) + (c + 1) * (e + r)
    assert data["prepared_shape"] == [2 * h, w + r] == old["prepared_source_shape"]
    assert data["field_files"] == c + 3 == old["total_field_files"]
    assert data["field_bytes"] == 4 * (2 * h * (w + r) + 16 * h * (w + r + (c + 1) * (e + r))) == old["total_field_bytes"]
    assert data["main_query_field_bytes"] == 4 * q * (w + r)
    assert not data["resource_plan_reserves_storage"] and not data["serialized_transport_bound_established"]
    assert data["backend_proofs"] == 0
    print("Independent resource arithmetic matches the retained small proof record")


if __name__ == "__main__":
    main()
