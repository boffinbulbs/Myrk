"""Conditional storage arithmetic from the unchanged retained model."""
import importlib.util
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate storage arithmetic")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    spec = importlib.util.spec_from_file_location("retained_model", ROOT / "research/storage-pcs/resources/model.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    data = json.loads((HERE / "costs.json").read_text(encoding="utf-8"))
    assert data["prior"] == model.payloads(8192, 47058, 74725)
    assert data["current"] == model.payloads(8192, 45266, 71141)
    assert data["current"]["raw_trace_bytes"] == 1483276288
    assert data["current"]["all_field_file_bytes"] == 26739081216
    assert data["raw_bytes_removed"] == 8192 * 1792 * 4 == 58720256
    assert data["assertions_removed"] == 2 * 1792 == 3584
    assert data["field_payload_bytes_removed"] == 1056964608
    assert data["backend_proofs"] == 0
    print("Retained conditional storage dimensions and unchanged model match")


if __name__ == "__main__":
    main()
