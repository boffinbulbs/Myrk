"""Independent integer interpolation of captured synthetic prepared columns."""
import json
from pathlib import Path

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate interpolation")

HERE = Path(__file__).resolve().parent
P = 2013265921
G = 31


def coefficients(values):
    n = len(values)
    inverse_root = pow(pow(G, (P - 1) // n, P), -1, P)
    inverse_n = pow(n, -1, P)
    result = []
    step = 1
    for _ in range(n):
        power, total = 1, 0
        for value in values:
            total = (total + value * power) % P
            power = power * step % P
        result.append(total * inverse_n % P)
        step = step * inverse_root % P
    return result


def evaluate(values, point):
    result = 0
    for value in reversed(values):
        result = (result * point + value) % P
    return result


def main():
    d = json.loads((HERE / "fixtures/interpolation.json").read_text(encoding="utf-8"))
    assert [d[x] for x in ["modulus", "generator", "input_height", "output_height"]] == [P, G, 512, 4096]
    assert d["backend_proofs"] == d["commitment_calls"] == 0
    assert d["columns"] == [0, 5] and len(d["prepared_columns"]) == 2
    assert all(len(column) == 512 and all(type(v) is int and 0 <= v < P for v in column) for column in d["prepared_columns"])
    polys = {c: coefficients(v) for c, v in zip(d["columns"], d["prepared_columns"])}
    root = pow(G, (P - 1) // 4096, P)
    expected_cells = {(r, c) for r in [0, 1, 2, 7, 31, 255, 511, 4095] for c in [0, 5]}
    assert len(d["cells"]) == 16 and {(v["row"], v["column"]) for v in d["cells"]} == expected_cells
    for cell in d["cells"]:
        reverse = int(format(cell["row"], "012b")[::-1], 2)
        point = G * pow(root, reverse, P) % P
        assert evaluate(polys[cell["column"]], point) == cell["value"], cell
    assert 2048 + 12288 + 98304 == 112640
    assert 12288 + 98304 == 110592
    print("Sixteen physical LDE cells match independent integer interpolation")


if __name__ == "__main__":
    main()
