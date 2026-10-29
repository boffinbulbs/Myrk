"""Recompute the finite salted roots with independent integer and SHA3 code."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
Q = 2013265921
LEAF = b"kova.storage-commitments.leaf.v1"
NODE = b"kova.storage-commitments.node.v1"
SHAPES = {1: [[8, 1]], 2: [[16, 4]], 3: [[256, 8]], 4: [[64, 4], [256, 8], [64, 1]]}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def framed(domain, values, width):
    payload = b"".join(value.to_bytes(width, "little") for value in values)
    return hashlib.sha3_512(len(domain).to_bytes(4, "big") + domain + payload
                           + len(values).to_bytes(8, "big")).digest()


def words(digest):
    return [int.from_bytes(digest[i:i + 8], "little") for i in range(0, 64, 8)]


def combine(left, right):
    return framed(NODE, words(left) + words(right), 8)


def row(case_id, matrix, index, width):
    return [(case_id * 1009 + matrix * 65537 + index * 97 + column * 13
             + index * column * 17) % Q for column in range(width)]


def calculate(corpus):
    require(type(corpus) is list and len(corpus) == 4, "Case set differs")
    require(all(type(c) is dict and set(c) == {"id", "dimensions", "root", "salts"}
                and type(c["id"]) is int for c in corpus), "Case schema differs")
    require([c["id"] for c in corpus] == [1, 2, 3, 4], "Case set differs")
    cases = []
    for case in corpus:
        identifier, dimensions, salts = case["id"], case["dimensions"], case["salts"]
        require(type(dimensions) is list and all(type(d) is list and len(d) == 2
                and all(type(v) is int for v in d) for d in dimensions), "Dimension encoding differs")
        require(dimensions == SHAPES[identifier], "Dimensions differ")
        require(type(case["root"]) is list and len(case["root"]) == 8
                and all(type(v) is int and 0 <= v < 2**64 for v in case["root"]), "Root encoding differs")
        require(len(salts) == len(dimensions), "Salt matrix count differs")
        for (height, _), matrix_salts in zip(dimensions, salts):
            require(len(matrix_salts) == height, "Salt height differs")
            for salt in matrix_salts:
                require(len(salt) == 16, "Salt width differs")
                require(all(type(v) is int and 0 <= v < Q for v in salt), "Noncanonical salt")

        def rows_at(height, index):
            values = []
            for m, (h, w) in enumerate(dimensions):
                if h == height:
                    values.extend(row(identifier, m, index, w))
                    values.extend(salts[m][index])
            return values

        height = max(d[0] for d in dimensions)
        layer = [framed(LEAF, rows_at(height, r), 4) for r in range(height)]
        while height > 1:
            height //= 2
            layer = [combine(layer[2 * r], layer[2 * r + 1]) for r in range(height)]
            if any(h == height for h, _ in dimensions):
                layer = [combine(digest, framed(LEAF, rows_at(height, r), 4))
                         for r, digest in enumerate(layer)]
        result = words(layer[0])
        require(result == case["root"], "Independent root differs from retained implementation")
        cases.append({"id": identifier, "dimensions": dimensions, "root": result,
                      "salt_rows": sum(d[0] for d in dimensions)})
    return {"format": "kova.storage-commitments.reference.v1", "field_order": Q,
            "salt_fields_per_row": 16, "cases": cases,
            "leaf_vector": {"values": [0, 1, Q - 1], "digest": words(framed(LEAF, [0, 1, Q - 1], 4))},
            "node_vector": {"values": list(range(16)), "digest": words(framed(NODE, list(range(16)), 8))},
            "scope": "Finite salted Merkle roots, not a PCS or STARK proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    corpus = json.loads((HERE / "fixtures/salts.json").read_text(encoding="utf-8"))
    result = calculate(corpus)
    encoded = (json.dumps(result, indent=2) + "\n").encode()
    output = HERE / "fixtures/reference.json"
    if args.check:
        require(output.read_bytes() == encoded, "Reference artifact differs")
    else:
        with output.open("xb") as file:
            file.write(encoded)
    print(json.dumps({"cases": len(result["cases"]), "independent_roots": "match"}))


if __name__ == "__main__":
    main()
