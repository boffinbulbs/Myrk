"""Independent SHA3 reconstruction of the public synthetic hiding Merkle root."""
from hashlib import sha3_512
import json
from pathlib import Path
import struct

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate Merkle roots")

HERE = Path(__file__).resolve().parent
P = 2013265921


def tagged(domain, values, count):
    return sha3_512(len(domain).to_bytes(4, "big") + domain + values + count.to_bytes(8, "big")).digest()


def merkle_root(data):
    if len(data) != 4096 * 22 * 4:
        raise ValueError("Exact bounded leaf payload required")
    fields = struct.unpack("<" + "I" * (4096 * 22), data)
    if any(v >= P for v in fields):
        raise ValueError("Noncanonical field")
    nodes = [tagged(b"kova.storage-pcs.leaf.v1", data[offset:offset + 88], 22) for offset in range(0, len(data), 88)]
    while len(nodes) > 1:
        nodes = [tagged(b"kova.storage-pcs.node.v1", nodes[i] + nodes[i + 1], 16) for i in range(0, len(nodes), 2)]
    return list(struct.unpack("<8Q", nodes[0]))


def main():
    record = json.loads((HERE / "fixtures/root.json").read_text(encoding="utf-8"))
    data = (HERE / "fixtures/salted-leaves.bin").read_bytes()
    assert record["leaf_rows"] == 4096 and record["leaf_fields"] == 22
    assert record["data_fields"] == 6 and record["salt_fields"] == 16
    assert record["input_commit_calls"] == 3
    assert record["opening_calls"] == record["backend_proofs"] == 0
    assert record["root"] == [merkle_root(data)]
    changed = bytearray(data)
    value = int.from_bytes(changed[:4], "little")
    changed[:4] = ((value + 1) % P).to_bytes(4, "little")
    assert merkle_root(changed) != record["root"][0]
    for invalid in [data[:-1], P.to_bytes(4, "little") + data[4:]]:
        try:
            merkle_root(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Malformed reference input accepted")
    print("4096 salted leaves and all Merkle levels match independent SHA3 arithmetic")


if __name__ == "__main__":
    main()
