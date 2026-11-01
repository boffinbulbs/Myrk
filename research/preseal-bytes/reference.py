"""Independent public synthetic fixture. No candidate or Kova imports."""
import hashlib
import json
from pathlib import Path
import struct


def frame(value):
    assert len(value) <= 65536
    return struct.pack(">I", len(value)) + value


def digest(*fields):
    return hashlib.sha3_512(b"".join(map(frame, fields))).hexdigest()


def main():
    assert hashlib.sha3_512(b"").hexdigest() == (
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615"
        "b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    )
    chain = bytes(range(32))
    rules = b"\x11" * 64
    policy = b"treasury:synthetic:v1"
    header = [
        b"\x00\x01", chain, rules, b"\x22" * 64, b"\x33" * 64,
        b"\x44" * 64, b"\x55" * 64, struct.pack(">Q", 42),
        struct.pack(">Q", 1700000000), struct.pack(">Q", 7), b"\x66" * 64,
        b"\x01" + bytes(31), b"\x77" * 64, policy, b"\x00\x00\x00\x02",
    ]
    records = [
        [b"\x00\x01", b"\x88" * 64, b"payment:public-effect:alpha",
         b"unverified-proof:alpha", b""],
        [b"\x00\x03", b"\x99" * 64, b"stake:public-effect:beta",
         b"unverified-proof:beta", b"encrypted:public-recovery:beta"],
    ]
    fields = header + records[0] + records[1]
    encoded = b"KOVAJOB\0" + b"".join(map(frame, fields))
    expected_length = 610 + 21 + 86 + 27 + 22 + 0 + 86 + 24 + 21 + 30
    # Literal lengths deliberately checked independently of their labels.
    assert [len(x) for x in records[0][2:]] == [27, 22, 0]
    assert [len(x) for x in records[1][2:]] == [24, 21, 30]
    assert encoded[:20].hex() == "4b4f56414a4f4200000000020001000000200001"
    assert encoded[20:48] == bytes(range(2, 30))
    assert len(encoded) == expected_length <= 65536
    effects = [digest(b"kova.effect-id.v1", chain, rules, r[0], r[1], r[2], r[4])
               for r in records]
    authorizations = [digest(b"kova.authorization-id.v1", bytes.fromhex(e), r[3])
                      for e, r in zip(effects, records)]
    job = digest(b"kova.preseal-job.commitment.v1", encoded)
    alternatives = [
        digest(b"kova.preseal-job.commitment.v1\0", encoded),
        hashlib.sha3_512(b"".join(struct.pack("<I", len(x)) + x for x in fields)).hexdigest(),
        digest(b"kova.preseal-job.commitment.v1", b"KOVAJOB\0" + b"".join(map(frame, header + records[1] + records[0]))),
        digest(b"kova.preseal-job.commitment.v1", encoded[:-34]),
    ]
    assert all(x != job for x in alternatives)
    result = {"fixture_bytes": len(encoded), "fixture_sha256": hashlib.sha256(encoded).hexdigest(),
              "job": job, "effects": effects, "authorizations": authorizations,
              "reference_alternatives": len(alternatives), "hash_constructor_module": hashlib.sha3_512.__module__}
    target = Path(__file__).parent / "fixtures"
    target.mkdir(exist_ok=True)
    with (target / "synthetic-job.bin").open("xb") as handle:
        handle.write(encoded)
    with (target / "identities.json").open("x", encoding="ascii", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
