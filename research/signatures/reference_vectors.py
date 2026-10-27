"""Public synthetic verifier cases and canonical transaction rebinding checks.

The retained fixture keys and signing seed are public test data. This generator
does not sign or import the native implementation. It does not construct a
private signature proof or authorize a ledger transition.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verification", DATA / "verify_reference.py")
if spec is None or spec.loader is None:
    raise RuntimeError("local mathematical verifier module")
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


def frame(value):
    return len(value).to_bytes(4, "big") + value


def digest(domain, *fields):
    return hashlib.sha3_512(frame(domain) + b"".join(frame(value) for value in fields)).digest()


def transaction(application):
    raw = lambda key: bytes.fromhex(application[key + "_hex"])
    chain = raw("chain")
    version = application["current_protocol_version"].to_bytes(4, "big")
    data = (frame(b"thorum.relation-lab.payment-statement.v1") + frame((1).to_bytes(2, "big"))
            + frame(chain) + frame(version) + frame(raw("validation_tag")) + frame(raw("anchor"))
            + frame((1).to_bytes(4, "big")) + frame(raw("input_nullifier"))
            + frame((1).to_bytes(4, "big")) + frame(raw("output_commitment"))
            + frame(raw("encoded_envelope")) + frame(application["native_fee"].to_bytes(8, "big")))
    message = digest(b"thorum.relation-lab.payment-authorization.v1", data)
    tag = digest(b"thorum.relation-lab.payment-auth-context.v1", message)[:32]
    crypto_context = frame(chain) + frame(version) + frame(tag)
    authorization = (frame(b"thorum.crypto-lab.authorization.v1") + frame((1).to_bytes(2, "big"))
                     + frame(crypto_context) + frame(message))
    return data, authorization


def build():
    native = json.loads((DATA / "synthetic_authorization.json").read_text())
    base = {key: bytes.fromhex(native[key + "_hex"]) for key in ["public_key", "signature", "message", "context"]}
    records = []

    def add(name, values, expected, reason):
        result = verification.verify(*[values[key] for key in ["public_key", "signature", "message", "context"]])
        assert result["valid"] is expected, name
        records.append({"name": name, **{key + "_hex": value.hex() for key, value in values.items()},
                        "expected_valid": expected, "expected_rejection": result["rejection"], "reason": reason})

    selected = verification.load_selected()
    for source in selected["cases"]:
        if source["id"].startswith("ml_dsa_87_verify_"):
            v = source["input"]
            add(source["id"], {"public_key": bytes.fromhex(v["pk"]), **{k: bytes.fromhex(v[k]) for k in ["signature", "message", "context"]}},
                source["expected"]["testPassed"], "Retained official external pure ML DSA 87 answer")
    add("synthetic_exact_authorization", base, True, "Valid pure contextual signature over exact A196 and context41")
    for alternate in native["alternate_signatures"]:
        values = {key: bytes.fromhex(alternate[key + "_hex"]) for key in base}
        add(alternate["name"] + "_valid_in_own_context", values, True, "Genuine signature under its own exact key, message and context")
        add(alternate["name"] + "_rejected_for_original", {**base, "signature": values["signature"]}, False,
            "A genuine other signature does not authorize the original key, message and context")
    for field, offsets in [("public_key", [0, 31, 32, 2591]), ("signature", [0, 63, 64, 65, 66, 67, 68, 4543])]:
        for offset in offsets:
            changed = bytearray(base[field])
            changed[offset] ^= 1
            add(f"changed_{field}_{offset}", {**base, field: bytes(changed)}, False, "Changed canonical source bytes require complete signature verification")
    for field, lengths in [("public_key", [0, 2591, 2593]), ("signature", [0, 4626, 4628])]:
        for length in lengths:
            value = (base[field] + bytes(max(0, length - len(base[field]))))[:length]
            add(f"wrong_{field}_length_{length}", {**base, field: value}, False, "Exact encoded length is required")
    for name, context in [("empty_context", b""), ("changed_context", b"Thorum crypto laboratory authorization v2"),
                          ("maximum_other_context", bytes(255)), ("oversized_context", bytes(256))]:
        add(name, {**base, "context": context}, False, "Pure FIPS context and its maximum length are part of verification")
    for signed in [-524288, -524168, -524167, 524167, 524168, 524288]:
        raw = verification.GAMMA1 - signed
        if not 0 <= raw < 1 << 20:
            continue
        signature = bytearray(base["signature"])
        packed = int.from_bytes(signature[64:69], "little")
        signature[64:69] = ((packed & ~((1 << 20) - 1)) | raw).to_bytes(5, "little")
        allowed = abs(signed) < 524168
        try:
            verification.decode(base["public_key"], bytes(signature))
            decoded = True
        except ValueError:
            decoded = False
        assert decoded == allowed
        add(f"z_signed_boundary_{signed}", {**base, "signature": bytes(signature)}, False,
            "Strict norm rejection at the boundary, and full challenge rejection for an altered admissible coefficient")
    for name, change in [
        ("hint_cut_above_75", lambda s: s.__setitem__(4619, 76)),
        ("hint_cut_decreasing", lambda s: (s.__setitem__(4619, 75), s.__setitem__(4620, 0))),
        ("hint_unused_nonzero", lambda s: s.__setitem__(4544 + s[4626], 1)),
        ("hint_duplicate", lambda s: s.__setitem__(4545, s[4544])),
        ("hint_descending", lambda s: (s.__setitem__(4544, 255), s.__setitem__(4545, 0))),
    ]:
        signature = bytearray(base["signature"])
        assert signature[4619] >= 2 and signature[4626] < 75
        change(signature)
        add(name, {**base, "signature": bytes(signature)}, False, "Canonical sparse hint encoding is mandatory")
    application = json.loads((REPO / "research/hash-proofs/application_inputs.json").read_text())
    encoded, authorization = transaction(application)
    assert encoded.hex() == application["transaction_hex"]
    assert authorization == base["message"]
    for field in ["chain", "validation_tag", "anchor", "input_nullifier", "output_commitment", "encoded_envelope"]:
        changed = dict(application)
        value = bytearray.fromhex(changed[field + "_hex"])
        value[-1] ^= 1
        changed[field + "_hex"] = value.hex()
        _, authorization = transaction(changed)
        add("transaction_changed_" + field, {**base, "message": authorization}, False, "Authorization is recomputed from the changed canonical transaction")
    for field in ["current_protocol_version", "native_fee"]:
        changed = dict(application)
        changed[field] += 1
        _, authorization = transaction(changed)
        add("transaction_changed_" + field, {**base, "message": authorization}, False, "Authorization is recomputed from the changed canonical transaction")
    return {"format": "thorum.signature-reference.cases.v1", "public_synthetic_fixture": True,
            "scope": "Transparent mathematical verifier cases, without a private signature AIR or transaction acceptance", "cases": records}


def stages():
    records = []
    for case in verification.load_selected()["cases"]:
        if not case["id"].startswith("ml_dsa_87_verify_"):
            continue
        source = case["input"]
        result = verification.verify(*[bytes.fromhex(source[key]) for key in ["pk", "signature", "message", "context"]])
        assert result["valid"] is case["expected"]["testPassed"]
        records.append({"name": case["id"], "source": "retained official verification answer", **result})
    native = json.loads((DATA / "synthetic_authorization.json").read_text())
    for case in [{"name": "synthetic_exact_authorization", **native}, *native["alternate_signatures"]]:
        result = verification.verify(*[bytes.fromhex(case[key + "_hex"]) for key in ["public_key", "signature", "message", "context"]])
        assert result["valid"] is True
        records.append({"name": case["name"], "source": "public synthetic native signature", **result})
    assert len(records) == 6
    return {"format": "thorum.signature-reference.stages.v1", "public_synthetic_fixture": True,
            "scope": "Transparent public intermediate values, not a private signature AIR or transaction acceptance", "cases": records}


def source_record():
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "format": "thorum.signature-reference.source-record.v1",
        "standards": [
            {"name": "NIST FIPS 204", "publication_date": "2024-08-13",
             "record": "https://csrc.nist.gov/pubs/fips/204/final",
             "publication": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf",
             "potential_updates": "https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx",
             "potential_updates_last_updated": "2026-07-31",
             "potential_errata_sha256": "5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793",
             "potential_errata_review_scope": "Potential updates, not a replacement standard. Reviewed mu followed by encoded w1, distinct M prime, odd root ordering, w1 coefficient bound 15 and normal residue arithmetic independent of Montgomery representation."},
            {"name": "NIST FIPS 202", "record": "https://csrc.nist.gov/pubs/fips/202/final"}
        ],
        "official_vectors": {
            "source": "National Institute of Standards and Technology ACVP sample data",
            "upstream_commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
            "retained_path": "research/crypto/vectors/selected.json",
            "retained_sha256": verification.SELECTED_SHA256,
            "upstream_notice": "research/crypto/vectors/UPSTREAM-NOTICE.txt",
            "changes": "Two original verification cases are selected without changing cryptographic values. Additional synthetic cases and diagnostic intermediate values were created on 2026-10-27."
        },
        "native_comparison": {
            "package": "ml-dsa", "version": "0.1.1",
            "vcs_commit": "f75d5b829948988f18d9463f286805fb9410bcdd",
            "registry_archive_sha256": "add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d",
            "source_url": "https://github.com/RustCrypto/signatures/tree/f75d5b829948988f18d9463f286805fb9410bcdd/ml-dsa",
            "verification_source_sha256": "966ac3d6f20db9c200755302fce29826211eed2a03a99a7c214fc12cad678eca",
            "ntt_source_sha256": "6461fa2933c816906a9baae09df8b6f989a2e9e058fd7607cdc7c8951100af06",
            "module_lattice_version": "0.2.3", "module_lattice_vcs_commit": "ac34c85db783520bda5a8fbe8e7b694c7c72d6fe"
        },
        "public_inputs": {
            "synthetic_authorization_sha256": sha(DATA / "synthetic_authorization.json"),
            "application_inputs_path": "research/hash-proofs/application_inputs.json",
            "application_inputs_sha256": sha(REPO / "research/hash-proofs/application_inputs.json"),
            "seed_source_case": "ml_dsa_87_keygen",
            "seed_scope": "The original seed and the one byte changed alternate seed are known public fixtures and must never be operational signing authority."
        },
        "independent_verifier": {"path": "research/signatures/verify_reference.py", "sha256": sha(DATA / "verify_reference.py"),
                                 "scope": "Python integers and standard library SHAKE. No Rust implementation or proof backend is imported."}
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare all retained JSON outputs without changing files")
    args = parser.parse_args()
    data = build()
    assert len(data["cases"]) == 49
    assert sum(case["expected_valid"] for case in data["cases"]) == 5
    outputs = {"cases.json": data, "verification_stages.json": stages(), "source_record.json": source_record()}
    for name, value in outputs.items():
        encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        path = DATA / name
        if args.check:
            if path.read_bytes() != encoded:
                raise SystemExit(f"Retained signature reference mismatch: {name}")
        else:
            path.write_bytes(encoded)
    print("Signature reference matches: 49 cases, 5 valid, 44 invalid, six detailed stage records")


if __name__ == "__main__":
    main()
