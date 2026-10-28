"""Check pinned sources and Python syntax without Cargo or mathematical imports."""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("Optimized Python is unsupported for source and reference checks")

import ast
import hashlib
import json
from pathlib import Path
import tomllib

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
LOCAL = {
    "producer/Cargo.toml", "producer/Cargo.lock", "producer/src/main.rs",
    "authorization.rs", "reference_vectors.py", "static_check.py", "README.md",
    "raw-fixture.json", "LICENSE", "UPSTREAM-NOTICE.txt",
    "licenses/ml-dsa-LICENSE-MIT", "licenses/ml-dsa-LICENSE-APACHE",
}
RETAINED = {
    "Cargo.toml", "Cargo.lock",
    "crates/thorum-core/Cargo.toml",
    "crates/thorum-core/src/lib.rs",
    "crates/thorum-core/src/accounting.rs",
    "crates/thorum-core/src/amount.rs",
    "crates/thorum-core/src/emission.rs",
    "crates/thorum-core/src/table.rs",
    "crates/thorum-crypto-lab/Cargo.toml",
    "crates/thorum-crypto-lab/src/lib.rs",
    "crates/thorum-crypto-lab/src/envelope.rs",
    "crates/thorum-crypto-lab/examples/signature_reference_fixture.rs",
    "crates/thorum-relation-lab/Cargo.toml",
    "crates/thorum-relation-lab/src/lib.rs",
    "crates/thorum-relation-lab/src/capability.rs",
    "crates/thorum-relation-lab/src/codec.rs",
    "crates/thorum-relation-lab/src/error.rs",
    "crates/thorum-relation-lab/src/merkle.rs",
    "crates/thorum-relation-lab/src/payment.rs",
    "crates/thorum-relation-lab/src/note.rs",
    "crates/thorum-relation-lab/src/stake.rs",
    "research/crypto/dependency-inventory.json",
    "research/crypto/vectors/selected.json",
    "research/crypto/vectors/UPSTREAM-NOTICE.txt",
    "research/signatures/synthetic_authorization.json",
    "research/signatures/verify_reference.py",
    "research/signatures/source_record.json",
    "research/ntt-proofs/reference_vectors.py",
    "research/coefficient-constraints/reference_vectors.py",
    "research/relations/recipient_vectors.py",
    "LICENSE",
}


def check():
    record = json.loads((BASE / "source_inventory.json").read_bytes())
    assert record["format"] == "thorum.signature-ownership.code-inventory.v1"
    assert set(record["local"]) == LOCAL and set(record["retained"]) == RETAINED
    for section, base in (("local", BASE), ("retained", ROOT)):
        for relative, expected in record[section].items():
            assert len(expected) == 64 and set(expected) <= set("0123456789abcdef")
            assert hashlib.sha256((base / relative).read_bytes()).hexdigest() == expected, relative
    for name in LOCAL:
        if name.endswith(".py"):
            ast.parse((BASE / name).read_text(), filename=name)
    package = tomllib.loads((BASE / "producer/Cargo.toml").read_text())
    assert package["package"]["rust-version"] == "1.94.1" and not package["package"]["publish"]
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    existing = {(p["name"], p["version"]) for p in lock["package"]}
    for name, entry in package["dependencies"].items():
        if isinstance(entry, str):
            assert (name, entry.removeprefix("=")) in existing
        elif "version" in entry:
            assert (name, entry["version"].removeprefix("=")) in existing
        else:
            assert (BASE / "producer" / entry["path"]).resolve().is_dir()
    include = BASE / "producer/src/../../authorization.rs"
    assert include.resolve() == (BASE / "authorization.rs").resolve()
    standalone = tomllib.loads((BASE / "producer/Cargo.lock").read_text())
    registry = lambda p: (p["name"], p["version"], p.get("source"), p.get("checksum"))
    original = {registry(p) for p in lock["package"] if "source" in p}
    assert {registry(p) for p in standalone["package"] if "source" in p} <= original
    assert package["workspace"] == {}
    return record


if __name__ == "__main__":
    check()
    print("Pinned sources, paths and syntax match. No mathematical generator or signing executed.")
