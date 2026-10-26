#!/usr/bin/env python3
"""Reproduce registry dependency metadata and original license notices."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_ROOT = ROOT / "research" / "crypto"
INVENTORY = ARTIFACT_ROOT / "dependency-inventory.json"
LICENSES = ARTIFACT_ROOT / "licenses"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LICENSE_PREFIXES = ("LICENSE", "COPYING", "NOTICE")
KNOWN_LICENSES = frozenset(
    {"MIT", "Apache-2.0", "Unlicense", "BSL-1.0", "Unicode-3.0", "LGPL-2.1-or-later"}
)

# This package contains its license grants and copyright in AUTHORS.
EXTRA_LICENSE_FILES = {("r-efi", "6.0.0"): ("AUTHORS",)}

# This is a dated source check. Generation does not query an advisory service.
ADVISORY_REVIEW = {
    "checked_on": "2026-10-26",
    "source": "https://api.osv.dev/v1/querybatch",
    "cargo_lock_sha256": "fcb640b672dc26ecf5cb051ab76e7e0a26e56dcb8341ca1644dfd160683b931d",
    "package_queries": 52,
    "matching_advisories": 0,
    "response_body_bytes": 169,
    "response_body_sha256": "8f96b1b7aa528c6256c0169be2e70b792354589655daacac7b173cfae52596b9",
}


class InventoryError(Exception):
    """A source or artifact does not meet the inventory requirements."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_license(expression: object, label: str) -> str:
    """Accept reviewed SPDX identifiers and explicit AND/OR expressions."""
    if not isinstance(expression, str) or not expression.strip():
        raise InventoryError(f"Missing SPDX license metadata for {label}")
    tokens = re.findall(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
    if "".join(tokens) != "".join(expression.split()):
        raise InventoryError(f"Unrecognized SPDX syntax for {label}")
    position = 0

    def atom() -> None:
        nonlocal position
        if position >= len(tokens):
            raise InventoryError(f"Incomplete SPDX expression for {label}")
        token = tokens[position]
        position += 1
        if token == "(":
            disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise InventoryError(f"Unbalanced SPDX expression for {label}")
            position += 1
        elif token not in KNOWN_LICENSES:
            raise InventoryError(f"Unreviewed SPDX identifier for {label}: {token}")

    def conjunction() -> None:
        nonlocal position
        atom()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            atom()

    def disjunction() -> None:
        nonlocal position
        conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            conjunction()

    disjunction()
    if position != len(tokens):
        raise InventoryError(f"Unrecognized SPDX expression for {label}")
    return expression


def repository_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise InventoryError(f"Missing repository metadata for {label}")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise InventoryError(f"Unrecognized public repository URL for {label}")
    return value


def metadata() -> dict:
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise InventoryError("cargo metadata could not be executed") from error
    if result.returncode != 0:
        raise InventoryError(
            "cargo metadata failed. The complete locked registry cache is required offline"
        )
    try:
        data = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InventoryError("cargo metadata did not return valid JSON") from error
    if Path(data.get("workspace_root", "")).resolve() != ROOT:
        raise InventoryError("cargo metadata returned a different workspace")
    return data


def source_notices(package: dict, checksum: str) -> dict[str, bytes]:
    """Read original bytes from the archive authenticated by Cargo.lock."""
    name = package["name"]
    version = package["version"]
    label = f"{name} {version}"
    source_root = Path(package["manifest_path"]).parent
    package_directory = f"{name}-{version}"
    if source_root.name != package_directory or source_root.parent.parent.name != "src":
        raise InventoryError(f"Unrecognized registry cache layout for {label}")
    archive_path = (
        source_root.parents[2] / "cache" / source_root.parent.name / f"{package_directory}.crate"
    )
    try:
        archive_bytes = archive_path.read_bytes()
    except OSError as error:
        raise InventoryError(f"Missing cached registry archive for {label}") from error
    if sha256(archive_bytes) != checksum:
        raise InventoryError(f"Registry archive checksum mismatch for {label}")

    additional = set(EXTRA_LICENSE_FILES.get((name, version), ()))
    declared_file = package.get("license_file")
    if declared_file:
        declared_path = Path(declared_file)
        if not declared_path.is_absolute():
            declared_path = source_root / declared_path
        try:
            additional.add(declared_path.resolve().relative_to(source_root.resolve()).as_posix())
        except ValueError as error:
            raise InventoryError(f"License metadata escapes the source package for {label}") from error

    selected: dict[str, bytes] = {}
    prefix = package_directory + "/"
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            names: set[str] = set()
            for member in members:
                if not member.name.startswith(prefix):
                    raise InventoryError(f"Unexpected registry archive entry for {label}")
                relative = member.name[len(prefix) :]
                path = PurePosixPath(relative)
                if not relative or path.is_absolute() or ".." in path.parts or "\\" in relative:
                    raise InventoryError(f"Unsafe registry archive entry for {label}")
                if relative in names:
                    raise InventoryError(f"Duplicate registry archive entry for {label}")
                names.add(relative)
                is_root_notice = len(path.parts) == 1 and path.name.upper().startswith(LICENSE_PREFIXES)
                if not is_root_notice and relative not in additional:
                    continue
                if not member.isfile():
                    raise InventoryError(f"License source is not a regular file for {label}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise InventoryError(f"Unreadable license source for {label}")
                contents = stream.read()
                if not contents:
                    raise InventoryError(f"Empty license source for {label}")
                contents.decode("utf-8")
                installed = source_root.joinpath(*path.parts)
                if installed.is_symlink() or installed.read_bytes() != contents:
                    raise InventoryError(f"Resolved license bytes differ from the archive for {label}")
                selected[relative] = contents
    except (OSError, tarfile.TarError, UnicodeDecodeError) as error:
        raise InventoryError(f"Invalid original license source for {label}") from error
    if additional - selected.keys():
        raise InventoryError(f"Missing declared or reviewed license file for {label}")
    if not selected:
        raise InventoryError(f"No original license notice files found for {label}")
    return selected


def build_inventory(lock_bytes: bytes, data: dict) -> tuple[dict, dict[str, bytes]]:
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    locked: dict[tuple[str, str], str] = {}
    for package in lock.get("package", []):
        source = package.get("source")
        if source is None:
            continue
        if source != REGISTRY:
            raise InventoryError("An unrecognized dependency source requires inventory review")
        key = (package["name"], package["version"])
        checksum = package.get("checksum", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or key in locked:
            raise InventoryError(f"Invalid lock checksum or duplicate record for {key[0]} {key[1]}")
        locked[key] = checksum

    workspace = set(data["workspace_members"])
    packages = []
    license_artifacts: dict[str, bytes] = {".gitattributes": b"* -text\n"}
    seen: set[tuple[str, str]] = set()
    for package in data["packages"]:
        if package["id"] in workspace:
            continue
        key = (package["name"], package["version"])
        label = f"{key[0]} {key[1]}"
        if package.get("source") != REGISTRY or key not in locked or key in seen:
            raise InventoryError(f"Metadata and locked registry records disagree for {label}")
        seen.add(key)
        expression = validate_license(package.get("license"), label)
        repository = repository_url(package.get("repository"), label)
        originals = source_notices(package, locked[key])
        records = []
        for filename, contents in sorted(originals.items()):
            digest = sha256(contents)
            artifact_name = f"{digest}.txt"
            if artifact_name in license_artifacts and license_artifacts[artifact_name] != contents:
                raise InventoryError("License content hash collision")
            license_artifacts[artifact_name] = contents
            records.append(
                {
                    "source_filename": filename,
                    "sha256": digest,
                    "artifact": f"licenses/{artifact_name}",
                }
            )
        packages.append(
            {
                "name": key[0],
                "version": key[1],
                "spdx_license": expression,
                "repository": repository,
                "registry_checksum_sha256": locked[key],
                "license_files": records,
            }
        )
    if seen != locked.keys():
        raise InventoryError("Cargo metadata omits locked registry packages")
    lock_hash = sha256(lock_bytes)
    review = dict(ADVISORY_REVIEW)
    review["matches_current_lock"] = lock_hash == review["cargo_lock_sha256"]
    return (
        {
            "cargo_lock_sha256": lock_hash,
            "advisory_review": review,
            "packages": sorted(packages, key=lambda package: (package["name"], package["version"])),
        },
        license_artifacts,
    )


def render_notices(inventory: dict) -> bytes:
    count = len(inventory["packages"])
    review = inventory["advisory_review"]
    coverage = (
        "The recorded response covers the current lock file."
        if review["matches_current_lock"]
        else "The current lock file differs from that snapshot and requires a new advisory source check."
    )
    text = f"""# Third party notices

## Scope and original notices

Thorum project code is covered by the project [MIT license](LICENSE). Registry dependencies retain their own licensing terms, copyrights and notices. The project license does not replace those terms.

The [dependency inventory](research/crypto/dependency-inventory.json) records all {count} registry packages in the current Cargo.lock, including development and target specific packages across all platforms represented by the resolution. The dependency graph covers the workspace and its isolated primitive and relation laboratories. No released binary distribution is represented by this inventory. A package in the lock file is not necessarily linked on every platform.

Each package record contains its name, version, upstream SPDX expression, repository URL, registry archive checksum, original license filenames and source byte hashes. The [license directory](research/crypto/licenses) preserves the original text bytes. Identical files share one content hash filename. Copyright statements are retained exactly rather than replaced with Thorum attribution. No license alternative is selected by this inventory.

The collection includes root LICENSE, COPYING and NOTICE files, explicit license files in package metadata, and reviewed packaging exceptions. The r-efi package stores its license grants and copyright in AUTHORS, which is preserved under its original filename in the inventory. The unicode-ident expression includes Unicode-3.0 in addition to its alternative code licenses. These source terms remain distinct from the project MIT license.

## Reproduction and byte verification

The generator uses Python 3.11 or later and captures `cargo metadata --format-version 1 --locked --offline` internally. Cargo.lock is parsed with the standard library TOML reader. Every cached registry archive is verified against its lock checksum before notice bytes are read. The selected bytes must also match the resolved source package. Full Cargo metadata, local paths, environment details and host identifiers are not published.

After the complete locked registry cache is available, the commands are:

```text
python research/crypto/dependency_inventory.py
python research/crypto/dependency_inventory.py --check
```

Generation reproduces the inventory, this notice and the copied license artifacts. Check mode compares exact bytes and the complete artifact set without rewriting files. Missing packages, old records, missing notices, altered bytes, stale copied files, unknown license identifiers and missing license metadata cause a failure. Additional license identifiers or packaging exceptions require an explicit generator review. The license directory disables Git text conversion so original bytes remain stable across checkouts.

## Dated advisory source check

On {review['checked_on']}, a public OSV query batch for all {review['package_queries']} exact resolved registry versions returned {review['matching_advisories']} matching advisories. {coverage} This is a dated database response and upstream source review, not a security audit or a guarantee of absent vulnerabilities. Inventory generation and check mode do not contact OSV or refresh this snapshot.

| Snapshot field | Value |
|---|---|
| Reviewed Cargo.lock SHA256 | `{review['cargo_lock_sha256']}` |
| Raw OSV response body SHA256 | `{review['response_body_sha256']}` |
| Raw OSV response body length | {review['response_body_bytes']} bytes |
| Source | [OSV query batch API](https://google.github.io/osv.dev/post-v1-querybatch/) |

The reviewed resolution contains ml-kem 0.3.3. Its [upstream security repair](https://github.com/RustCrypto/KEMs/pull/386) removes secret indexed CBD table access across all parameter sets, including ML-KEM-1024. That repair was identified through the upstream changelog despite an earlier empty advisory response for the older lock. An empty database result therefore does not replace source review. In the reviewed resolution, ctutils 0.4.6 is above the [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) patched threshold, and cmov 0.5.4 is above the [RUSTSEC-2026-0003](https://rustsec.org/advisories/RUSTSEC-2026-0003.html) patched threshold.

The inventory records upstream declarations and original notices. It is not a complete legal review, a dependency implementation audit, a cryptographic composition review, or evidence that private payments, confidential stake or production key management have been implemented. Distribution obligations require review for the actual source and binary artifacts being distributed.
"""
    return text.encode("utf-8")


def artifact_files() -> set[str]:
    if LICENSES.is_symlink():
        raise InventoryError("The license artifact directory cannot be a symlink")
    if not LICENSES.exists():
        return set()
    result = set()
    for path in LICENSES.iterdir():
        if not path.is_file() or path.is_symlink():
            raise InventoryError("The license artifact directory contains an unexpected entry")
        if path.name != ".gitattributes" and not re.fullmatch(r"[0-9a-f]{64}\.txt", path.name):
            raise InventoryError("The license artifact directory contains an unmanaged file")
        result.add(path.name)
    return result


def publish(inventory: dict, licenses: dict[str, bytes], check: bool) -> None:
    expected = {
        INVENTORY: (json.dumps(inventory, indent=2, ensure_ascii=True) + "\n").encode("utf-8"),
        NOTICES: render_notices(inventory),
        **{LICENSES / filename: contents for filename, contents in licenses.items()},
    }
    existing = artifact_files()
    if check:
        stale = existing - licenses.keys()
        different = [
            path.relative_to(ROOT).as_posix()
            for path, contents in expected.items()
            if not path.is_file() or path.is_symlink() or path.read_bytes() != contents
        ]
        if stale or different:
            details = ", ".join(sorted(different) + [f"licenses/{name}" for name in sorted(stale)])
            raise InventoryError(f"Inventory artifacts differ: {details}")
    else:
        LICENSES.mkdir(parents=True, exist_ok=True)
        for path, contents in expected.items():
            if path.is_symlink():
                raise InventoryError("A generated artifact cannot be a symlink")
            path.write_bytes(contents)
        for filename in sorted(existing - licenses.keys()):
            (LICENSES / filename).unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify exact bytes without rewriting")
    arguments = parser.parse_args()
    try:
        lock_bytes = (ROOT / "Cargo.lock").read_bytes()
        data = metadata()
        inventory, licenses = build_inventory(lock_bytes, data)
        if (ROOT / "Cargo.lock").read_bytes() != lock_bytes:
            raise InventoryError("Cargo.lock changed during inventory generation")
        publish(inventory, licenses, arguments.check)
    except (InventoryError, OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        print(f"Dependency inventory failed: {error}", file=sys.stderr)
        return 1
    action = "verified" if arguments.check else "generated"
    print(
        f"Dependency inventory {action}: {len(inventory['packages'])} registry packages, "
        f"{len(licenses) - 1} original license text files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
