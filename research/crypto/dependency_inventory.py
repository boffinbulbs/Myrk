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
LICENSE_SOURCES = ARTIFACT_ROOT / "license-sources"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LICENSE_PREFIXES = ("LICENSE", "COPYING", "NOTICE")
KNOWN_LICENSES = frozenset(
    {"MIT", "Apache-2.0", "Unlicense", "BSL-1.0", "Unicode-3.0", "LGPL-2.1-or-later", "CC0-1.0"}
)

# This package contains its license grants and copyright in AUTHORS.
EXTRA_LICENSE_FILES = {("r-efi", "6.0.0"): ("AUTHORS",)}

# The reviewed archive declares this repository as its homepage instead.
HOMEPAGE_REPOSITORIES = {
    ("tiny-keccak", "2.0.2"): "https://github.com/debris/tiny-keccak",
}

# These published subcrate archives omit the workspace root license texts.
# Their authenticated VCS metadata must match the release containing these originals.
P3_RELEASE_COMMIT = "a21e3ed42905040ad49c519e402f018381c12d0c"
P3_REPOSITORY = "https://github.com/Plonky3/Plonky3"
P3_PACKAGES = frozenset({
    "p3-air", "p3-baby-bear", "p3-challenger", "p3-commit", "p3-dft", "p3-field",
    "p3-fri", "p3-keccak", "p3-keccak-air", "p3-matrix", "p3-maybe-rayon", "p3-mds", "p3-merkle-tree",
    "p3-monty-31", "p3-poseidon1", "p3-poseidon2", "p3-security", "p3-symmetric",
    "p3-uni-stark", "p3-util",
})
P3_NOTICE_FILES = {
    "LICENSE-APACHE": (
        "3708458dee7f359ac6c9c5558023ed481be87e5372c43ebd7f2ca7ad23c12026",
        "1e5006dc141e22213c898c27abaded8d936c32f0",
    ),
    "LICENSE-MIT": (
        "d6543a1b0a0a51d10b5f8c389324c7dfeba556b7f39815efd292927bde808700",
        "ae8393261a5c288d5efe1208b7ea3de22b861f84",
    ),
}

# This is a dated source check. Generation does not query an advisory service.
ADVISORY_REVIEW = {
    "checked_on": "2026-10-26",
    "source": "https://api.osv.dev/v1/querybatch",
    "cargo_lock_sha256": "bdd8ad4493bdeff553dc0c72025d8d7c0f4446160cf48993d15636d9735dbff2",
    "package_queries": 92,
    "matching_advisories": 1,
    "response_body_bytes": 366,
    "response_body_sha256": "860fa05d158bf8441deeef59b79900ce68b7b170926a5bb3adbc54818977b748",
    "matches": [{
        "package": "paste",
        "version": "1.0.15",
        "id": "RUSTSEC-2024-0436",
        "classification": "informational_unmaintained",
        "patched_versions": [],
        "source": "https://rustsec.org/advisories/RUSTSEC-2024-0436.html",
    }],
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


def upstream_workspace_notices(package: dict, vcs_info: dict | None) -> tuple[dict[str, bytes], dict]:
    """Read reviewed upstream originals omitted from the authenticated subcrate archive."""
    name, version = package["name"], package["version"]
    if (
        name not in P3_PACKAGES
        or version != "0.8.0"
        or package.get("repository") != P3_REPOSITORY
        or package.get("license") != "MIT OR Apache-2.0"
        or not isinstance(vcs_info, dict)
        or not isinstance(vcs_info.get("git"), dict)
        or vcs_info.get("git", {}).get("sha1") != P3_RELEASE_COMMIT
        or vcs_info.get("path_in_vcs") != name.removeprefix("p3-")
    ):
        raise InventoryError(f"No reviewed original license sources for {name} {version}")
    expected_files = {".gitattributes"} | {f"p3-0.8.0/{name}" for name in P3_NOTICE_FILES}
    actual_files = set()
    if LICENSE_SOURCES.is_symlink():
        raise InventoryError("The upstream license source directory cannot be a symlink")
    for path in LICENSE_SOURCES.rglob("*"):
        if path.is_symlink():
            raise InventoryError("An upstream license source cannot be a symlink")
        if path.is_file():
            actual_files.add(path.relative_to(LICENSE_SOURCES).as_posix())
    if actual_files != expected_files:
        raise InventoryError("The upstream license source set differs from its reviewed files")
    if (LICENSE_SOURCES / ".gitattributes").read_bytes() != b"* -text -whitespace\n":
        raise InventoryError("Upstream license originals require stable Git byte handling")
    originals = {}
    for filename, (digest, blob) in P3_NOTICE_FILES.items():
        contents = (LICENSE_SOURCES / "p3-0.8.0" / filename).read_bytes()
        git_blob = hashlib.sha1(f"blob {len(contents)}\0".encode("ascii") + contents).hexdigest()
        if sha256(contents) != digest or git_blob != blob:
            raise InventoryError(f"Reviewed upstream license bytes differ for {filename}")
        contents.decode("utf-8")
        originals[filename] = contents
    return originals, {
        "source_kind": "upstream_repository",
        "repository": P3_REPOSITORY,
        "commit": P3_RELEASE_COMMIT,
    }


def source_notices(package: dict, checksum: str) -> tuple[dict[str, bytes], dict]:
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
    vcs_info = None
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
                if relative == ".cargo_vcs_info.json":
                    stream = archive.extractfile(member) if member.isfile() else None
                    if stream is None:
                        raise InventoryError(f"Invalid VCS source record for {label}")
                    vcs_bytes = stream.read()
                    if source_root.joinpath(relative).read_bytes() != vcs_bytes:
                        raise InventoryError(f"Resolved VCS metadata differs from the archive for {label}")
                    vcs_info = json.loads(vcs_bytes)
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
        return upstream_workspace_notices(package, vcs_info)
    return selected, {"source_kind": "registry_archive"}


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
        repository_value = package.get("repository")
        repository_metadata_field = "repository"
        if repository_value is None:
            reviewed_homepage = HOMEPAGE_REPOSITORIES.get(key)
            if reviewed_homepage is None or package.get("homepage") != reviewed_homepage:
                raise InventoryError(f"Missing reviewed repository metadata for {label}")
            repository_value = reviewed_homepage
            repository_metadata_field = "homepage"
        repository = repository_url(repository_value, label)
        originals, provenance = source_notices(package, locked[key])
        records = []
        for filename, contents in sorted(originals.items()):
            digest = sha256(contents)
            artifact_name = f"{digest}.txt"
            if artifact_name in license_artifacts and license_artifacts[artifact_name] != contents:
                raise InventoryError("License content hash collision")
            license_artifacts[artifact_name] = contents
            record = {
                "source_filename": filename,
                "sha256": digest,
                "artifact": f"licenses/{artifact_name}",
                **provenance,
            }
            if provenance["source_kind"] == "upstream_repository":
                record["git_blob_sha1"] = P3_NOTICE_FILES[filename][1]
                record["source_input"] = f"license-sources/p3-0.8.0/{filename}"
                record["source_url"] = f"{P3_REPOSITORY}/blob/{P3_RELEASE_COMMIT}/{filename}"
            records.append(record)
        packages.append(
            {
                "name": key[0],
                "version": key[1],
                "spdx_license": expression,
                "repository": repository,
                "repository_metadata_field": repository_metadata_field,
                "registry_checksum_sha256": locked[key],
                "license_files": records,
            }
        )
    if seen != locked.keys():
        raise InventoryError("Cargo metadata omits locked registry packages")
    lock_hash = sha256(lock_bytes)
    review = dict(ADVISORY_REVIEW)
    review["matches_current_lock"] = lock_hash == review["cargo_lock_sha256"]
    if review["matching_advisories"] != len(review["matches"]):
        raise InventoryError("The recorded advisory count differs from its matching records")
    if review["matches_current_lock"] and (
        review["package_queries"] != len(locked)
        or any((match["package"], match["version"]) not in locked for match in review["matches"])
    ):
        raise InventoryError("The recorded advisory package coverage differs from this lock")
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
    advisory_table = ""
    if review["matches"]:
        rows = [
            "| Package | Version | Record | Classification | Patched versions |",
            "|---|---|---|---|---|",
        ]
        for match in review["matches"]:
            patched = ", ".join(match["patched_versions"]) or "None recorded"
            classification = match["classification"].replace("_", " ")
            rows.append(
                f"| {match['package']} | {match['version']} | [{match['id']}]({match['source']}) | "
                f"{classification} | {patched} |"
            )
        advisory_table = "\n\n" + "\n".join(rows)
    text = f"""# Third party notices

## Scope and original notices

Thorum project code is covered by the project [MIT license](LICENSE). Registry dependencies retain their own licensing terms, copyrights and notices. The project license does not replace those terms.

The [dependency inventory](research/crypto/dependency-inventory.json) records all {count} registry packages in the current Cargo.lock, including development and target specific packages across all platforms represented by the resolution. The dependency graph covers the workspace and its isolated primitive, relation and proof laboratories. No released binary distribution is represented by this inventory. A package in the lock file is not necessarily linked on every platform.

Each package record contains its name, version, upstream SPDX expression, repository URL and metadata field, registry archive checksum, original license filenames, provenance and source byte hashes. The [license directory](research/crypto/licenses) preserves the original text bytes. Identical files share one content hash filename. Copyright statements are retained exactly rather than replaced with Thorum attribution. No license alternative is selected by this inventory.

The collection includes root LICENSE, COPYING and NOTICE files, explicit license files in package metadata, and reviewed packaging exceptions. The r-efi package stores its license grants and copyright in AUTHORS, which is preserved under its original filename in the inventory. The unicode-ident expression includes Unicode-3.0 in addition to its alternative code licenses. These source terms remain distinct from the project MIT license.

The {len(P3_PACKAGES)} p3 0.8.0 subcrate archives declare MIT OR Apache-2.0 but omit the workspace root license texts. Their archive authenticated VCS metadata identifies release commit `{P3_RELEASE_COMMIT}`. The [original workspace license sources](research/crypto/license-sources/p3-0.8.0) preserve both texts from that exact commit. Inventory records include their repository paths, commit, Git blob identifiers, SHA256 hashes and local source inputs. Generation verifies both hashes before copying their original bytes. The tiny-keccak 2.0.2 package declares CC0-1.0 and places its repository URL in the homepage field. The inventory records that reviewed metadata exception and retains the complete original CC0 text.

## Reproduction and byte verification

The generator uses Python 3.11 or later and captures `cargo metadata --format-version 1 --locked --offline` internally. Cargo.lock is parsed with the standard library TOML reader. Every cached registry archive is verified against its lock checksum before notice bytes are read. Archive notice bytes must also match the resolved source package. The separately preserved workspace originals are checked against their reviewed commit and content hashes. Full Cargo metadata, local paths, environment details and host identifiers are not published.

After the complete locked registry cache is available, the commands are:

```text
python research/crypto/dependency_inventory.py
python research/crypto/dependency_inventory.py --check
```

Generation reproduces the inventory, this notice and the copied license artifacts. Check mode compares exact bytes and the complete artifact set without rewriting files. Missing packages, old records, missing notices, altered bytes, stale copied files, unknown license identifiers and missing license metadata cause a failure. Additional license identifiers or packaging exceptions require an explicit generator review. The license directory disables Git text conversion so original bytes remain stable across checkouts.

## Dated advisory source check

On {review['checked_on']}, a public OSV query batch for all {review['package_queries']} exact resolved registry versions returned {review['matching_advisories']} matching advisory record. {coverage} This is a dated database response and upstream source review, not a security audit or a guarantee of absent vulnerabilities. Inventory generation and check mode do not contact OSV or refresh this snapshot.{advisory_table}

The paste record is an informational maintenance notice, with no patched version recorded. This procedural macro enters the graph through p3-field. The exact resolution is retained for the isolated experiment. Replacement or an upstream dependency migration remains an open maintenance task. This record is not described as a demonstrated runtime exploit.

| Snapshot field | Value |
|---|---|
| Reviewed Cargo.lock SHA256 | `{review['cargo_lock_sha256']}` |
| Raw OSV response body SHA256 | `{review['response_body_sha256']}` |
| Raw OSV response body length | {review['response_body_bytes']} bytes |
| Source | [OSV query batch API](https://google.github.io/osv.dev/post-v1-querybatch/) |

The reviewed resolution contains ml-kem 0.3.3. Its [upstream security repair](https://github.com/RustCrypto/KEMs/pull/386) removes secret indexed CBD table access across all parameter sets, including ML-KEM-1024. That repair was identified through the upstream changelog despite an earlier empty advisory response for the older lock. An empty database result therefore does not replace source review. In the reviewed resolution, ctutils 0.4.6 is above the [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) patched threshold, and cmov 0.5.4 is above the [RUSTSEC-2026-0003](https://rustsec.org/advisories/RUSTSEC-2026-0003.html) patched threshold.

The proof dependency source review also inspected the [upstream advisory index](https://github.com/Plonky3/Plonky3/security/advisories), including earlier FRI shape, final polynomial and transcript binding repairs. The retained 0.8.0 sources still contain the hiding RNG lock behavior reported in [issue 2363](https://github.com/Plonky3/Plonky3/issues/2363). The isolated proof profile disables every parallel feature and does not include Rayon. The [proof laboratory record](docs/proof-lab.md) states the exact configuration and remaining security limits. These source findings are separate from the OSV batch response.

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
