#!/usr/bin/env python3
"""Check the resolved serial proof profile. This is not a cryptographic audit.

Cargo runs with --locked and --offline for both default and all workspace
features. No manifest, lockfile or generated artifact is modified.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates" / "thorum-proof-lab" / "Cargo.toml"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
P3_VERSION = "0.8.0"
PROFILE = "thorum.proof-lab.u64-conservation.sha3-512.serial.p3-0.8.0.v1"
P3_DIRECT = {
    "p3-air", "p3-baby-bear", "p3-challenger", "p3-commit", "p3-dft",
    "p3-field", "p3-fri", "p3-matrix", "p3-merkle-tree", "p3-symmetric",
    "p3-uni-stark",
}
WRAPPER = {
    "rand": ("0.10.3", {"std_rng"}),
    "getrandom": ("0.4.3", {"sys_rng"}),
    "sha3": ("0.12.0", set()),
    "serde_json": ("1.0.145", {"std"}),
}


class ProfileError(Exception):
    """A resolved dependency or declared profile differs from this guard."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def check_manifest() -> None:
    with MANIFEST.open("rb") as stream:
        manifest = tomllib.load(stream)
    dependencies = manifest["dependencies"]
    require(
        {name for name in dependencies if name.startswith("p3-")} == P3_DIRECT,
        "The direct Plonky3 dependency set differs from the fixed proof profile.",
    )
    expected = {name: (P3_VERSION, set()) for name in P3_DIRECT} | WRAPPER
    for name, (version, features) in expected.items():
        dependency = dependencies.get(name)
        require(isinstance(dependency, dict), f"{name} requires an explicit dependency table.")
        require(dependency.get("version") == f"={version}", f"{name} must be pinned to ={version}.")
        require(dependency.get("default-features") is False, f"{name} must disable default features.")
        require(set(dependency.get("features", [])) == features, f"{name} has unexpected requested features.")
        require(not {"git", "path", "registry"} & dependency.keys(), f"{name} must use published crates.io sources.")


def check_declarations() -> None:
    source = (MANIFEST.parent / "src" / "lib.rs").read_text(encoding="utf-8")
    require(f'b"{PROFILE}"' in source, "The proof profile identifier differs from the guard.")
    compact = re.sub(r"\s+", "", source)
    for declaration in [
        "typeChallenge=BinomialExtensionField<BabyBear,4>;",
        "typeHidingMmcs=MerkleTreeHidingMmcs<BabyBear,u64,LeafHash,Compress,StdRng,2,8,16>;",
        "typePcs=HidingFriPcs<BabyBear,Radix2DitParallel<BabyBear>,HidingMmcs,ChallengeMmcs,StdRng>;",
        "Pcs::new(Radix2DitParallel::default(),mmcs,params,4,pcs_rng)",
    ]:
        require(declaration in compact, f"A fixed hiding declaration changed: {declaration}")
    parameters = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", source, re.S)
    require(len(parameters) == 1, "Expected exactly one fixed FRI parameter declaration.")
    for name, expected in {
        "log_blowup": 2, "log_final_poly_len": 0, "max_log_arity": 1,
        "num_queries": 64, "batch_proof_of_work_bits": 0,
        "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0,
    }.items():
        values = re.findall(rf"\b{re.escape(name)}\s*:\s*(\d+)\s*,", parameters[0])
        require(values == [str(expected)], f"The declared FRI {name} must remain {expected}.")
    air = (MANIFEST.parent / "src" / "air.rs").read_text(encoding="utf-8")
    for name, expected in {"HEIGHT": 256, "WIDTH": 77, "PUBLIC_VALUES": 128}.items():
        values = re.findall(rf"\bconst\s+{name}\s*:\s*usize\s*=\s*(\d+)\s*;", air)
        require(values == [str(expected)], f"The declared AIR {name} must remain {expected}.")


def check_resolved(all_features: bool) -> tuple[int, int]:
    command = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
    if all_features:
        command.append("--all-features")
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    if completed.returncode:
        raise ProfileError(f"Cargo metadata failed:\n{completed.stderr.strip()}")
    metadata = json.loads(completed.stdout)
    nodes = metadata["resolve"]["nodes"]
    resolved_ids = {node["id"] for node in nodes}
    packages = {package["id"]: package for package in metadata["packages"]}
    p3_count = 0
    for node in nodes:
        package = packages[node["id"]]
        name = package["name"]
        require(name not in {"rayon", "rayon-core"}, f"Forbidden resolved Rayon package: {name}.")
        require("parallel" not in node["features"], f"Forbidden resolved parallel feature: {name}.")
        if name.startswith("p3-"):
            p3_count += 1
            require(package["version"] == P3_VERSION, f"Resolved {name} must be {P3_VERSION}, got {package['version']}.")
            require(package["source"] == CRATES_IO, f"Resolved {name} is not the published crates.io source.")
    proof_ids = [identifier for identifier in resolved_ids if packages[identifier]["name"] == "thorum-proof-lab"]
    require(len(proof_ids) == 1, "Expected exactly one resolved thorum-proof-lab package.")
    proof_node = next(node for node in nodes if node["id"] == proof_ids[0])
    direct = {dependency["name"].replace("_", "-"): packages[dependency["pkg"]] for dependency in proof_node["deps"]}
    for name, (version, _) in WRAPPER.items():
        dependency = direct.get(name.replace("_", "-"))
        require(dependency is not None, f"Missing resolved wrapper dependency: {name}.")
        require(dependency["version"] == version, f"Resolved wrapper {name} must be {version}.")
        require(dependency["source"] == CRATES_IO, f"Resolved wrapper {name} is not a published crates.io source.")
    require(p3_count > 0, "No Plonky3 dependencies were resolved.")
    return len(nodes), p3_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate the profile (the default action).")
    parser.parse_args()
    try:
        check_manifest()
        check_declarations()
        for all_features in (False, True):
            packages, p3_count = check_resolved(all_features)
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {packages} resolved packages, {p3_count} Plonky3 packages at {P3_VERSION}, no Rayon or parallel feature.")
        print(f"PASS: fixed dependency declarations and profile {PROFILE}.")
        print("This feature guard is not a cryptographic audit or a security level estimate.")
    except (ProfileError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
