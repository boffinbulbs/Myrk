#!/usr/bin/env python3
"""Check the fixed note proof declarations and resolved serial dependency graph."""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates/thorum-note-proof-lab/Cargo.toml"
PROFILE = "thorum.note-proof-lab.v2-payment.sha3-512.serial.p3-0.8.0.v1"


def main() -> int:
    spec = importlib.util.spec_from_file_location("conservation_profile", ROOT / "research/proofs/profile_check.py")
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    require = baseline.require
    try:
        manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
        dependencies = manifest["dependencies"]
        expected_p3 = baseline.P3_DIRECT | {"p3-keccak-air"}
        require({name for name in dependencies if name.startswith("p3-")} == expected_p3,
                "The direct note proof dependency set changed.")
        expected = {name: ("0.8.0", set()) for name in expected_p3} | baseline.WRAPPER
        require(set(dependencies) == set(expected), "The reviewed direct dependency set changed.")
        for name, (version, features) in expected.items():
            dependency = dependencies[name]
            require(dependency.get("version") == f"={version}", f"Unexpected {name} version.")
            require(dependency.get("default-features") is False, f"{name} must disable default features.")
            require(set(dependency.get("features", [])) == features, f"Unexpected {name} features.")
            require(not {"git", "path", "registry"} & dependency.keys(), f"{name} must use published registry sources.")
        source = (MANIFEST.parent / "src/lib.rs").read_text(encoding="utf-8")
        require(f'b"{PROFILE}"' in source, "The note proof profile identifier changed.")
        compact = re.sub(r"\s+", "", source)
        for declaration in [
            "typeChallenge=BinomialExtensionField<BabyBear,4>;",
            "typeHidingMmcs=MerkleTreeHidingMmcs<BabyBear,u64,LeafHash,Compress,StdRng,2,8,16>;",
            "typePcs=HidingFriPcs<BabyBear,Radix2DitParallel<BabyBear>,HidingMmcs,ChallengeMmcs,StdRng>;",
            "Pcs::new(Radix2DitParallel::default(),mmcs,params,4,pcs_rng)",
            "pubconstMAX_PROOF_BYTES:usize=8*1024*1024;",
            "constMAX_JSON_DEPTH:usize=24;", "constMAX_JSON_TOKENS:usize=1_000_000;",
            "constMAX_JSON_ITEMS:usize=16_384;",
        ]:
            require(declaration in compact, f"Fixed note proof declaration changed: {declaration}")
        params = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", source, re.S)
        require(len(params) == 1, "Expected one fixed FRI declaration.")
        for name, value in {"log_blowup": 3, "log_final_poly_len": 0, "max_log_arity": 1,
                            "num_queries": 64, "batch_proof_of_work_bits": 0,
                            "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0}.items():
            actual = re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", params[0])
            require(actual == [str(value)], f"Fixed FRI {name} changed.")
        sponge = (MANIFEST.parent / "src/sponge.rs").read_text(encoding="utf-8")
        require("pub const HEIGHT: usize = 1024;" in sponge, "Fixed trace height changed.")
        require(re.search(r"fn max_constraint_degree\(&self\).*?Some\(4\)", sponge, re.S) is not None,
                "Fixed symbolic constraint degree changed.")
        hashes = (MANIFEST.parent / "src/hash.rs").read_text(encoding="utf-8")
        for role in ("leaf", "node", "transcript"):
            require(f'b"thorum.note-proof-lab.{role}.v1"' in hashes, f"Fixed {role} hash domain changed.")
        for all_features in (False, True):
            count, p3_count = baseline.check_resolved(all_features)
            command = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
            if all_features:
                command.append("--all-features")
            metadata = json.loads(subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True, timeout=60).stdout)
            packages = {p["id"]: p for p in metadata["packages"]}
            node = next(n for n in metadata["resolve"]["nodes"] if packages[n["id"]]["name"] == "thorum-note-proof-lab")
            direct = {d["name"].replace("_", "-"): packages[d["pkg"]] for d in node["deps"]}
            for name, (version, _) in expected.items():
                package = direct.get(name.replace("_", "-"))
                require(package is not None and package["version"] == version and package["source"] == baseline.CRATES_IO,
                        f"Resolved note proof dependency differs: {name}.")
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {count} packages, {p3_count} pinned p3 packages, no Rayon or parallel feature.")
        print(f"PASS: fixed note proof profile {PROFILE}.")
        print("This guard does not establish arithmetic correctness, witness privacy or a security level.")
    except (baseline.ProfileError, OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
