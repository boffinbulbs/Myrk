#!/usr/bin/env python3
"""Check fixed modular multiplication declarations and the serial package graph.

This profile change guard reads source and locked offline Cargo metadata. It
does not establish integer correctness, privacy, authorization or soundness.
"""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates/thorum-arithmetic-proof-lab/Cargo.toml"
PROFILE = "thorum.arithmetic-proof-lab.modq8380417.mul.radix4096.serial.p3-0.8.0.v1"
WORKSPACE_PACKAGES = 9
REGISTRY_PACKAGES = 92
P3_PACKAGES = 20


def compact(text):
    return re.sub(r"\s+", "", text)


def main() -> int:
    spec = importlib.util.spec_from_file_location(
        "conservation_profile", ROOT / "research/proofs/profile_check.py"
    )
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    require = baseline.require
    try:
        manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
        dependencies = manifest["dependencies"]
        expected = {name: ("0.8.0", set()) for name in baseline.P3_DIRECT} | baseline.WRAPPER
        require(set(dependencies) == set(expected), "The direct arithmetic dependency set changed.")
        for name, (version, features) in expected.items():
            dependency = dependencies[name]
            require(isinstance(dependency, dict), f"{name} requires an explicit dependency table.")
            require(dependency.get("version") == f"={version}", f"Unexpected {name} version.")
            require(dependency.get("default-features") is False, f"{name} must disable default features.")
            require(set(dependency.get("features", [])) == features, f"Unexpected {name} features.")
            require(not {"git", "path", "registry"} & dependency.keys(),
                    f"{name} must use the published registry source.")
        require(not manifest.get("dev-dependencies"), "Unexpected development dependencies.")
        require("build-dependencies" not in manifest, "Unexpected build dependencies.")

        source = (MANIFEST.parent / "src/lib.rs").read_text(encoding="utf-8")
        declarations = compact(source)
        require(f'b"{PROFILE}"' in source, "The arithmetic proof profile identifier changed.")
        for declaration in [
            "typeChallenge=BinomialExtensionField<BabyBear,4>;",
            "typeCompress=CompressionFunctionFromHasher<NodeHash,2,8>;",
            "typeHidingMmcs=MerkleTreeHidingMmcs<BabyBear,u64,LeafHash,Compress,StdRng,2,8,16>;",
            "typeChallengeMmcs=ExtensionMmcs<BabyBear,Challenge,HidingMmcs>;",
            "typeChallenger=SerializingChallenger32<BabyBear,HashChallenger<u8,TranscriptHash,64>>;",
            "typePcs=HidingFriPcs<BabyBear,Radix2DitParallel<BabyBear>,HidingMmcs,ChallengeMmcs,StdRng>;",
            "HidingMmcs::new(LeafHash,Compress::new(NodeHash),0,mmcs_rng)",
            "ChallengeMmcs::new(mmcs.clone())",
            "Pcs::new(Radix2DitParallel::default(),mmcs,params,4,pcs_rng)",
            "HashChallenger::new(PROFILE.to_vec(),TranscriptHash)",
            "getrandom::fill(&mutseed)", "build_config(fresh_rng()?,fresh_rng()?)",
            "pubconstMAX_PROOF_BYTES:usize=2*1024*1024;",
            "constMAX_JSON_DEPTH:usize=24;", "constMAX_JSON_TOKENS:usize=200_000;",
            "constMAX_JSON_ITEMS:usize=16_384;",
            "proof.degree_bits!=9", "proof.1.sibling_hashes.len()<=64*11",
            "opened.trace_local.len()!=air::WIDTH", "row.len()!=air::WIDTH",
            "opened.quotient_chunks.len()!=4",
            "fri.commit_phase_commits.len()!=9", "fri.commit_pow_witnesses.len()!=9",
            "fri.commit_phase_openings.len()!=9",
            "json_preflight(bytes)?;", "validate_shape(&proof)?;",
            "serde_json::to_vec(&proof).map_err(|_|Error::InvalidEncoding)?!=bytes",
            "index-start>=64", "index-start>20",
            "result.validate()?;",
            "[self.x,self.y,self.z].iter().any(|v|*v>=mul::MODULUS)",
            "pubfnprove_mod_mul(witness:&Witness,statement:&Statement)->Result<Vec<u8>,Error>{statement.validate()?;",
            "pubfnverify_mod_mul(bytes:&[u8],statement:&Statement)->Result<(),Error>{statement.validate()?;",
        ]:
            require(declaration in declarations, f"Fixed arithmetic declaration changed: {declaration}")
        require(re.findall(r"pubstructStatement\{([^}]+)\}", declarations) == [
            "x:u32,y:u32,z:u32,context:[u8;64],"
        ], "The typed public operand statement changed.")
        require(re.findall(r"pubstructWitness\{([^}]+)\}", declarations) == [
            "quotient:u32,carry0:i32,carry1:i32,"
        ], "The private quotient and carry witness changed.")
        parameters = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", source, re.S)
        require(len(parameters) == 1, "Expected one fixed FRI declaration.")
        for name, value in {
            "log_blowup": 2, "log_final_poly_len": 0, "max_log_arity": 1,
            "num_queries": 64, "batch_proof_of_work_bits": 0,
            "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0,
        }.items():
            actual = re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", parameters[0])
            require(actual == [str(value)], f"Fixed FRI {name} changed.")

        multiplication = compact((MANIFEST.parent / "src/mul.rs").read_text(encoding="utf-8"))
        for declaration in [
            "pubconstMODULUS:u32=8_380_417;", "pubconstRADIX:u32=4096;",
            "pubconstVALUE_BITS:usize=23;", "pubconstVALUES:usize=0;",
            "pubconstCOMPLEMENTS:usize=4*VALUE_BITS;",
            "pubconstCARRY0:usize=COMPLEMENTS+4*VALUE_BITS;",
            "pubconstCARRY1:usize=CARRY0+13;", "pubconstWIDTH:usize=CARRY1+14;",
            "pubfneval_mul<AB:AirBuilder<F=BabyBear>>(builder:&mutAB,local:&[AB::Var],)->[AB::Expr;4]",
            "assert_eq!(local.len(),WIDTH);", "forbitinlocal{builder.assert_bool(*bit);}",
            "builder.assert_eq(values[i].clone()+complement,AB::F::from_u32(MODULUS-1));",
            "packed::<AB>(&local[i*23..i*23+12])",
            "packed::<AB>(&local[i*23+12..(i+1)*23])",
            "letcarry0=packed::<AB>(&local[CARRY0..CARRY1])-AB::F::from_u8(2);",
            "letcarry1=packed::<AB>(&local[CARRY1..WIDTH])-AB::F::from_u32(4096);",
            "builder.assert_zero(lows[0].clone()*lows[1].clone()-lows[2].clone()-lows[3].clone()-carry0.clone()*AB::F::from_u32(RADIX),);",
            "builder.assert_zero(lows[0].clone()*highs[1].clone()+highs[0].clone()*lows[1].clone()-lows[2].clone()*AB::F::from_u32(2046)-highs[2].clone()-highs[3].clone()+carry0-carry1.clone()*AB::F::from_u32(RADIX),);",
            "builder.assert_zero(highs[0].clone()*highs[1].clone()-highs[2].clone()*AB::F::from_u32(2046)+carry1,);",
        ]:
            require(declaration in multiplication, f"Fixed multiplication declaration changed: {declaration}")
        air = compact((MANIFEST.parent / "src/air.rs").read_text(encoding="utf-8"))
        for declaration in [
            "pubconstHEIGHT:usize=256;", "pubconstWIDTH:usize=mul::WIDTH;",
            "pubconstPUBLIC_VALUES:usize=12+64;",
            "fnmax_constraint_degree(&self)->Option<usize>{Some(2)}",
            "impl<AB:AirBuilder<F=BabyBear>>Air<AB>forMultiplicationAir",
            "mul::eval_mul(builder,local)",
            "forcolumnin0..WIDTH{builder.when_transition().assert_eq(local[column],next[column]);}",
            "for(public_value,slot)in[0,1,3].into_iter().enumerate()",
            "forbytein0..4", "letstart=byte*8;",
            "letexpected=ifstart<23",
            "mul::packed::<AB>(&local[slot*23+start..slot*23+(start+8).min(23)])}else{AB::Expr::ZERO}",
            "builder.assert_eq(public[public_value*4+byte],expected);",
            ".flat_map(|v|v.to_le_bytes().map(BabyBear::from_u8))",
        ]:
            require(declaration in air, f"Fixed operand harness declaration changed: {declaration}")
        require(8 * 23 + 13 + 14 == 211 and 12 + 64 == 76,
                "The fixed trace or public vector width calculation changed.")
        hashes = (MANIFEST.parent / "src/hash.rs").read_text(encoding="utf-8")
        for role in ("leaf", "node", "transcript"):
            require(f'b"thorum.arithmetic-proof-lab.{role}.v1"' in hashes,
                    f"The fixed {role} adapter domain changed.")
        require("fn begin(domain: &[u8]) -> Sha3_512" in hashes,
                "The fixed adapter hash primitive changed.")

        for all_features in (False, True):
            count, p3_count = baseline.check_resolved(all_features)
            require(count == WORKSPACE_PACKAGES + REGISTRY_PACKAGES,
                    "The resolved package count changed.")
            require(p3_count == P3_PACKAGES, "The resolved pinned p3 package count changed.")
            command = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
            if all_features:
                command.append("--all-features")
            metadata = json.loads(subprocess.run(
                command, cwd=ROOT, check=True, capture_output=True, text=True, timeout=60
            ).stdout)
            require(len(metadata["workspace_members"]) == WORKSPACE_PACKAGES,
                    "The workspace package count changed.")
            packages = {package["id"]: package for package in metadata["packages"]}
            require(sum(package["source"] == baseline.CRATES_IO for package in packages.values())
                    == REGISTRY_PACKAGES, "The resolved registry package count changed.")
            nodes = [node for node in metadata["resolve"]["nodes"]
                     if packages[node["id"]]["name"] == "thorum-arithmetic-proof-lab"]
            require(len(nodes) == 1, "Expected one resolved arithmetic proof package.")
            direct = {dependency["name"].replace("_", "-"): packages[dependency["pkg"]]
                      for dependency in nodes[0]["deps"]}
            require(set(direct) == {name.replace("_", "-") for name in expected},
                    "The resolved direct arithmetic dependency set changed.")
            for name, (version, _) in expected.items():
                package = direct.get(name.replace("_", "-"))
                require(package is not None and package["version"] == version
                        and package["source"] == baseline.CRATES_IO,
                        f"The resolved arithmetic dependency differs: {name}.")
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {count} packages, {p3_count} pinned p3 packages, no Rayon or parallel feature.")
        print(f"PASS: fixed arithmetic profile {PROFILE}.")
        print("PASS: modulus 8380417, radix 4096, 256 by 211 trace, 76 public values, degree bound 2, stored degree bits 9.")
        print("This profile change guard does not establish integer correctness, privacy, authorization or a security level.")
    except (baseline.ProfileError, OSError, ValueError, KeyError, StopIteration,
            subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
