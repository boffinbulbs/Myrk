#!/usr/bin/env python3
"""Check fixed normal residue NTT declarations and the serial package graph.

This profile change guard reads source and locked offline Cargo metadata. It
does not establish transform correctness, privacy, authorization or soundness.
"""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates/thorum-ntt-proof-lab/Cargo.toml"
PROFILE = "thorum.ntt-proof-lab.modq8380417.radix4096.serial.p3-0.8.0.v1"
WORKSPACE_PACKAGES = 10
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
        local_name = "thorum-arithmetic-proof-lab"
        require(set(dependencies) == set(expected) | {local_name},
                "The direct transform dependency set changed.")
        require(dependencies[local_name] == {"path": "../thorum-arithmetic-proof-lab"},
                "The reused multiplication gadget source changed.")
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
        require(f'b"{PROFILE}"' in source, "The transform proof profile identifier changed.")
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
            "usethorum_arithmetic_proof_lab::mul;",
            "pubconstMAX_PROOF_BYTES:usize=64*1024*1024;",
            "constMAX_JSON_DEPTH:usize=24;", "constMAX_JSON_TOKENS:usize=8_000_000;",
            "constMAX_JSON_ITEMS:usize=65_536;",
            "proof.degree_bits!=9", "proof.1.sibling_hashes.len()<=64*11",
            "opened.trace_local.len()!=air::WIDTH", "row.len()!=air::WIDTH",
            "opened.quotient_chunks.len()!=4",
            "fri.commit_phase_commits.len()!=9", "fri.commit_pow_witnesses.len()!=9",
            "fri.commit_phase_openings.len()!=9",
            "json_preflight(bytes)?;", "validate_shape(&proof)?;",
            "serde_json::to_vec(&proof).map_err(|_|Error::InvalidEncoding)?!=bytes",
            "index-start>=64", "index-start>20",
            "result.validate()?;",
            "self.input.iter().chain(&self.output).any(|v|*v>=mul::MODULUS)",
            "pubfnprove_ntt(witness:&Witness,statement:&Statement)->Result<Vec<u8>,Error>{statement.validate()?;",
            "pubfnverify_ntt(bytes:&[u8],statement:&Statement)->Result<(),Error>{statement.validate()?;",
        ]:
            require(declaration in declarations, f"Fixed transform declaration changed: {declaration}")
        require(re.findall(r"pubenumMode\{([^}]+)\}", declarations) == ["Forward=1,Inverse=2,"],
                "The typed transform identifiers changed.")
        require(re.findall(r"pubstructStatement\{([^}]+)\}", declarations) == [
            "mode:Mode,input:[u32;256],output:[u32;256],context:[u8;64],"
        ], "The typed public polynomial statement changed.")
        require(re.findall(r"pubstructWitness\{([^}]+)\}", declarations) == [
            "input:[u32;256],"
        ], "The private polynomial witness changed.")
        parameters = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", source, re.S)
        require(len(parameters) == 1, "Expected one fixed FRI declaration.")
        for name, value in {
            "log_blowup": 2, "log_final_poly_len": 0, "max_log_arity": 1,
            "num_queries": 64, "batch_proof_of_work_bits": 0,
            "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0,
        }.items():
            actual = re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", parameters[0])
            require(actual == [str(value)], f"Fixed FRI {name} changed.")

        multiplication = compact((ROOT / "crates/thorum-arithmetic-proof-lab/src/mul.rs")
                                 .read_text(encoding="utf-8"))
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
        transform = compact((MANIFEST.parent / "src/ntt.rs").read_text(encoding="utf-8"))
        for declaration in [
            "pubconstROOT:u32=1753;", "pubconstINVERSE_256:u32=8_347_681;",
            "power(u64::from(ROOT),(kasu8).reverse_bits()asu32)",
            "assert!(stage<8);",
            "Mode::Forward=>128>>stage", "Mode::Inverse=>1<<stage",
            "Mode::Forward=>(1<<stage)+group", "Mode::Inverse=>(256>>stage)-1-group",
            "Mode::Forward=>z[k]", "Mode::Inverse=>mul::MODULUS-z[k]",
            "letleft=group*2*length+j;", "result.push((left,left+length,twiddle));",
        ]:
            require(declaration in transform, f"Fixed transform ordering changed: {declaration}")
        air = compact((MANIFEST.parent / "src/air.rs").read_text(encoding="utf-8"))
        for declaration in [
            "pubconstHEIGHT:usize=256;", "pubconstSELECTORS:usize=0;",
            "pubconstPADDING:usize=10;", "pubconstPOLYNOMIAL:usize=11;",
            "pubconstCOMPLEMENTS:usize=POLYNOMIAL+256*23;",
            "pubconstPRODUCTS:usize=COMPLEMENTS+256*23;",
            "pubconstCARRIES:usize=PRODUCTS+128*mul::WIDTH;",
            "pubconstWIDTH:usize=CARRIES+256;",
            "pubconstPUBLIC_VALUES:usize=1+1024+1024+64;",
            "fnmax_constraint_degree(&self)->Option<usize>{Some(2)}",
            "impl<AB:AirBuilder<F=BabyBear>>Air<AB>forNttAir",
            "letstages=ifself.mode==Mode::Forward{8}else{10};",
            "builder.assert_eq(public[0],BabyBear::from_u8(self.modeasu8));",
            "foriin0..=PADDING", "builder.assert_bool(selector);",
            "builder.when_first_row().assert_eq(selector,BabyBear::from_bool(i==0));",
            "local[stages-1].into()+local[PADDING]",
            "builder.when_transition().assert_eq(next[i],advance);",
            "builder.assert_one(selector_sum);", "builder.when_last_row().assert_one(local[PADDING]);",
            "forvaluein&local[POLYNOMIAL..PRODUCTS]{builder.assert_bool(*value);}",
            "polynomial[i].clone()+complement,BabyBear::from_u32(mul::MODULUS-1),",
            "builder.when_transition().when(local[PADDING]).assert_eq(polynomial[i].clone(),next_polynomial[i].clone());",
            "letproducts:Vec<_>=(0..128).map",
            "mul::eval_mul(builder,&local[PRODUCTS+slot*mul::WIDTH..PRODUCTS+(slot+1)*mul::WIDTH],)",
            "forcarryin&local[CARRIES..WIDTH]{builder.assert_bool(*carry);}",
            "builder.when(selector).assert_eq(product[0].clone(),BabyBear::from_u32(twiddle));",
            "builder.when(selector).assert_eq(product[1].clone(),b);",
            "a.clone()+product[3].clone()-add*BabyBear::from_u32(mul::MODULUS)",
            "a-product[3].clone()+borrow*BabyBear::from_u32(mul::MODULUS)",
            "a.clone()-b.clone()+borrow*BabyBear::from_u32(mul::MODULUS)",
            "a+b-add*BabyBear::from_u32(mul::MODULUS)",
            "builder.when_transition().when(selector).assert_eq(next_polynomial[right].clone(),product[3].clone());",
            "letselector=local[8+half];", "letindex=half*128+slot;",
            "builder.when(selector).assert_eq(product[0].clone(),BabyBear::from_u32(ntt::INVERSE_256));",
            "builder.when(selector).assert_eq(product[1].clone(),polynomial[index].clone());",
            "builder.when_transition().when(selector).assert_eq(product[3].clone(),next_polynomial[index].clone());",
            "letheld=(1-half)*128+slot;",
            "builder.when_transition().when(selector).assert_eq(polynomial[held].clone(),next_polynomial[held].clone());",
            "builder.when(non_butterfly.clone()).assert_zero(*carry);",
            "builder.when(local[PADDING]).assert_zero(value.clone());",
            "foriin0..256{forbytein0..4{",
            "&local[POLYNOMIAL+i*23+start..POLYNOMIAL+i*23+(start+8).min(23)],",
            "packed::<AB>(&local[POLYNOMIAL+i*23+start..POLYNOMIAL+i*23+(start+8).min(23)],)}else{AB::Expr::ZERO}",
            "builder.when_first_row().assert_eq(public[1+i*4+byte],expected.clone());",
            "builder.when(local[PADDING]).assert_eq(public[1025+i*4+byte],expected);",
            ".flat_map(|v|v.to_le_bytes().map(BabyBear::from_u8))",
        ]:
            require(declaration in air, f"Fixed transform dataflow declaration changed: {declaration}")
        require(11 + 2 * 256 * 23 + 128 * 211 + 256 == 39051 and 1 + 1024 + 1024 + 64 == 2113,
                "The fixed trace or public vector width calculation changed.")
        hashes = (MANIFEST.parent / "src/hash.rs").read_text(encoding="utf-8")
        for role in ("leaf", "node", "transcript"):
            require(f'b"thorum.ntt-proof-lab.{role}.v1"' in hashes,
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
                     if packages[node["id"]]["name"] == "thorum-ntt-proof-lab"]
            require(len(nodes) == 1, "Expected one resolved transform proof package.")
            direct = {dependency["name"].replace("_", "-"): packages[dependency["pkg"]]
                      for dependency in nodes[0]["deps"]}
            require(set(direct) == {name.replace("_", "-") for name in expected} | {local_name},
                    "The resolved direct transform dependency set changed.")
            local_package = direct[local_name]
            require(local_package["source"] is None
                    and Path(local_package["manifest_path"]).resolve()
                    == (ROOT / "crates/thorum-arithmetic-proof-lab/Cargo.toml").resolve(),
                    "The resolved multiplication gadget source changed.")
            for name, (version, _) in expected.items():
                package = direct.get(name.replace("_", "-"))
                require(package is not None and package["version"] == version
                        and package["source"] == baseline.CRATES_IO,
                        f"The resolved transform dependency differs: {name}.")
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {count} packages, {p3_count} pinned p3 packages, no Rayon or parallel feature.")
        print(f"PASS: fixed transform profile {PROFILE}.")
        print("PASS: modulus 8380417, root 1753, 256 by 39051 trace, 2113 public values, degree bound 2, stored degree bits 9.")
        print("This profile change guard does not establish transform correctness, privacy, authorization or a security level.")
    except (baseline.ProfileError, OSError, ValueError, KeyError, StopIteration,
            subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
