#!/usr/bin/env python3
"""Check fixed hash proof declarations and the resolved serial dependency graph.

This profile change guard reads source and locked offline Cargo metadata. It
does not establish primitive correctness, privacy, authorization or soundness.
"""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates/thorum-hash-proof-lab/Cargo.toml"
PROFILE = "thorum.hash-proof-lab.keccak.sha3-shake.serial.p3-0.8.0.v1"
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
        expected_p3 = baseline.P3_DIRECT | {"p3-keccak-air"}
        expected = {name: ("0.8.0", set()) for name in expected_p3} | baseline.WRAPPER
        require(set(dependencies) == set(expected), "The direct hash dependency set changed.")
        for name, (version, features) in expected.items():
            dependency = dependencies[name]
            require(isinstance(dependency, dict), f"{name} requires an explicit dependency table.")
            require(dependency.get("version") == f"={version}", f"Unexpected {name} version.")
            require(dependency.get("default-features") is False, f"{name} must disable default features.")
            require(set(dependency.get("features", [])) == features, f"Unexpected {name} features.")
            require(not {"git", "path", "registry"} & dependency.keys(),
                    f"{name} must use the published registry source.")
        require(manifest.get("dev-dependencies") == {
            "shake": {"version": "=0.1.0", "default-features": False},
        }, "The hash reference dependency set changed.")
        require("build-dependencies" not in manifest, "Unexpected build dependencies.")

        source = (MANIFEST.parent / "src/lib.rs").read_text(encoding="utf-8")
        declarations = compact(source)
        require(f'b"{PROFILE}"' in source, "The hash proof profile identifier changed.")
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
            "getrandom::fill(&mutseed)",
            "build_config(fresh_rng()?,fresh_rng()?)",
            "pubconstMAX_PROOF_BYTES:usize=8*1024*1024;",
            "constMAX_JSON_DEPTH:usize=24;",
            "constMAX_JSON_TOKENS:usize=1_000_000;",
            "constMAX_JSON_ITEMS:usize=16_384;",
            "pubconstMAX_INPUT_BYTES:usize=2592;",
            "pubconstMAX_OUTPUT_BYTES:usize=840;",
            "proof.degree_bits!=11",
            "proof.1.sibling_hashes.len()<=64*14",
            "opened.trace_local.len()!=sponge::WIDTH",
            "row.len()!=sponge::WIDTH",
            "opened.quotient_chunks.len()!=8",
            "fri.commit_phase_commits.len()!=11",
            "fri.commit_pow_witnesses.len()!=11",
            "fri.commit_phase_openings.len()!=11",
            "json_preflight(bytes)?;",
            "validate_shape(&proof)?;",
            "serde_json::to_vec(&proof).map_err(|_|Error::InvalidEncoding)?!=bytes",
            "index-start>=64", "index-start>20",
        ]:
            require(declaration in declarations, f"Fixed hash declaration changed: {declaration}")
        require(re.findall(r"pubenumMode\{([^}]+)\}", declarations) == [
            "Sha3_512=1,Shake128=2,Shake256=3,"
        ], "The typed primitive identifiers changed.")
        for declaration in [
            "fnrate(self)->usize{matchself{Self::Sha3_512=>72,Self::Shake128=>168,Self::Shake256=>136,}}",
            "fnsuffix(self)->u8{matchself{Self::Sha3_512=>6,Self::Shake128|Self::Shake256=>31,}}",
            "result.validate()?;",
            "self.input_length>MAX_INPUT_BYTES||self.output_length==0||self.output_length>MAX_OUTPUT_BYTES",
            "self.mode==Mode::Sha3_512&&self.output_length!=64",
            "self.output[self.output_length..].iter().any(|b|*b!=0)",
            "pubfnprove_hash(witness:&Witness,statement:&Statement)->Result<Vec<u8>,Error>{statement.validate()?;",
            "pubfnverify_hash(bytes:&[u8],statement:&Statement)->Result<(),Error>{statement.validate()?;",
            "ifwitness.input.len()!=statement.input_length{returnErr(Error::InvalidWitness);}",
        ]:
            require(declaration in declarations, f"Fixed typed boundary changed: {declaration}")
        require(re.findall(r"pubstructStatement\{([^}]+)\}", declarations) == [
            "mode:Mode,input_length:usize,output_length:usize,output:[u8;MAX_OUTPUT_BYTES],context:[u8;64],"
        ], "The private field statement boundary changed.")
        require(re.findall(r"pubstructWitness\{([^}]+)\}", declarations) == ["input:Vec<u8>,"],
                "The private input witness layout changed.")
        parameters = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", source, re.S)
        require(len(parameters) == 1, "Expected one fixed FRI declaration.")
        for name, value in {
            "log_blowup": 3, "log_final_poly_len": 0, "max_log_arity": 1,
            "num_queries": 64, "batch_proof_of_work_bits": 0,
            "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0,
        }.items():
            actual = re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", parameters[0])
            require(actual == [str(value)], f"Fixed FRI {name} changed.")

        sponge = (MANIFEST.parent / "src/sponge.rs").read_text(encoding="utf-8")
        layout = compact(sponge)
        for declaration in [
            "pubconstHEIGHT:usize=1024;", "pubconstMAX_PERMUTATIONS:usize=37;",
            "pubconstMAX_RATE:usize=168;", "constSELECTORS:usize=NUM_KECCAK_COLS;",
            "constMESSAGE:usize=SELECTORS+MAX_PERMUTATIONS+1;",
            "constOUTPUT:usize=MESSAGE+MAX_RATE*8;", "pubconstWIDTH:usize=OUTPUT+MAX_RATE*8;",
            "pubconstPUBLIC_VALUES:usize=1+4+4+MAX_OUTPUT_BYTES+64;",
            "constPUBLIC_OUTPUT:usize=9;",
            "fnmax_constraint_degree(&self)->Option<usize>{Some(4)}",
            "self.input_length/self.mode.rate()+1",
            "self.absorbs()+self.output_length.saturating_sub(1)/self.mode.rate()",
            "builder.assert_eq(public[0],AB::F::from_u8(self.modeasu8));",
            "forvaluein&public[PUBLIC_OUTPUT+self.output_length..PUBLIC_OUTPUT+MAX_OUTPUT_BYTES]{builder.assert_zero(*value);}",
            "ifabsolute+1==absorbs*rate{value|=128;}",
            "ifbit>=rate*8{builder.assert_zero(local[MESSAGE+bit]);builder.assert_zero(local[OUTPUT+bit]);}",
            "letoffset=(stage+1-absorbs)*rate;",
            "forbytein0..rate.min(self.output_length.saturating_sub(offset))",
            "forlimbin0..100",
            "acc.double()+a.xor(&b)",
            "builder.when(builder.is_transition()*final_round*absorb_next.clone()).assert_eq(input,expected);",
            "builder.when(builder.is_transition()*final_round*squeeze_next.clone()).assert_eq(input,last);",
        ]:
            require(declaration in layout, f"Fixed sponge declaration changed: {declaration}")
        require(2633 + 38 + 2 * 168 * 8 == 5359, "The fixed trace width calculation changed.")
        require(1 + 4 + 4 + 840 + 64 == 913, "The fixed public vector width calculation changed.")
        hashes = (MANIFEST.parent / "src/hash.rs").read_text(encoding="utf-8")
        for role in ("leaf", "node", "transcript"):
            require(f'b"thorum.hash-proof-lab.{role}.v1"' in hashes,
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
                     if packages[node["id"]]["name"] == "thorum-hash-proof-lab"]
            require(len(nodes) == 1, "Expected one resolved hash proof package.")
            direct = {dependency["name"].replace("_", "-"): packages[dependency["pkg"]]
                      for dependency in nodes[0]["deps"]}
            expected_resolved = expected | {"shake": ("0.1.0", set())}
            require(set(direct) == {name.replace("_", "-") for name in expected_resolved},
                    "The resolved direct hash dependency set changed.")
            for name, (version, _) in expected_resolved.items():
                package = direct.get(name.replace("_", "-"))
                require(package is not None and package["version"] == version
                        and package["source"] == baseline.CRATES_IO,
                        f"The resolved hash dependency differs: {name}.")
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {count} packages, {p3_count} pinned p3 packages, no Rayon or parallel feature.")
        print(f"PASS: fixed hash profile {PROFILE}.")
        print("PASS: 37 maximum permutations, 38 selectors, 1024 by 5359 trace, 913 public values, degree bound 4, stored degree bits 11.")
        print("This profile change guard does not establish primitive correctness, privacy, authorization or a security level.")
    except (baseline.ProfileError, OSError, ValueError, KeyError, StopIteration,
            subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
