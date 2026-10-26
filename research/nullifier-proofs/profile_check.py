#!/usr/bin/env python3
"""Check fixed nullifier proof declarations and the resolved serial graph.

This profile change guard reads source declarations and locked offline Cargo
metadata. It does not establish relation correctness, privacy or soundness.
"""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "crates/thorum-nullifier-proof-lab/Cargo.toml"
PROFILE = "thorum.nullifier-proof-lab.v2-payment.depth32.sha3-512.serial.p3-0.8.0.v1"
WORKSPACE_PACKAGES = 7
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
        require(set(dependencies) == set(expected), "The direct nullifier dependency set changed.")
        for name, (version, features) in expected.items():
            dependency = dependencies[name]
            require(isinstance(dependency, dict), f"{name} requires an explicit dependency table.")
            require(dependency.get("version") == f"={version}", f"Unexpected {name} version.")
            require(dependency.get("default-features") is False, f"{name} must disable default features.")
            require(set(dependency.get("features", [])) == features, f"Unexpected {name} features.")
            require(not {"git", "path", "registry"} & dependency.keys(),
                    f"{name} must use the published registry source.")
        require(manifest.get("dev-dependencies") == {
            name: {"path": f"../{name}"}
            for name in ("thorum-core", "thorum-crypto-lab", "thorum-relation-lab")
        }, "The local integration dependency set changed.")
        require("build-dependencies" not in manifest, "Unexpected build dependencies.")

        source = (MANIFEST.parent / "src/lib.rs").read_text(encoding="utf-8")
        declarations = compact(source)
        require(f'b"{PROFILE}"' in source, "The nullifier proof profile identifier changed.")
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
            "pubconstMAX_PROOF_BYTES:usize=8*1024*1024;",
            "constMAX_JSON_DEPTH:usize=24;",
            "constMAX_JSON_TOKENS:usize=1_000_000;",
            "constMAX_JSON_ITEMS:usize=16_384;",
            "proof.degree_bits!=14",
            "proof.1.sibling_hashes.len()<=64*17",
            "opened.quotient_chunks.len()!=8",
            "fri.commit_phase_commits.len()!=14",
            "fri.commit_pow_witnesses.len()!=14",
            "fri.commit_phase_openings.len()!=14",
            "index-start>=64",
            "index-start>20",
        ]:
            require(declaration in declarations,
                    f"Fixed nullifier proof declaration changed: {declaration}")
        statements = re.findall(r"pubstructStatement\{([^}]+)\}", declarations)
        require(statements == [
            "pubfee:u64,pubchain:[u8;32],puboutput_creation_versions:[u32;2],"
            "pubasset:[u8;32],pubroot:[u8;64],puboutput_commitments:[[u8;64];2],"
            "pubnullifiers:[[u8;64];2],pubcontext:[u8;64],"
        ], "The public nullifier statement layout changed.")
        witnesses = re.findall(r"pubstructWitness\{([^}]+)\}", declarations)
        require(witnesses == [
            "openings:[[u8;418];4],secrets:[[u8;32];2],indices:[u32;2],"
            "siblings:[[[u8;64];32];2],"
        ], "The private nullifier witness layout changed.")
        require(declarations.count(
            "ifstatement.nullifiers[0]==statement.nullifiers[1]{"
            "returnErr(Error::DuplicateNullifier);}") == 2,
            "Both public entry points must reject duplicate nullifiers.")
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
            "pubconstDEPTH:usize=32;", "pubconstHEIGHT:usize=8192;",
            "pubconstPERMUTATIONS:usize=234;",
            "constSELECTORS:usize=NUM_KECCAK_COLS;",
            "constMESSAGE:usize=SELECTORS+PERMUTATIONS+1;",
            "constOUTPUT:usize=MESSAGE+576;", "constAMOUNTS:usize=OUTPUT+576;",
            "constSUM:usize=AMOUNTS+256;", "constINPUT_CARRY:usize=SUM+64;",
            "constOUTPUT_CARRY:usize=INPUT_CARRY+64;",
            "constCOMMITMENTS:usize=OUTPUT_CARRY+64;",
            "constDISTINCT_INVERSE:usize=COMMITMENTS+64;",
            "constINPUT_VERSIONS:usize=DISTINCT_INVERSE+32;",
            "constSECRETS:usize=INPUT_VERSIONS+8;",
            "constBINDINGS:usize=SECRETS+64;",
            "constCM_SPLIT:usize=BINDINGS+128;",
            "constROLLING:usize=CM_SPLIT+4;", "constDIRECTION:usize=ROLLING+32;",
            "pubconstWIDTH:usize=DIRECTION+1;",
            "pubconstPUBLIC_VALUES:usize=64+32+8+32+64+128+128+64;",
            "constPUBLIC_ASSET:usize=104;", "constPUBLIC_ROOT:usize=136;",
            "constPUBLIC_OUTPUTS:usize=200;",
            "constPUBLIC_NULLIFIERS:usize=328;",
        ]:
            require(declaration in layout, f"Fixed trace layout changed: {declaration}")
        require("fnmax_constraint_degree(&self)->Option<usize>{Some(4)}" in layout,
                "The fixed symbolic constraint degree changed.")
        for declaration in [
            "add(Kind::Binding(input),2);", "add(Kind::Nullifier(input),3);",
            "forcolumninAMOUNTS..ROLLING{builder.when_transition().assert_eq(local[column],next[column]);}",
            "result[255+i]=Source::Binding(note*64+i);",
            "Source::Binding(i)=>local[BINDINGS+i].into(),",
            "local[SECRETS+input*32+absolute-secret_start].into()",
            "local[COMMITMENTS+input*32+13],local[CM_SPLIT+input*2].into()+local[CM_SPLIT+input*2+1]*AB::F::from_u16(256)",
            "ifabsolute==143||absolute==144{local[CM_SPLIT+input*2+absolute-143].into()}",
            "iflimb==13{continue;}",
            "s.last&&matches!(s.kind,Kind::Leaf(_)|Kind::Parent(_,_))",
            "assert_eq!(bytes.len(),123);", "assert_eq!(bytes.len(),181);",
        ]:
            require(declaration in layout,
                    f"Fixed nullifier binding declaration changed: {declaration}")
        # The pinned upstream permutation contributes 2633 columns. The checked
        # declarations add 235 selectors, rate bits, integer cells and registers.
        require(2633 + 235 + 576 + 576 + 256 + 64 + 64 + 64 + 64 + 32 + 8 + 64 + 128 + 4 + 32 + 1 == 4801,
                "The fixed trace width calculation changed.")
        require(64 + 32 + 8 + 32 + 64 + 128 + 128 + 64 == 520,
                "The fixed public vector width calculation changed.")
        for domain in ("note-opening.v2", "note-commitment.v2", "merkle-leaf.v1", "merkle-node.v1",
                       "nullifier-secret-binding.v2", "note-nullifier.v2"):
            require(f'b"thorum.relation-lab.{domain}"' in sponge,
                    f"The canonical relation hash domain changed: {domain}.")
        hashes = (MANIFEST.parent / "src/hash.rs").read_text(encoding="utf-8")
        for role in ("leaf", "node", "transcript"):
            require(f'b"thorum.nullifier-proof-lab.{role}.v1"' in hashes,
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
                     if packages[node["id"]]["name"] == "thorum-nullifier-proof-lab"]
            require(len(nodes) == 1, "Expected one resolved nullifier proof package.")
            direct = {dependency["name"].replace("_", "-"): packages[dependency["pkg"]]
                      for dependency in nodes[0]["deps"]}
            require(set(direct) == {name.replace("_", "-") for name in dependencies}
                    | set(manifest["dev-dependencies"]),
                    "The resolved direct nullifier dependency set changed.")
            for name, (version, _) in expected.items():
                package = direct.get(name.replace("_", "-"))
                require(package is not None and package["version"] == version
                        and package["source"] == baseline.CRATES_IO,
                        f"The resolved nullifier dependency differs: {name}.")
            mode = "all workspace features" if all_features else "default workspace features"
            print(f"PASS: {mode}: {count} packages, {p3_count} pinned p3 packages, no Rayon or parallel feature.")
        print(f"PASS: fixed nullifier profile {PROFILE}.")
        print("PASS: depth 32, 234 permutations, 235 selectors, 8192 by 4801 trace, 520 public values, stored degree bits 14.")
        print("This profile change guard does not establish relation correctness, witness privacy or a security level.")
    except (baseline.ProfileError, OSError, ValueError, KeyError, StopIteration,
            subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
