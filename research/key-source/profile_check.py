#!/usr/bin/env python3
"""Pin the private key source implementation and its closed diagnostic profile.

This source change guard is not a correctness, privacy, verifier or security
review. Mathematical provenance stays in source_record.json. The separate
implementation_record.json is written only by explicit --freeze-source after
the final public adaptation has been reviewed and its actual tests completed.
The existing hash profile guard remains responsible for resolved features.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
BASE_RELATIVE = "research/key-source"
PREFIX = "crates/thorum-hash-proof-lab"
MODULE = PREFIX + "/src/key_source"
PROFILE = "thorum.private-key-source-proof-lab.mldsa87.two-slots.four-rounds.serial.p3-0.8.0.v1"
RECORD_FORMAT = "thorum.key-source.implementation-record.v1"
RECORD_SCOPE = "Reviewed public source identity and fixed declarations only, without a correctness, privacy, authorization or security verdict"
SOURCE_PATHS = frozenset({
    "Cargo.toml", "Cargo.lock", PREFIX + "/Cargo.toml", PREFIX + "/src/lib.rs",
    MODULE + ".rs", MODULE + "/air.rs", MODULE + "/hash.rs",
    MODULE + "/keccak.rs", MODULE + "/keccak/tests.rs", MODULE + "/packing.rs",
    MODULE + "/proof.rs", MODULE + "/tests.rs", MODULE + "/proof/tests.rs",
    MODULE + "/proof/raw_tests.rs", PREFIX + "/tests/key_source.rs",
    "crates/thorum-arithmetic-proof-lab/src/packing.rs",
    "research/hash-proofs/profile_check.py", BASE_RELATIVE + "/profile_check.py",
})
DEPENDENCY_BASELINES = {
    "Cargo.toml": "2dad10da5dedfdef787a3eac95ddedf59e6d97dd7b51f9f076b6775fa9af8b17",
    "Cargo.lock": "79276c95e6772e0ed31470e8e7c7b7d54204dbc04ec5fbfb87ea6baccb0847c5",
    PREFIX + "/Cargo.toml": "2a33d56aa46171a1a071a818a031bf4e5a8323f87bf6dc780bf019ce6ebfad5c",
    "research/hash-proofs/profile_check.py": "11f7245567cb35ad8aedb703dfe50db215a7bec86c44c7065e1ed6df34725cd6",
    "crates/thorum-arithmetic-proof-lab/src/packing.rs": "cb8997c15b9bd5f1db231206142cfc84e6c5561b5383ad1ba8ffec79d8533d70",
}
REFERENCE_BASELINES = {
    "reference_vectors.py": "91cb13adaa4e6925c1ed8c8adbfb4560f1d9dbc2b0819b024c25c03b40b93c54",
    "vectors.json": "d780f548308905e417f08ea8b4b072ed363bad6751174a64cb3b875992527b29",
    "block_map.csv": "bc48df25b90181ad1a2d2143b6d4ecbe0cfeb7a24314bb7c512a74f97d322629",
    "t1_window_map.csv": "eede52920eb9ac031979a250c0e60415357c1f68804665baf9b265e18b775b8e",
    "logical_round_map.csv": "092ff3e6ebebed57b679c9dadc45841772f84139237a2a2754629bc8b94acc68",
    "lifetimes.json": "3940d7e06b5ad72c29f93336c3079d84320804a51e5c8c3be5c803dfefd7b8a2",
    "hostile_cases.json": "7d049e323297242515f150bb89d2b110930b5ae27a8c9022629e4743aaa2f8ac",
    "dummy_rounds.json": "62ac179370b61d31a6cf90dcbfa72cc827471d8f54eecc6503e54a0aa6897182",
    "hash_vectors.csv": "dc945a6d9213dacb973e16c7b1358677c00d6f925ff67763bb327019182a1cf1",
    "hash_preimages.json": "871d5cf7036abcecad45fb9494075e0f2bc3e480276bf85b4b86c24b32a2d3d1",
    "profile.json": "94295ae867cb102bd6a2462de258c9b10c337d6e9de2556afde752df35bcc4bc",
    "source_record.json": "fcdc85bfbf6fee4472ea13c050501720e978ed57070daa6a70f27214d3debc42",
    "README.md": "19f0c8491907e477cc3cff5fdf5d47614cc82d0290f05997714890eceb1aae3b",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compact(text):
    return re.sub(r"\s+", "", text)


def fingerprint(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON record key: {key}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def source_snapshot(root):
    expected_children = {name for name in SOURCE_PATHS if name.startswith(MODULE + "/")}
    actual_children = set()
    if (root / MODULE).is_dir():
        actual_children = {path.relative_to(root).as_posix() for path in (root / MODULE).rglob("*.rs")}
    require(actual_children == expected_children, "The key source Rust module file inventory changed")
    sources = {}
    for name in sorted(SOURCE_PATHS):
        path = root / name
        require(path.is_file(), f"Required public implementation source is missing: {name}")
        require(path.resolve().is_relative_to(root.resolve()), f"Source leaves repository: {name}")
        sources[name] = path.read_text(encoding="utf-8")
        require(bool(sources[name].strip()), f"Empty implementation source: {name}")
    return sources


def fragments(text, declarations, label):
    code = compact(text)
    for declaration in declarations:
        require(declaration in code, f"Fixed {label} declaration changed: {declaration}")


def check_references(root):
    base = root / BASE_RELATIVE
    for name, expected in REFERENCE_BASELINES.items():
        require(hashlib.sha256((base / name).read_bytes()).hexdigest() == expected,
                f"Frozen independent reference changed: {name}")
    profile = load_json(base / "profile.json")
    expected = {
        "profile": PROFILE, "height": 1024, "width": 20168, "actual_degree": 4,
        "public_values": 64, "key_bytes": 2592, "input_slots": 2,
        "keccak_rounds_per_row": 4, "meaningful_permutations": 114,
        "owner_permutations_per_key": 37, "tr_permutations_per_key": 20,
        "t1_coefficients_per_key": 2048, "t1_window_events_per_key": 256,
        "rows_per_key": 342, "terminal_first_row": 684, "stored_degree_bits": 11,
        "quotient_chunks": 8, "fri_rounds": 11, "queries": 64, "log_blowup": 3,
        "extension_degree": 4, "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
        "public_scope": "Opaque context only, without an AIR canonical transaction mapping",
        "closed_transport": {"bytes": 25165824, "tokens": 2000000, "items": 32768,
                             "depth": 24, "string_bytes": 64, "integer_digits": 20,
                             "merkle_siblings": 896},
    }
    for key, value in expected.items():
        require(type(profile[key]) is type(value) and profile[key] == value,
                f"Fixed private key source parameter changed: {key}")
    arrays = profile["analytical_arrays"]
    require((arrays["raw_trace_bytes"], arrays["randomized_trace_bytes"],
             arrays["main_lde_payload_bytes"]) == (82608128, 165249024, 1321992192),
            "Fixed analytical array dimensions changed")


def check_dependencies(sources):
    for name, expected in DEPENDENCY_BASELINES.items():
        require(fingerprint(sources[name]) == expected,
                f"Unchanged dependency or shared source changed: {name}")
    manifest = tomllib.loads(sources[PREFIX + "/Cargo.toml"])
    require(manifest["dependencies"]["thorum-arithmetic-proof-lab"] == {
        "path": "../thorum-arithmetic-proof-lab", "default-features": False,
    }, "The shared t1 decoder must use the exact existing workspace dependency")
    parent = compact(sources[PREFIX + "/src/lib.rs"])
    require(parent.count("pubmodkey_source;") == 1, "Expected exactly one public key_source child")
    old_parent = parent.replace("pubmodkey_source;", "")
    require(hashlib.sha256(old_parent.encode()).hexdigest()
            == "c1a9461ffd145498710e05817c71d5dee1bc5799742bf3aff4dc50e6af5a3445",
            "Existing parent hash source changed beyond the one child declaration")


def check_source_contracts(sources):
    module = compact(sources[MODULE + ".rs"])
    fragments(module, ["pubconstKEY_BYTES:usize=2592;", "modair;", "modhash;",
                       "modkeccak;", "modpacking;", "modproof;",
                       "pubfnfrom_keys(keys:[[u8;KEY_BYTES];2])->Self{Self{keys}}",
                       "pubfnnew(context:[u8;64])->Self{Self{context}}",
                       "prove_key_slots", "verify_key_slots", "MAX_PROOF_BYTES", "PROFILE"], "API")
    require(re.findall(r"pubstructStatement\{([^}]+)\}", module) == ["context:[u8;64],"],
            "The statement must contain only a private opaque context field")
    require(re.findall(r"pubstructWitness\{([^}]+)\}", module) == ["keys:[[u8;KEY_BYTES];2],"],
            "The witness must retain two private fixed key arrays")
    require(re.search(r"pubuse(?:super|crate)::Error;", module) is not None,
            "Use the existing parent Error type")
    require(not re.search(r"pub(?:\([^)]*\))?mod(?:air|hash|keccak|packing|proof);", module),
            "Key source implementation modules must remain private")

    air = sources[MODULE + "/air.rs"]
    fragments(air, [
        "pubconstHEIGHT:usize=1024;", "pubconstROUNDS:usize=4;",
        "pubconstLOGICAL_HEIGHT:usize=HEIGHT*ROUNDS;", "pubconstGENERATOR_INPUTS:usize=170;",
        "pubconstPERMUTATIONS:usize=114;", "pubconstHASH_PC:usize=ROUNDS*NUM_KECCAK_COLS;",
        "pubconstKEY:usize=HASH_PC+PERMUTATIONS+1;", "pubconstMESSAGE:usize=KEY+KEY_BYTES;",
        "pubconstOUTPUT:usize=MESSAGE+136*8;", "pubconstRHO:usize=OUTPUT+136*8;",
        "pubconstOWNER:usize=RHO+2*32;", "pubconstTR:usize=OWNER+2*64;",
        "pubconstT1:usize=TR+2*64;", "pubconstT1_PC:usize=T1+2*2048;",
        "pubconstT1_MESSAGE:usize=T1_PC+257;", "pubconstWIDTH:usize=T1_MESSAGE+80;",
        "pubconstPUBLIC_VALUES:usize=64;", "forlimbin0..100",
        "letreload=local[HASH_PC+56]*last;",
        "builder.when(reload.clone()).assert_one(local[T1_PC+256]);",
        "(AB::Expr::ONE-reload.clone())*(next[KEY+byte]-local[KEY+byte])",
        "letfresh:AB::Expr=[0,37,57,94]", "letphase=stage%57;",
        "(byte<rate&&offset<KEY_BYTES).then_some(offset)",
        "ifphase==36{ifbyte==0{6}elseifbyte==71{128}else{0}}",
        "elseifphase==56{ifbyte==8{31}elseifbyte==135{128}else{0}}",
        "acc.double()+a.xor(&b)", "builder.is_transition()*last*owner_continue.clone()",
        "builder.is_transition()*last*tr_continue.clone()",
        "local[KEY+32+position*10+byte]", "forindexin0..2048",
        "for(bank,stage)in[(OWNER,slot*57+36),(TR,slot*57+56)]",
        "builder.when_first_row().assert_zero(local[column]);",
        "local[column].into()+write.clone()*(producer-local[column])",
        "local[column].into()+write*(t1[index%8].clone()-local[column])",
        "pubfnpublic_values(statement:&Statement)->Vec<BabyBear>{statement.context.iter().copied().map(BabyBear::from_u8).collect()}",
    ], "source and lifetime")
    require("builder.public_values()" not in compact(air),
            "The diagnostic AIR must not claim a new transaction or public owner mapping")
    packing = sources[MODULE + "/packing.rs"]
    shared_decoder = "thorum_arithmetic_proof_lab::packing::decode_t1"
    require(shared_decoder in compact(packing + air), "Missing direct retained shared t1 decoder")
    require("fndecode_t1" not in compact(packing + air), "Do not copy the shared t1 decoder")
    require(len(re.findall(r"(?:packing::)?decode_t1\(builder,", compact(air))) == 2,
            "Both four coefficient windows must consume the shared decoder")

    keccak = compact(sources[MODULE + "/keccak.rs"])
    fragments(keccak, ["ifSLOT<3{", "ifSLOT==0{", "ifSLOT==3{",
                       "AB::Expr::ONE", "self.0.is_transition()",
                       "KeccakAir{}.eval(&mutKeccakBuilder::<_,0>(builder));",
                       "KeccakAir{}.eval(&mutKeccakBuilder::<_,1>(builder));",
                       "KeccakAir{}.eval(&mutKeccakBuilder::<_,2>(builder));",
                       "KeccakAir{}.eval(&mutKeccakBuilder::<_,3>(builder));"], "four slot Keccak")

    hashes = sources[MODULE + "/hash.rs"]
    for role in ["leaf", "node", "transcript"]:
        require(f'b"thorum.private-key-source-proof-lab.{role}.v1"' in hashes,
                f"Changed {role} namespace")
    fragments(hashes, ["fnwords(bytes:[u8;64])->[u64;8]", "Sha3_512::new()",
                       "(domain.len()asu32).to_be_bytes()", "u64::from_le_bytes(",
                       "value.as_canonical_u32().to_le_bytes()", "word.to_le_bytes()",
                       "count.to_be_bytes()", "hash.finalize().into()"], "full SHA3 adapter")

    proof = sources[MODULE + "/proof.rs"]
    fragments(proof, [
        f'b"{PROFILE}"', "typeChallenge=BinomialExtensionField<BabyBear,4>;",
        "typeCompress=CompressionFunctionFromHasher<NodeHash,2,8>;",
        "typeHidingMmcs=MerkleTreeHidingMmcs<BabyBear,u64,LeafHash,Compress,StdRng,2,8,16>;",
        "typeChallengeMmcs=ExtensionMmcs<BabyBear,Challenge,HidingMmcs>;",
        "typeChallenger=SerializingChallenger32<BabyBear,HashChallenger<u8,TranscriptHash,64>>;",
        "typePcs=HidingFriPcs<BabyBear,Radix2DitParallel<BabyBear>,HidingMmcs,ChallengeMmcs,StdRng>;",
        "HidingMmcs::new(LeafHash,Compress::new(NodeHash),0,mmcs_rng)",
        "ChallengeMmcs::new(mmcs.clone())", "Pcs::new(Radix2DitParallel::default(),mmcs,params,4,pcs_rng)",
        "HashChallenger::new(PROFILE.to_vec(),TranscriptHash)",
        "getrandom::fill(&mutseed).map_err(|_|Error::EntropyUnavailable)?;",
        "build_config(fresh_rng()?,fresh_rng()?)",
        "build_config(StdRng::from_seed([0;32]),StdRng::from_seed([0;32]))",
        "pubconstMAX_PROOF_BYTES:usize=24*1024*1024;", "constMAX_JSON_DEPTH:usize=24;",
        "constMAX_JSON_TOKENS:usize=2_000_000;", "constMAX_JSON_ITEMS:usize=32_768;",
        "pubfnprove_key_slots(witness:&Witness,statement:&Statement)->Result<Vec<u8>,Error>",
        "pubfnverify_key_slots(bytes:&[u8],statement:&Statement)->Result<(),Error>",
        "prove(&config,&KeySlotsAir,trace,&public_values(statement))",
        "verify(&config,&KeySlotsAir,&proof,&public_values(statement))",
        "json_preflight(bytes)?;", "validate_shape(&proof)?;",
        "serde_json::to_vec(&proof).map_err(|_|Error::InvalidEncoding)?!=bytes",
        "proof.degree_bits!=11", "proof.ood_pow_witness!=BabyBear::ZERO",
        "proof.commitments.trace.num_roots()!=1", "proof.commitments.quotient_chunks.num_roots()!=1",
        "opened.trace_local.len()!=air::WIDTH", "row.len()!=air::WIDTH",
        "opened.preprocessed.is_some()", "opened.quotient_chunks.len()!=8",
        "opened.quotient_chunks.iter().any(|chunk|chunk.len()!=4)", "masks.len()!=3",
        "[(0,1,1),(1,1,2),(2,8,1)]", "fri.batch_pow_witness!=BabyBear::ZERO",
        "fri.query_pow_witness!=BabyBear::ZERO", "fri.commit_phase_commits.len()!=11",
        "fri.commit_pow_witnesses.len()!=11", "fri.commit_phase_openings.len()!=11",
        "fri.final_poly.len()!=1", "fri.input_openings.len()!=3",
        "[(0,1,8),(1,1,air::WIDTH+4),(2,8,8)]", "input.opened_values.len()!=64",
        "round.sibling_values.len()!=64", "values.len()!=1", "proof.0.len()==64",
        "salt.len()==16", "proof.1.sibling_hashes.len()<=64*14",
        "ifbytes.len()>MAX_PROOF_BYTES", "ifdepth==MAX_JSON_DEPTH",
        "if*counter>=MAX_JSON_ITEMS", "index-start>=64", "index-start>20",
        "iftokens>MAX_JSON_TOKENS", "ifdepth!=0",
    ], "proof shape and parser")
    params = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", proof, re.S)
    require(len(params) == 1, "Expected exactly one fixed FRI declaration")
    for name, value in {"log_blowup": 3, "log_final_poly_len": 0, "max_log_arity": 1,
                        "num_queries": 64, "batch_proof_of_work_bits": 0,
                        "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0}.items():
        require(re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", params[0]) == [str(value)],
                f"Fixed FRI parameter changed: {name}")
    tests = sources[MODULE + "/proof/tests.rs"]
    require("opaque_context_does_not_claim_canonical_transaction_constraints" in tests,
            "The explicit opaque context scope test is required")
    fragments(tests, ["Statement::new([0x61;64])", "Statement::new([0x62;64])"], "context scope test")
    fragments(sources[MODULE + "/tests.rs"], [
        '"/../../research/key-source/vectors.json"',
        '"/../../research/key-source/dummy_rounds.json"',
        '"/../../research/key-source/hostile_cases.json"',
    ], "public independent fixture paths")
    fragments(tests, ['"/../../research/key-source/hash_vectors.csv"',
                      '"/../../research/signatures/synthetic_authorization.json"'],
              "public proof fixture paths")
    raw = sources[MODULE + "/proof/raw_tests.rs"]
    fragments(raw, ["fnfifteen_raw_key_source_proofs_reject()",
                    "assert_eq!(rejected.len(),15);",
                    "verify(&verifier_config(),&KeySlotsAir,&proof,&public_values(statement))",
                    "verify_key_slots(&encoded,statement)", "Err(Error::InvalidProof)",
                    "letproof=prove(", '"/../../research/key-source/hostile_cases.json"'],
              "raw backend rejection tests")
    fragments(sources[PREFIX + "/tests/key_source.rs"], [
        "thorum_hash_proof_lab::key_source", "#[test]", "prove_key_slots(", "verify_key_slots(",
    ], "public API integration test")
    for name, text in sources.items():
        if name.startswith(MODULE) or name == PREFIX + "/tests/key_source.rs":
            for private_path in ["outputs/thorum", "private-key-slots-reference",
                                 "packed-keccak-joint-reference", "C:/Users", "C:\\Users"]:
                require(private_path not in text, f"Private source path remains in {name}")


def make_record(sources):
    return {"format": RECORD_FORMAT, "profile": PROFILE, "scope": RECORD_SCOPE,
            "source_encoding": "UTF-8 with LF normalization",
            "source_sha256": {name: fingerprint(sources[name]) for name in sorted(SOURCE_PATHS)}}


def validate_record(record, sources):
    require(isinstance(record, dict) and set(record) == {
        "format", "profile", "scope", "source_encoding", "source_sha256",
    }, "Missing, incomplete or unsupported implementation record")
    for name, expected in {"format": RECORD_FORMAT, "profile": PROFILE, "scope": RECORD_SCOPE,
                           "source_encoding": "UTF-8 with LF normalization"}.items():
        require(record[name] == expected, f"Implementation record header changed: {name}")
    hashes = record["source_sha256"]
    require(isinstance(hashes, dict) and set(hashes) == SOURCE_PATHS,
            "Implementation record requires the exact complete public source path set")
    for name in sorted(SOURCE_PATHS):
        digest = hashes[name]
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                and len(set(digest)) > 1, f"Missing or placeholder source fingerprint: {name}")
        require(fingerprint(sources[name]) == digest, f"Frozen public implementation changed: {name}")


def check(root, freeze=False):
    record_path = root / BASE_RELATIVE / "implementation_record.json"
    require(record_path.resolve().is_relative_to(root.resolve()),
            "Implementation record leaves the repository")
    if not freeze:
        require(record_path.is_file(),
                "Missing implementation_record.json. Final source review and explicit --freeze-source are required")
        record = load_json(record_path)
    sources = source_snapshot(root)
    check_references(root)
    check_dependencies(sources)
    check_source_contracts(sources)
    if freeze:
        record = make_record(sources)
        validate_record(record, sources)
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    else:
        validate_record(record, sources)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="Check the existing final source freeze; this is the default")
    modes.add_argument("--freeze-source", action="store_true",
                       help="Write a new separate implementation record after final reviewed public adaptation")
    parser.add_argument("--repository-root", type=Path, default=ROOT,
                        help="Override the repository root only while staging the public guard")
    args = parser.parse_args(argv)
    try:
        check(args.repository_root.resolve(), args.freeze_source)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if args.freeze_source:
        print("WROTE: separate implementation_record.json for the reviewed final public path set")
    print("PASS: fixed private key source declarations, shared decoder and unchanged hash dependency profile")
    print("PASS: complete source freeze, 1024 by 20168 profile and opaque 64 byte context scope")
    print("This change guard does not establish correctness, signature validity, ownership, privacy or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
