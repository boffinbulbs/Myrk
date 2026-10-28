#!/usr/bin/env python3
"""Pin the conditional row source, independent data and closed profile.

This is a source/profile change detector, not a correctness, privacy, complete
signature or security verdict. Mathematical provenance is source_record.json.
The separate implementation_record.json requires explicit --freeze-source
after reviewed public adaptation and actual validation. Ordinary checks never
regenerate that record and require no Cargo runtime or registry cache.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
BASE_RELATIVE = "research/reconstructed-row"
PREFIX = "crates/thorum-hash-proof-lab"
MODULE = PREFIX + "/src/reconstructed_row"
PROFILE = "thorum.reconstructed-row-proof-lab.mldsa87.private-row.four-rounds.serial.p3-0.8.0.v1"
RECORD_FORMAT = "thorum.reconstructed-row.implementation-record.v1"
RECORD_SCOPE = "Reviewed conditional row public source and fixed declarations only, without correctness, privacy, signature, ownership, payment or security certification"
ROW_CHILDREN = frozenset({
    "air.rs", "arithmetic.rs", "build.rs", "build/replay.rs", "control.rs", "hash.rs",
    "ntt.rs", "program.rs", "proof.rs", "proof/tests.rs", "proof/corpus_tests.rs",
    "row_hash.rs", "tests.rs", "tests/reference.rs", "tests/causal.rs",
})
SOURCE_PATHS = frozenset({
    "Cargo.toml", "Cargo.lock", PREFIX + "/Cargo.toml", PREFIX + "/src/lib.rs",
    PREFIX + "/src/key_source.rs", PREFIX + "/src/key_source/keccak.rs",
    PREFIX + "/src/key_source/keccak/tests.rs", MODULE + ".rs",
    PREFIX + "/tests/reconstructed_row.rs",
    "crates/thorum-arithmetic-proof-lab/Cargo.toml",
    "crates/thorum-arithmetic-proof-lab/src/mul.rs",
    "crates/thorum-arithmetic-proof-lab/src/hints.rs",
    "crates/thorum-arithmetic-proof-lab/src/packing.rs",
    "crates/thorum-ntt-proof-lab/src/ntt.rs",
    "research/hash-proofs/profile_check.py", "research/key-source/profile_check.py",
    BASE_RELATIVE + "/check_test_inventory.py",
}) | frozenset(MODULE + "/" + name for name in ROW_CHILDREN)
DATA_PATHS = frozenset({
    "vectors.json", "hostile_cases.json", "injected_boundaries.json", "schedule.json",
    "continuation_faults.json", "hash_vectors.csv", "hash_preimages.json", "profile.json",
})
REFERENCE_PATHS = DATA_PATHS | frozenset({
    "reference_vectors.py", "stream_math.py", "source_record.json", "README.md", "profile_check.py",
})
UNCHANGED_SOURCE_HASHES = {
    "Cargo.toml": "2dad10da5dedfdef787a3eac95ddedf59e6d97dd7b51f9f076b6775fa9af8b17",
    "Cargo.lock": "79276c95e6772e0ed31470e8e7c7b7d54204dbc04ec5fbfb87ea6baccb0847c5",
    PREFIX + "/Cargo.toml": "2a33d56aa46171a1a071a818a031bf4e5a8323f87bf6dc780bf019ce6ebfad5c",
    "crates/thorum-arithmetic-proof-lab/Cargo.toml": "70510dfde7aa29a95427a911d617cca5f16732c9f05877a4724d2dd73cac4334",
    PREFIX + "/src/key_source/keccak.rs": "78dfe4e43514ba2547238d5518bf0c6241891aa36864cb9e351ab9b3cd31ff19",
    PREFIX + "/src/key_source/keccak/tests.rs": "f5bb0b29fc7dddae868dfcbcf9c5a1b70472848afad53e8e457d2a9d3caead0e",
    "crates/thorum-arithmetic-proof-lab/src/mul.rs": "fdf7c8dcb834539b566dab21baf2762de25bc56f907e393f01e8d9b05b09a7e1",
    "crates/thorum-arithmetic-proof-lab/src/hints.rs": "d235c1273f90c7d967bdc33e54699cf223fe6060c807d7c4415e5a51d843eeb5",
    "crates/thorum-arithmetic-proof-lab/src/packing.rs": "cb8997c15b9bd5f1db231206142cfc84e6c5561b5383ad1ba8ffec79d8533d70",
    "crates/thorum-ntt-proof-lab/src/ntt.rs": "b9c6bd044d9a91a1ef187bd0c334079d89870b7fff3a1f99a4da70c44e77492d",
    "research/hash-proofs/profile_check.py": "11f7245567cb35ad8aedb703dfe50db215a7bec86c44c7065e1ed6df34725cd6",
}
MATH_SOURCE_HASHES = {
    "research/signatures/synthetic_authorization.json": "61959ca6b2d0e8ea88c5313798266915ebed1589c4e6428001d79d559f019f22",
    "research/signatures/verify_reference.py": "05ba244ecb91c3eb0f1c51a7b42b92f6ea49d5bca54fde9c25881a5ce47b2406",
    "research/ntt-proofs/reference_vectors.py": "021c8d5600e43d813bfd73ab5885e553e852ba5fa9ec2078c296e6ad823d1650",
    "research/coefficient-constraints/reference_vectors.py": "2bad900a9b4c4cfe6e8dc63ac68e3d6b8e99713d4091676c807afcc8dd35455a",
    "research/coefficient-constraints/packing_vectors.py": "d9e4781aec66ce2b18e5e4409c630bede350ff914b09450ca4ac67600faa717a",
    "research/hash-proofs/reference_vectors.py": "2ad944ceccf50ad1e088a3e6626641c23519e2bd3d642e3f90980d6212dac877",
    "research/matrix-sampling/vectors.json": "d52a052141c0b9b13eaa412a6dabac5d695bde1f76c9ae003fff98ac0c062e2d",
    "research/crypto/vectors/selected.json": "fe61306ae7bafad8b36d2ef8cac9cf12ce3706afe12171b8e7b27d97edba7de4",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compact(text):
    return re.sub(r"\s+", "", text)


def fingerprint(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode()).hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def fragments(text, expected, label):
    source = compact(text)
    for declaration in expected:
        require(declaration in source, f"Fixed {label} declaration changed: {declaration}")


def snapshot(root):
    actual = {path.relative_to(root / MODULE).as_posix()
              for path in (root / MODULE).rglob("*.rs")}
    require(actual == ROW_CHILDREN, "Conditional row Rust file inventory changed")
    base = root / BASE_RELATIVE
    allowed_files = REFERENCE_PATHS | frozenset({"check_test_inventory.py", "implementation_record.json"})
    require({path.name for path in base.iterdir() if path.is_file()} <= allowed_files,
            "Unexpected top level row reference artifact")
    sources = {}
    for name in sorted(SOURCE_PATHS):
        path = root / name
        require(path.is_file() and path.resolve().is_relative_to(root), f"Missing or external source: {name}")
        sources[name] = path.read_text(encoding="utf-8")
        require(sources[name].strip(), f"Empty source: {name}")
    references = {}
    for name in sorted(REFERENCE_PATHS):
        path = root / BASE_RELATIVE / name
        require(path.is_file() and path.resolve().is_relative_to(root), f"Missing or external reference: {name}")
        references[name] = path.read_bytes()
        require(references[name], f"Empty reference: {name}")
    return sources, references


def check_dependencies(sources):
    for name, digest in UNCHANGED_SOURCE_HASHES.items():
        require(fingerprint(sources[name]) == digest, f"Unchanged retained source changed: {name}")
    manifest = tomllib.loads(sources[PREFIX + "/Cargo.toml"])
    require(manifest["dependencies"]["thorum-arithmetic-proof-lab"] == {
        "path": "../thorum-arithmetic-proof-lab", "default-features": False,
    }, "Expected exact existing arithmetic workspace dependency")
    parent = compact(sources[PREFIX + "/src/lib.rs"])
    for child in ["key_source", "reconstructed_row"]:
        declaration = f"pubmod{child};"
        require(parent.count(declaration) == 1, f"Expected one {child} declaration")
        parent = parent.replace(declaration, "")
    require(hashlib.sha256(parent.encode()).hexdigest()
            == "c1a9461ffd145498710e05817c71d5dee1bc5799742bf3aff4dc50e6af5a3445",
            "Parent primitive source changed beyond the two exact child declarations")
    key_source = compact(sources[PREFIX + "/src/key_source.rs"])
    require(key_source.count("pub(super)modkeccak;") == 1, "Expected the narrow shared adapter visibility")
    # The CI test inventory script is pinned as source only. This Python-only
    # reference guard never imports or invokes its Cargo-dependent test listing.
    require(sources[BASE_RELATIVE + "/check_test_inventory.py"].strip(),
            "The explicit ignored test inventory checker is required")


def check_reference_data(root, references):
    base = root / BASE_RELATIVE
    record = load_json(base / "source_record.json")
    require(record["public_math_source_sha256"] == MATH_SOURCE_HASHES, "Retained public math source inventory changed")
    for name, digest in MATH_SOURCE_HASHES.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, f"Math source changed: {name}")
    model = record["independent_integer_model"]
    require(model == {"path": BASE_RELATIVE + "/stream_math.py",
                      "sha256": hashlib.sha256(references["stream_math.py"]).hexdigest()},
            "The reference integer helper source changed")
    require(record["generator_sha256"] == hashlib.sha256(references["reference_vectors.py"]).hexdigest(),
            "The reference generator source changed")
    require(record["retained_public_input_revision"] == "061a4ba5a930f8031ea39aa93595311305d07bd8",
            "Retained public input provenance changed")
    origin = record["integer_math_provenance"]
    require(origin["origin_source_sha256"] == "44b016e9977318763bd5f043485eef2434618eaa856deaa3594d7ee9db835126"
            and origin["retained_functions"] == ["multiplication", "stream_model", "changed_continuation"],
            "Independent integer function provenance changed")
    require(set(record["generated_sha256"]) == DATA_PATHS, "Generated mathematical data inventory changed")
    for name, digest in record["generated_sha256"].items():
        require(hashlib.sha256(references[name]).hexdigest() == digest, f"Generated reference changed: {name}")
    for name, value in {"retained_sources": 2, "retained_complete_rows": 4, "synthetic_endpoint_rows": 4,
                        "matrix_records": 28, "full_sponge_records": 168, "selected_full_round_records": 288,
                        "candidate_events_per_row": 2352, "false_splices": 13,
                        "valid_whole_input_alternatives": 3, "injected_late_completion_lanes": 8,
                        "injected_unsupported_capacity": 3, "selected_continuation_faults": 1,
                        "full_proof_hash_goldens": 3, "compiler_run": False, "prover_run": False,
                        "actual_air_verdict_claim": False, "external_streamed_data_file_read": False}.items():
        require(type(record[name]) is type(value) and record[name] == value, f"Reference scope/count changed: {name}")
    profile = load_json(base / "profile.json")
    expected = {"profile": PROFILE, "height": 1024, "width": 24794, "actual_degree": 3,
                "public_values": 65, "private_output_bytes": 128, "keccak_rounds_per_row": 4,
                "matrix_columns": 7, "matrix_output_blocks": 6, "matrix_stream_bytes": 1008,
                "candidate_events_per_column": 336, "candidate_lanes": 8, "completion_count": 256,
                "matrix_end": 294, "forward_end": 422, "point_end": 454, "inverse_end": 582,
                "normalize_end": 614, "hint_end": 646, "stored_degree_bits": 11, "quotient_chunks": 8,
                "fri_rounds": 11, "queries": 64, "log_blowup": 3, "extension_degree": 4,
                "random_codewords": 4, "row_salts": 16, "grinding_bits": 0,
                "hiding_main_mmcs": True, "hiding_extension_mmcs": True, "independent_os_rngs": 2,
                "closed_transport": {"bytes": 33554432, "tokens": 3000000, "items": 32768,
                                     "depth": 24, "string_bytes": 64, "integer_digits": 20, "merkle_siblings": 896},
                "analytical_arrays": {"raw_trace_bytes": 101556224, "randomized_trace_bytes": 203145216,
                                      "main_lde_payload_bytes": 1625161728},
                "public_scope": "Row 0 through 7 and opaque context only, without key/signature/note/T binding",
                "hash_domains": [f"thorum.reconstructed-row-proof-lab.{role}.v1" for role in ["leaf", "node", "transcript"]]}
    for name, value in expected.items():
        require(type(profile[name]) is type(value) and profile[name] == value, f"Fixed profile changed: {name}")
    corpus = load_json(base / "vectors.json")
    require(len(corpus["sources"]) == 2 and len(corpus["cases"]) == 8 and len(corpus["matrix_records"]) == 28,
            "Complete conditional row corpus changed")
    hostile = load_json(base / "hostile_cases.json")
    require(len(hostile["faults"]) == 13 and len(hostile["valid_alternatives"]) == 3,
            "False splice or valid whole input classifications changed")
    injected = load_json(base / "injected_boundaries.json")
    require(len(injected["supported"]) == 8 and len(injected["unsupported"]) == 3,
            "Bounded stream classification changed")
    selected = load_json(base / "continuation_faults.json")["hash_continuation_faults"]
    require(len(selected) == 1 and selected[0]["name"] == "unused_sixth_output_block_capacity_change"
            and selected[0]["seed_claim"] is False and selected[0]["broken_join_stage"] == 5
            and selected[0]["preserved_output_prefix_bytes"] == 840,
            "Selected full-state continuation scope changed")


def check_source_contracts(sources):
    module = sources[MODULE + ".rs"]
    fragments(module, ["modair;", "modproof;", "usesuper::key_source::keccak;",
                       "usethorum_arithmetic_proof_lab::{hints,mul,packing};",
                       "pubconstMODULUS:u32=8_380_417;", "ifself.row>=8", "ifrow>=8",
                       "pubfnnew(row:u8,context:[u8;64])->Result<Self,Error>",
                       "pubfnfrom_inputs(", "UnsupportedCapacity", "prove_reconstructed_row",
                       "verify_reconstructed_row", "MAX_PROOF_BYTES", "PROFILE"], "public API")
    code = compact(module)
    require(re.findall(r"pubstructStatement\{([^}]+)\}", code) == ["row:u8,context:[u8;64],"],
            "The row statement must contain only row and opaque context")
    require(re.findall(r"pubstructWitness\{([^}]+)\}", code) == [
        "rho:[u8;32],zhat:[[u32;256];7],t1:[u16;256],chat:[u32;256],hints:[u8;256],"],
        "The held private operand layout changed")
    require(not re.search(r"pub(?:\([^)]*\))?mod(?:air|arithmetic|build|control|hash|ntt|program|proof|row_hash);", code),
            "Implementation modules must remain private")
    require("pubusebuild::trace" not in code, "Trace export is not the public proof API")
    combined = "\n".join(sources[MODULE + "/" + name] for name in ROW_CHILDREN)
    require(not re.search(r"fn\s+(?:eval_mul|eval_use_hint|decode_t1|scaled_t1)\s*[<(]", combined),
            "Do not duplicate the retained arithmetic/decoder kernels")
    air = sources[MODULE + "/air.rs"]
    fragments(air, ["pubconstHEIGHT:usize=1024;", "pubconstCLOCK:usize=4*p3_keccak_air::NUM_KECCAK_COLS;",
                    "pubconstPUBLIC_VALUES:usize=65;", "pubconstWIDTH:usize=ROW_BITS+3;",
                    "keccak::eval(builder);", "eval_state(builder);", "row_hash::eval(builder);",
                    "control::eval(builder);", "arithmetic::eval(self,builder);",
                    "core::iter::once(statement.row).chain(statement.context).map(BabyBear::from_u8).collect()"], "row AIR")
    program = sources[MODULE + "/program.rs"]
    fragments(program, ["pubconstMATRIX_END:usize=294;", "pubconstFORWARD_END:usize=422;",
                        "pubconstPOINT_END:usize=454;", "pubconstINVERSE_END:usize=582;",
                        "pubconstNORMALIZE_END:usize=614;", "pubconstHINT_END:usize=646;"], "schedule")
    hashes = sources[MODULE + "/row_hash.rs"]
    fragments(hashes, ["forlimbin0..100", "builder.when_transition().when(joins).assert_eq(",
                       "next_first.preimage[limb/20][(limb/4)%5][limb%4]",
                       "last.a_prime_prime_prime(limb/20,(limb/4)%5,limb%4)",
                       "forblockin0..6", "row[XOF+block*168+byte]",
                       "(AB::Expr::ONE-reset::<AB>(row))*(next[column]-row[column])"], "sponge source and lifetime")
    control = sources[MODULE + "/control.rs"]
    fragments(control, ["forstatein0..=8", "forlanein0..8", "builder.when(boundary).assert_one(row[COUNT+8*257+256]);",
                        "builder.when_last_row().assert_one(row[COUNT+256]);",
                        "letactive=AB::Expr::ONE-row[start+256];", "cursor.clone()+active.clone()*BabyBear::from_u8(3)"], "candidate controls")
    arithmetic = sources[MODULE + "/arithmetic.rs"]
    fragments(arithmetic, ["mul::eval_mul(", "packing::scaled_t1(", "hints::eval_use_hint(",
                           "builder.assert_eq(value.input.clone(),input);", "builder.assert_eq(value.hint.clone(),hint);",
                           "used[lane].output.clone()+used[lane+1].output.clone()*BabyBear::from_u8(16)",
                           "next[W1+index]", "row[TAKE+lane]*row[COUNT+lane*257+index]"], "private arithmetic routes")
    ntt = compact(sources[MODULE + "/ntt.rs"])
    original_ntt = compact(sources["crates/thorum-ntt-proof-lab/src/ntt.rs"])
    ntt = ntt[ntt.index("pubconstROOT"):]
    original_ntt = original_ntt[original_ntt.index("pubconstROOT"):]
    require(original_ntt.startswith(ntt), "Retained pure NTT helper prefix changed")
    proof_hash = sources[MODULE + "/hash.rs"]
    for role in ["leaf", "node", "transcript"]:
        require(f'b"thorum.reconstructed-row-proof-lab.{role}.v1"' in proof_hash, f"Changed {role} domain")
    fragments(proof_hash, ["Sha3_512::new()", "(domain.len()asu32).to_be_bytes()",
                           "u64::from_le_bytes(", "value.as_canonical_u32().to_le_bytes()",
                           "word.to_le_bytes()", "count.to_be_bytes()", "hash.finalize().into()"], "full SHA3 adapter")
    proof = sources[MODULE + "/proof.rs"]
    fragments(proof, [f'b"{PROFILE}"', "HidingMmcs::new(LeafHash,Compress::new(NodeHash),0,mmcs_rng)",
                      "ChallengeMmcs::new(mmcs.clone())", "Pcs::new(Radix2DitParallel::default(),mmcs,params,4,pcs_rng)",
                      "HashChallenger::new(PROFILE.to_vec(),TranscriptHash)", "getrandom::fill(&mutseed)",
                      "build_config(fresh_rng()?,fresh_rng()?)", "pubconstMAX_PROOF_BYTES:usize=32*1024*1024;",
                      "constMAX_JSON_DEPTH:usize=24;", "constMAX_JSON_TOKENS:usize=3_000_000;",
                      "constMAX_JSON_ITEMS:usize=32_768;", "statement.validate()?;", "json_preflight(bytes)?;",
                      "validate_shape(&proof)?;", "serde_json::to_vec(&proof).map_err(|_|Error::InvalidEncoding)?!=bytes",
                      "proof.degree_bits!=11", "proof.ood_pow_witness!=BabyBear::ZERO",
                      "proof.commitments.trace.num_roots()!=1", "proof.commitments.quotient_chunks.num_roots()!=1",
                      "opened.trace_local.len()!=air::WIDTH", "opened.quotient_chunks.len()!=8",
                      "opened.quotient_chunks.iter().any(|chunk|chunk.len()!=4)", "masks.len()!=3",
                      "fri.commit_phase_commits.len()!=11", "fri.commit_pow_witnesses.len()!=11",
                      "fri.commit_phase_openings.len()!=11", "fri.final_poly.len()!=1", "fri.input_openings.len()!=3",
                      "[(0,1,8),(1,1,air::WIDTH+4),(2,8,8)]", "input.opened_values.len()!=64",
                      "salt.len()==16", "proof.1.sibling_hashes.len()<=64*14", "iftokens>MAX_JSON_TOKENS"], "closed proof profile")
    params = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};", proof, re.S)
    require(len(params) == 1, "Expected exactly one FRI parameter object")
    for name, value in {"log_blowup": 3, "log_final_poly_len": 0, "max_log_arity": 1, "num_queries": 64,
                        "batch_proof_of_work_bits": 0, "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0}.items():
        require(re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", params[0]) == [str(value)], f"Fixed FRI setting changed: {name}")
    corpus = sources[MODULE + "/proof/corpus_tests.rs"]
    fragments(corpus, ["fnthree_fresh_private_rows_public_mutations_and_transport()",
                       "fnsixteen_raw_false_row_proofs_reject_backend_and_wrapper()", "letp=prove(",
                       "json_preflight(&encoded).unwrap();", "validate_shape(&p).unwrap();",
                       "verify_reconstructed_row(&encoded,&s)", "Err(Error::InvalidProof)",
                       "assert_eq!(records.len(),RAW_NAMES.len());"], "actual proof corpus")
    require(re.search(r"const\s+RAW_NAMES\s*:\s*\[&str;\s*16\]", corpus) is not None,
            "The sixteen raw case inventory changed")
    external = sources[PREFIX + "/tests/reconstructed_row.rs"]
    fragments(external, ["thorum_hash_proof_lab::reconstructed_row", "prove_reconstructed_row(",
                         "verify_reconstructed_row(", "conditional_row_external_api_and_separate_profiles"], "external API test")
    tests = "\n".join(value for name, value in sources.items() if name.startswith(MODULE))
    for name in ["vectors.json", "hostile_cases.json", "injected_boundaries.json", "continuation_faults.json", "hash_vectors.csv"]:
        require(name in tests, f"Missing public fixture: {name}")
    require("research/reconstructed-row" in tests, "Missing public fixture root")
    for name, value in sources.items():
        if name.startswith(MODULE) or name == PREFIX + "/tests/reconstructed_row.rs":
            require(not re.search(r"[A-Za-z]:[\\/]", value), f"Absolute host path in {name}")
            for forbidden in ["outputs" + "/thorum", "work" + "/", "streamed-matrix" + "-reference",
                              "reconstructed-row" + "-reference", "std::fs::write(", "Root" + "-only"]:
                require(forbidden not in value, f"Private path or result writer remains in {name}")


def make_record(sources, references):
    return {"format": RECORD_FORMAT, "profile": PROFILE, "scope": RECORD_SCOPE,
            "source_encoding": "UTF-8 with LF normalization; reference files use exact bytes",
            "source_sha256": {name: fingerprint(value) for name, value in sorted(sources.items())},
            "reference_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(references.items())}}


def validate_record(record, expected):
    require(isinstance(record, dict) and set(record) == set(expected), "Missing or incomplete implementation record")
    for field in ["format", "profile", "scope", "source_encoding"]:
        require(record[field] == expected[field], f"Implementation record header changed: {field}")
    for field in ["source_sha256", "reference_sha256"]:
        hashes = record[field]
        require(isinstance(hashes, dict) and set(hashes) == set(expected[field]), f"Exact {field} inventory required")
        for name, digest in hashes.items():
            require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) and len(set(digest)) > 1,
                    f"Missing or placeholder fingerprint: {name}")
            require(digest == expected[field][name], f"Reviewed source/reference changed: {name}")


def check(root, freeze=False):
    target = root / BASE_RELATIVE / "implementation_record.json"
    require(target.resolve().is_relative_to(root), "Implementation record leaves repository")
    if not freeze:
        require(target.is_file(), "Missing implementation_record.json; final review and explicit --freeze-source required")
        record = load_json(target)
    sources, references = snapshot(root)
    check_dependencies(sources)
    check_reference_data(root, references)
    check_source_contracts(sources)
    expected = make_record(sources, references)
    if freeze:
        validate_record(expected, expected)
        target.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8", newline="\n")
    else:
        validate_record(record, expected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--freeze-source", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        check(args.repository_root.resolve(), args.freeze_source)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if args.freeze_source:
        print("WROTE: separate reviewed public implementation source record")
    print("PASS: fixed conditional row profile, shared kernels, complete independent references and closed source inventory")
    print("This guard does not establish complete signature validity, ownership, private payment or a security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
