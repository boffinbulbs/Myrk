#!/usr/bin/env python3
"""Check frozen coefficient declarations, fixtures and the test only proof profile.

This source profile change guard does not prove the mathematics, privacy,
authorization, soundness or a security level. Dependency resolution is checked
separately by research/arithmetic-proofs/profile_check.py. No prover is run.
"""

import hashlib
import json
from pathlib import Path
import re
import sys


BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
CRATE = ROOT / "crates/thorum-arithmetic-proof-lab/src"
PROFILE = "thorum.use-hint-proof-lab.mldsa87.decompose.serial.p3-0.8.0.v1"
NATIVE_REVISION = "f75d5b829948988f18d9463f286805fb9410bcdd"

# Comments and formatting may change without changing a source declaration.
# These fingerprints pin reviewed source, rather than certify its semantics.
SOURCE_FINGERPRINTS = {
    "hints": "13784b5dfd154fbb3278666285244853463239da1ed0d47a75345144bc7097b9",
    "packing": "1c94d991bb3c6fa91b1646053d6d72d0932bf7f739e2d935e35d2fd9e259799e",
    "air": "01d42c919667dd78715efd0c2a70577805ec91a4b5434477c86997c0456838d0",
    "hash": "ce1de0949e9aa982e9838b327ab99a55bf5aa77e84c8460241c70ec2bb80d64d",
}
FUNCTION_FINGERPRINTS = {
    "fresh_rng": "dd17475874f148de5e3f5803f8aceba5512a4d7f7de1569a9c48a42e6bb50538",
    "build_config": "2e762a31d91f3159d7eeccc573a89be7d39298bb79e474456c4b573ab462e51a",
    "prover_config": "c32104a0a5222d4a113d703b1fbc806caabaeb59309bf640034ebd06e4705c1d",
    "verifier_config": "a3e730cdea48806c5d1262b3ec7908f89fc2cb1becac69574c6b8c28532bd49f",
    "trace_is_valid": "8c2c4a9eed370051263d9b9f95b5d277bf12bf9ea9ea5cb292bd2d85b897df50",
    "prove_diagnostic": "de31272f12ada4689a66827d128e550600878b11b170e24620e3ceff9b7b69bd",
    "prove_trace": "e2521dd39e6da1e476e0bd269e91e5320913289e398f3bc58023fbb92a31fbf7",
    "verify_diagnostic": "56f111a2e84cf6f64b03fe7b27d6e0eb4ae60c66e534c398df36bad12a96856e",
    "merkle_shape": "b1f3053882dfc1291350893adb153fb209e8cc32c6250b88c867bbe097ab7ebb",
    "validate_shape": "152db9397b2ec7a38fa230b2f1b34565d0b3fa1a73143ddf7f30ee00d91fe820",
    "json_preflight": "08b3ea707b434c8cda0ded5c457c3185018740d6b30a575cc63f821f851d6e91",
}


class ProfileError(Exception):
    """A fixed declaration or fixture differs from the retained profile."""


def require(condition, message):
    if not condition:
        raise ProfileError(message)


def compact(text):
    text = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"\s+", "", text)


def fingerprint(text):
    return hashlib.sha256(compact(text).encode()).hexdigest()


def function_source(source, name):
    starts = list(re.finditer(rf"^fn\s+{name}\b", source, re.M))
    require(len(starts) == 1, f"Expected one private {name} function.")
    start = starts[0]
    following = re.search(r"^fn\s+|^type\s+", source[start.end():], re.M)
    end = start.end() + following.start() if following else len(source)
    return source[start.start():end]


def read_sources():
    return {name: path.read_text(encoding="utf-8") for name, path in {
        "lib": CRATE / "lib.rs",
        "hints": CRATE / "hints.rs",
        "packing": CRATE / "packing.rs",
        "harness": CRATE / "hints/proof_harness.rs",
        "air": CRATE / "hints/proof_harness/proof_air.rs",
        "hash": CRATE / "hints/proof_harness/proof_hash.rs",
        "tests": CRATE / "hints/proof_harness/proof_tests.rs",
    }.items()}


def check_sources(sources):
    code = {name: compact(text) for name, text in sources.items()}
    require("pubmodhints;" in code["lib"] and "pubmodpacking;" in code["lib"],
            "The reusable coefficient modules changed.")
    require('b"thorum.arithmetic-proof-lab.modq8380417.mul.radix4096.serial.p3-0.8.0.v1"'
            in code["lib"], "The existing multiplication profile changed.")
    require("#[cfg(test)]modproof_harness;" in code["hints"],
            "The diagnostic proof harness must remain nested under cfg(test).")
    require("modproof_harness;" not in code["lib"],
            "The diagnostic proof harness cannot move to the crate root.")
    for name, expected in SOURCE_FINGERPRINTS.items():
        require(fingerprint(sources[name]) == expected, f"Frozen {name} source changed.")
    for name, expected in FUNCTION_FINGERPRINTS.items():
        require(fingerprint(function_source(sources["harness"], name)) == expected,
                f"Frozen proof wrapper function changed: {name}.")

    harness = code["harness"]
    for declaration in [
        "modproof_air;modproof_hash;modproof_tests;",
        "constHEIGHT:usize=256;", "constPUBLIC_VALUES:usize=70;",
        f'pubconstPROFILE:&[u8]=b"{PROFILE}";',
        "pubconstMAX_PROOF_BYTES:usize=2*1024*1024;",
        "constMAX_JSON_DEPTH:usize=24;", "constMAX_JSON_TOKENS:usize=200_000;",
        "constMAX_JSON_ITEMS:usize=16_384;",
        "typeChallenge=BinomialExtensionField<BabyBear,4>;",
        "typeCompress=CompressionFunctionFromHasher<NodeHash,2,8>;",
        "typeHidingMmcs=MerkleTreeHidingMmcs<BabyBear,u64,LeafHash,Compress,StdRng,2,8,16>;",
        "typeChallengeMmcs=ExtensionMmcs<BabyBear,Challenge,HidingMmcs>;",
        "typeChallenger=SerializingChallenger32<BabyBear,HashChallenger<u8,TranscriptHash,64>>;",
        "typePcs=HidingFriPcs<BabyBear,Radix2DitParallel<BabyBear>,HidingMmcs,ChallengeMmcs,StdRng>;",
        "self.r>=MODULUS||self.hint>1||self.output>15",
    ]:
        require(declaration in harness, f"Fixed proof declaration changed: {declaration}")
    require(re.findall(r"structStatement\{([^}]+)\}", harness) == [
        "r:u32,hint:u8,output:u8,context:[u8;64],"
    ], "The test only diagnostic statement changed.")
    parameters = re.findall(r"let\s+params\s*=\s*FriParameters\s*\{(.*?)\};",
                            sources["harness"], re.S)
    require(len(parameters) == 1, "Expected one fixed FRI declaration.")
    for name, value in {
        "log_blowup": 2, "log_final_poly_len": 0, "max_log_arity": 1,
        "num_queries": 64, "batch_proof_of_work_bits": 0,
        "commit_proof_of_work_bits": 0, "query_proof_of_work_bits": 0,
    }.items():
        require(re.findall(rf"\b{name}\s*:\s*(\d+)\s*,", parameters[0]) == [str(value)],
                f"Fixed FRI {name} changed.")
    require("Values{input,hint,high,low,positive,output,}" in code["hints"],
            "The complete returned private expressions changed.")
    require("pubstructValues<E>{pubinput:E,pubhint:E,pubhigh:E,publow:E,pubpositive:E,puboutput:E,}"
            in code["hints"], "The complete private expression interface changed.")
    for role in ("leaf", "node", "transcript"):
        require(f'b"thorum.use-hint-proof-lab.{role}.v1"' in code["hash"],
                f"The {role} adapter domain changed.")
    require("#[cfg(not(debug_assertions))]#[test]fneight_raw_false_proofs_bypass_local_checks_and_fail_verification()"
            in code["tests"], "The raw false proof test must retain its release gate.")
    require("constFAULTS:[Fault;8]=[Fault::TieQuotient,Fault::RemainderBound,Fault::EdgeHigh,"
            "Fault::ZeroSign,Fault::QEdgeSign,Fault::OverflowWrap,Fault::OutputDetach,"
            "Fault::PublicIntegerAlias,];" in code["tests"],
            "The eight retained raw false proof cases changed.")
    for declaration in [
        "forfaultinFAULTS", "letproof=prove(&prover_config().unwrap(),&ProofAir,trace,&public)",
        "validate_shape(&proof).unwrap();",
        "verify(&verifier_config(),&ProofAir,&proof,&public).is_err()",
        "verify_diagnostic(&bytes,&s)",
    ]:
        require(declaration in code["tests"], f"The raw backend rejection test changed: {declaration}")
    require(2 * 23 + 2 * 5 + 2 * 19 + 4 + 3 + 4 + 18 + 2 == 125,
            "The fixed hint bit layout calculation changed.")
    require(4 + 1 + 1 + 64 == 70, "The fixed diagnostic public width changed.")


def check_fixtures():
    profile = json.loads((BASE / "profile.json").read_bytes())
    for name, value in {
        "q": 8380417, "alpha": 523776, "gamma2": 261888,
        "gadget_width": 125, "expected_degree": 2,
        "pinned_native_revision": NATIVE_REVISION,
        "decomposition_residual_integer_box": [-8642304, 8642303],
        "positive_branch_residual_integer_box": [-524032, 261887],
        "nonpositive_branch_residual_integer_box": [-261888, 524031],
        "output_residual_integer_box": [-32, 32],
    }.items():
        require(profile[name] == value, f"Fixture parameter changed: {name}.")
    for name, count in [("boundary_vectors.json", 322), ("signature_vectors.json", 10240),
                        ("invalid_diagnostics.json", 169)]:
        data = json.loads((BASE / name).read_bytes())
        require(len(data["cases"]) == count, f"The retained {name} count changed.")
    packing = json.loads((BASE / "packing_vectors.json").read_bytes())
    require((packing["q"], packing["gamma1"], packing["beta"]) == (8380417, 524288, 120),
            "The coefficient packing parameters changed.")
    require(len(packing["t1"]) == 2602 and len(packing["z"]) == 4624,
            "The retained coefficient window counts changed.")
    require(sum(case["accepted"] for case in packing["z"]) == 4529,
            "The retained strict norm classification count changed.")
    source_hash = hashlib.sha256((ROOT / "research/signatures/cases.json").read_bytes()).hexdigest()
    require(profile["source_cases_sha256"] == packing["source_cases_sha256"] == source_hash,
            "The genuine source signature fixture identity changed.")

    vectors = json.loads((BASE / "hash_adapter_vectors.json").read_bytes())["vectors"]
    require(len(vectors) == 3, "Expected three full hash adapter goldens.")
    retained = {
        "leaf.v1": ([0, 1, 2013265920, 0x12345678], 4),
        "node.v1": ([0, 1, (1 << 64) - 1] + list(range(13)), 8),
        "transcript.v1": (list(range(64)), 1),
    }
    require({vector["domain_suffix"] for vector in vectors} == set(retained),
            "The full adapter golden roles changed.")
    for vector in vectors:
        inputs, width = retained[vector["domain_suffix"]]
        require(vector["inputs"] == inputs, "The retained adapter inputs changed.")
        domain = ("thorum.use-hint-proof-lab." + vector["domain_suffix"]).encode()
        preimage = len(domain).to_bytes(4, "big") + domain
        preimage += b"".join(value.to_bytes(width, "little") for value in inputs)
        preimage += len(inputs).to_bytes(8, "big")
        digest = hashlib.sha3_512(preimage).digest()
        words = [int.from_bytes(digest[i:i + 8], "little") for i in range(0, 64, 8)]
        require(vector["preimage_hex"] == preimage.hex() and vector["digest_hex"] == digest.hex()
                and vector["little_endian_u64_words"] == words,
                f"The complete {vector['domain_suffix']} golden changed.")


def main():
    try:
        check_sources(read_sources())
        check_fixtures()
    except (ProfileError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: frozen test only profile {PROFILE}.")
    print("PASS: 256 by 125 trace, 70 public values, degree 2, stored degree bits 9, four quotient chunks and nine FRI rounds.")
    print("PASS: fresh hiding seeds, 64 queries, log blowup 2, four random columns, sixteen salts and bounded canonical transport.")
    print("PASS: source provenance, retained coefficient fixtures and three complete adapter goldens.")
    print("This source profile change guard does not establish mathematical correctness, privacy, authorization, soundness or a security level.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
