//! One complete synthetic proof and finite mutations at the retained verifier.
#![forbid(unsafe_code)]

use crate::{Context, Phase, diagnostics_setup as setup};
use kova_source_extension::reference_air::QuarticAir;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::{Proof, StarkConfig};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::PathBuf, sync::Arc};

type VerifierConfig = StarkConfig<setup::Anchor, crate::composite::Challenge, setup::Challenger>;
const PROOF_CAP: usize = 2 * 1024 * 1024;
const REPORT_CAP: usize = 16 * 1024;

struct Bounded(Vec<u8>, usize);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.1)
        {
            return Err(std::io::Error::other("fixed transport cap exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize, cap: usize) -> Vec<u8> {
    let mut output = Bounded(Vec::new(), cap);
    serde_json::to_writer(&mut output, value).unwrap();
    output.0
}
fn write(name: &str, bytes: &[u8]) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn public() -> [BabyBear; 2] {
    [BabyBear::from_u32(5), BabyBear::from_u32(260)]
}
fn no_prover_effects(before: setup::Counts, after: setup::Counts) {
    let mut after = after;
    after.verify_calls = before.verify_calls;
    assert_eq!(
        before, after,
        "verifier did not commit, open or sample private RNGs"
    );
}

// Change one real serialized scalar, then decode it back into the original
// verifier's proof type. A decode refusal cannot count as proof rejection.
fn changed_proof(bytes: &[u8], path: &str, field: bool) -> Proof<VerifierConfig> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let scalar = value.pointer_mut(path).expect("fixed proof scalar path");
    let original = scalar.as_u64().expect("canonical numeric scalar");
    let changed = if field {
        assert!(original < u64::from(BabyBear::ORDER_U32));
        (original + 1) % u64::from(BabyBear::ORDER_U32)
    } else {
        original ^ 1
    };
    *scalar = serde_json::json!(changed);
    let encoded = encode(&value, PROOF_CAP);
    serde_json::from_slice(&encoded).expect("well formed mutated proof")
}

/// Fixed public fixture only. No witness predicate or expected root is accepted.
#[allow(
    clippy::assertions_on_constants,
    reason = "Only the admitted release binary may prove."
)]
pub fn fixed_complete_proof() {
    assert!(!cfg!(debug_assertions), "release diagnostic required");
    let results = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&results).unwrap();
    for name in ["proof.json", "measurement.json"] {
        assert!(
            !results.join(name).exists(),
            "fresh single admission outputs required"
        );
    }

    let (anchor, anchor_audit) = setup::anchor();
    let anchor_before = anchor_audit.detailed_counts();
    let (pcs, audit) = setup::base();
    let context = Arc::new(Context::new(pcs, setup::challenger(), &anchor).unwrap());
    audit.bind_owner(&context);
    let proof = context.prove(setup::rawliteral()).unwrap();
    assert_eq!(proof.degree_bits, 9);
    let state = context.snapshot().unwrap();
    assert_eq!(state.phase, Phase::ProofProduced);
    assert_eq!(
        (state.reserved_files, state.reserved_bytes),
        (13, 1_325_056)
    );
    assert!(state.failure.is_none());
    assert!(state.cleanup_failures.is_empty());
    let produced = audit.detailed_counts();
    assert_eq!(produced.input_commits, 3);
    assert_eq!(produced.extension_commits, 9);
    assert_eq!(produced.input_multi_opens, 3);
    assert_eq!(produced.extension_multi_opens, 9);
    assert_eq!(produced.scalar_opens, 0);
    assert_eq!(produced.verify_calls, 0);
    assert_eq!(produced.dft.coset_lde_batch, 3);
    assert_eq!(produced.dft.idft_batch, 0);
    assert_eq!(produced.dft.dft_batch, 8);
    assert_eq!(produced.dft.coset_dft_batch, 0);
    assert_eq!(produced.dft.coset_idft_batch, 8);
    assert_eq!(produced.dft.lde_batch, 0);
    assert_eq!(produced.dft.coset_lde_batch_with_transform, 0);
    assert_eq!(produced.dft.coset_lde_batch_with_blocks, 0);

    let bytes = encode(&proof, PROOF_CAP);
    let parsed: Proof<VerifierConfig> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bytes, encode(&parsed, PROOF_CAP));
    let roots = audit.roots();
    assert_eq!(roots.len(), 12);
    let serialized: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serialized["commitments"]["trace"], roots[0]);
    assert_eq!(serialized["commitments"]["quotient_chunks"], roots[1]);
    assert_eq!(serialized["commitments"]["random"], roots[2]);
    assert_eq!(
        serialized["opening_proof"][1]["commit_phase_commits"],
        serde_json::to_value(&roots[3..]).unwrap()
    );
    drop(serialized);

    // The independently compiled nominal verifier uses the original backend.
    // Its configuration is moved, never cloned to reset a private stream.
    assert_eq!(anchor_before, anchor_audit.detailed_counts());
    let verifier = StarkConfig::new(anchor, setup::challenger());
    p3_uni_stark::verify(&verifier, &QuarticAir, &parsed, &public()).unwrap();
    let accepted = anchor_audit.detailed_counts();
    no_prover_effects(anchor_before, accepted);
    assert_eq!(accepted.verify_calls, 12);

    let mut rejected = Vec::new();
    for (name, values) in [
        (
            "initial_public_value",
            [BabyBear::from_u32(6), BabyBear::from_u32(260)],
        ),
        (
            "final_public_value",
            [BabyBear::from_u32(5), BabyBear::from_u32(261)],
        ),
    ] {
        let before = anchor_audit.detailed_counts();
        assert!(p3_uni_stark::verify(&verifier, &QuarticAir, &parsed, &values).is_err());
        let after = anchor_audit.detailed_counts();
        no_prover_effects(before, after);
        assert!(after.verify_calls - before.verify_calls <= 12);
        rejected.push(name);
    }
    for (name, path, field) in [
        ("trace_commitment", "/commitments/trace/cap/0/0", false),
        (
            "quotient_commitment",
            "/commitments/quotient_chunks/cap/0/0",
            false,
        ),
        ("auxiliary_commitment", "/commitments/random/cap/0/0", false),
        (
            "trace_opened_value",
            "/opened_values/trace_local/0/value/0",
            true,
        ),
        (
            "quotient_opened_value",
            "/opened_values/quotient_chunks/0/0/value/0",
            true,
        ),
        (
            "auxiliary_opened_value",
            "/opened_values/random/0/value/0",
            true,
        ),
        ("degree_bits", "/degree_bits", false),
    ] {
        let changed = changed_proof(&bytes, path, field);
        let before = anchor_audit.detailed_counts();
        assert!(
            p3_uni_stark::verify(&verifier, &QuarticAir, &changed, &public()).is_err(),
            "{name}"
        );
        let after = anchor_audit.detailed_counts();
        no_prover_effects(before, after);
        assert!(after.verify_calls - before.verify_calls <= 12);
        rejected.push(name);
    }
    let (other_anchor, other_audit) = setup::anchor();
    let before = other_audit.detailed_counts();
    let other_verifier = StarkConfig::new(other_anchor, setup::different_challenger());
    assert!(p3_uni_stark::verify(&other_verifier, &QuarticAir, &parsed, &public()).is_err());
    let after = other_audit.detailed_counts();
    no_prover_effects(before, after);
    assert!(after.verify_calls <= 12);
    rejected.push("transcript_context");
    assert_eq!(rejected.len(), 10);

    // The second entry fails its lifecycle admission before another raw write.
    // It never starts another prover or restores consumed private opening flags.
    assert!(context.prove(setup::rawliteral()).is_err());
    assert_eq!(produced, audit.detailed_counts());
    assert_eq!(context.snapshot().unwrap().phase, Phase::ProofProduced);
    let fingerprints = audit.delivered_fingerprints();
    let measurement = serde_json::json!({
        "profile": "quartic-source-prover-v1",
        "whole_stark_proofs": 1,
        "retained_verifier_accepts": 1,
        "retained_verifier_rejects": rejected,
        "degree_bits": 9, "raw_height": 256, "main_width": 2,
        "public_values": [5, 260], "queries": 64, "extension_degree": 4,
        "reserved_files": 13, "reserved_field_bytes": 1_325_056,
        "encoded_proof_bytes": bytes.len(), "proof_produced_after_construction": true,
        "prover_observations": produced,
        "correct_verifier_observations": accepted,
        "verifier_observations_after_mutations": anchor_audit.detailed_counts(),
        "other_context_verifier_observations": after,
        "delivered_rng_fingerprints": fingerprints,
        "commit_roots": roots,
        "reentry_refused_without_protocol_effects": true
    });
    let report = encode(&measurement, REPORT_CAP);
    write("proof.json", &bytes);
    write("measurement.json", &report);
}
