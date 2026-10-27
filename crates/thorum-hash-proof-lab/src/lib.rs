//! Isolated hiding STARK experiment for SHA3 and SHAKE over private bytes.
//! Signature verification, ownership and spending authorization are not proved.

#![forbid(unsafe_code)]

#[cfg(test)]
mod causal;
pub mod challenge_sampler;
mod hash;
pub mod matrix_sampler;
#[cfg(test)]
mod reference;
mod sponge;
#[cfg(test)]
mod tests;

use p3_air::check_all_constraints;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeHidingMmcs, PrunedMerklePaths};
use p3_symmetric::CompressionFunctionFromHasher;
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand::{SeedableRng, rngs::StdRng};

use hash::{LeafHash, NodeHash, TranscriptHash};
use sponge::{HashAir, public_values, trace};

type Challenge = BinomialExtensionField<BabyBear, 4>;
type Compress = CompressionFunctionFromHasher<NodeHash, 2, 8>;
type HidingMmcs = MerkleTreeHidingMmcs<BabyBear, u64, LeafHash, Compress, StdRng, 2, 8, 16>;
type ChallengeMmcs = ExtensionMmcs<BabyBear, Challenge, HidingMmcs>;
type Challenger = SerializingChallenger32<BabyBear, HashChallenger<u8, TranscriptHash, 64>>;
type Pcs = HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, HidingMmcs, ChallengeMmcs, StdRng>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub const PROFILE: &[u8] = b"thorum.hash-proof-lab.keccak.sha3-shake.serial.p3-0.8.0.v1";
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_TOKENS: usize = 1_000_000;
const MAX_JSON_ITEMS: usize = 16_384;

pub const MAX_INPUT_BYTES: usize = 2592;
pub const MAX_OUTPUT_BYTES: usize = 840;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    Sha3_512 = 1,
    Shake128 = 2,
    Shake256 = 3,
}
impl Mode {
    pub(crate) fn rate(self) -> usize {
        match self {
            Self::Sha3_512 => 72,
            Self::Shake128 => 168,
            Self::Shake256 => 136,
        }
    }
    pub(crate) fn suffix(self) -> u8 {
        match self {
            Self::Sha3_512 => 6,
            Self::Shake128 | Self::Shake256 => 31,
        }
    }
}

/// The caller supplies the expected primitive, lengths, output and context.
/// The verifier builds its AIR schedule from this typed statement.
#[derive(Clone, Copy)]
pub struct Statement {
    mode: Mode,
    input_length: usize,
    output_length: usize,
    output: [u8; MAX_OUTPUT_BYTES],
    context: [u8; 64],
}
impl Statement {
    pub fn new(
        mode: Mode,
        input_length: usize,
        output: &[u8],
        context: [u8; 64],
    ) -> Result<Self, Error> {
        if output.len() > MAX_OUTPUT_BYTES {
            return Err(Error::InvalidStatement);
        }
        let mut padded = [0; MAX_OUTPUT_BYTES];
        padded[..output.len()].copy_from_slice(output);
        let result = Self {
            mode,
            input_length,
            output_length: output.len(),
            output: padded,
            context,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.input_length > MAX_INPUT_BYTES
            || self.output_length == 0
            || self.output_length > MAX_OUTPUT_BYTES
            || (self.mode == Mode::Sha3_512 && self.output_length != 64)
            || self.output[self.output_length..].iter().any(|b| *b != 0)
        {
            return Err(Error::InvalidStatement);
        }
        Ok(())
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn input_length(&self) -> usize {
        self.input_length
    }
    pub fn output(&self) -> &[u8] {
        &self.output[..self.output_length]
    }
    pub fn context(&self) -> &[u8; 64] {
        &self.context
    }
}

/// This type has no Debug, Clone, serialization or public plaintext export.
pub struct Witness {
    input: Vec<u8>,
}
impl Witness {
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(Error::InvalidWitness);
        }
        Ok(Self {
            input: input.to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidStatement,
    EntropyUnavailable,
    InvalidWitness,
    ProvingFailed,
    InvalidEncoding,
    LimitExceeded,
    InvalidProof,
}

fn fresh_rng() -> Result<StdRng, Error> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::EntropyUnavailable)?;
    Ok(StdRng::from_seed(seed))
}

fn build_config(mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
    let mmcs = HidingMmcs::new(LeafHash, Compress::new(NodeHash), 0, mmcs_rng);
    let challenge_mmcs = ChallengeMmcs::new(mmcs.clone());
    let params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 64,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Radix2DitParallel::default(), mmcs, params, 4, pcs_rng);
    let challenger = Challenger::new(HashChallenger::new(PROFILE.to_vec(), TranscriptHash));
    Config::new(pcs, challenger)
}

fn prover_config() -> Result<Config, Error> {
    Ok(build_config(fresh_rng()?, fresh_rng()?))
}

fn verifier_config() -> Config {
    // Verification never samples private masks or salts. These public dummy
    // generators only satisfy the shared PCS type and are never used to prove.
    build_config(StdRng::from_seed([0; 32]), StdRng::from_seed([0; 32]))
}

/// A successful local constraint check is not accepted as a proof by the verifier.
fn trace_is_valid(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    use p3_matrix::Matrix;
    statement.validate().is_ok()
        && trace.width() == sponge::WIDTH
        && trace.height() == sponge::HEIGHT
        && check_all_constraints(
            &HashAir::new(statement),
            trace,
            &public_values(statement),
            Some(1),
        )
        .is_ok()
}

/// Every invocation commits a fresh trace using new OS seeded hiding generators.
pub fn prove_hash(witness: &Witness, statement: &Statement) -> Result<Vec<u8>, Error> {
    statement.validate()?;
    if witness.input.len() != statement.input_length {
        return Err(Error::InvalidWitness);
    }
    prove_trace(trace(witness, statement), statement)
}

fn prove_trace(trace: RowMajorMatrix<BabyBear>, statement: &Statement) -> Result<Vec<u8>, Error> {
    if !trace_is_valid(&trace, statement) {
        return Err(Error::InvalidWitness);
    }
    let config = prover_config()?;
    let proof = prove(
        &config,
        &HashAir::new(statement),
        trace,
        &public_values(statement),
    )
    .map_err(|_| Error::ProvingFailed)?;
    let bytes = serde_json::to_vec(&proof).map_err(|_| Error::InvalidEncoding)?;
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::LimitExceeded);
    }
    json_preflight(&bytes)?;
    Ok(bytes)
}

/// The expected statement and all proof parameters come from this verifier.
/// No private witness or host acceptance callback is consumed.
pub fn verify_hash(bytes: &[u8], statement: &Statement) -> Result<(), Error> {
    statement.validate()?;
    json_preflight(bytes)?;
    let proof: Proof<Config> = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)?;
    validate_shape(&proof)?;
    if serde_json::to_vec(&proof).map_err(|_| Error::InvalidEncoding)? != bytes {
        return Err(Error::InvalidEncoding);
    }
    let config = verifier_config();
    verify(
        &config,
        &HashAir::new(statement),
        &proof,
        &public_values(statement),
    )
    .map_err(|_| Error::InvalidProof)
}

type MerkleMultiProof = (Vec<Vec<Vec<BabyBear>>>, PrunedMerklePaths<u64, 8>);

fn merkle_shape(proof: &MerkleMultiProof, matrices: usize) -> bool {
    proof.0.len() == 64
        && proof
            .0
            .iter()
            .all(|query| query.len() == matrices && query.iter().all(|salt| salt.len() == 16))
        && proof.1.sibling_hashes.len() <= 64 * 14
}

// All dimensions follow from the fixed AIR, degree, extension and FRI profile.
// Transcript dependent Merkle pruning sizes have conservative fixed maxima.
fn validate_shape(proof: &Proof<Config>) -> Result<(), Error> {
    let opened = &proof.opened_values;
    let (masks, fri) = &proof.opening_proof;
    let invalid = || Error::InvalidProof;
    if proof.degree_bits != 11
        || proof.ood_pow_witness != BabyBear::ZERO
        || proof.commitments.trace.num_roots() != 1
        || proof.commitments.quotient_chunks.num_roots() != 1
        || proof
            .commitments
            .random
            .as_ref()
            .is_none_or(|cap| cap.num_roots() != 1)
        || opened.trace_local.len() != sponge::WIDTH
        || opened
            .trace_next
            .as_ref()
            .is_none_or(|row| row.len() != sponge::WIDTH)
        || opened.preprocessed.is_some()
        || opened.quotient_chunks.len() != 8
        || opened.quotient_chunks.iter().any(|chunk| chunk.len() != 4)
        || opened
            .random
            .as_ref()
            .is_none_or(|values| values.len() != 4)
        || masks.len() != 3
    {
        return Err(invalid());
    }
    for (round, matrix_count, points) in [(0, 1, 1), (1, 1, 2), (2, 8, 1)] {
        if masks[round].len() != matrix_count
            || masks[round].iter().any(|matrix| {
                matrix.len() != points || matrix.iter().any(|values| values.len() != 4)
            })
        {
            return Err(invalid());
        }
    }
    if fri.batch_pow_witness != BabyBear::ZERO
        || fri.query_pow_witness != BabyBear::ZERO
        || fri.commit_phase_commits.len() != 11
        || fri
            .commit_phase_commits
            .iter()
            .any(|cap| cap.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != 11
        || fri
            .commit_pow_witnesses
            .iter()
            .any(|value| *value != BabyBear::ZERO)
        || fri.commit_phase_openings.len() != 11
        || fri.final_poly.len() != 1
        || fri.input_openings.len() != 3
    {
        return Err(invalid());
    }
    for (batch, matrix_count, width) in [(0, 1, 8), (1, 1, sponge::WIDTH + 4), (2, 8, 8)] {
        let input = &fri.input_openings[batch];
        if input.opened_values.len() != 64
            || input.opened_values.iter().any(|query| {
                query.len() != matrix_count || query.iter().any(|row| row.len() != width)
            })
            || !merkle_shape(&input.opening_proof, matrix_count)
        {
            return Err(invalid());
        }
    }
    for round in &fri.commit_phase_openings {
        if round.sibling_values.len() != 64
            || round.sibling_values.iter().any(|values| values.len() != 1)
            || !merkle_shape(&round.opening_proof, 1)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

// The JSON decoder exposes no declared sequence lengths. Preflight bounds nesting,
// total tokens and collection sizes before any owned proof collections allocate.
// Strings in canonical proofs are fixed field names. Escapes are not emitted.
fn json_preflight(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::LimitExceeded);
    }
    let mut depth = 0usize;
    let mut items = [0usize; MAX_JSON_DEPTH];
    let mut tokens = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'[' | b'{' => {
                if depth == MAX_JSON_DEPTH {
                    return Err(Error::LimitExceeded);
                }
                items[depth] = 0;
                depth += 1;
                tokens += 1;
                index += 1;
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or(Error::InvalidEncoding)?;
                index += 1;
            }
            b',' => {
                let counter = items
                    .get_mut(depth.checked_sub(1).ok_or(Error::InvalidEncoding)?)
                    .ok_or(Error::InvalidEncoding)?;
                *counter += 1;
                if *counter >= MAX_JSON_ITEMS {
                    return Err(Error::LimitExceeded);
                }
                index += 1;
            }
            b'"' => {
                index += 1;
                let start = index;
                while bytes.get(index).is_some_and(|byte| *byte != b'"') {
                    if bytes[index] == b'\\' || index - start >= 64 {
                        return Err(Error::InvalidEncoding);
                    }
                    index += 1;
                }
                if bytes.get(index) != Some(&b'"') {
                    return Err(Error::InvalidEncoding);
                }
                tokens += 1;
                index += 1;
            }
            b'0'..=b'9' => {
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                if index - start > 20 {
                    return Err(Error::InvalidEncoding);
                }
                tokens += 1;
            }
            b'n' => {
                if bytes.get(index..index + 4) != Some(b"null") {
                    return Err(Error::InvalidEncoding);
                }
                tokens += 1;
                index += 4;
            }
            b':' | b' ' | b'\n' | b'\r' | b'\t' => index += 1,
            _ => return Err(Error::InvalidEncoding),
        }
        if tokens > MAX_JSON_TOKENS {
            return Err(Error::LimitExceeded);
        }
    }
    if depth != 0 {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}
