use crate::transport::{self, Admitted, CanonicalWriter};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_merkle_tree::{MerkleTreeHidingMmcs, PrunedMerklePaths};
use p3_symmetric::CompressionFunctionFromHasher;
use p3_uni_stark::{Proof, StarkConfig};
use rand::rngs::StdRng;

#[path = "../../storage-pcs/tests/common/hash.rs"]
mod hash;
type Challenge = BinomialExtensionField<BabyBear, 4>;
type Compress = CompressionFunctionFromHasher<hash::NodeHash, 2, 8>;
type Input = MerkleTreeHidingMmcs<BabyBear, u64, hash::LeafHash, Compress, StdRng, 2, 8, 16>;
type Ext = ExtensionMmcs<BabyBear, Challenge, Input>;
type Pcs =
    kova_proof_preflight::HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Input, Ext, StdRng>;
type Challenger = SerializingChallenger32<BabyBear, HashChallenger<u8, hash::TranscriptHash, 64>>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub(crate) type Decoded = Proof<Config>;
type MultiProof = (Vec<Vec<Vec<BabyBear>>>, PrunedMerklePaths<u64, 8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Budget(transport::Error),
    Encoding,
    Shape,
    Canonical,
}

#[derive(Default, serde::Serialize)]
pub(crate) struct Counts {
    pub(crate) admissions: usize,
    pub(crate) typed_decodes: usize,
    pub(crate) decoded_shapes: usize,
    pub(crate) canonical_encodings: usize,
}

pub(crate) fn decode_frame(frame: &[u8], counts: &mut Counts) -> Result<Decoded, Error> {
    counts.admissions += 1;
    let admitted = transport::admit_frame(frame).map_err(Error::Budget)?;
    decode(admitted, counts)
}

pub(crate) fn decode_json(bytes: &[u8], counts: &mut Counts) -> Result<Decoded, Error> {
    counts.admissions += 1;
    let admitted = transport::admit_json(bytes).map_err(Error::Budget)?;
    decode(admitted, counts)
}

fn decode(admitted: Admitted<'_>, counts: &mut Counts) -> Result<Decoded, Error> {
    counts.typed_decodes += 1;
    let proof: Decoded = serde_json::from_slice(admitted.bytes()).map_err(|_| Error::Encoding)?;
    validate_shape(&proof)?;
    counts.decoded_shapes += 1;
    let mut writer = CanonicalWriter::new(&admitted);
    serde_json::to_writer(&mut writer, &proof).map_err(|_| Error::Canonical)?;
    writer.finish().map_err(|_| Error::Canonical)?;
    counts.canonical_encodings += 1;
    Ok(proof)
}

fn merkle_shape(proof: &MultiProof, matrices: usize, levels: usize) -> bool {
    proof.0.len() == 64
        && proof
            .0
            .iter()
            .all(|query| query.len() == matrices && query.iter().all(|salt| salt.len() == 16))
        && proof.1.sibling_hashes.len() <= 64 * levels
}

/// Fixed dimensions follow the actual source relation, not supplied proof parameters.
fn validate_shape(proof: &Decoded) -> Result<(), Error> {
    let opened = &proof.opened_values;
    let (masks, fri) = &proof.opening_proof;
    if proof.degree_bits != 9
        || proof.ood_pow_witness != BabyBear::ZERO
        || proof.commitments.trace.num_roots() != 1
        || proof.commitments.quotient_chunks.num_roots() != 1
        || proof
            .commitments
            .random
            .as_ref()
            .is_none_or(|c| c.num_roots() != 1)
        || opened.trace_local.len() != 2
        || opened.trace_next.as_ref().is_none_or(|r| r.len() != 2)
        || opened.preprocessed.is_some()
        || opened.quotient_chunks.len() != 8
        || opened.quotient_chunks.iter().any(|r| r.len() != 4)
        || opened.random.as_ref().is_none_or(|r| r.len() != 4)
        || masks.len() != 3
    {
        return Err(Error::Shape);
    }
    for (batch, matrices, points) in [(0, 1, 1), (1, 1, 2), (2, 8, 1)] {
        if masks[batch].len() != matrices
            || masks[batch]
                .iter()
                .any(|m| m.len() != points || m.iter().any(|r| r.len() != 4))
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != BabyBear::ZERO
        || fri.query_pow_witness != BabyBear::ZERO
        || fri.commit_phase_commits.len() != 9
        || fri.commit_phase_commits.iter().any(|c| c.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != 9
        || fri
            .commit_pow_witnesses
            .iter()
            .any(|v| *v != BabyBear::ZERO)
        || fri.commit_phase_openings.len() != 9
        || fri.final_poly.len() != 1
        || fri.input_openings.len() != 3
    {
        return Err(Error::Shape);
    }
    for (batch, matrices, width) in [(0, 1, 8), (1, 1, 6), (2, 8, 8)] {
        let input = &fri.input_openings[batch];
        if input.opened_values.len() != 64
            || input
                .opened_values
                .iter()
                .any(|q| q.len() != matrices || q.iter().any(|r| r.len() != width))
            || !merkle_shape(&input.opening_proof, matrices, 12)
        {
            return Err(Error::Shape);
        }
    }
    for (index, round) in fri.commit_phase_openings.iter().enumerate() {
        if round.sibling_values.len() != 64
            || round.sibling_values.iter().any(|r| r.len() != 1)
            || !merkle_shape(&round.opening_proof, 1, 11 - index)
        {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
