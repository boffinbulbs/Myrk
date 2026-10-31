//! Source construction for the complete bounded signature and note owner AIR.
//! Construction is not constraint acceptance, a proof or payment acceptance.
//! One bounded ordinary permutation matrix is dropped before the next begins.
use crate::{
    layout::*,
    program::{self, Kind},
    sources::{self, Source},
    Statement, Witness,
};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{generate_trace_rows, KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use thorum_relation_lab::{PaymentStatement, RelationError};

#[path = "../../signature-complete-native/src/build/decode.rs"]
mod decode;
#[path = "../../signature-complete-native/src/build/sample.rs"]
mod sample;

#[derive(Debug)]
pub enum BuildError {
    InvalidEncoding,
    ExecutionNotAdmitted,
    UnsupportedChallengeClass,
    UnsupportedMatrixClass,
    InvalidPublicStatement(RelationError),
}

pub fn build_full_private_signature_owner_sources(
    witness: &Witness,
    transaction: &PaymentStatement,
) -> Result<RowMajorMatrix<BabyBear>, BuildError> {
    // The complete constructor remains dormant without a separate native gate.
    if !cfg!(feature = "native-execution") {
        return Err(BuildError::ExecutionNotAdmitted);
    }
    let statement =
        Statement::from_transaction(transaction).map_err(BuildError::InvalidPublicStatement)?;
    trace(witness, &statement)
}

pub(crate) fn bits(row: &mut [BabyBear], start: usize, value: u32, width: usize) {
    for bit in 0..width {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

pub(crate) fn permutation(input: [u64; 25]) -> RowMajorMatrix<BabyBear> {
    // The pinned generator allocates32 rows, and temporarily24 zero padding
    // rows. No full ordinary journal or list of permutation inputs is retained.
    let trace = generate_trace_rows::<BabyBear>(vec![input], 0);
    assert_eq!((trace.height(), trace.width()), (32, NUM_KECCAK_COLS));
    trace
}

pub(crate) fn state_after(logical: &RowMajorMatrix<BabyBear>) -> [u64; 25] {
    let row = logical.row_slice(23).unwrap();
    let k: &KeccakCols<BabyBear> = (*row).borrow();
    core::array::from_fn(|lane| {
        (0..4)
            .map(|limb| {
                u64::from(
                    k.a_prime_prime_prime(lane / 5, lane % 5, limb)
                        .as_canonical_u32(),
                ) << (16 * limb)
            })
            .sum()
    })
}

fn message(w: &Witness, s: &Statement, tr: &[u8; 64], permutation: usize) -> [u8; 168] {
    core::array::from_fn(|byte| match sources::message_source(permutation, byte) {
        Source::Fixed(v) => v,
        Source::Key(i) => w.key[i],
        Source::Signature(i) => w.signature[i],
        Source::Note(i) => w.note[i],
        Source::Tr(i) => tr[i],
        Source::Public(i) => s.authorization_input[i],
    })
}

fn absorb(state: &mut [u64; 25], message: &[u8; 168], rate: usize) {
    for lane in 0..rate / 8 {
        state[lane] ^= u64::from_le_bytes(message[lane * 8..lane * 8 + 8].try_into().unwrap());
    }
}

fn challenge_preflight(w: &Witness, s: &Statement) -> Result<(), BuildError> {
    let mut state = [0; 25];
    let mut xof = [0u8; 272];
    for block in 0..2 {
        absorb(&mut state, &message(w, s, &[0; 64], block), 136);
        let logical = permutation(state);
        state = state_after(&logical);
        for byte in 0..136 {
            xof[block * 136 + byte] = state[byte / 8].to_le_bytes()[byte % 8];
        }
        drop(logical);
    }
    let mut count = 0;
    for candidate in &xof[8..] {
        if count == 60 {
            break;
        }
        if usize::from(*candidate) <= 196 + count {
            count += 1;
        }
    }
    if count == 60 {
        Ok(())
    } else {
        Err(BuildError::UnsupportedChallengeClass)
    }
}

struct HashBanks {
    rho: [u8; 32],
    owner: [u8; 64],
    tr: [u8; 64],
    mu: [u8; 64],
    note: [u8; 64],
    xof: [u8; 272],
}
impl HashBanks {
    fn new() -> Self {
        Self {
            rho: [0; 32],
            owner: [0; 64],
            tr: [0; 64],
            mu: [0; 64],
            note: [0; 64],
            xof: [0; 272],
        }
    }
    fn write(&self, row: &mut [BabyBear]) {
        for (offset, bytes) in [
            (RHO, self.rho.as_slice()),
            (OWNER, self.owner.as_slice()),
            (TR, self.tr.as_slice()),
            (MU, self.mu.as_slice()),
            (NOTE_COMMITMENT, self.note.as_slice()),
            (CHALLENGE_XOF, self.xof.as_slice()),
        ] {
            for (i, value) in bytes.iter().enumerate() {
                row[offset + i] = BabyBear::from_u8(*value);
            }
        }
    }
    fn advance(&mut self, w: &Witness, global: usize, hash: program::Hash, output: &[u8; 168]) {
        if global == 0 {
            self.rho.copy_from_slice(&w.key[..32]);
        }
        if global % 6 != 5 {
            return;
        }
        if hash.kind == Kind::Challenge {
            self.xof[hash.block * 136..(hash.block + 1) * 136].copy_from_slice(&output[..136]);
        }
        if hash.block + 1 == hash.blocks {
            match hash.kind {
                Kind::Owner => self.owner.copy_from_slice(&output[..64]),
                Kind::Tr => self.tr.copy_from_slice(&output[..64]),
                Kind::Mu => self.mu.copy_from_slice(&output[..64]),
                Kind::Note => self.note.copy_from_slice(&output[..64]),
                Kind::Challenge => {}
            }
        }
    }
}

pub(crate) fn copy_rounds(row: &mut [BabyBear], logical: &RowMajorMatrix<BabyBear>, first: usize) {
    for slot in 0..4 {
        row[slot * NUM_KECCAK_COLS..(slot + 1) * NUM_KECCAK_COLS]
            .copy_from_slice(&logical.row_slice(first + slot).unwrap());
    }
}

fn stream_hashes(values: &mut [BabyBear], w: &Witness, s: &Statement) {
    let mut banks = HashBanks::new();
    let mut state = [0; 25];
    for permutation_index in 0..program::SOURCE_PERMUTATIONS {
        let hash = program::hash(permutation_index).unwrap();
        if hash.block == 0 {
            state = [0; 25];
        }
        let input = message(w, s, &banks.tr, permutation_index);
        absorb(&mut state, &input, hash.rate);
        let logical = permutation(state);
        for local_row in 0..6 {
            let global = 6 * permutation_index + local_row;
            let row = &mut values[global * WIDTH..(global + 1) * WIDTH];
            copy_rounds(row, &logical, 4 * local_row);
            for (i, byte) in input.iter().enumerate() {
                bits(row, MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            let round = logical.row_slice(4 * local_row + 3).unwrap();
            let k: &KeccakCols<BabyBear> = (*round).borrow();
            let mut output = [0u8; 168];
            for limb in 0..hash.rate / 2 {
                let word = k
                    .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32();
                bits(row, OUTPUT + 16 * limb, word, 16);
                output[2 * limb..2 * limb + 2].copy_from_slice(&(word as u16).to_le_bytes());
            }
            banks.write(row);
            banks.advance(w, global, hash, &output);
        }
        state = state_after(&logical);
        // The one logical matrix drops at this scope boundary. Only the full
        // 200-byte state and small derived source banks survive into the next.
        drop(logical);
    }
    let zero = permutation([0; 25]);
    for global in program::SOURCE_END..HEIGHT {
        let row = &mut values[global * WIDTH..(global + 1) * WIDTH];
        copy_rounds(row, &zero, (global % 6) * 4);
        banks.write(row);
        // Both message/output banks stay zero. The last global row copies
        // genuine zero-input rounds4..7, not a repeated terminal row.
    }
}

pub(crate) fn trace(w: &Witness, s: &Statement) -> Result<RowMajorMatrix<BabyBear>, BuildError> {
    decode::preflight(w)?;
    challenge_preflight(w, s)?;
    crate::sponge::matrix_preflight(w)?;
    let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    stream_hashes(&mut values, w, s);
    decode::fill(&mut values, w);
    sample::fill(&mut values);
    crate::ntt::fill(&mut values);
    crate::sponge::fill_matrix(&mut values);
    crate::matrix::fill_xof(&mut values);
    crate::matrix::fill(&mut values);
    crate::ntt::fill_inverse(&mut values);
    crate::hint_rows::fill(&mut values);
    crate::sponge::fill_final(&mut values);
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        row[CLOCK + at % CLOCK_LOW] = BabyBear::ONE;
        row[CLOCK + CLOCK_LOW + at / CLOCK_LOW] = BabyBear::ONE;
        row[ACTIVE_CHALLENGE] =
            BabyBear::from_bool((program::SAMPLE_START..program::SAMPLE_END).contains(&at))
                * (BabyBear::ONE - row[COUNT + 60]);
        let matrix_phase = crate::full_program::matrix(at).is_some_and(|(_, _, local)| local >= 6);
        for index in 0..8 {
            row[ACTIVE_MATRIX + index] = BabyBear::from_bool(matrix_phase)
                * (BabyBear::ONE - row[MATRIX_COUNT + 257 * index + 256]);
        }
        crate::packed::fill(row, at, w);
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

#[cfg(feature = "stream-controls")]
#[path = "../../signature-hash-source/src/decoder_state.rs"]
pub(crate) mod decoder_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-hash-source/src/hash_source.rs"]
pub(crate) mod hash_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-sample-source/src/sample_state.rs"]
pub(crate) mod sample_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-sample-source/src/initial_source.rs"]
pub(crate) mod initial_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-forward-source/src/forward_state.rs"]
pub(crate) mod forward_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-forward-source/src/forward_source.rs"]
pub(crate) mod forward_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-matrix-source/src/matrix_overlay.rs"]
pub(crate) mod matrix_overlay;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-matrix-source/src/matrix_source.rs"]
pub(crate) mod matrix_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-accumulator-source/src/accumulator_state.rs"]
pub(crate) mod accumulator_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-accumulator-source/src/accumulator_source.rs"]
// Retained fixed fault entry points are outside this single main walk.
#[allow(dead_code)]
pub(crate) mod accumulator_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-inverse-source/src/inverse_state.rs"]
pub(crate) mod inverse_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-inverse-source/src/inverse_source.rs"]
pub(crate) mod inverse_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-hint-source/src/hint_state.rs"]
pub(crate) mod hint_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-hint-source/src/hint_source.rs"]
pub(crate) mod hint_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-final-source/src/final_state.rs"]
pub(crate) mod final_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-final-source/src/final_source.rs"]
pub(crate) mod final_source;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-port-source/src/port_state.rs"]
pub(crate) mod port_state;

#[cfg(feature = "stream-controls")]
#[path = "../../signature-port-source/src/port_source.rs"]
pub(crate) mod port_source;
