//! Full source, matrix and final sponge IO on the retained four round engine.
use crate::{
    build,
    full_program::{self as fp, Byte, Hash},
    layout::*,
    packing, program,
    sources::Source,
};
use core::borrow::Borrow;
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::Matrix;
fn source_expr<AB: AirBuilder<F = BabyBear>>(
    src: Byte,
    pc: usize,
    row: &[AB::Var],
    public: &[AB::PublicVar],
) -> AB::Expr {
    match src {
        Byte::Fixed(v) => BabyBear::from_u8(v).into(),
        Byte::Rho(i) => row[RHO + i].into(),
        Byte::Mu(i) => row[MU + i].into(),
        Byte::W1(i) => row[W1 + i].into(),
        Byte::Initial(s) => match s {
            Source::Fixed(v) => BabyBear::from_u8(v).into(),
            Source::Key(i) => crate::packed::byte_at::<AB>(row, pc, crate::packed::Bank::Key, i),
            Source::Signature(i) => {
                crate::packed::byte_at::<AB>(row, pc, crate::packed::Bank::Signature, i)
            }
            Source::Note(i) => crate::packed::byte_at::<AB>(row, pc, crate::packed::Bank::Note, i),
            Source::Tr(i) => row[TR + i].into(),
            Source::Public(i) => public[i].into(),
        },
    }
}
pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let public = b.public_values().to_vec();
    let first: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
    let last: &KeccakCols<AB::Var> = row[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
    let nf: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
    for bit in &row[MESSAGE..RHO] {
        b.assert_bool(*bit);
    }
    for byte in 0..168 {
        let expected: AB::Expr = (0..HEIGHT)
            .step_by(6)
            .filter(|r| fp::hash(*r) != Hash::Dummy)
            .map(|r| {
                let source = fp::message(fp::hash(r), byte);
                if matches!(
                    source,
                    Byte::Initial(Source::Key(_) | Source::Signature(_) | Source::Note(_))
                ) {
                    // Read-port ranks can change inside the six physical rows.
                    (r..r + 6)
                        .map(|pc| {
                            program::at::<AB>(row, pc) * source_expr::<AB>(source, pc, row, &public)
                        })
                        .sum()
                } else {
                    program::hash_selector::<AB>(row, r / 6)
                        * source_expr::<AB>(source, r, row, &public)
                }
            })
            .sum();
        b.assert_eq(
            packing::packed::<AB>(&row[MESSAGE + 8 * byte..MESSAGE + 8 * (byte + 1)]),
            expected,
        );
    }
    for limb in 0..84 {
        let enabled: AB::Expr = (0..HEIGHT)
            .step_by(6)
            .filter(|r| 2 * limb < fp::rate(fp::hash(*r)))
            .map(|r| program::hash_selector::<AB>(row, r / 6))
            .sum();
        let value = packing::packed::<AB>(&row[OUTPUT + 16 * limb..OUTPUT + 16 * (limb + 1)]);
        b.when(enabled.clone()).assert_eq(
            value.clone(),
            last.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
        );
        b.when(AB::Expr::ONE - enabled).assert_zero(value);
    }
    let fresh: AB::Expr = (0..HEIGHT)
        .step_by(6)
        .filter(|r| fp::fresh(fp::hash(*r)))
        .map(|r| program::at::<AB>(row, r))
        .sum();
    for r in (0..HEIGHT).step_by(6) {
        b.when(program::at::<AB>(row, r))
            .assert_one(first.step_flags[0]);
    }
    for limb in 0..100 {
        let (y, x, l) = (limb / 20, (limb / 4) % 5, limb % 4);
        let message = if limb < 84 {
            packing::packed::<AB>(&row[MESSAGE + 16 * limb..MESSAGE + 16 * (limb + 1)])
        } else {
            AB::Expr::ZERO
        };
        b.when(fresh.clone())
            .assert_eq(first.preimage[y][x][l], message);
        for rate in [72usize, 136, 168] {
            let join: AB::Expr = (0..HEIGHT)
                .step_by(6)
                .filter(|r| fp::continuation(fp::hash(*r)) == Some(rate))
                .map(|r| program::at::<AB>(row, r + 5))
                .sum();
            let previous: AB::Expr = last.a_prime_prime_prime(y, x, l).into();
            let joined = if limb < rate / 2 {
                (0..16).rev().fold(AB::Expr::ZERO, |a, bit| {
                    let old: AB::Expr = row[OUTPUT + 16 * limb + bit].into();
                    let msg: AB::Expr = next[MESSAGE + 16 * limb + bit].into();
                    a.double() + old.xor(&msg)
                })
            } else {
                previous
            };
            b.when_transition()
                .when(join)
                .assert_eq(nf.preimage[y][x][l], joined);
        }
    }
    for byte in 0..64 {
        b.when(program::at::<AB>(row, fp::FINAL_END - 1)).assert_eq(
            packing::packed::<AB>(&row[OUTPUT + 8 * byte..OUTPUT + 8 * (byte + 1)]),
            crate::packed::byte_at::<AB>(
                row,
                fp::FINAL_END - 1,
                crate::packed::Bank::Signature,
                byte,
            ),
        );
    }
}
fn row_message(hash: Hash, row: &[BabyBear]) -> [u8; 168] {
    core::array::from_fn(|byte| match fp::message(hash, byte) {
        Byte::Fixed(v) => v,
        Byte::Rho(i) => row[RHO + i].as_canonical_u32() as u8,
        Byte::Mu(i) => row[MU + i].as_canonical_u32() as u8,
        Byte::W1(i) => row[W1 + i].as_canonical_u32() as u8,
        Byte::Initial(_) => {
            unreachable!("Only matrix and final intervals are written by this pass")
        }
    })
}
fn fill_permutation(values: &mut [BabyBear], start: usize, hash: Hash, state: &mut [u64; 25]) {
    let message = row_message(hash, &values[start * WIDTH..(start + 1) * WIDTH]);
    let rate = fp::rate(hash);
    if fp::fresh(hash) {
        *state = [0; 25];
    }
    for lane in 0..rate / 8 {
        state[lane] ^= u64::from_le_bytes(message[8 * lane..8 * (lane + 1)].try_into().unwrap());
    }
    let logical = build::permutation(*state);
    for local in 0..6 {
        let row = &mut values[(start + local) * WIDTH..(start + local + 1) * WIDTH];
        build::copy_rounds(row, &logical, 4 * local);
        for (byte, v) in message.iter().enumerate() {
            build::bits(row, MESSAGE + 8 * byte, u32::from(*v), 8);
        }
        let round = logical.row_slice(4 * local + 3).unwrap();
        let k: &KeccakCols<BabyBear> = (*round).borrow();
        for limb in 0..84 {
            let v = if limb < rate / 2 {
                k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32()
            } else {
                0
            };
            build::bits(row, OUTPUT + 16 * limb, v, 16);
        }
    }
    *state = build::state_after(&logical);
    drop(logical);
}
pub(crate) fn fill_matrix(values: &mut [BabyBear]) {
    let mut state = [0u64; 25];
    for j in 0..7 {
        for i in 0..8 {
            for block in 0..6 {
                fill_permutation(
                    values,
                    fp::matrix_start(i, j) + 6 * block,
                    Hash::Matrix {
                        row: i,
                        column: j,
                        block,
                    },
                    &mut state,
                );
            }
        }
    }
}
pub(crate) fn fill_final(values: &mut [BabyBear]) {
    let mut state = [0u64; 25];
    for block in 0..9 {
        fill_permutation(
            values,
            fp::FINAL_START + 6 * block,
            Hash::Final(block),
            &mut state,
        );
    }
}
pub(crate) fn matrix_preflight(w: &crate::Witness) -> Result<(), build::BuildError> {
    for j in 0..7 {
        for i in 0..8 {
            let mut message = [0u8; 168];
            message[..32].copy_from_slice(&w.key[..32]);
            message[32] = j;
            message[33] = i;
            message[34] = 31;
            message[167] = 128;
            let mut state = [0u64; 25];
            for lane in 0..21 {
                state[lane] =
                    u64::from_le_bytes(message[8 * lane..8 * (lane + 1)].try_into().unwrap());
            }
            let mut accepted = 0;
            for _ in 0..6 {
                let logical = build::permutation(state);
                state = build::state_after(&logical);
                drop(logical);
                for candidate in 0..56 {
                    let at = 3 * candidate;
                    let byte = |n: usize| state[n / 8].to_le_bytes()[n % 8];
                    let a = u32::from(byte(at))
                        + (u32::from(byte(at + 1)) << 8)
                        + (u32::from(byte(at + 2) & 127) << 16);
                    if a < crate::MODULUS && accepted < 256 {
                        accepted += 1;
                    }
                }
            }
            if accepted != 256 {
                return Err(build::BuildError::UnsupportedMatrixClass);
            }
        }
    }
    Ok(())
}
