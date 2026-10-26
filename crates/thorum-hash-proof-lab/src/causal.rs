use super::*;
use p3_field::PrimeField32;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::Matrix;
use sha3::{Digest, Sha3_512};
use shake::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::borrow::Borrow;

fn expected(mode: Mode, input: &[u8], length: usize) -> Vec<u8> {
    match mode {
        Mode::Sha3_512 => Sha3_512::digest(input).to_vec(),
        Mode::Shake128 => {
            let mut hash = Shake128::default();
            Update::update(&mut hash, input);
            let mut output = vec![0; length];
            hash.finalize_xof().read(&mut output);
            output
        }
        Mode::Shake256 => {
            let mut hash = Shake256::default();
            Update::update(&mut hash, input);
            let mut output = vec![0; length];
            hash.finalize_xof().read(&mut output);
            output
        }
    }
}

fn fixture(mode: Mode, input_length: usize, output_length: usize) -> (Witness, Statement) {
    let input: Vec<u8> = (0..input_length).map(|i| (i * 73 + 19) as u8).collect();
    let output = expected(mode, &input, output_length);
    (
        Witness::from_bytes(&input).unwrap(),
        Statement::new(mode, input_length, &output, [0x6a; 64]).unwrap(),
    )
}

fn row_state(trace: &RowMajorMatrix<BabyBear>, row: usize, before: bool) -> [u64; 25] {
    let row = trace.row_slice(row).unwrap();
    let typed: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    core::array::from_fn(|lane| {
        (0..4)
            .map(|limb| {
                let value = if before {
                    typed.preimage[lane / 5][lane % 5][limb]
                } else {
                    typed.a_prime_prime_prime(lane / 5, lane % 5, limb)
                };
                (value.as_canonical_u32() as u64) << (limb * 16)
            })
            .sum()
    })
}

fn published_output(
    trace: &RowMajorMatrix<BabyBear>,
    statement: &Statement,
) -> [u8; MAX_OUTPUT_BYTES] {
    let air = HashAir::new(statement);
    let mut output = Vec::new();
    for stage in air.absorbs() - 1..air.permutations() {
        let state = row_state(trace, (stage + 1) * 24 - 1, false);
        for word in state.iter().take(statement.mode.rate() / 8) {
            output.extend_from_slice(&word.to_le_bytes());
        }
    }
    let mut result = [0; MAX_OUTPUT_BYTES];
    result[..statement.output_length].copy_from_slice(&output[..statement.output_length]);
    result
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    CombinedSuffix,
    CombinedTerminalBit,
    ZeroPadding,
    ExactRatePaddingBlock,
    InitialCapacity,
    AbsorbCapacity,
    AbsorbRate,
    OutsideRateMessage,
    SqueezeCapacity,
    SqueezeRate,
    SqueezeAbsorption,
    SqueezeReset,
    OutputBoundary,
    OutputLastPartial,
}

pub(crate) fn attack_trace(mode: Mode, attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let rate = mode.rate();
    let input_length = match attack {
        Attack::CombinedSuffix | Attack::CombinedTerminalBit => rate - 1,
        Attack::ZeroPadding => rate - 7,
        Attack::ExactRatePaddingBlock => rate,
        Attack::AbsorbCapacity | Attack::AbsorbRate => rate + 7,
        _ => 17,
    };
    let output_length = if mode == Mode::Sha3_512 {
        64
    } else if matches!(attack, Attack::OutputBoundary | Attack::OutputLastPartial) {
        rate + 7
    } else {
        840
    };
    let (witness, mut statement) = fixture(mode, input_length, output_length);
    let air = HashAir::new(&statement);
    let mut blocks = sponge::blocks(&witness, &statement);
    let mut overrides = Vec::new();
    match attack {
        Attack::CombinedSuffix => blocks[0][rate - 1] ^= 1,
        Attack::CombinedTerminalBit => blocks[0][rate - 1] ^= 128,
        Attack::ZeroPadding => blocks[0][rate - 4] = 1,
        Attack::ExactRatePaddingBlock => blocks[1].fill(0),
        Attack::InitialCapacity => overrides.push((0, rate / 8, 1)),
        Attack::AbsorbCapacity => overrides.push((1, rate / 8, 1)),
        Attack::AbsorbRate => overrides.push((1, 0, 1)),
        Attack::OutsideRateMessage => {
            assert!(rate < sponge::MAX_RATE);
            blocks[0][rate] = 1;
        }
        Attack::SqueezeCapacity => overrides.push((air.absorbs(), rate / 8, 1)),
        Attack::SqueezeRate => overrides.push((air.absorbs(), 0, 1)),
        Attack::SqueezeAbsorption => {
            blocks[air.absorbs()][0] = 1;
            overrides.push((air.absorbs(), 0, 1));
        }
        Attack::SqueezeReset => {
            let honest = trace(&witness, &statement);
            let original = row_state(&honest, air.absorbs() * 24, true);
            for (lane, mask) in original.into_iter().enumerate() {
                overrides.push((air.absorbs(), lane, mask));
            }
        }
        Attack::OutputBoundary | Attack::OutputLastPartial => {}
    }
    let trace = sponge::trace_with_blocks(&statement, &blocks, &overrides);
    statement.output = published_output(&trace, &statement);
    if matches!(attack, Attack::OutputBoundary) {
        statement.output[rate] ^= 1;
    }
    if matches!(attack, Attack::OutputLastPartial) {
        statement.output[statement.output_length - 1] ^= 1;
    }
    (trace, statement)
}

fn keccak_only_is_valid(trace: &RowMajorMatrix<BabyBear>) -> bool {
    let values = trace
        .values
        .chunks_exact(sponge::WIDTH)
        .flat_map(|row| row[..NUM_KECCAK_COLS].iter().copied())
        .collect();
    check_all_constraints(
        &p3_keccak_air::KeccakAir {},
        &RowMajorMatrix::new(values, NUM_KECCAK_COLS),
        &[],
        Some(1),
    )
    .is_ok()
}

#[test]
fn all_mode_honest_padding_and_squeezing_boundaries_pass() {
    for mode in [Mode::Sha3_512, Mode::Shake128, Mode::Shake256] {
        let rate = mode.rate();
        for input_length in [0, rate - 1, rate, rate + 1, 2592] {
            let output_length = if mode == Mode::Sha3_512 { 64 } else { 840 };
            let (witness, statement) = fixture(mode, input_length, output_length);
            let trace = trace(&witness, &statement);
            assert!(
                trace_is_valid(&trace, &statement),
                "{mode:?} {input_length}"
            );
            assert_eq!(published_output(&trace, &statement), statement.output);
        }
    }
}

#[test]
fn valid_keccak_and_published_actual_outputs_do_not_allow_wrapper_bypasses() {
    let mut count = 0;
    for mode in [Mode::Sha3_512, Mode::Shake128, Mode::Shake256] {
        for attack in [
            Attack::CombinedSuffix,
            Attack::CombinedTerminalBit,
            Attack::ZeroPadding,
            Attack::ExactRatePaddingBlock,
            Attack::InitialCapacity,
            Attack::AbsorbCapacity,
            Attack::AbsorbRate,
        ] {
            let (trace, statement) = attack_trace(mode, attack);
            assert!(
                keccak_only_is_valid(&trace),
                "{mode:?} {attack:?}: genuine Keccak"
            );
            assert_eq!(published_output(&trace, &statement), statement.output);
            assert!(!trace_is_valid(&trace, &statement), "{mode:?} {attack:?}");
            count += 1;
        }
    }
    for mode in [Mode::Sha3_512, Mode::Shake256] {
        let (trace, statement) = attack_trace(mode, Attack::OutsideRateMessage);
        assert!(keccak_only_is_valid(&trace));
        assert_eq!(published_output(&trace, &statement), statement.output);
        assert!(!trace_is_valid(&trace, &statement), "{mode:?} outside rate");
        count += 1;
    }
    for mode in [Mode::Shake128, Mode::Shake256] {
        for attack in [
            Attack::SqueezeCapacity,
            Attack::SqueezeRate,
            Attack::SqueezeAbsorption,
            Attack::SqueezeReset,
        ] {
            let (trace, statement) = attack_trace(mode, attack);
            assert!(
                keccak_only_is_valid(&trace),
                "{mode:?} {attack:?}: genuine Keccak"
            );
            assert_eq!(published_output(&trace, &statement), statement.output);
            assert!(!trace_is_valid(&trace, &statement), "{mode:?} {attack:?}");
            count += 1;
        }
    }
    assert_eq!(count, 31);
}

#[test]
fn squeeze_output_rate_boundaries_and_last_partial_bytes_are_pinned() {
    for mode in [Mode::Shake128, Mode::Shake256] {
        for attack in [Attack::OutputBoundary, Attack::OutputLastPartial] {
            let (trace, statement) = attack_trace(mode, attack);
            assert!(
                keccak_only_is_valid(&trace),
                "{mode:?} {attack:?}: genuine Keccak"
            );
            assert_ne!(published_output(&trace, &statement), statement.output);
            assert!(!trace_is_valid(&trace, &statement), "{mode:?} {attack:?}");
        }
    }
}
