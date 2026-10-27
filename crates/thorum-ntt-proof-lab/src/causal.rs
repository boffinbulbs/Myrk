use super::*;

const FIELD_MODULUS: u32 = 2_013_265_921;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    WrongTwiddle,
    DetachedMultiplicand,
    WrongIndices,
    WrongStage,
    SkippedStageProgramCounter,
    DetachedMiddleState,
    OmittedNormalization,
    DetachedNormalizationOutput,
    FirstHalfCopy,
    SecondHalfCopy,
    DetachedFinalState,
    PublicInputAlias,
    PublicOutputAlias,
    ModeMismatch,
    NoncanonicalPrivateState,
    PaddingProduct,
    UnusedNormalizationCarry,
}

fn input() -> [u32; 256] {
    core::array::from_fn(|i| ((i * i * 97 + i * 13 + 1) % mul::MODULUS as usize) as u32)
}

fn layer(
    mode: Mode,
    stage: usize,
    current: [u32; 256],
    attack: Option<Attack>,
) -> (ntt::Row, [u32; 256]) {
    let mut row = ntt::empty_row(current);
    let mut next = current;
    let target_stage = if matches!(
        attack,
        Some(Attack::WrongStage | Attack::SkippedStageProgramCounter)
    ) && stage == 3
    {
        4
    } else {
        stage
    };
    for (slot, (mut left, mut right, mut twiddle)) in
        ntt::butterflies(mode, target_stage).into_iter().enumerate()
    {
        if stage == 3 && slot == 7 {
            if matches!(attack, Some(Attack::WrongTwiddle)) {
                twiddle = (twiddle + 1) % mul::MODULUS;
            }
            if matches!(attack, Some(Attack::WrongIndices)) {
                core::mem::swap(&mut left, &mut right);
            }
        }
        let (a, b) = (current[left], current[right]);
        let (product, add, borrow) = match mode {
            Mode::Forward => {
                let b = if stage == 3
                    && slot == 7
                    && matches!(attack, Some(Attack::DetachedMultiplicand))
                {
                    (b + 1) % mul::MODULUS
                } else {
                    b
                };
                let product = ntt::product(twiddle, b);
                let t = product.values[3];
                let add = a + t >= mul::MODULUS;
                let borrow = a < t;
                next[left] = a + t - if add { mul::MODULUS } else { 0 };
                next[right] = (u64::from(a) + if borrow { u64::from(mul::MODULUS) } else { 0 }
                    - u64::from(t)) as u32;
                (product, add, borrow)
            }
            Mode::Inverse => {
                let add = a + b >= mul::MODULUS;
                let borrow = a < b;
                let difference = (u64::from(a) + if borrow { u64::from(mul::MODULUS) } else { 0 }
                    - u64::from(b)) as u32;
                let operand = if stage == 3
                    && slot == 7
                    && matches!(attack, Some(Attack::DetachedMultiplicand))
                {
                    (difference + 1) % mul::MODULUS
                } else {
                    difference
                };
                let product = ntt::product(twiddle, operand);
                next[left] = a + b - if add { mul::MODULUS } else { 0 };
                next[right] = product.values[3];
                (product, add, borrow)
            }
        };
        row.products[slot] = product;
        row.carries[slot] = [add, borrow];
    }
    (row, next)
}

fn normalize(half: usize, current: [u32; 256], attack: Option<Attack>) -> (ntt::Row, [u32; 256]) {
    let mut row = ntt::empty_row(current);
    let mut next = current;
    for slot in 0..128 {
        let index = half * 128 + slot;
        let factor = if matches!(attack, Some(Attack::OmittedNormalization)) {
            1
        } else {
            ntt::INVERSE_256
        };
        let product = ntt::product(factor, current[index]);
        next[index] = if matches!(attack, Some(Attack::DetachedNormalizationOutput)) {
            current[index]
        } else {
            product.values[3]
        };
        row.products[slot] = product;
    }
    if half == 0 && matches!(attack, Some(Attack::UnusedNormalizationCarry)) {
        row.carries[17][0] = true;
    }
    if half == 0 && matches!(attack, Some(Attack::FirstHalfCopy)) {
        next[200] = (next[200] + 1) % mul::MODULUS;
    }
    if half == 1 && matches!(attack, Some(Attack::SecondHalfCopy)) {
        next[17] = (next[17] + 1) % mul::MODULUS;
    }
    (row, next)
}

fn rows(mode: Mode, attack: Option<Attack>) -> Vec<ntt::Row> {
    let mut current = input();
    let mut result = Vec::new();
    for stage in 0..8 {
        if stage == 5 && matches!(attack, Some(Attack::DetachedMiddleState)) {
            current[17] = (current[17] + 1) % mul::MODULUS;
        }
        if stage == 3 && matches!(attack, Some(Attack::NoncanonicalPrivateState)) {
            current[0] = mul::MODULUS;
        }
        let (row, next) = layer(mode, stage, current, attack);
        result.push(row);
        current = next;
    }
    if mode == Mode::Inverse {
        for half in 0..2 {
            let (row, next) = normalize(half, current, attack);
            result.push(row);
            current = next;
        }
    }
    if matches!(attack, Some(Attack::DetachedFinalState)) {
        current[77] = (current[77] + 1) % mul::MODULUS;
    }
    let mut padding = ntt::empty_row(current);
    if matches!(attack, Some(Attack::PaddingProduct)) {
        padding.products[17] = ntt::product(1, 1);
    }
    result.push(padding);
    result
}

fn assert_actual_integer_products(rows: &[ntt::Row]) {
    for row in rows {
        for product in row.products {
            let [x, y, k, z] = product.values;
            assert!(product.values.iter().all(|v| *v < mul::MODULUS));
            assert_eq!(
                u64::from(x) * u64::from(y),
                u64::from(k) * u64::from(mul::MODULUS) + u64::from(z)
            );
            let low = |v: u32| i64::from(v & 4095);
            let high = |v: u32| i64::from(v >> 12);
            assert_eq!(
                low(x) * low(y) - low(k) - low(z),
                4096 * i64::from(product.carry0)
            );
            assert_eq!(
                low(x) * high(y) + high(x) * low(y) - 2046 * low(k) - high(k) - high(z)
                    + i64::from(product.carry0),
                4096 * i64::from(product.carry1)
            );
            assert_eq!(
                high(x) * high(y) - 2046 * high(k) + i64::from(product.carry1),
                0
            );
        }
    }
}

pub(crate) fn attack_trace(mode: Mode, attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let altered = rows(mode, Some(attack));
    assert_actual_integer_products(&altered);
    let output = altered.last().unwrap().polynomial;
    let mut statement = Statement::new(mode, input(), output, [0x9a; 64]).unwrap();
    if matches!(attack, Attack::ModeMismatch) {
        statement.mode = if mode == Mode::Forward {
            Mode::Inverse
        } else {
            Mode::Forward
        };
    }
    if matches!(attack, Attack::PublicInputAlias) {
        statement.input[23] += FIELD_MODULUS;
    }
    if matches!(attack, Attack::PublicOutputAlias) {
        statement.output[47] += FIELD_MODULUS;
    }
    let mut trace = air::trace_with_rows(mode, &altered);
    if matches!(attack, Attack::SkippedStageProgramCounter) {
        // The row itself computes stage four correctly. Only skipping stage
        // three and repeating stage four violates the fixed program sequence.
        trace.values[3 * air::WIDTH + 3] = BabyBear::ZERO;
        trace.values[3 * air::WIDTH + 4] = BabyBear::ONE;
    }
    (trace, statement)
}

fn check_air(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    // Bypass the host statement validator for public integer alias evidence.
    check_all_constraints(
        &NttAir::new(statement),
        trace,
        &public_values(statement),
        Some(1),
    )
    .is_ok()
}

#[test]
fn independent_layer_builders_match_honest_both_mode_traces() {
    for mode in [Mode::Forward, Mode::Inverse] {
        let correct = rows(mode, None);
        assert_actual_integer_products(&correct);
        let statement = Statement::new(
            mode,
            input(),
            correct.last().unwrap().polynomial,
            [0x9a; 64],
        )
        .unwrap();
        let trace = air::trace_with_rows(mode, &correct);
        assert!(check_air(&trace, &statement));
    }
}

#[test]
fn valid_local_products_with_matching_altered_outputs_fail_ntt_wiring() {
    for mode in [Mode::Forward, Mode::Inverse] {
        for attack in [
            Attack::WrongTwiddle,
            Attack::DetachedMultiplicand,
            Attack::WrongIndices,
            Attack::WrongStage,
            Attack::SkippedStageProgramCounter,
            Attack::DetachedMiddleState,
            Attack::DetachedFinalState,
            Attack::ModeMismatch,
            Attack::NoncanonicalPrivateState,
            Attack::PaddingProduct,
        ] {
            let (trace, statement) = attack_trace(mode, attack);
            assert!(!check_air(&trace, &statement), "{mode:?} {attack:?}");
        }
    }
    for attack in [
        Attack::OmittedNormalization,
        Attack::DetachedNormalizationOutput,
        Attack::FirstHalfCopy,
        Attack::SecondHalfCopy,
        Attack::UnusedNormalizationCarry,
    ] {
        let (trace, statement) = attack_trace(Mode::Inverse, attack);
        assert!(!check_air(&trace, &statement), "{attack:?}");
    }
}

#[test]
fn bytewise_public_polynomials_reject_field_modulus_aliases_in_the_air() {
    for mode in [Mode::Forward, Mode::Inverse] {
        for attack in [Attack::PublicInputAlias, Attack::PublicOutputAlias] {
            let (trace, statement) = attack_trace(mode, attack);
            assert!(!check_air(&trace, &statement), "{mode:?} {attack:?}");
        }
    }
}
