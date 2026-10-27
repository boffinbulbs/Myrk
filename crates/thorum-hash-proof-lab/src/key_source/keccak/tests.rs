use super::*;
use crate::key_source::air::{HEIGHT, KeySlotsAir, WIDTH, public_values, trace};
use crate::key_source::{Statement, Witness};
use core::borrow::BorrowMut;
use p3_air::{BaseAir, check_all_constraints};

// These deliberately weakened diagnostic builders are test only. The actual
// key segment always uses all four correct virtual transitions.
struct ModeBuilder<'a, AB, const SLOT: usize, const MODE: usize>(KeccakBuilder<'a, AB, SLOT>);
impl<AB: AirBuilder, const SLOT: usize, const MODE: usize> AirBuilder
    for ModeBuilder<'_, AB, SLOT, MODE>
{
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = KeccakWindow<AB::MainWindow, SLOT>;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    const WINDOW: usize = AB::WINDOW;
    fn main(&self) -> Self::MainWindow {
        self.0.main()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.0.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.0.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.0.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        if MODE == 0 {
            AB::Expr::ZERO
        } else {
            self.0.0.is_transition()
        }
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, v: I) {
        self.0.assert_zero(v);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.0.periodic_values()
    }
}
struct Diagnostic<const MODE: usize>;
impl<F, const MODE: usize> BaseAir<F> for Diagnostic<MODE> {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        64
    }
}
impl<AB: AirBuilder, const MODE: usize> Air<AB> for Diagnostic<MODE> {
    fn eval(&self, b: &mut AB) {
        KeccakAir {}.eval(&mut ModeBuilder::<_, 0, MODE>(KeccakBuilder(b)));
        KeccakAir {}.eval(&mut ModeBuilder::<_, 1, MODE>(KeccakBuilder(b)));
        KeccakAir {}.eval(&mut ModeBuilder::<_, 2, MODE>(KeccakBuilder(b)));
        KeccakAir {}.eval(&mut ModeBuilder::<_, 3, MODE>(KeccakBuilder(b)));
    }
}
#[test]
fn every_internal_join_remains_live_on_the_last_outer_row() {
    let w = Witness::from_keys(core::array::from_fn(|slot| {
        core::array::from_fn(|i| ((i * 17 + slot * 43 + 7) % 256) as u8)
    }));
    let original = trace(&w);
    let public = public_values(&Statement::new([0x61; 64]));
    let mut input = [0u64; 25];
    input[0] = 1;
    let alternate = generate_trace_rows::<BabyBear>(vec![input], 0);
    for start in [4093, 4094, 4095] {
        let mut changed = original.clone();
        for logical in start..4096 {
            let offset = (logical / 4) * WIDTH + (logical % 4) * NUM_KECCAK_COLS;
            let before = changed.values[offset..offset + NUM_KECCAK_COLS].to_vec();
            let prior: &KeccakCols<BabyBear> = before.as_slice().borrow();
            changed.values[offset..offset + NUM_KECCAK_COLS]
                .copy_from_slice(&alternate.row_slice(logical % 24).unwrap());
            let after: &mut KeccakCols<BabyBear> =
                changed.values[offset..offset + NUM_KECCAK_COLS].borrow_mut();
            after.preimage = prior.preimage;
        }
        assert!(
            check_all_constraints(&Diagnostic::<0>, &changed, &public, Some(1)).is_ok(),
            "individual rounds {start}"
        );
        assert!(
            check_all_constraints(&Diagnostic::<1>, &changed, &public, Some(1)).is_ok(),
            "incorrect outer masks miss join {start}"
        );
        assert!(
            !check_all_constraints(&KeySlotsAir, &changed, &public, Some(1)).is_ok(),
            "actual inner join {start}"
        );
    }
    assert_eq!(HEIGHT * 4, 4096);
}

#[test]
fn outer_row_join_rejects_a_locally_valid_padding_round_suffix() {
    let w = Witness::from_keys(core::array::from_fn(|slot| {
        core::array::from_fn(|i| ((i * 17 + slot * 43 + 7) % 256) as u8)
    }));
    let mut changed = trace(&w);
    let public = public_values(&Statement::new([0x61; 64]));
    let mut input = [0u64; 25];
    input[0] = 1;
    let alternate = generate_trace_rows::<BabyBear>(vec![input], 0);
    // Dummy permutation 116 has no live output consumers. Starting at round 4
    // breaks only its round 3 to round 4 outer-row state link.
    for logical in 2788..2808 {
        let offset = (logical / 4) * WIDTH + (logical % 4) * NUM_KECCAK_COLS;
        let before = changed.values[offset..offset + NUM_KECCAK_COLS].to_vec();
        let prior: &KeccakCols<BabyBear> = before.as_slice().borrow();
        changed.values[offset..offset + NUM_KECCAK_COLS]
            .copy_from_slice(&alternate.row_slice(logical % 24).unwrap());
        let after: &mut KeccakCols<BabyBear> =
            changed.values[offset..offset + NUM_KECCAK_COLS].borrow_mut();
        after.preimage = prior.preimage;
    }
    assert!(check_all_constraints(&Diagnostic::<0>, &changed, &public, Some(1)).is_ok());
    assert!(!check_all_constraints(&Diagnostic::<1>, &changed, &public, Some(1)).is_ok());
    assert!(!check_all_constraints(&KeySlotsAir, &changed, &public, Some(1)).is_ok());
}
