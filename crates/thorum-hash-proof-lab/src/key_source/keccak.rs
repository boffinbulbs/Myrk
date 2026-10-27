use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::Matrix;

#[cfg(test)]
mod tests;
// Each virtual row sees one pinned Keccak block. Internal slots advance
// on every physical row, including the last. Only slot three ends outward.
#[derive(Clone)]
struct KeccakWindow<W, const SLOT: usize>(W);
impl<T, W: WindowAccess<T>, const SLOT: usize> WindowAccess<T> for KeccakWindow<W, SLOT> {
    fn current_slice(&self) -> &[T] {
        &self.0.current_slice()[SLOT * NUM_KECCAK_COLS..(SLOT + 1) * NUM_KECCAK_COLS]
    }
    fn next_slice(&self) -> &[T] {
        if SLOT < 3 {
            &self.0.current_slice()[(SLOT + 1) * NUM_KECCAK_COLS..(SLOT + 2) * NUM_KECCAK_COLS]
        } else {
            &self.0.next_slice()[..NUM_KECCAK_COLS]
        }
    }
}
struct KeccakBuilder<'a, AB, const SLOT: usize>(&'a mut AB);
impl<AB: AirBuilder, const SLOT: usize> AirBuilder for KeccakBuilder<'_, AB, SLOT> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = KeccakWindow<AB::MainWindow, SLOT>;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    const WINDOW: usize = AB::WINDOW;
    fn main(&self) -> Self::MainWindow {
        KeccakWindow(self.0.main())
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.0.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        if SLOT == 0 {
            self.0.is_first_row()
        } else {
            AB::Expr::ZERO
        }
    }
    fn is_last_row(&self) -> Self::Expr {
        if SLOT == 3 {
            self.0.is_last_row()
        } else {
            AB::Expr::ZERO
        }
    }
    fn is_transition(&self) -> Self::Expr {
        if SLOT < 3 {
            AB::Expr::ONE
        } else {
            self.0.is_transition()
        }
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.0.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.0.periodic_values()
    }
}

pub(crate) fn eval<AB: AirBuilder>(builder: &mut AB) {
    KeccakAir {}.eval(&mut KeccakBuilder::<_, 0>(builder));
    KeccakAir {}.eval(&mut KeccakBuilder::<_, 1>(builder));
    KeccakAir {}.eval(&mut KeccakBuilder::<_, 2>(builder));
    KeccakAir {}.eval(&mut KeccakBuilder::<_, 3>(builder));
}

pub(crate) fn state_after(input: [u64; 25]) -> [u64; 25] {
    let trace = generate_trace_rows::<BabyBear>(vec![input], 0);
    let row = trace.row_slice(23).unwrap();
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
