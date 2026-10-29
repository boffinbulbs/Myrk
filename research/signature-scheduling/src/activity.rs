//! Activity is a constrained intermediate value from the actual private state.
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn bind<AB: AirBuilder>(
    builder: &mut AB,
    cached: AB::Var,
    phase: AB::Expr,
    completed: AB::Var,
) -> AB::Expr {
    builder.assert_bool(cached);
    builder.assert_eq(cached, phase * (AB::Expr::ONE - completed));
    cached.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_air::{check_all_constraints, Air, BaseAir, WindowAccess};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    // Mode one deliberately omits the producer relation as a negative control.
    struct GateAir(u8);
    impl<F> BaseAir<F> for GateAir {
        fn width(&self) -> usize {
            6
        }
    }
    impl<AB: AirBuilder<F = BabyBear>> Air<AB> for GateAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let row = main.current_slice();
            for value in &row[..3] {
                builder.assert_bool(*value);
            }
            let low: AB::Expr = row[0].into();
            let phase = low * row[1];
            let source = phase.clone() * row[4];
            let active = match self.0 {
                0 => phase * (AB::Expr::ONE - row[2]),
                1 => row[3].into(),
                2 => bind(builder, row[3], phase, row[2]),
                _ => unreachable!(),
            };
            builder.when(active).assert_eq(row[5], source);
        }
    }

    fn accepts(mode: u8, row: [BabyBear; 6]) -> bool {
        let data = row.into_iter().chain(row).collect();
        check_all_constraints(&GateAir(mode), &RowMajorMatrix::new(data, 6), &[], Some(1)).is_ok()
    }

    #[test]
    fn bound_activity_truth_table_and_corruption() {
        for low in [0, 1] {
            for high in [0, 1] {
                for done in [0, 1] {
                    let active = low * high * (1 - done);
                    let mut row =
                        [low, high, done, active, 7, low * high * 7].map(BabyBear::from_u32);
                    assert!(accepts(0, row));
                    assert!(accepts(2, row));
                    row[3] = BabyBear::ONE - row[3];
                    assert!(!accepts(2, row));
                    row[3] = BabyBear::from_u32(active);
                    assert!(accepts(2, row));
                }
            }
        }
    }

    #[test]
    fn detached_activity_cannot_hide_a_false_source() {
        let row = [1, 1, 0, 0, 7, 8].map(BabyBear::from_u32);
        assert!(accepts(1, row));
        assert!(!accepts(2, row));
        assert!(!accepts(0, row));
    }

    #[test]
    fn constrained_intermediate_keeps_the_source_gate_at_degree_four() {
        let degree = |mode| {
            let air = GateAir(mode);
            get_symbolic_constraints::<BabyBear, _>(&air, AirLayout::from_air::<BabyBear>(&air))
                .iter()
                .map(|value| value.degree_multiple())
                .max()
                .unwrap()
        };
        assert_eq!(degree(0), 6);
        assert_eq!(degree(2), 4);
    }
}
