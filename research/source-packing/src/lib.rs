//! Small private packed-source mechanism. No signature or payment verifier.
#![forbid(unsafe_code)]

pub mod routes;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use routes::{Bank, WINDOWS, WORD_COUNT};

pub const HEIGHT: usize = 16;
pub const PORTS: usize = 48;
pub const CONSUMERS: usize = 136;
pub const CLOCK: usize = WORD_COUNT;
pub const BITS: usize = CLOCK + HEIGHT;
pub const OUTPUT: usize = BITS + PORTS * 24;
pub const WIDTH: usize = OUTPUT + CONSUMERS;
pub const RAW_BYTES: usize = HEIGHT * WIDTH * 4;
const _: () = assert!(WIDTH == 1364 && RAW_BYTES == 87296);
const _: () = assert!(WORD_COUNT <= 64 && WIDTH <= 2048 && RAW_BYTES <= 524288);

fn byte<AB: AirBuilder>(row: &[AB::Var], port: usize, byte: usize) -> AB::Expr {
    (0..8)
        .map(|bit| row[BITS + port * 24 + byte * 8 + bit] * AB::F::from_u32(1 << bit))
        .sum()
}

pub struct PackedSourceAir;
impl<F> BaseAir<F> for PackedSourceAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for PackedSourceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let mut clock_sum = AB::Expr::ZERO;
        for tick in 0..HEIGHT {
            let q = row[CLOCK + tick];
            builder.assert_bool(q);
            clock_sum += q.into();
            builder
                .when_first_row()
                .assert_eq(q, BabyBear::from_bool(tick == 0));
            let predecessor = if tick == 0 {
                AB::Expr::ZERO
            } else {
                row[CLOCK + tick - 1].into()
            };
            builder
                .when_transition()
                .assert_eq(next[CLOCK + tick], predecessor);
        }
        builder.assert_one(clock_sum);
        builder.when_last_row().assert_one(row[CLOCK + HEIGHT - 1]);
        for slot in 0..WORD_COUNT {
            builder.when_transition().assert_eq(next[slot], row[slot]);
        }
        for bit in &row[BITS..OUTPUT] {
            builder.assert_bool(*bit);
        }
        for port in 0..PORTS {
            let value = byte::<AB>(row, port, 0)
                + byte::<AB>(row, port, 1) * BabyBear::from_u32(256)
                + byte::<AB>(row, port, 2) * BabyBear::from_u32(65536);
            let selected: AB::Expr = WINDOWS
                .iter()
                .enumerate()
                .filter_map(|(tick, &window)| {
                    routes::port(window, port).map(|slot| row[CLOCK + tick] * row[slot])
                })
                .sum();
            builder.assert_eq(value, selected);
            for (tick, &window) in WINDOWS.iter().enumerate() {
                if let Some(slot) = routes::port(window, port) {
                    let word = routes::word(slot);
                    for offset in 0..3 {
                        if word.index * 3 + offset >= word.bank.len() {
                            builder
                                .when(row[CLOCK + tick])
                                .assert_zero(byte::<AB>(row, port, offset));
                        }
                    }
                }
            }
        }
        for index in 0..CONSUMERS {
            let selected: AB::Expr = WINDOWS
                .iter()
                .enumerate()
                .filter_map(|(tick, &window)| {
                    routes::consumer(window, index)
                        .map(|(port, offset)| row[CLOCK + tick] * byte::<AB>(row, port, offset))
                })
                .sum();
            builder.assert_eq(row[OUTPUT + index], selected);
        }
        // The selected last note byte is fixed by the canonical note framing.
        builder.when(row[CLOCK + 6]).assert_zero(row[OUTPUT]);
    }
}

pub struct Sources {
    key: [u8; 2592],
    signature: [u8; 4627],
    note: [u8; 418],
}
impl Sources {
    pub fn new(key: [u8; 2592], signature: [u8; 4627], note: [u8; 418]) -> Self {
        Self {
            key,
            signature,
            note,
        }
    }
    fn bytes(&self, bank: Bank) -> &[u8] {
        match bank {
            Bank::Key => &self.key,
            Bank::Signature => &self.signature,
            Bank::Note => &self.note,
        }
    }
    pub fn trace(&self) -> RowMajorMatrix<BabyBear> {
        const { assert!(HEIGHT <= 64 && WIDTH <= 2048 && RAW_BYTES <= 524288) };
        let packed: [u32; WORD_COUNT] = core::array::from_fn(|slot| {
            let word = routes::word(slot);
            let bytes = self.bytes(word.bank);
            (0..3)
                .map(|offset| {
                    u32::from(bytes.get(word.index * 3 + offset).copied().unwrap_or(0))
                        << (8 * offset)
                })
                .sum()
        });
        let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
        for (tick, row) in values.chunks_exact_mut(WIDTH).enumerate() {
            for slot in 0..WORD_COUNT {
                row[slot] = BabyBear::from_u32(packed[slot]);
            }
            row[CLOCK + tick] = BabyBear::ONE;
            if let Some(&window) = WINDOWS.get(tick) {
                for port in 0..PORTS {
                    if let Some(slot) = routes::port(window, port) {
                        for bit in 0..24 {
                            row[BITS + port * 24 + bit] =
                                BabyBear::from_bool((packed[slot] >> bit) & 1 != 0);
                        }
                    }
                }
                for index in 0..window.len {
                    row[OUTPUT + index] =
                        BabyBear::from_u8(self.bytes(window.bank)[window.first + index]);
                }
            }
        }
        RowMajorMatrix::new(values, WIDTH)
    }
}
