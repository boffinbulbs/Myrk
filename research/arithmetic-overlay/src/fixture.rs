//! Fixed saved independent literals. This module computes no expected arithmetic.
use super::{hints, layout::*, mul, schedule};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use serde::Deserialize;
use std::{fs::File, io::Read, path::PathBuf};

#[derive(Deserialize)]
pub struct Product {
    pub name: String,
    pub inputs: [u32; 2],
    pub result: u32,
    pub bits: Vec<u32>,
}
#[derive(Deserialize)]
pub struct Hint {
    pub name: String,
    pub input: u32,
    pub hint: u32,
    pub result: u32,
    pub bits: Vec<u32>,
}
#[derive(Deserialize)]
pub struct Fixture {
    pub products: Vec<Product>,
    pub hints: Vec<Hint>,
}

pub fn load() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures.json");
    let mut file = File::open(path).unwrap();
    assert!(file.metadata().unwrap().len() <= 65536);
    let mut bytes = Vec::new();
    file.by_ref().take(65537).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 65536);
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(fixture.products.len(), 8);
    assert_eq!(fixture.hints.len(), 8);
    for product in &fixture.products {
        assert_eq!(product.bits.len(), mul::WIDTH);
        assert!(product.bits.iter().all(|b| *b <= 1));
    }
    for hint in &fixture.hints {
        assert_eq!(hint.bits.len(), hints::WIDTH);
        assert!(hint.bits.iter().all(|b| *b <= 1));
    }
    fixture
}

pub fn fixed_trace(fixture: &Fixture) -> (RowMajorMatrix<BabyBear>, Vec<BabyBear>, [usize; 3]) {
    let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    let mut product_sink = [0; 8];
    let mut hint_sink = [0; 8];
    let mut modes = [0; 3];
    for (pc, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        row[pc % LOW] = BabyBear::ONE;
        row[LOW + pc / LOW] = BabyBear::ONE;
        let (product, hint) = schedule::modes_at(pc);
        row[PRODUCT_MODE] = BabyBear::from_bool(product);
        row[HINT_MODE] = BabyBear::from_bool(hint);
        modes[if product {
            0
        } else if hint {
            1
        } else {
            2
        }] += 1;
        for slot in 0..8 {
            let source = SOURCE + 4 * slot;
            for (index, value) in [
                fixture.products[slot].inputs[0],
                fixture.products[slot].inputs[1],
                fixture.hints[slot].input,
                fixture.hints[slot].hint,
            ]
            .into_iter()
            .enumerate()
            {
                row[source + index] = BabyBear::from_u32(value);
            }
            row[PRODUCT_SINK + slot] = BabyBear::from_u32(product_sink[slot]);
            row[HINT_SINK + slot] = BabyBear::from_u32(hint_sink[slot]);
            if product {
                for (bit, value) in fixture.products[slot].bits.iter().enumerate() {
                    row[BANK + slot * mul::WIDTH + bit] = BabyBear::from_u32(*value);
                }
                product_sink[slot] = fixture.products[slot].result;
            } else if hint {
                for (bit, value) in fixture.hints[slot].bits.iter().enumerate() {
                    row[BANK + slot * hints::WIDTH + bit] = BabyBear::from_u32(*value);
                }
                hint_sink[slot] = fixture.hints[slot].result;
            }
        }
    }
    let public = fixture
        .products
        .iter()
        .map(|p| p.result)
        .chain(fixture.hints.iter().map(|h| h.result))
        .map(BabyBear::from_u32)
        .collect();
    (RowMajorMatrix::new(values, WIDTH), public, modes)
}
