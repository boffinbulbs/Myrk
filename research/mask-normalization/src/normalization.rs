// Fixed public mask bank capture. This is not a production entropy source.
use p3_field::PrimeField32;
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn literal_bank_value(chunk: usize, row: usize, column: usize) -> BabyBear {
    if row == 0 && column == 0 {
        BabyBear::ZERO
    } else if row == 255 && column == 7 {
        BabyBear::from_u32(BabyBear::ORDER_U32 - 1)
    } else {
        BabyBear::from_u32((11 + 23 * chunk + 9 * row + 17 * column) as u32)
    }
}

fn save_normalization(name: &str, value: &Value, cap: usize) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= cap);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

/// Capture actual original normalizers and the same helper used by the adapter.
/// No PCS, owner, RNG, DFT, MMCS, verifier or proof constructor is called here.
pub fn fixed_normalization() -> Value {
    let domain = TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 11).unwrap();
    let domains = domain.split_domains(8);
    assert!(domains.iter().all(|d| d.size() == 256));
    let cis = get_zp_cis(&domains);
    assert_eq!(cis.len(), 8);
    let last_inverse = cis[7].inverse();
    let multipliers = (0..7).map(|i| cis[i] * last_inverse).collect::<Vec<_>>();
    let mut masks = vec![BabyBear::ZERO; 8 * 256 * 8];
    for chunk in 0..7 {
        for row in 0..256 {
            for column in 0..8 {
                masks[(chunk * 256 + row) * 8 + column] = literal_bank_value(chunk, row, column);
            }
        }
    }
    assert!(masks[7 * 256 * 8..].iter().all(|v| *v == BabyBear::ZERO));
    // Shape controls return before any coordinate update. Both compare every
    // stored input field against the original public bank after refusal.
    let before = masks.clone();
    assert_eq!(
        couple_mask_banks(&multipliers[..6], &mut masks),
        Err(CompositeError::Shape)
    );
    assert_eq!(masks, before);
    assert_eq!(
        couple_mask_banks(&multipliers, &mut masks[..8 * 256 * 8 - 1]),
        Err(CompositeError::Shape)
    );
    assert_eq!(masks, before);
    couple_mask_banks(&multipliers, &mut masks).unwrap();
    assert_eq!(&masks[..7 * 256 * 8], &before[..7 * 256 * 8]);
    let capture = json!({
        "format":"kova.mask-normalization.capture.v1", "recipe":"edge-affine-v1",
        "domains":domains.iter().map(|d| d.shift().as_canonical_u32()).collect::<Vec<_>>(),
        "normalizers":cis.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>(),
        "final_bank":masks[7 * 256 * 8..].iter().map(|v|v.as_canonical_u32()).collect::<Vec<_>>()
    });
    save_normalization("synthetic-capture.json", &capture, 65536);
    let measurement = json!({
        "normalizer_calls":1,"domains":8,"first_bank_fields":14336,"final_coordinates":2048,
        "coupled_updates":14336,"shape_refusals":2,"unchanged_input_fields_per_refusal":16384,
        "preserved_first_bank_fields":14336,"literal_zero_inputs":7,"literal_modulus_minus_one_inputs":7,
        "protocol_effects_scope":"Source inspected: no owner, RNG, DFT, MMCS, opening or proof constructors",
        "proofs":0,"scope":"Actual fixed normalization and coupled update helper, public synthetic banks"
    });
    save_normalization("measurement.json", &measurement, 16384);
    measurement
}
