//! Raw byte decoding and canonical auxiliary witness construction only.
use super::{bits, BuildError};
use crate::{layout::*, packing, sources, Witness, MODULUS};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

fn cuts(w: &Witness) -> [usize; 8] {
    core::array::from_fn(|i| usize::from(w.signature[4619 + i]))
}
fn word5(bytes: &[u8]) -> u64 {
    let mut encoded = [0u8; 8];
    encoded[..5].copy_from_slice(bytes);
    u64::from_le_bytes(encoded)
}

pub(super) fn preflight(w: &Witness) -> Result<(), BuildError> {
    for i in 0..418 {
        if sources::note_fixed(i).is_some_and(|expected| w.note[i] != expected) {
            return Err(BuildError::InvalidEncoding);
        }
    }
    for window in w.signature[64..4544].chunks_exact(5) {
        let encoded = word5(window);
        for coefficient in 0..2 {
            let d = ((encoded >> (20 * coefficient)) & 0xfffff) as u32;
            if !(121..=1_048_455).contains(&d) {
                return Err(BuildError::InvalidEncoding);
            }
        }
    }
    let cuts = cuts(w);
    let mut previous = 0;
    for cut in cuts {
        if cut < previous || cut > 75 {
            return Err(BuildError::InvalidEncoding);
        }
        let segment = &w.signature[4544 + previous..4544 + cut];
        if segment.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BuildError::InvalidEncoding);
        }
        previous = cut;
    }
    if w.signature[4544 + previous..4619]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(BuildError::InvalidEncoding);
    }
    Ok(())
}

pub(super) fn fill(values: &mut [BabyBear], w: &Witness) {
    let cuts = cuts(w);
    let mut t1 = [0u32; 2048];
    let mut z = [0u32; 1792];
    let mut hints = [[false; 256]; 8];
    let mut last = [0usize; 8];
    let mut seen = [false; 8];
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for (i, value) in t1.iter().enumerate() {
            row[T1 + i] = BabyBear::from_u32(*value);
        }
        for (i, value) in z.iter().enumerate() {
            row[Z_VALUES + i] = BabyBear::from_u32(*value);
        }
        for i in 0..8 {
            bits(row, CUTS + 7 * i, cuts[i] as u32, 7);
            bits(row, CUT_COMPLEMENTS + 7 * i, (75 - cuts[i]) as u32, 7);
            if i > 0 {
                bits(
                    row,
                    CUT_DIFFERENCES + 7 * (i - 1),
                    (cuts[i] - cuts[i - 1]) as u32,
                    7,
                );
            }
            bits(row, LAST + 8 * i, last[i] as u32, 8);
            row[SEEN + i] = BabyBear::from_bool(seen[i]);
            for k in 0..256 {
                row[HINTS + 256 * i + k] = BabyBear::from_bool(hints[i][k]);
            }
        }
        if at < 256 {
            let source = &w.key[32 + 10 * at..32 + 10 * at + 10];
            for (i, byte) in source.iter().enumerate() {
                bits(row, T1_MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            for window in 0..2 {
                let encoded = word5(&source[5 * window..5 * window + 5]);
                for coefficient in 0..4 {
                    t1[8 * at + 4 * window + coefficient] =
                        ((encoded >> (10 * coefficient)) & 1023) as u32;
                }
            }
        }
        if at < 448 {
            let source = &w.signature[64 + 10 * at..64 + 10 * at + 10];
            for (i, byte) in source.iter().enumerate() {
                bits(row, Z_MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            for window in 0..2 {
                let encoded = word5(&source[5 * window..5 * window + 5]);
                let base = Z_AUX + window * packing::Z_AUX_WIDTH;
                for coefficient in 0..2 {
                    let d = ((encoded >> (20 * coefficient)) & 0xfffff) as u32;
                    let normal = (524_288i64 - i64::from(d)).rem_euclid(i64::from(MODULUS)) as u32;
                    bits(row, base + packing::LOWER + 20 * coefficient, d - 121, 20);
                    bits(
                        row,
                        base + packing::UPPER + 20 * coefficient,
                        1_048_455 - d,
                        20,
                    );
                    bits(row, base + packing::NORMAL + 23 * coefficient, normal, 23);
                    bits(
                        row,
                        base + packing::COMPLEMENTS + 23 * coefficient,
                        MODULUS - 1 - normal,
                        23,
                    );
                    row[base + packing::NEGATIVE + coefficient] = BabyBear::from_bool(d > 524_288);
                    z[4 * at + 2 * window + coefficient] = normal;
                }
            }
        }
        if at < 75 {
            let index = usize::from(w.signature[4544 + at]);
            bits(row, HINT_MESSAGE, index as u32, 8);
            let active = at < cuts[7];
            row[HINT_ACTIVE] = BabyBear::from_bool(active);
            if active {
                bits(row, ACTIVE_UPPER, (cuts[7] - at - 1) as u32, 7);
            } else {
                bits(row, ACTIVE_LOWER, (at - cuts[7]) as u32, 7);
            }
            if active {
                let group = (0..8)
                    .find(|i| {
                        let previous = if *i == 0 { 0 } else { cuts[*i - 1] };
                        previous <= at && at < cuts[*i]
                    })
                    .unwrap();
                let previous = if group == 0 { 0 } else { cuts[group - 1] };
                row[GROUP + group] = BabyBear::ONE;
                row[ONE_HOT + index] = BabyBear::ONE;
                bits(row, SEGMENT_LOWER + 7 * group, (at - previous) as u32, 7);
                bits(
                    row,
                    SEGMENT_UPPER + 7 * group,
                    (cuts[group] - at - 1) as u32,
                    7,
                );
                if seen[group] {
                    bits(row, ORDER + 8 * group, (index - last[group] - 1) as u32, 8);
                }
                last[group] = index;
                seen[group] = true;
                hints[group][index] = true;
            }
        }
    }
}
