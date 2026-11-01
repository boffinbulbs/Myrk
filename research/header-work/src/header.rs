//! Fixed Zcash-format header work predicate, without chain acceptance authority.

use sha2::{Digest, Sha256};
use std::{cmp::Ordering, fmt};

pub const HEADER_BYTES: usize = 1487;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    Negative,
    Zero,
    Overflow,
}

/// Public diagnostic context. A node must derive these bits from prior state.
#[derive(Debug)]
pub struct ExpectedWork {
    bits: u32,
    target_le: [u8; 32],
}

impl ExpectedWork {
    pub fn new(bits: u32) -> Result<Self, TargetError> {
        Ok(Self {
            bits,
            target_le: expand_target(bits)?,
        })
    }
}

#[derive(Debug)]
pub enum WorkError {
    Length { actual: usize },
    Version { actual: i32 },
    SolutionFraming,
    UnexpectedTarget { expected: u32, actual: u32 },
    Equihash(equihash::Error),
    InsufficientWork,
}

impl fmt::Display for WorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => {
                write!(f, "expected {HEADER_BYTES} header bytes, got {actual}")
            }
            Self::Version { actual } => write!(f, "unsupported signed header version {actual}"),
            Self::SolutionFraming => f.write_str("noncanonical fixed solution framing"),
            Self::UnexpectedTarget { expected, actual } => {
                write!(f, "expected target bits {expected:08x}, got {actual:08x}")
            }
            Self::Equihash(error) => write!(f, "{error}"),
            Self::InsufficientWork => f.write_str("header hash exceeds expected target"),
        }
    }
}

// The no_std Equihash dependency exposes its original error through this enum,
// but does not implement std::error::Error without its unselected std feature.
impl std::error::Error for WorkError {}

fn expand_target(bits: u32) -> Result<[u8; 32], TargetError> {
    if bits & 0x0080_0000 != 0 {
        return Err(TargetError::Negative);
    }
    let mantissa = bits & 0x007f_ffff;
    let exponent = (bits >> 24) as usize;
    let mut bytes = [0; 32];
    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        bytes[..4].copy_from_slice(&value.to_le_bytes());
    } else {
        for (offset, byte) in mantissa.to_le_bytes()[..3].iter().enumerate() {
            if *byte != 0 {
                let position = exponent - 3 + offset;
                if position >= bytes.len() {
                    return Err(TargetError::Overflow);
                }
                bytes[position] = *byte;
            }
        }
    }
    if bytes == [0; 32] {
        return Err(TargetError::Zero);
    }
    Ok(bytes)
}

fn meets_target(hash_le: &[u8; 32], target_le: &[u8; 32]) -> bool {
    hash_le.iter().rev().cmp(target_le.iter().rev()) != Ordering::Greater
}

#[derive(Default)]
struct Invocations {
    equihash: usize,
    sha256d: usize,
}

/// Checks only fixed header work. The returned actual digest is not a receipt
/// for parent history, auxiliary child binding, stake eligibility or payment.
pub fn verify_header(header: &[u8], expected: &ExpectedWork) -> Result<[u8; 32], WorkError> {
    verify_counted(header, expected, &mut Invocations::default())
}

fn verify_counted(
    header: &[u8],
    expected: &ExpectedWork,
    calls: &mut Invocations,
) -> Result<[u8; 32], WorkError> {
    let header: &[u8; HEADER_BYTES] = header.try_into().map_err(|_| WorkError::Length {
        actual: header.len(),
    })?;
    let version = i32::from_le_bytes(header[..4].try_into().expect("fixed header slice"));
    if version < 4 {
        return Err(WorkError::Version { actual: version });
    }
    if header[140..143] != [0xfd, 0x40, 0x05] {
        return Err(WorkError::SolutionFraming);
    }
    let bits = u32::from_le_bytes(header[104..108].try_into().expect("fixed header slice"));
    if bits != expected.bits {
        return Err(WorkError::UnexpectedTarget {
            expected: expected.bits,
            actual: bits,
        });
    }
    calls.equihash += 1;
    equihash::is_valid_solution(200, 9, &header[..108], &header[108..140], &header[143..])
        .map_err(WorkError::Equihash)?;
    calls.sha256d += 1;
    let hash_le: [u8; 32] = Sha256::digest(Sha256::digest(header)).into();
    if !meets_target(&hash_le, &expected.target_le) {
        return Err(WorkError::InsufficientWork);
    }
    Ok(hash_le)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &[u8; 1692] = include_bytes!("../fixtures/mainnet-genesis.bin");
    const EXPECTED_BITS: u32 = 0x1f07_ffff;
    const EXPECTED_HASH_DISPLAY: &str =
        "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";

    fn display_hash(bytes: &[u8; 32]) -> String {
        bytes
            .iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    // Independent bit-by-bit test framing, not the dependency's array expander.
    fn read_index(solution: &[u8], index: usize) -> u32 {
        (0..21).fold(0, |value, bit| {
            let position = 21 * index + bit;
            (value << 1) | u32::from((solution[position / 8] >> (7 - position % 8)) & 1)
        })
    }

    fn write_index(solution: &mut [u8], index: usize, value: u32) {
        assert!(value < 1 << 21);
        for bit in 0..21 {
            let position = 21 * index + bit;
            let mask = 1 << (7 - position % 8);
            solution[position / 8] =
                (solution[position / 8] & !mask) | (((value >> (20 - bit)) as u8 & 1) * mask);
        }
    }

    fn metadata_refusal(header: &[u8], expected: &ExpectedWork, layer: &str) {
        let mut calls = Invocations::default();
        let error = verify_counted(header, expected, &mut calls).unwrap_err();
        assert!(match layer {
            "length" => matches!(error, WorkError::Length { .. }),
            "version" => matches!(error, WorkError::Version { .. }),
            "framing" => matches!(error, WorkError::SolutionFraming),
            "policy" => matches!(error, WorkError::UnexpectedTarget { .. }),
            _ => unreachable!(),
        });
        assert_eq!((calls.equihash, calls.sha256d), (0, 0));
    }

    fn actual_equihash_refusal(header: &[u8], expected: &ExpectedWork, cause: Option<&str>) {
        let mut calls = Invocations::default();
        let error = verify_counted(header, expected, &mut calls).unwrap_err();
        let WorkError::Equihash(actual) = error else {
            panic!("wrong layer: {error}")
        };
        if let Some(cause) = cause {
            assert!(actual.to_string().contains(cause), "{actual}");
        }
        assert_eq!((calls.equihash, calls.sha256d), (1, 0));
    }

    #[test]
    #[ignore = "finite guarded release diagnostic"]
    fn fixed_header_controls() {
        assert_eq!(
            std::env::var("KOVA_HEADER_WORK_ADMISSION").as_deref(),
            Ok("v72-fixed-header-1")
        );
        let expected = ExpectedWork::new(EXPECTED_BITS).unwrap();
        let header = &BLOCK[..HEADER_BYTES];
        let mut calls = Invocations::default();
        let hash = verify_counted(header, &expected, &mut calls).unwrap();
        assert_eq!(display_hash(&hash), EXPECTED_HASH_DISPLAY);
        assert_eq!((calls.equihash, calls.sha256d), (1, 1));
        assert_eq!(&header[..4], &[4, 0, 0, 0]);
        assert_eq!(&header[104..108], &[0xff, 0xff, 0x07, 0x1f]);

        for length in [0, 140, HEADER_BYTES - 1, HEADER_BYTES + 1, BLOCK.len()] {
            metadata_refusal(&BLOCK[..length], &expected, "length");
        }
        for version in [i32::MIN, -1, 0, 3] {
            let mut changed = header.to_vec();
            changed[..4].copy_from_slice(&version.to_le_bytes());
            metadata_refusal(&changed, &expected, "version");
        }
        for prefix in [
            [0x40, 0x05, 0],
            [0xfd, 0x3f, 0x05],
            [0xfe, 0x40, 0x05],
            [0xff, 0x40, 0x05],
        ] {
            let mut changed = header.to_vec();
            changed[140..143].copy_from_slice(&prefix);
            metadata_refusal(&changed, &expected, "framing");
        }
        let harder = ExpectedWork::new(0x1e07_ffff).unwrap();
        metadata_refusal(header, &harder, "policy");
        let mut changed = header.to_vec();
        changed[104] ^= 1;
        metadata_refusal(&changed, &expected, "policy");

        for (bits, low) in [
            (0x0112_3456, [0x12, 0, 0, 0]),
            (0x0212_3456, [0x34, 0x12, 0, 0]),
            (0x0312_3456, [0x56, 0x34, 0x12, 0]),
            (0x0412_3456, [0, 0x56, 0x34, 0x12]),
        ] {
            let target = expand_target(bits).unwrap();
            assert_eq!(&target[..4], &low);
            assert_eq!(&target[4..], &[0; 28]);
        }
        for (bits, suffix) in [
            (0x1f07_ffff, [0xff, 0xff, 7, 0]),
            (0x2100_ffff, [0, 0, 0xff, 0xff]),
            (0x2200_00ff, [0, 0, 0, 0xff]),
        ] {
            let target = expand_target(bits).unwrap();
            assert_eq!(&target[..28], &[0; 28]);
            assert_eq!(&target[28..], &suffix);
        }
        for (bits, error) in [
            (0x1f87_ffff, TargetError::Negative),
            (0, TargetError::Zero),
            (0x0100_0001, TargetError::Zero),
            (0x2200_0100, TargetError::Overflow),
            (0x2101_0000, TargetError::Overflow),
            (0x2300_0001, TargetError::Overflow),
            (0xff00_0001, TargetError::Overflow),
        ] {
            assert_eq!(ExpectedWork::new(bits).unwrap_err(), error);
        }
        let mut target = [0; 32];
        target[1] = 1;
        let mut below = [0; 32];
        below[0] = 0xff;
        let mut above = target;
        above[0] = 1;
        assert!(meets_target(&below, &target));
        assert!(meets_target(&target, &target));
        assert!(!meets_target(&above, &target));
        let mut reversed = target;
        reversed.reverse();
        assert!(!meets_target(&reversed, &target));
        assert!(!meets_target(&hash, &expand_target(0x0101_0000).unwrap()));

        // Saved 21-bit literal from the upstream encoding example, not a work solution.
        let literal = [
            0x00, 0x02, 0x20, 0x00, 0x0a, 0x7f, 0xff, 0xfe, 0x00, 0x12, 0x30, 0x22, 0xb3, 0x82,
            0x26, 0xac, 0x19, 0xbd, 0xf2, 0x34, 0x56,
        ];
        let literal_indices = [68, 41, 2097151, 291, 17767, 35243, 52719, 1193046];
        let mut restored_literal = [0; 21];
        for (index, value) in literal_indices.iter().enumerate() {
            assert_eq!(read_index(&literal, index), *value);
            write_index(&mut restored_literal, index, *value);
        }
        assert_eq!(restored_literal, literal);

        for position in [4, 100, 108, 139, 143, HEADER_BYTES - 1] {
            let mut changed = header.to_vec();
            changed[position] ^= 1;
            actual_equihash_refusal(&changed, &expected, None);
        }
        for version in [5_i32, i32::MAX] {
            let mut changed = header.to_vec();
            changed[..4].copy_from_slice(&version.to_le_bytes());
            actual_equihash_refusal(&changed, &expected, None);
        }
        let mut duplicate = header.to_vec();
        let first = read_index(&header[143..], 0);
        write_index(&mut duplicate[143..], 1, first);
        actual_equihash_refusal(&duplicate, &expected, Some("duplicate indices"));
        let second = read_index(&header[143..], 1);
        assert!(first < second);
        let mut reordered = header.to_vec();
        write_index(&mut reordered[143..], 0, second);
        write_index(&mut reordered[143..], 1, first);
        actual_equihash_refusal(&reordered, &expected, Some("incorrectly ordered"));
        let mut restored = reordered;
        write_index(&mut restored[143..], 0, first);
        write_index(&mut restored[143..], 1, second);
        assert_eq!(restored, header);
        assert_eq!(
            display_hash(&verify_header(&restored, &expected).unwrap()),
            EXPECTED_HASH_DISPLAY
        );
        println!(
            "HEADER_WORK_RESULT positives=2 metadata_refusals=15 target_literals=14 numeric_checks=5 equihash_refusals=10 encoding_literals=8"
        );
    }
}
