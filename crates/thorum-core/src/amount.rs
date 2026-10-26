use core::fmt;
use core::str::FromStr;

use crate::ATOMIC_UNITS_PER_THM;

/// A nonnegative quantity of atomic units.
///
/// An amount is not evidence of issuance or ownership. It can represent any
/// `u64` quantity. [`crate::SupplyState`] separately enforces the issuance cap.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);

    pub const fn from_atomic(atomic: u64) -> Self {
        Self(atomic)
    }

    pub const fn atomic(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AmountError::Underflow)
    }
}

/// Exact THM display with eight fractional digits and no unit suffix.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:08}",
            self.0 / ATOMIC_UNITS_PER_THM,
            self.0 % ATOMIC_UNITS_PER_THM
        )
    }
}

/// Parse an unsigned THM decimal with zero to eight fractional digits.
///
/// A decimal point requires digits on both sides. Signs, whitespace, exponent
/// notation, separators, digits outside ASCII, and rounding are not accepted.
impl FromStr for Amount {
    type Err = AmountError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(AmountError::InvalidDecimal);
        }
        let (whole, fraction) = match input.split_once('.') {
            Some((whole, fraction)) => {
                if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(AmountError::InvalidDecimal);
                }
                if fraction.len() > 8 {
                    return Err(AmountError::TooManyDecimals);
                }
                (whole, Some(fraction))
            }
            None => (input, None),
        };

        let whole = parse_digits(whole)?;
        let whole_atomic = whole
            .checked_mul(ATOMIC_UNITS_PER_THM)
            .ok_or(AmountError::Overflow)?;
        let fractional_atomic = match fraction {
            Some(digits) => {
                let value = parse_digits(digits)?;
                // The fractional length was bounded above, so the power is at most 8.
                value
                    .checked_mul(10_u64.pow(8 - digits.len() as u32))
                    .ok_or(AmountError::Overflow)?
            }
            None => 0,
        };
        whole_atomic
            .checked_add(fractional_atomic)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }
}

fn parse_digits(input: &str) -> Result<u64, AmountError> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::InvalidDecimal);
    }
    input.bytes().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(AmountError::Overflow)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountError {
    InvalidDecimal,
    TooManyDecimals,
    Overflow,
    Underflow,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDecimal => "expected an unsigned THM decimal",
            Self::TooManyDecimals => "THM amounts allow at most eight fractional digits",
            Self::Overflow => "amount exceeds the atomic unit range",
            Self::Underflow => "amount subtraction would be negative",
        })
    }
}

impl std::error::Error for AmountError {}
