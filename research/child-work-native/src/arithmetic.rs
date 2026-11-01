//! Exact prospective child work arithmetic over unverified public inputs.
//!
//! ASERT polynomial: Mark Lundeberg and Bitcoin Cash Node contributors.
//! Original notices and source identities are retained in licenses and provenance.

use std::{cmp::Ordering, error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticError {
    ZeroTarget,
    InitialAboveLimit,
    HeightExhausted,
    GenesisTimeMismatch,
    TimeDifferenceOutOfRange,
    UnsupportedSpacing,
    ZeroHeight,
    WindowLength,
    Overflow,
    Underflow,
}

impl fmt::Display for ArithmeticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ArithmeticError {}

/// Positive numeric target. Positivity supplies no history or policy authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedTarget256([u64; 4]);

impl UnverifiedTarget256 {
    pub fn from_le_bytes(bytes: [u8; 32]) -> Result<Self, ArithmeticError> {
        let mut words = [0; 4];
        for (i, word) in words.iter_mut().enumerate() {
            let mut part = [0; 8];
            part.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            *word = u64::from_le_bytes(part);
        }
        if words == [0; 4] {
            return Err(ArithmeticError::ZeroTarget);
        }
        Ok(Self(words))
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, word) in self.0.iter().enumerate() {
            bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn wide(self) -> Word320 {
        Word320([self.0[0], self.0[1], self.0[2], self.0[3], 0])
    }
}

/// Caller-owned numeric context. It authenticates no genesis, branch or rules.
#[derive(Debug, Clone, Copy)]
pub struct UnverifiedWorkContext {
    initial: UnverifiedTarget256,
    limit: UnverifiedTarget256,
    genesis_time: u64,
}

impl UnverifiedWorkContext {
    pub fn new(
        initial: UnverifiedTarget256,
        limit: UnverifiedTarget256,
        genesis_time: u64,
    ) -> Result<Self, ArithmeticError> {
        if initial.wide().compare(limit.wide()) == Ordering::Greater {
            return Err(ArithmeticError::InitialAboveLimit);
        }
        Ok(Self {
            initial,
            limit,
            genesis_time,
        })
    }

    /// Candidate time, candidate target and parent bits are deliberately absent.
    /// The supplied predecessor is public numeric data, not verified ancestry.
    pub fn expected_target(
        &self,
        predecessor_height: u64,
        predecessor_time: u64,
    ) -> Result<UnverifiedTarget256, ArithmeticError> {
        if predecessor_height == u64::MAX {
            return Err(ArithmeticError::HeightExhausted);
        }
        if predecessor_height == 0 {
            if predecessor_time != self.genesis_time {
                return Err(ArithmeticError::GenesisTimeMismatch);
            }
            return Ok(self.initial);
        }
        asert(
            self.initial,
            self.limit,
            i128::from(predecessor_time) - i128::from(self.genesis_time),
            predecessor_height - 1,
            60,
        )
    }
}

// The original spacing600 is private comparison scope. Public callers use60.
pub(crate) fn asert(
    initial: UnverifiedTarget256,
    limit: UnverifiedTarget256,
    dt: i128,
    dh: u64,
    spacing: u64,
) -> Result<UnverifiedTarget256, ArithmeticError> {
    if initial.wide().compare(limit.wide()) == Ordering::Greater {
        return Err(ArithmeticError::InitialAboveLimit);
    }
    if !(-i128::from(u64::MAX)..=i128::from(u64::MAX)).contains(&dt) {
        return Err(ArithmeticError::TimeDifferenceOutOfRange);
    }
    if spacing != 60 && spacing != 600 {
        return Err(ArithmeticError::UnsupportedSpacing);
    }
    // Admitted extremes keep this numerator below 2^91 in magnitude.
    let exponent = ((dt - i128::from(spacing) * (i128::from(dh) + 1)) * 65536) / 172800;
    let whole = exponent.div_euclid(65536);
    let fraction = exponent.rem_euclid(65536) as u128;
    let factor = (65536
        + ((((5127 * fraction + 971821376) * fraction + 195766423245049) * fraction + (1 << 47))
            >> 48)) as u64;
    let product = multiply_target(initial, factor);
    let shift = whole - 16;
    let bits = i128::from(product.bits());
    let value = if shift >= 0 {
        if bits + shift > 256 {
            return Ok(limit);
        }
        let mut shifted = product;
        // Here shift<=255. No attacker-sized loop or giant shift is possible.
        for _ in 0..shift as usize {
            shifted = shifted.shl_one()?;
        }
        shifted
    } else {
        if -shift >= bits {
            return Ok(UnverifiedTarget256([1, 0, 0, 0]));
        }
        product.shr((-shift) as usize)
    };
    if value.compare(limit.wide()) == Ordering::Greater {
        return Ok(limit);
    }
    // Scaling admission and comparison ensure the high limb is zero.
    Ok(UnverifiedTarget256([
        value.0[0], value.0[1], value.0[2], value.0[3],
    ]))
}

fn multiply_target(target: UnverifiedTarget256, factor: u64) -> Word320 {
    let mut result = [0; 5];
    let mut carry = 0u128;
    for (i, word) in target.0.iter().enumerate() {
        let product = u128::from(*word) * u128::from(factor) + carry;
        result[i] = product as u64;
        carry = product >> 64;
    }
    result[4] = carry as u64;
    Word320(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Word320(pub(crate) [u64; 5]);

impl Word320 {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    fn compare(self, rhs: Self) -> Ordering {
        self.0.iter().rev().cmp(rhs.0.iter().rev())
    }

    fn bits(self) -> u32 {
        for (i, word) in self.0.iter().enumerate().rev() {
            if *word != 0 {
                return (i as u32) * 64 + 64 - word.leading_zeros();
            }
        }
        0
    }

    fn add(self, rhs: Self) -> Result<Self, ArithmeticError> {
        let mut result = [0; 5];
        let mut carry = false;
        for (i, output) in result.iter_mut().enumerate() {
            let (first, a) = self.0[i].overflowing_add(rhs.0[i]);
            let (second, b) = first.overflowing_add(u64::from(carry));
            *output = second;
            carry = a || b;
        }
        if carry {
            Err(ArithmeticError::Overflow)
        } else {
            Ok(Self(result))
        }
    }

    fn sub(self, rhs: Self) -> Result<Self, ArithmeticError> {
        let mut result = [0; 5];
        let mut borrow = false;
        for (i, output) in result.iter_mut().enumerate() {
            let (first, a) = self.0[i].overflowing_sub(rhs.0[i]);
            let (second, b) = first.overflowing_sub(u64::from(borrow));
            *output = second;
            borrow = a || b;
        }
        if borrow {
            Err(ArithmeticError::Underflow)
        } else {
            Ok(Self(result))
        }
    }

    fn shl_one(self) -> Result<Self, ArithmeticError> {
        let mut result = [0; 5];
        let mut carry = 0;
        for (i, output) in result.iter_mut().enumerate() {
            *output = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        if carry != 0 {
            Err(ArithmeticError::Overflow)
        } else {
            Ok(Self(result))
        }
    }

    fn shr(self, shift: usize) -> Self {
        if shift >= 320 {
            return Self::ZERO;
        }
        let words = shift / 64;
        let bits = shift % 64;
        let mut result = [0; 5];
        for (i, output) in result.iter_mut().enumerate().take(5 - words) {
            *output = self.0[i + words] >> bits;
            if bits != 0 && i + words + 1 < 5 {
                *output |= self.0[i + words + 1] << (64 - bits);
            }
        }
        Self(result)
    }
}

/// Pure unsigned score contents. Arbitrary decoded values are not chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedWork320(Word320);

impl UnverifiedWork320 {
    pub const ZERO: Self = Self(Word320::ZERO);

    pub fn from_le_bytes(bytes: [u8; 40]) -> Self {
        let mut words = [0; 5];
        for (i, word) in words.iter_mut().enumerate() {
            let mut part = [0; 8];
            part.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            *word = u64::from_le_bytes(part);
        }
        Self(Word320(words))
    }

    pub fn to_le_bytes(self) -> [u8; 40] {
        let mut bytes = [0; 40];
        for (i, word) in self.0.0.iter().enumerate() {
            bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ArithmeticError> {
        self.0.add(rhs.0).map(Self)
    }

    pub fn compare_numeric(self, rhs: Self) -> Ordering {
        self.0.compare(rhs.0)
    }
}

/// Exact floor(2^256/(T+1)), not work verification or authenticated chain score.
pub fn unverified_work(target: UnverifiedTarget256) -> Result<UnverifiedWork320, ArithmeticError> {
    let denominator = target.wide().add(Word320::ONE)?;
    let mut remainder = Word320::ZERO;
    let mut quotient = Word320::ZERO;
    for bit in (0..257).rev() {
        remainder = remainder.shl_one()?;
        if bit == 256 {
            remainder.0[0] |= 1;
        }
        if remainder.compare(denominator) != Ordering::Less {
            remainder = remainder.sub(denominator)?;
            quotient.0[bit / 64] |= 1u64 << (bit % 64);
        }
    }
    Ok(UnverifiedWork320(quotient))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiedNumericTime {
    BelowOrEqualMedian,
    DeferMissingClock,
    DeferFuture,
    NumericallyEligible,
}

/// Literal numeric comparisons. The caller supplies no authenticated clock here.
pub fn classify_unverified_time(
    candidate_height: u64,
    candidate_time: u64,
    previous: &[u64],
    local_utc: Option<u64>,
) -> Result<UnverifiedNumericTime, ArithmeticError> {
    if candidate_height == 0 {
        return Err(ArithmeticError::ZeroHeight);
    }
    let count = candidate_height.min(11) as usize;
    if previous.len() != count {
        return Err(ArithmeticError::WindowLength);
    }
    let mut window = [0; 11];
    window[..count].copy_from_slice(previous);
    for i in 1..count {
        let mut j = i;
        while j > 0 && window[j] < window[j - 1] {
            window.swap(j, j - 1);
            j -= 1;
        }
    }
    if candidate_time <= window[count / 2] {
        return Ok(UnverifiedNumericTime::BelowOrEqualMedian);
    }
    let Some(utc) = local_utc else {
        return Ok(UnverifiedNumericTime::DeferMissingClock);
    };
    if u128::from(candidate_time) > u128::from(utc) + 7200 {
        return Ok(UnverifiedNumericTime::DeferFuture);
    }
    Ok(UnverifiedNumericTime::NumericallyEligible)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
