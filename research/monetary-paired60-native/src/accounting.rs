//! Bounded arithmetic for the prospective from-genesis paired profile.
//!
//! Inputs and outputs are unverified numeric data. No duties, destinations,
//! height ordering, lineage, proof, maturity or commit permission are checked.

use crate::retained_table::{PERIOD_SUBSIDIES_ATOMIC, SUBSIDY_TABLE_SHA256};
use std::{error::Error, fmt};

pub const PROFILE_ID: &str = "kova.monetary.paired60.v1";
pub const BLOCK_SECONDS: u64 = 60;
pub const PERIOD_BLOCKS: u64 = 43_800;
pub const CAP_ATOMS: u64 = 6_300_000_000_000_000;
pub const FIRST_TAIL_HEIGHT: u64 = 10_512_001;
pub const TABLE_TEXT_SHA256: &str = SUBSIDY_TABLE_SHA256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericError {
    Overflow,
    Underflow,
    IssuedAboveCap { issued: u64 },
    BurnedAboveIssued { issued: u64, burned: u64 },
    EarnedAboveBudget { earned: u64, budget: u64 },
    BurnAboveOutstanding { requested: u64, available: u64 },
}

impl fmt::Display for NumericError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

impl Error for NumericError {}

/// Any nonnegative u64 quantity. This type grants no value or ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnverifiedAmount(u64);

impl UnverifiedAmount {
    pub const ZERO: Self = Self(0);
    pub const fn from_atomic(value: u64) -> Self {
        Self(value)
    }
    pub const fn atomic(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, NumericError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or(NumericError::Overflow)
    }

    pub fn checked_sub(self, rhs: Self) -> Result<Self, NumericError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or(NumericError::Underflow)
    }
}

/// Four numeric budget amounts in miner, stake, pool, developer order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedAllocation([UnverifiedAmount; 4]);

impl UnverifiedAllocation {
    pub const fn miner(self) -> UnverifiedAmount {
        self.0[0]
    }
    pub const fn staking_budget(self) -> UnverifiedAmount {
        self.0[1]
    }
    pub const fn protocol_pool(self) -> UnverifiedAmount {
        self.0[2]
    }
    pub const fn developer(self) -> UnverifiedAmount {
        self.0[3]
    }
    pub fn atoms(self) -> [u64; 4] {
        self.0.map(UnverifiedAmount::atomic)
    }
}

pub fn paired_amounts(total: UnverifiedAmount) -> (UnverifiedAmount, UnverifiedAmount) {
    // The product is at most total/2, including u64::MAX.
    let first = (total.0 / 20) * 10;
    (UnverifiedAmount(first), UnverifiedAmount(total.0 - first))
}

pub fn planned_allocation(total: UnverifiedAmount) -> UnverifiedAllocation {
    let stake = total.0 / 5;
    let pool = total.0 / 10;
    // Equivalent to the four original floors with every remainder to the miner.
    let miner = total.0 - stake - 2 * pool;
    UnverifiedAllocation([miner, stake, pool, pool].map(UnverifiedAmount))
}

pub fn nominal_subsidy(height: u64) -> UnverifiedAmount {
    let Some(index) = height.checked_sub(1) else {
        return UnverifiedAmount::ZERO;
    };
    let period = index / PERIOD_BLOCKS;
    let old = if period < 240 {
        PERIOD_SUBSIDIES_ATOMIC[period as usize]
    } else {
        50_000_000
    };
    let pair = paired_amounts(UnverifiedAmount(old));
    if index & 1 == 0 { pair.0 } else { pair.1 }
}

/// Uncapped nominal sum. It is not cumulative authenticated issuance.
pub fn nominal_prefix(height: u64) -> Result<u128, NumericError> {
    let mut remaining = height / 2;
    let mut total = 0u128;
    for subsidy in PERIOD_SUBSIDIES_ATOMIC {
        let count = remaining.min(21_900);
        let amount = u128::from(count)
            .checked_mul(u128::from(subsidy))
            .ok_or(NumericError::Overflow)?;
        total = total.checked_add(amount).ok_or(NumericError::Overflow)?;
        remaining -= count;
        if remaining == 0 {
            break;
        }
    }
    let tail = u128::from(remaining)
        .checked_mul(50_000_000)
        .ok_or(NumericError::Overflow)?;
    total = total.checked_add(tail).ok_or(NumericError::Overflow)?;
    if height & 1 == 1 {
        total = total
            .checked_add(u128::from(nominal_subsidy(height).0))
            .ok_or(NumericError::Overflow)?;
    }
    Ok(total)
}

/// Caller-supplied totals. Invariants authenticate no history or chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedTotals {
    issued: UnverifiedAmount,
    burned: UnverifiedAmount,
}

impl UnverifiedTotals {
    pub const fn genesis() -> Self {
        Self {
            issued: UnverifiedAmount::ZERO,
            burned: UnverifiedAmount::ZERO,
        }
    }

    pub fn new(issued: UnverifiedAmount, burned: UnverifiedAmount) -> Result<Self, NumericError> {
        if issued.0 > CAP_ATOMS {
            return Err(NumericError::IssuedAboveCap { issued: issued.0 });
        }
        if burned > issued {
            return Err(NumericError::BurnedAboveIssued {
                issued: issued.0,
                burned: burned.0,
            });
        }
        Ok(Self { issued, burned })
    }

    pub const fn issued(self) -> UnverifiedAmount {
        self.issued
    }
    pub const fn burned(self) -> UnverifiedAmount {
        self.burned
    }
    pub const fn outstanding(self) -> UnverifiedAmount {
        UnverifiedAmount(self.issued.0 - self.burned.0)
    }
    pub const fn remaining(self) -> UnverifiedAmount {
        UnverifiedAmount(CAP_ATOMS - self.issued.0)
    }

    pub fn quote(self, height: u64) -> UnverifiedBudget {
        let nominal = nominal_subsidy(height);
        let capped = nominal.min(self.remaining());
        UnverifiedBudget {
            height,
            nominal,
            capped,
            allocation: planned_allocation(capped),
        }
    }

    /// Recompute the current numeric quote. No previous quote is an input.
    /// Caller-supplied earned atoms remain unverified duty data.
    pub fn issue(
        &mut self,
        height: u64,
        earned: UnverifiedAmount,
    ) -> Result<UnverifiedIssuance, NumericError> {
        let budget = self.quote(height);
        let allocation = budget.allocation;
        if earned > allocation.staking_budget() {
            return Err(NumericError::EarnedAboveBudget {
                earned: earned.0,
                budget: allocation.staking_budget().0,
            });
        }
        let actual = allocation
            .miner()
            .checked_add(allocation.protocol_pool())?
            .checked_add(allocation.developer())?
            .checked_add(earned)?;
        let unearned = allocation.staking_budget().checked_sub(earned)?;
        let next = Self::new(self.issued.checked_add(actual)?, self.burned)?;
        let result = UnverifiedIssuance {
            budget,
            earned,
            unearned,
            actual,
        };
        *self = next;
        Ok(result)
    }

    /// A separate numeric operation. An issue/burn sequence is not a DB transaction.
    pub fn burn(&mut self, amount: UnverifiedAmount) -> Result<(), NumericError> {
        if amount > self.outstanding() {
            return Err(NumericError::BurnAboveOutstanding {
                requested: amount.0,
                available: self.outstanding().0,
            });
        }
        let next = Self::new(self.issued, self.burned.checked_add(amount)?)?;
        *self = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedBudget {
    height: u64,
    nominal: UnverifiedAmount,
    capped: UnverifiedAmount,
    allocation: UnverifiedAllocation,
}

impl UnverifiedBudget {
    pub const fn height(self) -> u64 {
        self.height
    }
    pub const fn nominal(self) -> UnverifiedAmount {
        self.nominal
    }
    pub const fn capped(self) -> UnverifiedAmount {
        self.capped
    }
    pub const fn allocation(self) -> UnverifiedAllocation {
        self.allocation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedIssuance {
    budget: UnverifiedBudget,
    earned: UnverifiedAmount,
    unearned: UnverifiedAmount,
    actual: UnverifiedAmount,
}

impl UnverifiedIssuance {
    pub const fn budget(self) -> UnverifiedBudget {
        self.budget
    }
    pub const fn earned(self) -> UnverifiedAmount {
        self.earned
    }
    pub const fn unearned(self) -> UnverifiedAmount {
        self.unearned
    }
    pub const fn actual(self) -> UnverifiedAmount {
        self.actual
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
