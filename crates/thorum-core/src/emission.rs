use crate::{Amount, PERIOD_SUBSIDIES_ATOMIC};

pub const TICKER: &str = "THM";
pub const ATOMIC_DECIMALS: u32 = 8;
pub const ATOMIC_UNITS_PER_THM: u64 = 100_000_000;
pub const BLOCK_TARGET_SECONDS: u64 = 120;
pub const BLOCKS_PER_SUBSIDY_PERIOD: u64 = 21_900;
pub const SUBSIDY_PERIODS: u64 = 240;
pub const ISSUANCE_CAP_ATOMIC: u64 = 63_000_000 * ATOMIC_UNITS_PER_THM;
pub const ISSUANCE_CAP: Amount = Amount::from_atomic(ISSUANCE_CAP_ATOMIC);
pub const LONG_TERM_SUBSIDY: Amount = Amount::from_atomic(50_000_000);
pub const FIRST_LONG_TERM_HEIGHT: u64 = SUBSIDY_PERIODS * BLOCKS_PER_SUBSIDY_PERIOD + 1;

/// The reward index is `height - 1`. Genesis has no reward index.
pub const fn reward_block_index(height: u64) -> Option<u64> {
    height.checked_sub(1)
}

/// Nominal subsidy before the issuance cap or unearned staking allocation.
///
/// Height zero is genesis and pays zero. For other heights, the period is
/// `floor((height - 1) / 21_900)`. Periods 0 through 239 use the frozen table
/// `floor(16 * 10^8 * 2^(-period/48))`. Subsequent periods use 50,000,000 atoms.
/// The table avoids floating point arithmetic and rounding that depends on the platform.
pub fn scheduled_subsidy(height: u64) -> Amount {
    match reward_block_index(height) {
        None => Amount::ZERO,
        Some(index) => {
            let period = index / BLOCKS_PER_SUBSIDY_PERIOD;
            if period < SUBSIDY_PERIODS {
                Amount::from_atomic(PERIOD_SUBSIDIES_ATOMIC[period as usize])
            } else {
                LONG_TERM_SUBSIDY
            }
        }
    }
}

/// Planned 70/30 allocation of a capped subsidy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    miner: Amount,
    staking_budget: Amount,
}

impl Allocation {
    pub const fn miner(self) -> Amount {
        self.miner
    }

    pub const fn staking_budget(self) -> Amount {
        self.staking_budget
    }
}

/// Allocate `floor(7 * subsidy / 10)` to the miner and the remainder to staking.
///
/// Widening the multiplication permits every `u64` amount without overflow.
pub fn planned_allocation(subsidy: Amount) -> Allocation {
    let miner = (u128::from(subsidy.atomic()) * 7 / 10) as u64;
    Allocation {
        miner: Amount::from_atomic(miner),
        staking_budget: Amount::from_atomic(subsidy.atomic() - miner),
    }
}
