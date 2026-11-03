//! Integer monetary accounting for Myrk development parameters.
//!
//! This crate implements an issuance ceiling, a frozen subsidy schedule, planned
//! reward allocation, and cumulative burns. All monetary calculations use atomic
//! units. One THM contains 100,000,000 atomic units.
//! The allocation profile is 60/20/10/10 for miner, staking, protocol pool and
//! development maintenance budgets. Every atomic rounding remainder goes to the
//! miner. Required pool and development credits count as issued immediately.
//! Unearned stake remains unissued. No development sunset height is defined.
//!
//! [`SupplyState`] is an accounting component, not a chain or transaction validator.
//! Its caller must establish valid height ordering, branch membership, replay
//! prevention, note ownership, transaction conservation, and evidence that staking
//! rewards were earned. No networking, proof system, or staking cryptography is
//! implemented here. Constructing a state from totals checks monetary invariants.
//! It does not authenticate the history that produced them.
//! The caller must also bind required allocation credits to valid ledger outputs
//! and destinations. Accounting does not create fund wallets or spending authority.

#![forbid(unsafe_code)]

mod accounting;
mod amount;
mod emission;
mod reward_height;
mod table;

pub use accounting::{AccountingError, BlockBudget, BlockIssuance, SupplyState};
pub use amount::{Amount, AmountError};
pub use emission::{
    planned_allocation, reward_block_index, scheduled_subsidy, Allocation, ATOMIC_DECIMALS,
    ATOMIC_UNITS_PER_THM, BLOCKS_PER_SUBSIDY_PERIOD, BLOCK_TARGET_SECONDS, FIRST_LONG_TERM_HEIGHT,
    ISSUANCE_CAP, ISSUANCE_CAP_ATOMIC, LONG_TERM_SUBSIDY, SUBSIDY_PERIODS, TICKER,
};
pub use reward_height::{unverified_reward_blocks_remaining, RewardHeightError};
pub use table::{PERIOD_SUBSIDIES_ATOMIC, SUBSIDY_TABLE_SHA256};
