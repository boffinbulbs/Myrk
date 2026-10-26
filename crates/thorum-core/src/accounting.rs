use core::fmt;

use crate::{planned_allocation, scheduled_subsidy, Allocation, Amount, AmountError, ISSUANCE_CAP};

/// Validated monetary totals, including all historically issued and burned atoms.
///
/// Invariants are `burned <= issued <= ISSUANCE_CAP` and
/// `outstanding = issued - burned`. Burns reduce outstanding supply but never
/// restore issuance capacity. Unearned reward budgets have never been issued.
///
/// Callers must authenticate restored totals and ensure that each accepted block
/// or burn is applied exactly once to the appropriate branch. This type does not
/// validate height ordering, branch membership, replay prevention, note ownership,
/// transaction conservation, or staking duty evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SupplyState {
    cumulative_issued: Amount,
    cumulative_burned: Amount,
}

impl SupplyState {
    pub const fn genesis() -> Self {
        Self {
            cumulative_issued: Amount::ZERO,
            cumulative_burned: Amount::ZERO,
        }
    }

    /// Check monetary invariants when restoring accounting totals.
    pub fn new(
        cumulative_issued: Amount,
        cumulative_burned: Amount,
    ) -> Result<Self, AccountingError> {
        if cumulative_issued > ISSUANCE_CAP {
            return Err(AccountingError::IssuanceAboveCap {
                issued: cumulative_issued,
            });
        }
        if cumulative_burned > cumulative_issued {
            return Err(AccountingError::BurnExceedsIssued {
                issued: cumulative_issued,
                burned: cumulative_burned,
            });
        }
        Ok(Self {
            cumulative_issued,
            cumulative_burned,
        })
    }

    pub const fn cumulative_issued(self) -> Amount {
        self.cumulative_issued
    }

    pub const fn cumulative_burned(self) -> Amount {
        self.cumulative_burned
    }

    /// Total outstanding supply. A ledger's balances, including locked balances,
    /// must sum to this after all transaction conservation checks.
    pub const fn outstanding(self) -> Amount {
        // Construction and every mutation preserve burned <= issued.
        Amount::from_atomic(self.cumulative_issued.atomic() - self.cumulative_burned.atomic())
    }

    pub const fn remaining_issuance(self) -> Amount {
        // Construction and every mutation preserve issued <= ISSUANCE_CAP.
        Amount::from_atomic(ISSUANCE_CAP.atomic() - self.cumulative_issued.atomic())
    }

    /// Clip the nominal subsidy to remaining issuance capacity, then split it.
    ///
    /// The cap is a ceiling, not a promise of exact issuance. With one atom of
    /// remaining capacity, the miner allocation is zero and the staking budget
    /// is one atom. If that atom is unearned, it remains unissued.
    pub fn block_budget(self, height: u64) -> BlockBudget {
        let scheduled = scheduled_subsidy(height);
        let capped = scheduled.min(self.remaining_issuance());
        BlockBudget {
            height,
            scheduled,
            capped,
            allocation: planned_allocation(capped),
        }
    }

    /// Credit the miner allocation plus only the staking amount actually earned.
    ///
    /// The caller must prove staking eligibility and duty evidence. The supplied
    /// earned amount must lie in `0..=staking_budget`. Unearned staking allocation
    /// is not credited to the miner, issued, or burned. Budgets are recomputed
    /// against the current totals. An earlier quote cannot authorize extra minting.
    /// Errors leave the state unchanged.
    pub fn issue_block(
        &mut self,
        height: u64,
        earned_staking: Amount,
    ) -> Result<BlockIssuance, AccountingError> {
        let budget = self.block_budget(height);
        if earned_staking > budget.staking_budget() {
            return Err(AccountingError::StakeExceedsBudget {
                earned: earned_staking,
                budget: budget.staking_budget(),
            });
        }

        let actual_issued = budget.miner().checked_add(earned_staking)?;
        let unearned_staking = budget.staking_budget().checked_sub(earned_staking)?;
        let next = Self::new(
            self.cumulative_issued.checked_add(actual_issued)?,
            self.cumulative_burned,
        )?;
        let issuance = BlockIssuance {
            budget,
            earned_staking,
            unearned_staking,
            actual_issued,
        };
        *self = next;
        Ok(issuance)
    }

    /// Destroy authorized outstanding supply without restoring issuance capacity.
    ///
    /// The caller must establish ownership and transaction conservation. Errors
    /// leave the state unchanged. Zero is a valid burn with no state change.
    pub fn burn(&mut self, amount: Amount) -> Result<(), AccountingError> {
        if amount > self.outstanding() {
            return Err(AccountingError::InsufficientOutstanding {
                requested: amount,
                available: self.outstanding(),
            });
        }
        let next = Self::new(
            self.cumulative_issued,
            self.cumulative_burned.checked_add(amount)?,
        )?;
        *self = next;
        Ok(())
    }
}

/// An immutable accounting quote, not evidence that a reward was earned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBudget {
    height: u64,
    scheduled: Amount,
    capped: Amount,
    allocation: Allocation,
}

impl BlockBudget {
    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn scheduled(self) -> Amount {
        self.scheduled
    }

    pub const fn capped(self) -> Amount {
        self.capped
    }

    pub const fn miner(self) -> Amount {
        self.allocation.miner()
    }

    pub const fn staking_budget(self) -> Amount {
        self.allocation.staking_budget()
    }
}

/// The allocation actually credited by one successful issuance transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockIssuance {
    budget: BlockBudget,
    earned_staking: Amount,
    unearned_staking: Amount,
    actual_issued: Amount,
}

impl BlockIssuance {
    pub const fn budget(self) -> BlockBudget {
        self.budget
    }

    pub const fn earned_staking(self) -> Amount {
        self.earned_staking
    }

    pub const fn unearned_staking(self) -> Amount {
        self.unearned_staking
    }

    pub const fn actual_issued(self) -> Amount {
        self.actual_issued
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingError {
    IssuanceAboveCap {
        issued: Amount,
    },
    BurnExceedsIssued {
        issued: Amount,
        burned: Amount,
    },
    StakeExceedsBudget {
        earned: Amount,
        budget: Amount,
    },
    InsufficientOutstanding {
        requested: Amount,
        available: Amount,
    },
    Amount(AmountError),
}

impl From<AmountError> for AccountingError {
    fn from(error: AmountError) -> Self {
        Self::Amount(error)
    }
}

impl fmt::Display for AccountingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuanceAboveCap { issued } => {
                write!(
                    f,
                    "cumulative issuance {issued} exceeds the THM issuance cap"
                )
            }
            Self::BurnExceedsIssued { issued, burned } => {
                write!(f, "cumulative burns {burned} exceed issuance {issued}")
            }
            Self::StakeExceedsBudget { earned, budget } => {
                write!(f, "earned staking amount {earned} exceeds budget {budget}")
            }
            Self::InsufficientOutstanding {
                requested,
                available,
            } => write!(
                f,
                "burn amount {requested} exceeds outstanding supply {available}"
            ),
            Self::Amount(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for AccountingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Amount(error) => Some(error),
            _ => None,
        }
    }
}
