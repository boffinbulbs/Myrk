//! Unverified reward age arithmetic over numeric height inputs.
//!
//! These functions do not authenticate reward class, origin, ancestry, finality,
//! unspentness or private proof validity. A numeric result is not spendability or
//! commit permission. Hidden origins must remain inside the local private witness
//! boundary. A validator cannot request them to replace the complete private proof.
//! The distance and error category also depend on the inputs. A positive distance
//! and known consuming height determine the origin. Keep these results inside the
//! same authorized private boundary, outside public RPC and logs.

use core::fmt;

const REWARD_MATURITY_BLOCKS: u64 = 10_080;

/// Remaining blocks at the consuming successor of the supplied numeric parent.
///
/// The successor and age use checked arithmetic, in that order. Zero means only
/// that the numeric age is at least 10080. A positive distance at the last possible
/// candidate height does not imply that another successor exists.
///
/// This fixed arithmetic fragment does not select a production rule set, assign
/// an origin class or apply the reward rule to principal or other allocation types.
pub fn unverified_reward_blocks_remaining(
    parent_height: u64,
    reward_origin: u64,
) -> Result<u64, RewardHeightError> {
    let candidate_height = parent_height
        .checked_add(1)
        .ok_or(RewardHeightError::HeightExhausted)?;
    let age = candidate_height
        .checked_sub(reward_origin)
        .ok_or(RewardHeightError::OriginAfterCandidate)?;
    if age < REWARD_MATURITY_BLOCKS {
        Ok(REWARD_MATURITY_BLOCKS - age)
    } else {
        Ok(0)
    }
}

/// Numeric failures without an embedded origin or parent height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewardHeightError {
    HeightExhausted,
    OriginAfterCandidate,
}

impl fmt::Display for RewardHeightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeightExhausted => "numeric parent height has no successor",
            Self::OriginAfterCandidate => "numeric reward origin exceeds the consuming height",
        })
    }
}

impl std::error::Error for RewardHeightError {}
