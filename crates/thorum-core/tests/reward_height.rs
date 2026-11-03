use thorum_core::{unverified_reward_blocks_remaining, RewardHeightError};

// Public integer fixtures only. These do not describe authenticated chain history.

#[test]
fn consuming_height_uses_the_successor() {
    assert_eq!(unverified_reward_blocks_remaining(10178, 100), Ok(1));
    assert_eq!(unverified_reward_blocks_remaining(10179, 100), Ok(0));
    assert_eq!(unverified_reward_blocks_remaining(10180, 100), Ok(0));
}

#[test]
fn creation_height_has_zero_age() {
    assert_eq!(unverified_reward_blocks_remaining(99, 100), Ok(10080));
    assert_eq!(unverified_reward_blocks_remaining(0, 1), Ok(10080));
    assert_eq!(unverified_reward_blocks_remaining(0, 0), Ok(10079));
}

#[test]
fn future_origins_are_refused() {
    assert_eq!(
        unverified_reward_blocks_remaining(98, 100),
        Err(RewardHeightError::OriginAfterCandidate)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(0, 2),
        Err(RewardHeightError::OriginAfterCandidate)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551613, 18446744073709551615),
        Err(RewardHeightError::OriginAfterCandidate)
    );
}

#[test]
fn exhausted_parent_is_refused_before_origin_checks() {
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551615, 0),
        Err(RewardHeightError::HeightExhausted)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551615, 100),
        Err(RewardHeightError::HeightExhausted)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551615, 18446744073709551615),
        Err(RewardHeightError::HeightExhausted)
    );
}

#[test]
fn maximum_age_does_not_need_an_origin_plus_delay_sum() {
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551614, 0),
        Ok(0)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551614, 18446744073709551615),
        Ok(10080)
    );
}

#[test]
fn last_candidate_retains_the_exact_maturity_boundary() {
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551614, 18446744073709541535),
        Ok(0)
    );
    assert_eq!(
        unverified_reward_blocks_remaining(18446744073709551614, 18446744073709541536),
        Ok(1)
    );
}

#[test]
fn lower_candidate_recomputes_the_numeric_distance() {
    assert_eq!(unverified_reward_blocks_remaining(10179, 100), Ok(0));
    assert_eq!(unverified_reward_blocks_remaining(10178, 100), Ok(1));
    assert_eq!(unverified_reward_blocks_remaining(10179, 100), Ok(0));
}
