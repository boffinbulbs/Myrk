use thorum_core::{
    planned_allocation, reward_block_index, scheduled_subsidy, AccountingError, Amount,
    AmountError, SupplyState, BLOCKS_PER_SUBSIDY_PERIOD, FIRST_LONG_TERM_HEIGHT, ISSUANCE_CAP,
    ISSUANCE_CAP_ATOMIC, LONG_TERM_SUBSIDY, PERIOD_SUBSIDIES_ATOMIC, SUBSIDY_PERIODS,
};

fn atoms(value: u64) -> Amount {
    Amount::from_atomic(value)
}

#[test]
fn genesis_has_no_issuance_or_reward_index() {
    let mut state = SupplyState::genesis();
    assert_eq!(state, SupplyState::default());
    assert_eq!(reward_block_index(0), None);
    assert_eq!(scheduled_subsidy(0), Amount::ZERO);
    let receipt = state.issue_block(0, Amount::ZERO).unwrap();
    assert_eq!(receipt.actual_issued(), Amount::ZERO);
    assert_eq!(state.cumulative_issued(), Amount::ZERO);
    assert_eq!(state.cumulative_burned(), Amount::ZERO);
    assert_eq!(state.outstanding(), Amount::ZERO);
    assert_eq!(state.remaining_issuance(), ISSUANCE_CAP);
    assert!(state.issue_block(0, atoms(1)).is_err());
    assert!(state.burn(atoms(1)).is_err());
    assert_eq!(state, SupplyState::genesis());
}

#[test]
fn every_period_boundary_uses_height_minus_one() {
    for (period, subsidy) in PERIOD_SUBSIDIES_ATOMIC.iter().enumerate() {
        let first_height = period as u64 * BLOCKS_PER_SUBSIDY_PERIOD + 1;
        let last_height = first_height + BLOCKS_PER_SUBSIDY_PERIOD - 1;
        assert_eq!(scheduled_subsidy(first_height), atoms(*subsidy));
        assert_eq!(scheduled_subsidy(last_height), atoms(*subsidy));
        assert_eq!(reward_block_index(first_height), Some(first_height - 1));
    }
    assert_eq!(scheduled_subsidy(1), atoms(1_600_000_000));
    assert_eq!(scheduled_subsidy(21_900), atoms(1_600_000_000));
    assert_eq!(scheduled_subsidy(21_901), atoms(1_577_061_117));
    assert_eq!(FIRST_LONG_TERM_HEIGHT, 5_256_001);
    assert_eq!(scheduled_subsidy(5_256_000), atoms(50_727_266));
    assert_eq!(scheduled_subsidy(5_256_001), LONG_TERM_SUBSIDY);
    assert_eq!(scheduled_subsidy(u64::MAX), LONG_TERM_SUBSIDY);
    assert_eq!(reward_block_index(u64::MAX), Some(u64::MAX - 1));
}

#[test]
fn frozen_table_matches_independent_exact_values_and_total() {
    assert_eq!(PERIOD_SUBSIDIES_ATOMIC.len() as u64, SUBSIDY_PERIODS);
    let checkpoints = [
        (0, 1_600_000_000),
        (1, 1_577_061_117),
        (47, 811_636_267),
        (48, 800_000_000),
        (49, 788_530_558),
        (95, 405_818_133),
        (96, 400_000_000),
        (143, 202_909_066),
        (144, 200_000_000),
        (191, 101_454_533),
        (192, 100_000_000),
        (238, 51_465_111),
        (239, 50_727_266),
    ];
    for (period, expected) in checkpoints {
        assert_eq!(PERIOD_SUBSIDIES_ATOMIC[period], expected);
    }
    assert!(PERIOD_SUBSIDIES_ATOMIC
        .windows(2)
        .all(|pair| pair[0] > pair[1]));
    let scheduled: u64 = PERIOD_SUBSIDIES_ATOMIC.iter().sum::<u64>() * BLOCKS_PER_SUBSIDY_PERIOD;
    assert_eq!(scheduled, 2_367_682_937_882_100);
}

#[test]
fn planned_split_conserves_every_table_entry_and_small_remainders() {
    for value in PERIOD_SUBSIDIES_ATOMIC
        .into_iter()
        .chain([0, 1, 2, 9, 10, 11, 50_000_000, u64::MAX])
        .chain(0..10_000)
    {
        let split = planned_allocation(atoms(value));
        let miner = split.miner().atomic();
        let stake = split.staking_budget().atomic();
        assert_eq!(miner as u128, u128::from(value) * 7 / 10);
        assert_eq!(miner.checked_add(stake), Some(value));
    }
    let split = planned_allocation(atoms(1_577_061_117));
    assert_eq!(split.miner(), atoms(1_103_942_781));
    assert_eq!(split.staking_budget(), atoms(473_118_336));
}

#[test]
fn actual_issuance_credits_only_earned_stake() {
    for earned in [0, 123_456_789, 480_000_000] {
        let mut state = SupplyState::genesis();
        let receipt = state.issue_block(1, atoms(earned)).unwrap();
        let budget = receipt.budget();
        assert_eq!(budget.height(), 1);
        assert_eq!(budget.scheduled(), atoms(1_600_000_000));
        assert_eq!(budget.capped(), atoms(1_600_000_000));
        assert_eq!(budget.miner(), atoms(1_120_000_000));
        assert_eq!(budget.staking_budget(), atoms(480_000_000));
        assert_eq!(receipt.earned_staking(), atoms(earned));
        assert_eq!(receipt.unearned_staking(), atoms(480_000_000 - earned));
        assert_eq!(receipt.actual_issued(), atoms(1_120_000_000 + earned));
        assert_eq!(state.outstanding(), receipt.actual_issued());
        assert_eq!(state.cumulative_issued(), receipt.actual_issued());
        assert_eq!(state.cumulative_burned(), Amount::ZERO);
        assert_eq!(
            state.remaining_issuance().atomic(),
            ISSUANCE_CAP_ATOMIC - receipt.actual_issued().atomic()
        );
    }
}

#[test]
fn invalid_stake_earning_is_rejected_without_mutation() {
    let mut state = SupplyState::new(atoms(500), atoms(100)).unwrap();
    let before = state;
    for earned in [480_000_001, u64::MAX] {
        assert!(matches!(
            state.issue_block(1, atoms(earned)),
            Err(AccountingError::StakeExceedsBudget { .. })
        ));
        assert_eq!(state, before);
    }
}

#[test]
fn near_cap_clips_before_allocating_and_can_reach_the_cap() {
    for remaining in [1, 2, 9, 10, 11, 49_999_999, 50_000_000, 50_000_001] {
        let mut state =
            SupplyState::new(atoms(ISSUANCE_CAP_ATOMIC - remaining), atoms(17)).unwrap();
        let budget = state.block_budget(u64::MAX);
        let capped = remaining.min(50_000_000);
        assert_eq!(budget.capped(), atoms(capped));
        assert_eq!(budget.miner().atomic(), capped * 7 / 10);
        let receipt = state
            .issue_block(u64::MAX, budget.staking_budget())
            .unwrap();
        assert_eq!(receipt.actual_issued(), atoms(capped));
        assert_eq!(
            state.cumulative_issued().atomic(),
            ISSUANCE_CAP_ATOMIC - remaining + capped
        );
        assert_eq!(state.cumulative_burned(), atoms(17));
        assert!(state.cumulative_issued() <= ISSUANCE_CAP);
    }
}

#[test]
fn final_atom_requires_earned_stake_and_never_redirects_to_miner() {
    let mut state = SupplyState::new(atoms(ISSUANCE_CAP_ATOMIC - 1), Amount::ZERO).unwrap();
    let budget = state.block_budget(1);
    assert_eq!(budget.capped(), atoms(1));
    assert_eq!(budget.miner(), Amount::ZERO);
    assert_eq!(budget.staking_budget(), atoms(1));
    let before = state;
    let unearned = state.issue_block(1, Amount::ZERO).unwrap();
    assert_eq!(unearned.actual_issued(), Amount::ZERO);
    assert_eq!(unearned.unearned_staking(), atoms(1));
    assert_eq!(state, before);
    let earned = state.issue_block(2, atoms(1)).unwrap();
    assert_eq!(earned.actual_issued(), atoms(1));
    assert_eq!(state.cumulative_issued(), ISSUANCE_CAP);
    assert_eq!(state.remaining_issuance(), Amount::ZERO);
}

#[test]
fn successive_partial_earnings_preserve_remaining_capacity_and_rounding() {
    let mut state = SupplyState::new(atoms(ISSUANCE_CAP_ATOMIC - 11), Amount::ZERO).unwrap();
    let first = state.issue_block(1, atoms(1)).unwrap();
    assert_eq!(first.budget().miner(), atoms(7));
    assert_eq!(first.unearned_staking(), atoms(3));
    assert_eq!(first.actual_issued(), atoms(8));
    assert_eq!(state.remaining_issuance(), atoms(3));
    state.burn(atoms(8)).unwrap();
    assert_eq!(state.remaining_issuance(), atoms(3));

    let second = state.issue_block(2, Amount::ZERO).unwrap();
    assert_eq!(second.actual_issued(), atoms(2));
    assert_eq!(state.remaining_issuance(), atoms(1));
    for height in 3..=5 {
        let stalled = state.issue_block(height, Amount::ZERO).unwrap();
        assert_eq!(stalled.actual_issued(), Amount::ZERO);
        assert_eq!(state.remaining_issuance(), atoms(1));
    }
    state.issue_block(6, atoms(1)).unwrap();
    assert_eq!(state.cumulative_issued(), ISSUANCE_CAP);
    assert_eq!(state.cumulative_burned(), atoms(8));
    assert_eq!(state.outstanding(), atoms(ISSUANCE_CAP_ATOMIC - 8));
}

#[test]
fn exhausted_cap_and_burns_never_reopen_minting_capacity() {
    let mut state = SupplyState::new(ISSUANCE_CAP, Amount::ZERO).unwrap();
    state.burn(atoms(1_000_000_000)).unwrap();
    assert_eq!(state.cumulative_issued(), ISSUANCE_CAP);
    assert_eq!(state.cumulative_burned(), atoms(1_000_000_000));
    assert_eq!(
        state.outstanding(),
        atoms(ISSUANCE_CAP_ATOMIC - 1_000_000_000)
    );
    assert_eq!(state.remaining_issuance(), Amount::ZERO);
    for height in [0, 1, FIRST_LONG_TERM_HEIGHT, u64::MAX] {
        let receipt = state.issue_block(height, Amount::ZERO).unwrap();
        assert_eq!(receipt.budget().capped(), Amount::ZERO);
        assert_eq!(receipt.actual_issued(), Amount::ZERO);
        assert!(state.issue_block(height, atoms(1)).is_err());
    }
    let remaining = state.outstanding();
    state.burn(remaining).unwrap();
    assert_eq!(state.cumulative_burned(), ISSUANCE_CAP);
    assert_eq!(state.outstanding(), Amount::ZERO);
    assert_eq!(state.remaining_issuance(), Amount::ZERO);
    assert!(state.burn(atoms(1)).is_err());
}

#[test]
fn overburn_and_malformed_restored_totals_are_errors() {
    assert!(matches!(
        SupplyState::new(atoms(ISSUANCE_CAP_ATOMIC + 1), Amount::ZERO),
        Err(AccountingError::IssuanceAboveCap { .. })
    ));
    assert!(matches!(
        SupplyState::new(atoms(u64::MAX), atoms(u64::MAX)),
        Err(AccountingError::IssuanceAboveCap { .. })
    ));
    assert!(matches!(
        SupplyState::new(atoms(1), atoms(2)),
        Err(AccountingError::BurnExceedsIssued { .. })
    ));
    let mut state = SupplyState::new(atoms(1_000), atoms(250)).unwrap();
    let before = state;
    state.burn(Amount::ZERO).unwrap();
    for amount in [751, u64::MAX] {
        assert!(matches!(
            state.burn(atoms(amount)),
            Err(AccountingError::InsufficientOutstanding { .. })
        ));
        assert_eq!(state, before);
    }
}

#[test]
fn budget_is_recomputed_after_state_changes() {
    let mut state = SupplyState::new(atoms(ISSUANCE_CAP_ATOMIC - 100), Amount::ZERO).unwrap();
    let earlier = state.block_budget(1);
    assert_eq!(earlier.staking_budget(), atoms(30));
    state.issue_block(1, earlier.staking_budget()).unwrap();
    let before = state;
    assert!(matches!(
        state.issue_block(2, earlier.staking_budget()),
        Err(AccountingError::StakeExceedsBudget { .. })
    ));
    assert_eq!(state, before);
}

#[test]
fn caller_must_prevent_duplicate_block_application() {
    let mut state = SupplyState::genesis();
    let first = state.issue_block(1, Amount::ZERO).unwrap();
    let second = state.issue_block(1, Amount::ZERO).unwrap();
    assert_eq!(first.actual_issued(), second.actual_issued());
    assert_eq!(
        state.cumulative_issued().atomic(),
        2 * first.actual_issued().atomic()
    );
}

#[test]
fn long_sequence_preserves_issued_burned_and_outstanding_conservation() {
    let mut state = SupplyState::genesis();
    let mut issued = 0_u64;
    let mut burned = 0_u64;
    for height in 1..=25_000 {
        let budget = state.block_budget(height);
        let earned = atoms(budget.staking_budget().atomic() / (height % 3 + 1));
        let receipt = state.issue_block(height, earned).unwrap();
        issued += receipt.actual_issued().atomic();
        assert_eq!(
            receipt.actual_issued().atomic() + receipt.unearned_staking().atomic(),
            budget.capped().atomic()
        );
        let burn = atoms(receipt.actual_issued().atomic() / 13);
        state.burn(burn).unwrap();
        burned += burn.atomic();
        assert_eq!(state.cumulative_issued(), atoms(issued));
        assert_eq!(state.cumulative_burned(), atoms(burned));
        assert_eq!(state.outstanding(), atoms(issued - burned));
        assert_eq!(
            state.remaining_issuance(),
            atoms(ISSUANCE_CAP_ATOMIC - issued)
        );
    }
}

#[test]
fn exact_decimal_amounts_round_trip_without_floating_point() {
    for (input, expected) in [
        ("0", 0),
        ("0001", 100_000_000),
        ("1.2", 120_000_000),
        ("0.00000001", 1),
        ("63000000.00000000", ISSUANCE_CAP_ATOMIC),
        ("184467440737.09551615", u64::MAX),
    ] {
        let value: Amount = input.parse().unwrap();
        assert_eq!(value, atoms(expected));
        assert_eq!(value.to_string().parse::<Amount>().unwrap(), value);
    }
    assert_eq!(atoms(1).to_string(), "0.00000001");
    assert_eq!(ISSUANCE_CAP.to_string(), "63000000.00000000");
}

#[test]
fn invalid_decimals_and_arithmetic_overflow_return_errors() {
    for malformed in [
        "", ".", ".1", "1.", "-1", "+1", " 1", "1 ", "1e2", "1_000", "1,0", "1.2.3", "NaN", "∞",
        "１",
    ] {
        assert_eq!(
            malformed.parse::<Amount>(),
            Err(AmountError::InvalidDecimal)
        );
    }
    for too_precise in ["0.000000001", "1.123456789"] {
        assert_eq!(
            too_precise.parse::<Amount>(),
            Err(AmountError::TooManyDecimals)
        );
    }
    for overflow in [
        "184467440737.09551616",
        "184467440738",
        "18446744073709551616",
    ] {
        assert_eq!(overflow.parse::<Amount>(), Err(AmountError::Overflow));
    }
    assert_eq!(
        atoms(u64::MAX).checked_add(atoms(1)),
        Err(AmountError::Overflow)
    );
    assert_eq!(
        Amount::ZERO.checked_sub(atoms(1)),
        Err(AmountError::Underflow)
    );
    assert_eq!(
        atoms(u64::MAX).checked_add(Amount::ZERO),
        Ok(atoms(u64::MAX))
    );
}
