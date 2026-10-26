//! Check Rust accounting against the independent exact integer reference model.

use thorum_core::{
    reward_block_index, scheduled_subsidy, Amount, SupplyState, PERIOD_SUBSIDIES_ATOMIC,
};

const GOLDEN: &str = include_str!("../../../research/emission/golden_vectors.csv");
const SCHEDULE: &str = include_str!("../../../research/emission/schedule.csv");

#[test]
fn independent_schedule_matches_every_frozen_entry_and_height() {
    let mut lines = SCHEDULE.lines();
    assert_eq!(
        lines.next(),
        Some("period,first_reward_block_index,last_reward_block_index,first_paid_height,last_paid_height,reward_atoms,reward_coins")
    );
    let mut rows = 0;
    for (period, line) in lines.enumerate() {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 7);
        let value = |column: usize| fields[column].parse::<u64>().unwrap();
        assert_eq!(value(0), period as u64);
        let subsidy = Amount::from_atomic(value(5));
        assert_eq!(PERIOD_SUBSIDIES_ATOMIC[period], value(5));
        assert_eq!(scheduled_subsidy(value(3)), subsidy);
        assert_eq!(scheduled_subsidy(value(4)), subsidy);
        assert_eq!(reward_block_index(value(3)), Some(value(1)));
        assert_eq!(reward_block_index(value(4)), Some(value(2)));
        assert_eq!(fields[6].parse::<Amount>().unwrap(), subsidy);
        rows += 1;
    }
    assert_eq!(rows, 240);
}

#[test]
fn independent_golden_transitions_match_all_accounting_outputs() {
    let mut lines = GOLDEN.lines();
    assert_eq!(
        lines.next(),
        Some("id,height,reward_block_index,cumulative_issued_before_atoms,cumulative_burned_before_atoms,remaining_cap_before_atoms,scheduled_reward_atoms,capped_reward_atoms,miner_atoms,staking_budget_atoms,earned_staking_atoms,unearned_staking_atoms,actual_issued_atoms,burn_after_atoms,cumulative_issued_after_atoms,cumulative_burned_after_atoms,outstanding_after_atoms,remaining_cap_after_atoms")
    );
    let mut rows = 0;
    for line in lines {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 18);
        let id = fields[0];
        let value = |column: usize| fields[column].parse::<u64>().unwrap();
        let amount = |column: usize| Amount::from_atomic(value(column));
        let height = value(1);
        let expected_index = if fields[2].is_empty() {
            None
        } else {
            Some(value(2))
        };
        assert_eq!(reward_block_index(height), expected_index, "{id}");
        let mut state = SupplyState::new(amount(3), amount(4)).unwrap();
        assert_eq!(state.remaining_issuance(), amount(5), "{id}");
        let budget = state.block_budget(height);
        assert_eq!(budget.scheduled(), amount(6), "{id}");
        assert_eq!(budget.capped(), amount(7), "{id}");
        assert_eq!(budget.miner(), amount(8), "{id}");
        assert_eq!(budget.staking_budget(), amount(9), "{id}");
        let receipt = state.issue_block(height, amount(10)).unwrap();
        assert_eq!(receipt.budget(), budget, "{id}");
        assert_eq!(receipt.earned_staking(), amount(10), "{id}");
        assert_eq!(receipt.unearned_staking(), amount(11), "{id}");
        assert_eq!(receipt.actual_issued(), amount(12), "{id}");
        state.burn(amount(13)).unwrap();
        assert_eq!(state.cumulative_issued(), amount(14), "{id}");
        assert_eq!(state.cumulative_burned(), amount(15), "{id}");
        assert_eq!(state.outstanding(), amount(16), "{id}");
        assert_eq!(state.remaining_issuance(), amount(17), "{id}");
        rows += 1;
    }
    assert!(rows >= 18);
}
