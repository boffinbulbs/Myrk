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
    let columns: Vec<_> = lines.next().unwrap().split(',').collect();
    let required = [
        "id",
        "height",
        "reward_block_index",
        "cumulative_issued_before_atoms",
        "cumulative_burned_before_atoms",
        "remaining_cap_before_atoms",
        "scheduled_reward_atoms",
        "capped_reward_atoms",
        "miner_atoms",
        "staking_budget_atoms",
        "protocol_pool_atoms",
        "development_maintenance_atoms",
        "earned_staking_atoms",
        "unearned_staking_atoms",
        "actual_issued_atoms",
        "burn_after_atoms",
        "cumulative_issued_after_atoms",
        "cumulative_burned_after_atoms",
        "outstanding_after_atoms",
        "remaining_cap_after_atoms",
    ];
    assert_eq!(columns.len(), required.len());
    for name in required {
        assert_eq!(columns.iter().filter(|column| **column == name).count(), 1);
    }
    let mut rows = 0;
    for line in lines {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), columns.len());
        let field = |name: &str| {
            let column = columns.iter().position(|column| *column == name).unwrap();
            fields[column]
        };
        let id = field("id");
        let value = |name: &str| field(name).parse::<u64>().unwrap();
        let amount = |name: &str| Amount::from_atomic(value(name));
        let height = value("height");
        let expected_index = if field("reward_block_index").is_empty() {
            None
        } else {
            Some(value("reward_block_index"))
        };
        assert_eq!(reward_block_index(height), expected_index, "{id}");
        let mut state = SupplyState::new(
            amount("cumulative_issued_before_atoms"),
            amount("cumulative_burned_before_atoms"),
        )
        .unwrap();
        assert_eq!(
            state.remaining_issuance(),
            amount("remaining_cap_before_atoms"),
            "{id}"
        );
        let budget = state.block_budget(height);
        assert_eq!(budget.scheduled(), amount("scheduled_reward_atoms"), "{id}");
        assert_eq!(budget.capped(), amount("capped_reward_atoms"), "{id}");
        assert_eq!(budget.miner(), amount("miner_atoms"), "{id}");
        assert_eq!(
            budget.staking_budget(),
            amount("staking_budget_atoms"),
            "{id}"
        );
        assert_eq!(
            budget.protocol_pool(),
            amount("protocol_pool_atoms"),
            "{id}"
        );
        assert_eq!(
            budget.development_maintenance(),
            amount("development_maintenance_atoms"),
            "{id}"
        );
        let receipt = state
            .issue_block(height, amount("earned_staking_atoms"))
            .unwrap();
        assert_eq!(receipt.budget(), budget, "{id}");
        assert_eq!(receipt.miner(), amount("miner_atoms"), "{id}");
        assert_eq!(
            receipt.protocol_pool(),
            amount("protocol_pool_atoms"),
            "{id}"
        );
        assert_eq!(
            receipt.development_maintenance(),
            amount("development_maintenance_atoms"),
            "{id}"
        );
        assert_eq!(
            receipt.earned_staking(),
            amount("earned_staking_atoms"),
            "{id}"
        );
        assert_eq!(
            receipt.unearned_staking(),
            amount("unearned_staking_atoms"),
            "{id}"
        );
        assert_eq!(
            receipt.actual_issued(),
            amount("actual_issued_atoms"),
            "{id}"
        );
        state.burn(amount("burn_after_atoms")).unwrap();
        assert_eq!(
            state.cumulative_issued(),
            amount("cumulative_issued_after_atoms"),
            "{id}"
        );
        assert_eq!(
            state.cumulative_burned(),
            amount("cumulative_burned_after_atoms"),
            "{id}"
        );
        assert_eq!(
            state.outstanding(),
            amount("outstanding_after_atoms"),
            "{id}"
        );
        assert_eq!(
            state.remaining_issuance(),
            amount("remaining_cap_after_atoms"),
            "{id}"
        );
        rows += 1;
    }
    assert!(rows >= 20);
}
