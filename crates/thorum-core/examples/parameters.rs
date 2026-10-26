use thorum_core::{
    SupplyState, ATOMIC_DECIMALS, BLOCKS_PER_SUBSIDY_PERIOD, BLOCK_TARGET_SECONDS,
    FIRST_LONG_TERM_HEIGHT, ISSUANCE_CAP, SUBSIDY_PERIODS, TICKER,
};

fn main() {
    println!("Thorum development parameters ({TICKER})");
    println!("Atomic decimals: {ATOMIC_DECIMALS}");
    println!("Cumulative issuance ceiling: {ISSUANCE_CAP} {TICKER}");
    println!("Target spacing: {BLOCK_TARGET_SECONDS} seconds");
    println!(
        "Subsidy period: {BLOCKS_PER_SUBSIDY_PERIOD} blocks; frozen periods: {SUBSIDY_PERIODS}"
    );
    let state = SupplyState::genesis();
    for height in [0, 1, 21_900, 21_901, FIRST_LONG_TERM_HEIGHT, u64::MAX] {
        let budget = state.block_budget(height);
        println!(
            "height {height}: subsidy={} miner={} staking_budget={} {TICKER}",
            budget.scheduled(),
            budget.miner(),
            budget.staking_budget()
        );
    }
    println!("Staking budgets are issued only when earned; burns never reopen the ceiling.");
}
