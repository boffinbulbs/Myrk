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
        "Subsidy period: {BLOCKS_PER_SUBSIDY_PERIOD} blocks. Frozen periods: {SUBSIDY_PERIODS}"
    );
    let state = SupplyState::genesis();
    for height in [0, 1, 21_900, 21_901, FIRST_LONG_TERM_HEIGHT, u64::MAX] {
        let budget = state.block_budget(height);
        println!(
            "height {height}: subsidy={} miner={} staking_budget={} protocol_pool={} development_maintenance={} {TICKER}",
            budget.scheduled(),
            budget.miner(),
            budget.staking_budget(),
            budget.protocol_pool(),
            budget.development_maintenance()
        );
    }
    println!("Profile: 60/20/10/10 with every atomic remainder assigned to the miner.");
    println!("Pool and development allocations count as issued immediately. No sunset height is defined.");
    println!("Staking budgets are issued only when earned. Burns never reopen the ceiling.");
}
