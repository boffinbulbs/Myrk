# Development parameters

These values define the current reference profile. A production genesis and consensus encoding have not been released.

| Parameter | Value |
|---|---:|
| Name | Thorum |
| Ticker | THM |
| Atomic units per THM | 100,000,000 |
| Cumulative issuance ceiling | 63,000,000 THM |
| Average target block interval | 120 seconds |
| Checkpoint test interval | 5 blocks |
| Subsidy period | 21,900 consecutive non genesis block heights |
| Declining periods | 240 |
| Initial maximum subsidy | 16 THM |
| Long reward phase | 0.5 THM until issuance allowance is exhausted |
| Miner allocation | floor(7 * available subsidy / 10) atomic units |
| Stake budget | available subsidy minus miner allocation |
| Parent work profile | Equihash (200,9), supported parent format |

Genesis has height zero and no subsidy. Every height h >= 1 has reward index h - 1, independently of actual issuance. Schedule generation, exact integer vectors, rounding and projection assumptions are documented in [the reference model](../research/emission/README.md). The implementation is in [emission.rs](../crates/thorum-core/src/emission.rs), with an executable [parameter example](../crates/thorum-core/examples/parameters.rs).

Cumulative issued value and completed burned value are separate counters. Outstanding monetary value is issued minus burned. Burns do not reopen the issuance ceiling. Scheduled stake budget is not issued without valid duty evidence. The core accounting API accepts an explicitly earned amount, while the future kernel must validate its authorization.

The profile's theoretical full issuance projections are analytical results, not a launch distribution, price model, or guarantee that all stake allocations are earned. No premine is included in those projections. Bootstrap omissions, slower block production and unearned allocations change actual issuance.

The [ecosystem governance extension](governance.md) studies a separate 60/30/10 allocation. It does not alter this executable 70/30 profile, the frozen reference artifacts, or the cumulative issuance ceiling.

Production difficulty adjustment, stake threshold, finality/quorum rounds, lifecycle delays, bootstrap activation, resource limits, fee policy, recovery data availability, treasury destination updates and genesis configuration remain open specification items.
