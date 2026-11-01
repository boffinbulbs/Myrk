# Development parameters

The selected testnet target and retained executable accounting reference are separate profiles. A production genesis and consensus encoding have not been released.

Emission values are development parameters rather than frozen production commitments. A production selection or later change requires an explicit version, integer schedule, allocation rules and independent vectors. The retained reference remains reproducible while that selection is open.

## Testnet development target

| Parameter | Target |
|---|---|
| Average block interval | 60 seconds |
| Checkpoint opportunity interval | Four blocks |
| Mining and staking reward maturity | 10080 blocks per newly issued reward |
| Ordinary incoming payments | Acceptance and checkpoint finality rules without a seven day reward delay |
| Initial onward spending | After checkpoint finality |
| Fast payment indication | A valid private payment lock certificate, separately from finality |

The [protocol safety requirements](protocol-extensions.md) define the timing boundaries, private Safe, migration, compact history and payment capacity targets. The maturity delay does not define staking principal withdrawal or pool/developer spendability. The testnet schedule must adjust subsidy amounts and period lengths together before implementation. Current cryptographic components do not implement these consensus services.

The later [Aegis protocol](aegis.md) evaluates certified spending before mining through a separate consensus version. Its initial latency experiment target is approximately eight seconds after submission of a complete valid transaction, excluding local proving and recipient synchronization. No such latency has been measured. Aegis activation, committee and backlog limits are unset. It does not change the base targets above or the first chain scope.

## Retained accounting reference

The values below describe the existing executable monetary model and its historical figures. Its 120 second cadence is retained for reproducibility. The new testnet timing target is documented separately above.

| Parameter | Value |
|---|---:|
| Name | Kova |
| Ticker | THM |
| Atomic units per THM | 100,000,000 |
| Cumulative issuance ceiling | 63,000,000 THM |
| Accounting reference block interval | 120 seconds |
| Subsidy period | 21,900 consecutive non genesis block heights |
| Declining periods | 240 |
| Initial maximum subsidy | 16 THM |
| Long reward phase | 0.5 THM until issuance allowance is exhausted |
| Miner allocation | floor(6 * available subsidy / 10) plus every atomic rounding remainder |
| Stake budget | floor(2 * available subsidy / 10) atomic units |
| Protocol pool allocation | floor(available subsidy / 10) atomic units |
| Development maintenance allocation | floor(available subsidy / 10) atomic units, designated for the project developer |
| Parent work profile | Equihash (200,9), supported parent format |

Genesis has height zero and no subsidy. Every height h >= 1 has reward index h - 1, independently of actual issuance. Schedule generation, exact integer vectors, rounding and projection assumptions are documented in [the reference model](../research/emission/README.md). The implementation is in [emission.rs](../crates/thorum-core/src/emission.rs), with an executable [parameter example](../crates/thorum-core/examples/parameters.rs).

Cumulative issued value and completed burned value are separate counters. Outstanding monetary value is issued minus burned. Burns do not reopen the issuance ceiling. The [allocation specification](subsidy-allocation.md) defines the complete 60/20/10/10 integer rule. Its first 16 THM budget allocates 9.6 THM to miners, 3.2 THM to staking, 1.6 THM to the protocol pool, and 1.6 THM to development maintenance. Every rounding remainder, including the final available atom, belongs to the miner.

Only explicitly earned staking value is issued. Unearned staking remains unissued. Pool and developer amounts count as issued immediately even while unspent. The core calculates amounts and supply counters without creating payout notes or authenticating destinations. The future kernel must validate duty evidence, destination authority, accepted block context, and atomic state changes. These subsidy shares do not determine fee allocation.

The profile's theoretical full issuance projections are analytical results, not a launch distribution, price model, or guarantee that all stake allocations are earned. No premine is included in those projections. Bootstrap omissions, slower block production and unearned allocations change actual issuance.

The [protocol pool governance research](governance.md) addresses spending and ballots for the pool allocation. It is separate from developer credits and the operator external treasury. Pool governance is unimplemented. The current subsidy profile supersedes earlier allocation profiles without changing the cumulative issuance ceiling.

The development maintenance share is temporary. Retirement requires a future consensus hard fork after work completion and community handover, with its future 10 percent redistributed to mining and staking. Completion criteria, the handover and change process, activation height, and successor miner/stake ratio remain unresolved. The pool share remains 10 percent unless a separate explicit change modifies it. Existing legitimately earned credits are unaffected. There is no automatic sunset or milestone key in code.

Production difficulty adjustment, stake threshold, finality/quorum rounds, lifecycle delays, bootstrap activation, resource limits, fee policy, recovery data availability, treasury destination updates and genesis configuration remain open specification items.

The [prospective child work policy](child-work-policy.md) selects an exact integer ASERT experiment at the 60 second target. Its arithmetic has a bounded independent reference. Production genesis, initial and easiest targets, authenticated history, clock source and activation remain unselected. The executable 120 second monetary reference is unchanged.
