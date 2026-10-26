# Implementation milestones

## Initial executable boundary

The current milestone is deterministic monetary accounting with an independent reference model and reproducible research artifacts. It establishes arithmetic and module boundaries. It does not implement a private transaction system or active consensus network.

## Milestones and evidence

| Milestone | Deliverable | Acceptance evidence |
|---|---|---|
| Accounting | Atomic units, frozen subsidy table, allocation, cap, actual issuance and burns | Boundary/rejection/conservation tests and independent vectors |
| Private transition feasibility | One fully specified and executable private payment relation | Authorization, ranges, conservation, nullifier binding, malformed proof rejection, measured costs and security rationale |
| Private stake feasibility | Confidential eligible weight and checkpoint support | No duplicate weight/reuse, epoch/domain binding, PQ assumptions, bounded certificates and adversarial simulations |
| Ledger kernel | State roots, global nullifiers, canonical decoding, fees, issuance integration and rollback | Independent node agreement, inflation rejection, replay rejection and atomic persistence |
| Applications | Timed escrow and confidential asset policy | Successful release/refund, race rejection and unauthorized mint/burn rejection |
| Mining and finality | Supported parent adapter, AuxPoW, difficulty, branch selection and stake lifecycle | Compatible same-work results, tamper/replay rejection, partition/reorg/hash-change tests |
| Wallet and recovery | Private Send, local validation/proving, restricted voting, backup/restore and metadata controls | Named-hardware measurements, restore/pruning/reorg tests and observer leakage report |
| Treasury simulation | Durable receipts, orders, withdrawals, reconciliation and native burns | Restart/deduplication correctness, failure cases and no worker-fund consumption |
| Public test network | Independent operators, pools and adversarial trials | Reproduced validation, payouts, resource limits, concentration/availability observations |
| Release evaluation | Independent composition/implementation reviews and reproducible distributions | Material findings resolved and relevant checks repeated |

## Measurement discipline

Separate analytical schedule projections from measured code performance. Record workload, machine, operating system, toolchain, dependency versions, parameters, repetitions, resource use and uncertainty. Retain raw data and generation commands for published figures.

## Release gates

Private PQ transaction and staking constructions must pass their feasibility and review gates before production-dependent interfaces are frozen. The bootstrap, genesis, difficulty, finality, withdrawal and recovery rules need complete specifications. Source licenses and dependency notices must be inventoried. No release date or security audit completion is implied by a development milestone.
