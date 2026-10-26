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
| Mining and finality | Supported parent adapter, AuxPoW, difficulty, branch selection and stake lifecycle | Compatible results from the same work, tamper/replay rejection, partition/reorg/hash change tests |
| Wallet and recovery | Private Send, local validation/proving, restricted voting, backup/restore and metadata controls | Measurements on named hardware, restore/pruning/reorg tests and observer leakage report |
| Treasury simulation | Durable receipts, orders, withdrawals, reconciliation and native burns | Restart/deduplication correctness, failure cases and no consumption of worker funds |
| Ecosystem governance research | Separate native fund rules, private eligible stake ballots, verifiable tally, desktop flow and grant payment lifecycle | Snapshot/weight/duplicate vote proofs, quorum and capture simulations, bounded spending, malformed proposal rejection and private data review |
| Public test network | Independent operators, pools and adversarial trials | Reproduced validation, payouts, resource limits, concentration/availability observations |
| Release evaluation | Independent composition/implementation reviews and reproducible distributions | Material findings resolved and relevant checks repeated |

## Measurement discipline

Separate analytical schedule projections from measured code performance. Record workload, machine, operating system, toolchain, dependency versions, parameters, repetitions, resource use and uncertainty. Retain raw data and generation commands for published figures.

The [private protocol research specification](research-target.md) defines the formal relations and privacy evaluation gates. The [ecosystem governance specification](governance.md) records a separate research extension. Governance funding and the 60/30/10 allocation remain outside the implemented monetary profile until their accounting, consensus, privacy, and activation rules are complete and independently checked.

## Release gates

Private PQ transaction and staking constructions must pass their feasibility and review gates before production interfaces that depend on them are frozen. The bootstrap, genesis, difficulty, finality, withdrawal and recovery rules need complete specifications. Source licenses and dependency notices must be inventoried. No release date or security audit completion is implied by a development milestone.
