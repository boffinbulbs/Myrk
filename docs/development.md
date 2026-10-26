# Implementation milestones

## Initial executable boundary

The current executable scope is deterministic monetary accounting and an isolated [primitive laboratory](crypto-lab.md), with reference vectors and reproducible research artifacts. It establishes arithmetic, primitive integration, and module boundaries. It does not implement a private transaction system or active consensus network.

## Milestones and evidence

| Milestone | Deliverable | Acceptance evidence |
|---|---|---|
| Accounting | Atomic units, frozen subsidy table, allocation, cap, actual issuance and burns | Boundary/rejection/conservation tests and independent vectors |
| Primitive feasibility laboratory | Isolated operations for signing, verification, encapsulation, decapsulation and authenticated encryption | Exact backend versions and parameters, real primitive operations, altered input rejection, reproducible size and cost measurements |
| Private transition feasibility | One fully specified and executable private payment relation | Authorization, ranges, conservation, nullifier binding, malformed proof rejection, measured costs and security rationale |
| Private stake feasibility | Confidential eligible weight and checkpoint support | No duplicate weight/reuse, epoch/domain binding, PQ assumptions, bounded certificates and adversarial simulations |
| Ledger kernel | State roots, global nullifiers, canonical decoding, fees, issuance integration and rollback | Independent node agreement, inflation rejection, replay rejection and atomic persistence |
| Applications | Timed escrow and confidential asset policy | Successful release/refund, race rejection and unauthorized mint/burn rejection |
| Mining and finality | Supported parent adapter, AuxPoW, difficulty, branch selection and stake lifecycle | Compatible results from the same work, tamper/replay rejection, partition/reorg/hash change tests |
| Wallet and recovery | Private Send, local validation/proving, restricted voting, backup/restore and metadata controls | Measurements on named hardware, restore/pruning/reorg tests and observer leakage report |
| Treasury simulation | Durable receipts, orders, withdrawals, reconciliation and native burns | Restart/deduplication correctness, failure cases and no consumption of worker funds |
| Ecosystem governance research | Separate native fund rules, private eligible stake ballots, verifiable tally, desktop flow and grant payment lifecycle | Snapshot/weight/duplicate vote proofs, quorum and capture simulations, bounded spending, malformed proposal rejection and private data review |
| Combined synthetic demonstration | Payment, escrow, assets, recovery, auxiliary work, confidential stake and simulated treasury execution | One reproducible checklist with valid and invalid cases, durable reconciliation and no real funds |
| Public test network | Independent operators, pools and adversarial trials | Reproduced validation, payouts, resource limits, concentration/availability observations |
| Release evaluation | Independent composition/implementation reviews and reproducible distributions | Material findings resolved and relevant checks repeated |

The primitive laboratory is a narrower prerequisite to relation feasibility. A successful signature, KEM round trip, or authenticated encryption test establishes only the tested primitive behavior. Conformance claims require applicable reference vectors and recorded coverage. Such results do not complete a private payment relation, confidential stake eligibility, recipient anonymity, proof soundness, or a composed post quantum security argument.

Both complete private payment feasibility and confidential stake feasibility must pass before ledger kernel integration can satisfy its milestone. The two feasibility tracks may progress independently. Neither can be replaced by monetary tests or a primitive laboratory result. Their exact constructions, assumptions, malformed input behavior, and measured resource requirements must be recorded before dependent interfaces are frozen.

## First application demonstration

The first application demonstration must execute timed private escrow and confidential asset transitions through the common ledger relation. Escrow release and refund must consume the same spending right under the canonical expiry boundary. Asset issuance, transfer, and burn must preserve per asset conservation and policy authority. Local execution and proof generation must be reproducible, with rejection cases for conflicting escrow paths, expired release, unauthorized minting, asset substitution, range violations, and malformed proofs.

## Combined demonstration checklist

The first complete demonstration must cover all of the following in a controlled environment. This checklist records required evidence and is not a claim that the demonstration exists.

1. A private native payment with change, local witness and proof construction, authorized consumption, conservation, recipient recovery, and rejection of a repeated spend.
2. Private escrow release and expiry/refund using one committed spending right, with canonical boundary and conflicting submission tests.
3. Confidential fungible asset issuance, transfer, and burn under an explicit policy, including rejection of unauthorized inflation and asset substitution.
4. Recovery of private notes and application state from declared backup material and retained encrypted data, including missing or corrupted data and branch changes.
5. Acceptance of a valid auxiliary witness and rejection of altered commitments, unsupported parent context, malformed encodings, and replayed work.
6. Confidential eligible stake with chain, epoch, and state binding, with rejection of reused weight after spending, withdrawal, delegation changes, or reorganization.
7. A mock treasury cycle covering receipt, deposit, purchase, partial execution, withdrawal, native receipt, and burn. Restart, duplicate events, failed operations, and reconciliation must preserve worker liabilities and distinguish completed burns from orders or announcements.

Treasury execution in this demonstration uses synthetic records or a sandbox with no real funds. It does not place live orders, transfer external assets, or require production spending keys. Every checklist item must retain its input fixtures, exact reproduction commands, expected valid and invalid outcomes, raw results, and implementation versions. The demonstration does not replace independent review or establish production privacy.

The combined demonstration uses the implemented 70/30 monetary profile. Optional ecosystem governance is separately gated and is not a prerequisite for demonstrating the core protocol. Its research allocation cannot silently replace the executable profile.

## Measurement discipline

Separate analytical schedule projections from measured code performance. Record workload, machine, operating system, toolchain, dependency versions, parameters, repetitions, resource use and uncertainty. Retain raw data and generation commands for published figures.

The [private protocol research specification](research-target.md) defines the formal relations and privacy evaluation gates. The [ecosystem governance specification](governance.md) records a separate research extension. Governance funding and the 60/30/10 allocation remain outside the implemented monetary profile until their accounting, consensus, privacy, and activation rules are complete and independently checked.

## Release gates

Private PQ transaction and staking constructions must pass their feasibility and review gates before production interfaces that depend on them are frozen. The bootstrap, genesis, difficulty, finality, withdrawal and recovery rules need complete specifications. Source licenses and dependency notices must be inventoried. No release date or security audit completion is implied by a development milestone.
