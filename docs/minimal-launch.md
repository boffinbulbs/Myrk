# Minimum private cash launch

The first release target is a private native cash chain with independently validating nodes, supported mining and confidential checkpoint consensus, a usable payment client and recoverable state. General private smart contracts, confidential asset issuance, the Safe interface and other later applications can follow through separately reviewed protocol upgrades. Their absence does not prevent this smaller release once all base requirements below are complete.

This is a delivery boundary, not an implemented network, selected production genesis or release date. The current workspace has no complete private payment proof, confidential stake service or accepting chain. The [delivery roadmap](delivery-roadmap.md) and [architecture](architecture.md) retain the complete project.

## Required base behavior

| Base responsibility | Required before the corresponding launch claim |
|---|---|
| Private native payments | One complete proof connects the same hidden notes, membership, note owner and real authorization, stable nullifiers, ranges, native asset binding, conservation, policy, output encryption and recovery data |
| Independent validation | Canonical bounded decoding and a complete proof schema/verifier, supported class registry, authenticated expected state, resource checks and rejection of unsupported versions before expensive work |
| Atomic ledger | Global spent state, eligible roots, monetary counters, reward origins, encrypted data, branch identity and checkpoint state commit together and recover consistently after interruption |
| Monetary rules | A selected versioned schedule, cap and allocations, only actually earned rewards, authenticated destinations and origin, burn accounting and no administrative mint |
| Mining and work | Complete child-to-parent commitment binding for the selected supported parent profile, expected child difficulty from preceding state, timestamps, valid branch work and ordinary miner integration |
| Confidential checkpoint consensus | Conserved bond rights, complete authenticated eligible weight, restricted voting authority, quorum/round/liveness rules, durable anti-equivocation history and a reviewed first-activation construction |
| Nodes and synchronization | Independent instances agree on the same valid history, reject invalid/replayed data, survive partitions and restarts and retain the information needed to verify and recover state |
| Basic payment client | Local key handling, private note discovery, real proof construction, private Send/receive, encrypted backup and restoration, with correct pending, finalized and mature status |
| Release evidence | Reproducible builds and whole-system valid/invalid tests, measured resources and leakage, independent review and resolution of material findings |

Native-only application scope does not remove private asset binding or permit a public witness list. Additional asset issuance and programmable policies require their own activated classes. It does not change the authorization primitive, expose witnesses or select a smaller security profile to make a proof fit.

The first client can be a bounded local payment client with reproducible commands. A complete Qt/mobile experience, exchange compatibility, broad service APIs and an explorer can follow. Local scanning, retained encrypted delivery data, backup and restoration are already base requirements. Running a node does not require spending or voting secrets, a hosted prover or an unstated parent full-node dependency.

Protocol pool and developer allocations require real accounting and authenticated authority in the base rules. A later grant interface or external treasury automation is not required for private cash transfers. Deferring those interfaces cannot authorize arbitrary pool spending, substitute an announcement for a completed burn or promise external parent receipts that were not authenticated.

## Features retained for later activation

| Later milestone | Architectural commitment retained now |
|---|---|
| General private smart contracts | Kova's own deterministic private execution and proof model with private inputs/state, explicit public effects, bounded resources and the common ledger's authority/consumption rules |
| Confidential assets and application templates | Versioned policy authority, per-asset conservation, private escrow and application state under the same kernel |
| Private Safe | Protected receiving, delayed requests, restricted recovery cancellation, common pending-right consumption and the separate wallet view |
| Expanded clients and services | Qt/mobile interfaces, scoped viewing, exchange/service APIs and bounded public indexing without exporting spending authority |
| Protocol pool governance | Private eligible voting and bounded authorized grants through the same state, without a privileged mint or automatic consensus rewrite |
| Fast locks and later Aegis | Separately reviewed consensus/availability/consumption rules, never a shortcut around base proof validity or finality |
| Migration and compact history | Explicit cryptographic version transitions, retained recovery and complete historical verification obligations |

The [private contract architecture](private-contracts.md) is a general programmable application target. EVM bytecode compatibility is not required. The [Safe design](private-safe.md) remains a full later milestone, not a wallet label for protection that the chain does not enforce.

## Versioned upgrade rules

Every release has an explicit supported rule set, relation/class registry, resource profile and canonical encodings. A peer-provided label cannot enable an unsupported feature. Before activation, nodes refuse contract, Safe and other unsupported transition types. No placeholder operation returns success.

A later hard fork specifies its exact rules, activation context, old/new block handling, compatibility, tests and recovery behavior before deployment. A wallet flag, developer key or generic governance tally cannot activate new consensus. No activation height or automatic upgrade mechanism is selected here.

Old notes retain their original authenticated meaning, authorization and stable spent identity. A new contract or Safe encoding cannot reinterpret an existing note or reset its nullifier. Moving value into a new policy requires an authorized conservation-preserving transition. Reward creation height, 10080-block maturity, finalized checkpoint requirements, bond restrictions and any pending rights survive supported upgrades.

The retained 120-second monetary reference and prospective 60-second research profiles remain separate versions. Launch requires an explicit production choice and matching genesis/activation/state rules. This scope decision does not choose those economic parameters or define a live migration.

## Evidence sequence and present blocker

1. Complete private payment and confidential stake feasibility, including a proof/parser that fits its justified resources and security assumptions.
2. An actual ledger and consensus implementation with reproducible local multi-node operation using disposable test values, the real validation rules and genuine rejection/recovery behavior.
3. An operator test network with independent validation, partitions, restarts, branch changes, mining/checkpoint interaction and wallet restoration.
4. A minimal public release only after the relevant implementation, privacy, consensus, bootstrap, recovery, resource and independent-review gates pass.

The complete private payment proof and parser remain the dominant construction blocker. The full signature is refused by the current proving class before symbolic collection. The bounded [whole GCM reference](../research/gcm-word-reference/README.md) supplies tested integer correspondence for one necessary operation, not the combined private proof. Finite KEM sampling, same-source constraints, confidential eligibility, authenticated state and bootstrap also remain open.

Production genesis, initial/limiting targets, the live parent profile, authenticated rule registries and the applicable clock policy also require explicit selection and validation. Neither the numerical work modules nor a synthetic initialized state supplies that authority.

The smaller release removes later application dependencies from the launch critical path. It does not turn separate component successes into a working chain or waive a base gate.
