# Node operation and service integration

Kova targets a custom ledger and consensus implementation with reviewed cryptographic dependencies. The current workspace contains research components and specifications. A network node, wallet RPC service and exchange integration are not implemented yet. Complete private payment and confidential stake feasibility precede their dependent interfaces.

## Independent node operation

A regular node independently verifies the supported chain rules and maintains authenticated state. Mining, stake participation, a funded wallet and application hosting are separate roles. A node operator can support verification and peer synchronization without enabling those services.

| Mode | Responsibilities | Additional authority |
|---|---|---|
| Regular validating node | Verify blocks, private proofs, work, checkpoints, state transitions and resource limits, persist state and synchronize peers | No wallet spending key or stake voting key |
| Mining integration | Build compatible work candidates and submit supported auxiliary witnesses | Mining payout configuration and applicable parent node access |
| Stake service | Verify eligible duties and produce permitted checkpoint or governance messages | Restricted stake authority under the stake lifecycle rules |
| Wallet service | Discover owned notes, construct local witnesses and private proofs, manage restoration data | Explicitly scoped viewing, recovery or spending authority |

Roles may share a process after their interfaces are defined, but their permissions remain separate. The Qt wallet can start a local validation node with explicit background and resource settings. A server can run validation without the desktop interface. Node operation alone does not earn mining or staking rewards.

Public peer messages and an ordinary node RPC must not require plaintext note amounts, hidden input commitments, private authentication paths or owner keys. Private wallet operations belong to an authenticated local or explicitly authorized wallet boundary. Logs, metrics, crash reports and remote queries must preserve that separation.

The [RPC data specification](rpc-and-data.md) defines public chain retrieval for explorers and synchronization, scoped wallet and exchange recovery, local private membership construction, submission identity and versioned receipt states. Public APIs expose verification data while each service recovers its own private information through authorized capabilities.

The first server trials require multiple independent instances, restart and synchronization checks, malformed peers, partitions, resource exhaustion, branch changes and consistent atomic rollback. Full validation and any later pruning mode must retain the state and recovery availability obligations in the [wallet specification](wallet.md).

The later [Aegis state architecture](aegis.md) adds verification and synchronization of a certified private sequence and its mined recording prefix. A normal node would verify both without a voting or spending key. Restart and pruning must retain outstanding certified payloads and prevent duplicate state application during recording. This additional protocol is not implemented or required for the first server trial milestone.

## Service and exchange boundary

Service integration is an engineering target. An exchange independently decides whether and when to support an asset. Protocol software cannot guarantee admission, liquidity or a listing date.

A service needs a documented network identifier, canonical address codec, stable transaction and node APIs, reproducible node builds, supported upgrade behavior and a private wallet integration. The main address namespace target remains `kova`, with versioned types and checksums still subject to the [address specification](wallet.md#address-namespace).

| Interface | Required behavior |
|---|---|
| Deposit discovery | Scan notes addressed to the service using its own scoped discovery and viewing authority, with resumable progress and authenticated creation context |
| Deposit accounting | Bind each credit to one owned note and account assignment, distinguish pending and finalized receipts, and prevent duplicate credit after restart or replay |
| Chain status | Report synchronization, authenticated tip, checkpoint certificate, rule version and branch changes separately |
| Withdrawals | Construct and prove normal private payments locally, enforce spendable inputs and broadcast canonical transactions without exporting private witnesses |
| Reconciliation | Recover scan progress, credit records, withdrawals and relevant branch state consistently after interruption or reorganization |
| Operations | Document key separation, encrypted backups, bounded authenticated RPC, fee handling, upgrade procedure and data retention |

Viewing and deposit monitoring must not confer unrestricted withdrawal authority. A service can view its own deposit data under the capability model. No global viewing key or transparent payment pool is required for integration. Spending authority and any external account trading system remain separate from node validation.

A service must define its credit policy against the actual consensus construction. A fast payment lock is distinct from inclusion and checkpoint finality. Mining and staking reward maturity also remains applicable to those reward classes. An ordinary payment does not acquire a fresh seven day delay. Missing finality, unavailable data or unsupported rule versions must remain explicit service states.

Acceptance tests use synthetic deposits and withdrawals. They cover duplicate scans, note reassignment attempts, repeated withdrawal submission, fee changes, wallet restoration, partial synchronization, provisional branch changes, unavailable quorum and upgrade boundaries. Production custody, live trading and external fund transfers are outside the current development scope.

## Delivery boundary

The [delivery roadmap](delivery-roadmap.md) places independent server agreement and private wallet recovery before service integration claims. The [private Safe](architecture.md#private-wallet-safe) remains a separate protected wallet application, with chain enforced policy and a later interface milestone. Service compatibility cannot bypass its delayed withdrawal or restricted recovery rules.
