# Wallet, disclosure and recovery

## Local operation

The desktop architecture targets a Qt interface with Rust wallet, node and execution boundaries. The wallet implementation must start local validation and note scanning, expose background operation after close and login startup as explicit settings, and distinguish synchronization, inclusion, confirmation depth, checkpoint finality, and staking readiness. These are interface requirements; no wallet implementation is present.

The normal Send path must construct a private transaction. A separate public payment pool or optional privacy toggle is not part of the design.

## Authority separation

Spending, viewing, recipient discovery/encryption, recovery, and restricted staking authority require distinct domains and documented capabilities. An online voting service must not gain unrestricted spend/withdraw authority. Delegation must describe operator influence, availability, privacy leakage, and any misconduct consequences.

Running a validating node alone does not earn a subsidy. Eligible stake and compatible mining work have separate protocol duties.

## Recovery data

The protocol must define encrypted note/application-data availability and the backup material necessary for a complete restore. A recovery secret alone cannot recover essential offchain data that was never made available.

Pruning removes selected historical block data only after validation and must retain live consensus state. It must not silently destroy the only recovery source for private notes. Tests include missing archives, stale backups, interrupted writes, duplicates, reorganizations and restored signers on multiple devices.

## Disclosure and metadata

Scoped viewing and payment proofs are deliberate disclosures. They do not grant general spending access or establish a mandatory viewing authority over other users.

Local scanning, minimized remote queries, encrypted transport where appropriate, anonymous relay support, careful logs, padding/resource classes, and traffic analysis have distinct threat models. A private ledger alone does not hide every IP address, timing pattern, or fact already known to a counterparty.
